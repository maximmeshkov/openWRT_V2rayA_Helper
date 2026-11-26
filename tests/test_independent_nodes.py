"""Exercise per-member HTTPS, profile rotation and an established client stream."""
import json
import os
from pathlib import Path
import socket
from socketserver import StreamRequestHandler, ThreadingTCPServer
import ssl
import subprocess
from threading import Event, Thread
import time
from unittest.mock import patch

from test_monitor import MonitorHarness, assignment, profile, rows


class NodeFixture(MonitorHarness):
    def setUp(self):
        super().setUp()
        self.config = Path(self.tmp.name, "core.json")
        cert, key = [Path(self.tmp.name, name) for name in ("ca.pem", "key.pem")]
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-subj", "/CN=check.invalid", "-addext",
                        "subjectAltName=DNS:check.invalid", "-keyout", key, "-out", cert],
                       check=True, stderr=subprocess.DEVNULL)
        self.cert = str(cert)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        self.hold = Event()
        self.waiting = Event()
        self.release = Event()
        self.seen = []
        self.auth_failures = []
        fixture = self

        class Socks(StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(6)
                if self.rfile.read(1) != b"\x05":  # separate TCP endpoint checks
                    return
                methods = self.rfile.read(self.rfile.read(1)[0])
                if 2 not in methods:
                    return
                self.wfile.write(b"\x05\x02")
                if self.rfile.read(1) != b"\x01":
                    return
                user = self.rfile.read(self.rfile.read(1)[0])
                password = self.rfile.read(self.rfile.read(1)[0])
                if (user, password) != (b"fixture", b"correct"):
                    fixture.auth_failures.append(time.monotonic())
                    self.wfile.write(b"\x01\x01")
                    return
                self.wfile.write(b"\x01\x00")
                if self.rfile.read(4) != b"\x05\x01\x00\x03":
                    return
                host = self.rfile.read(self.rfile.read(1)[0])
                port = int.from_bytes(self.rfile.read(2), "big")
                self.wfile.write(b"\x05\x00\x00\x01" + bytes(6))
                if host == b"session.invalid" and port == 1234:
                    self.connection.settimeout(60)
                    while line := self.rfile.readline():
                        self.wfile.write(line)
                    return
                if (host, port) != (b"check.invalid", 443):
                    return
                try:
                    with tls.wrap_socket(self.connection, server_side=True) as s, s.makefile("rb") as request:
                        if request.readline().split()[:2] != [b"GET", b"/generate_204"]:
                            return
                        while request.readline() not in (b"\r\n", b""):
                            pass
                        fixture.seen.append((host, port))
                        if fixture.hold.is_set():
                            fixture.waiting.set()
                            fixture.release.wait(5)
                        s.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                except (ssl.SSLError, OSError):
                    pass  # The daemon may cancel an in-flight request.

        self.socks = ThreadingTCPServer(("127.0.0.1", 0), Socks)
        self.socks.daemon_threads = True
        self.addCleanup(self.socks.server_close)
        self.addCleanup(self.socks.shutdown)
        self.addCleanup(self.release.set)
        Thread(target=self.socks.serve_forever, daemon=True).start()
        self.port = self.socks.server_address[1]

    def configure(self, entries):
        """All profiles deliberately share a physical IP and TCP port."""
        outbounds = [{"tag": name, "protocol": "socks", "settings": {"servers": [{
            "address": "127.0.0.1", "port": self.port,
            "users": [{"user": "fixture", "pass": password}]}]}} for name, _, password in entries]
        with self.api.lock:
            update = self.config.with_suffix(".next")
            update.write_text(json.dumps({"outbounds": outbounds, "routing": {"rules": []}}))
            update.replace(self.config)
            self.api.names = [name for name, _, _ in entries]
            # v2rayA assigns these IDs from the one-based index of the complete
            # server list, which also contains saved, unassigned profiles.
            self.api.servers = [profile(n, f"Profile {n}", f"127.0.0.1:{self.port}", "socks5")
                                for n in range(1, max(n for _, n, _ in entries) + 1)]
            self.api.connected = [assignment(name, n) for name, n, _ in entries]

    def existing_client(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=8)
        self.addCleanup(sock.close)
        stream = sock.makefile("rwb", buffering=0)
        self.addCleanup(stream.close)
        stream.write(b"\x05\x01\x02")
        self.assertEqual(stream.read(2), b"\x05\x02")
        stream.write(b"\x01\x07fixture\x07correct")
        self.assertEqual(stream.read(2), b"\x01\x00")
        stream.write(b"\x05\x01\x00\x03\x0fsession.invalid\x04\xd2")
        self.assertEqual(stream.read(10), b"\x05\x00\x00\x01" + bytes(6))
        return stream


class IndependentNodes(NodeFixture):
    def test_unused_members_credential_change_removal_and_inflight_result(self):
        keep, drop, new = "Произвольный тег", "Unused Side", "Добавлен при работе"
        self.configure([(keep, 1, "correct"), (drop, 2, "wrong")])
        live = self.existing_client()

        def echo(message):
            live.write(message)
            self.assertEqual(live.readline(), message)

        def sample(s, tag):
            members = rows(s).get(tag, {}).get("members", [])
            return members[0].get("https", {}) if members else {}

        echo(b"before probes\n")
        # Trust applies only to this process tree, including qemu-user. The
        # production binary performs normal chain and name verification.
        with patch.dict(os.environ, SSL_CERT_FILE=self.cert):
            self.start("--node-url", "https://check.invalid/generate_204", "--node-code", "204",
                       "--node-timeout", "3", "--node-interval", "1", "--xray-config", str(self.config))
        first = self.wait_for(lambda s: sample(s, keep).get("state") == "ok" and
                              sample(s, drop).get("state") == "error", timeout=14)
        self.assertEqual(sample(first, keep)["http_code"], 204)
        self.assertTrue(self.seen)
        self.assertEqual(rows(first)[drop]["members"][0]["server"]["state"], "ok")
        self.hold.set()
        self.assertTrue(self.waiting.wait(8), "no repeat HTTPS check on working profile")
        echo(b"while old check is in flight\n")
        # Keep the same name, API id, address and TCP port but rotate the
        # credentials. The just-completing response belongs to the old profile.
        self.configure([(new, 3, "correct"), (keep, 1, "rotated")])
        self.release.set()
        changed = self.wait_for(lambda s: set(rows(s)) == {new, keep}, timeout=14)
        self.assertNotEqual(sample(changed, keep).get("state"), "ok")
        final = self.wait_for(lambda s: sample(s, new).get("state") == "ok" and
                              sample(s, keep).get("state") == "error", timeout=14)
        self.assertEqual(sample(final, new)["http_code"], 204)
        self.assertNotIn("correct", self.output.read_text())
        self.assertNotIn("rotated", self.output.read_text())
        self.configure([(new, 3, "correct")])
        self.wait_for(lambda s: set(rows(s)) == {new} and sample(s, new).get("state") == "ok", timeout=14)
        self.assertEqual(set(self.api.paths), {"/ui/api/outbounds", "/ui/api/touch"})
        echo(b"same established connection after removal\n")
