"""Optional loopback integration with a real core. Set V2RAYA_HELPER and
V2RAYA_TEST_XRAY to the native helper and an Xray binary before unittest
discovery. The helper checks each server through its own probe core."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

import test_monitor as fixtures

UUID = "27370a4b-3145-4685-b3c7-005cb232b92a"


def free_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def probe_cores(binary):
    """Processes of this binary started the way the helper starts its probe core."""
    found = []
    for entry in Path("/proc").iterdir():
        try:
            if entry.name.isdigit() and Path(entry, "exe").resolve() == binary and \
                    Path(entry, "cmdline").read_bytes().split(b"\0")[1:4] == [b"run", b"-c", b"stdin:"]:
                found.append(int(entry.name))
        except OSError:
            pass
    return found


@unittest.skipUnless(os.environ.get("V2RAYA_TEST_XRAY"), "requires a local Xray test binary")
class NodeXrayTest(fixtures.MonitorHarness):
    def test_https_through_a_real_probe_core(self):
        core = Path(os.environ["V2RAYA_TEST_XRAY"]).resolve()
        root = Path(self.tmp.name)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "1", "-nodes",
                        "-subj", "/CN=outer.test", "-addext", "subjectAltName=DNS:outer.test,IP:127.0.0.1",
                        "-keyout", key, "-out", cert], check=True, stderr=subprocess.DEVNULL)
        visits = []

        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                visits.append(self.path)
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        https = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        https.socket = context.wrap_socket(https.socket, server_side=True)
        threading.Thread(target=https.serve_forever, daemon=True).start()
        self.addCleanup(https.server_close)
        self.addCleanup(https.shutdown)

        # One real core plays both servers. No TLS to them: xray-core 26 refuses
        # allowInsecure, and the origin's own TLS is what libcurl verifies.
        vless_port, vmess_port = free_port(), free_port()
        server = {"log": {"loglevel": "none"}, "outbounds": [{"protocol": "freedom"}], "inbounds": [
            {"listen": "127.0.0.1", "port": vless_port, "protocol": "vless",
             "settings": {"decryption": "none", "clients": [{"id": UUID}]},
             "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/x"}}},
            {"listen": "127.0.0.1", "port": vmess_port, "protocol": "vmess",
             "settings": {"clients": [{"id": UUID}]},
             "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}}]}
        server_file = root / "server.json"
        server_file.write_text(json.dumps(server))
        server_core = Path(os.environ.get("V2RAYA_TEST_SERVER_CORE", core))
        xray = subprocess.Popen([server_core, "run", "-c", str(server_file)], cwd=root,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(xray.wait, 5)
        self.addCleanup(xray.terminate)
        for port in (vless_port, vmess_port):
            for _ in range(200):
                self.assertIsNone(xray.poll(), "test Xray exited")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.02)
            else:
                self.fail("test Xray did not start its loopback listeners")

        def vless(tag, user):
            return {"protocol": "vless", "tag": tag, "settings": {"vnext": [
                {"address": "127.0.0.1", "port": vless_port, "users": [{"id": user, "encryption": "none"}]}]},
                "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/x"}}}
        outbounds = [vless("vless", UUID), vless("wrongUUID", UUID[:-1] + "b"),
                     {"protocol": "vmess", "tag": "vmess", "settings": {"vnext": [
                         {"address": "127.0.0.1", "port": vmess_port, "users": [{"id": UUID, "security": "auto"}]}]},
                      "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}}]
        nets = {"vless": "vless(xhttp)", "wrongUUID": "vless(xhttp)", "vmess": "vmess(ws)"}
        ports = {"vless": vless_port, "wrongUUID": vless_port, "vmess": vmess_port}
        self.api.names = list(nets)
        self.api.servers = [fixtures.profile(n, tag, f"127.0.0.1:{ports[tag]}", net)
                            for n, (tag, net) in enumerate(nets.items(), 1)]
        self.api.connected = [fixtures.assignment(tag, n) for n, tag in enumerate(nets, 1)]
        config = root / "client.json"
        config.write_text(json.dumps({"outbounds": outbounds, "routing": {}}))
        with patch.dict(os.environ, {"SSL_CERT_FILE": str(cert)}):
            self.start("--xray-config", str(config), "--node-url", f"https://127.0.0.1:{https.server_port}/probe",
                       "--node-interval", "60", "--node-timeout", "8", "--probe-core", str(core))

        def measurements(snapshot):
            return {tag: row["members"][0]["https"] for tag, row in fixtures.rows(snapshot).items()
                    if row.get("members") and "https" in row["members"][0]}

        snapshot = self.wait_for(lambda s: len(measurements(s)) == len(nets) and
                                 all(m["state"] in ("ok", "error", "unsupported", "timeout")
                                     for m in measurements(s).values()), timeout=30)
        self.stop()
        self.process = None
        results = measurements(snapshot)
        for tag in ("vless", "vmess"):
            with self.subTest(tag=tag):
                self.assertEqual((results[tag]["state"], results[tag].get("http_code")), ("ok", 204), results[tag])
        self.assertEqual(results["wrongUUID"]["state"], "error", results["wrongUUID"])
        self.assertEqual(len(visits), sum(m["state"] == "ok" for m in results.values()))
        self.assertNotIn(UUID, self.output.read_text())
        self.assertEqual(probe_cores(core), [], "a probe core outlived the helper")
        self.assertIsNone(xray.poll(), "the server Xray was disturbed")
