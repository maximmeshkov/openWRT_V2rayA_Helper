"""Optional loopback integration. Set V2RAYA_HELPER and V2RAYA_TEST_XRAY
to the native helper and Xray 25.10.15 binaries before unittest discovery."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

import test_monitor as fixtures


def count_tls_connections(test, port):
    """Forward one profile to Xray and count TLS handshakes. TCP-only health
    checks close their connection without sending a ClientHello."""
    handshakes = []

    class Forward(socketserver.BaseRequestHandler):
        def handle(self):
            client = self.request
            client.settimeout(6)
            try:
                hello = client.recv(65536)
                if not hello:
                    return
                if hello[0] == 0x16:
                    handshakes.append(1)
                with socket.create_connection(("127.0.0.1", port), timeout=6) as peer:
                    # Keep negotiation pending until the helper has its inner
                    # ClientHello ready for the first XHTTP packet POST.
                    time.sleep(.05)
                    peer.sendall(hello)
                    while True:
                        readable, _, _ = select.select([client, peer], [], [], 6)
                        if not readable:
                            return
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            (peer if source is client else client).sendall(data)
            except OSError:
                pass  # A completed or cancelled probe may close either side.

    listener = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Forward)
    listener.daemon_threads = True
    thread = threading.Thread(target=listener.serve_forever, daemon=True)
    thread.start()
    test.addCleanup(thread.join)
    test.addCleanup(listener.server_close)
    test.addCleanup(listener.shutdown)
    return listener.server_address[1], handshakes


@unittest.skipUnless(os.environ.get("V2RAYA_TEST_XRAY"), "requires a local Xray 25.10.15 test binary")
class NodeXrayTest(fixtures.MonitorHarness):
    def test_https_via_real_vless_xhttp(self):
        core = os.environ["V2RAYA_TEST_XRAY"]
        self.assertIn("Xray 25.10.15 ", subprocess.check_output([core, "version"], text=True))
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
        thread = threading.Thread(target=https.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(https.server_close)
        self.addCleanup(https.shutdown)

        uuid = "27370a4b-3145-4685-b3c7-005cb232b92a"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        inbound = {"listen": "127.0.0.1", "port": port, "protocol": "vless",
                   "settings": {"decryption": "none", "clients": [{"id": uuid}]},
                   "streamSettings": {"network": "xhttp", "security": "tls",
                                      "xhttpSettings": {"path": "/test bench", "host": "front.test"},
                                      "tlsSettings": {"alpn": ["h2", "http/1.1"], "certificates": [
                                          {"certificateFile": str(cert), "keyFile": str(key)}]}}}
        server_file = root / "server.json"
        server_file.write_text(json.dumps({"inbounds": [inbound], "outbounds": [{"protocol": "freedom"}]}))
        xray = subprocess.Popen([core, "run", "-c", str(server_file)], cwd=root,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(xray.wait, 5)
        self.addCleanup(xray.terminate)
        with self.subTest("Xray listener started"):
            for _ in range(100):
                self.assertIsNone(xray.poll())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.02)
            else:
                self.fail("test Xray did not start its loopback listener")

        modes = {"auto": "auto", "packetH2": "packet-up", "packetH1": "packet-up",
                 "streamUp": "stream-up", "streamOne": "stream-one",
                 "wrongUUID": "auto", "wrongSNI": "auto"}
        self.api.names = list(modes)
        self.api.connected = []
        outbounds = []
        forwarded_port, tls_connections = count_tls_connections(self, port)
        for id_, (tag, mode) in enumerate(modes.items(), 1):
            node_port = forwarded_port if tag == "packetH2" else port
            self.api.servers.append(fixtures.profile(id_, tag, f"127.0.0.1:{node_port}", "vless(xhttp+tls)"))
            self.api.connected.append(fixtures.assignment(tag, id_))
            account = {"id": uuid[:-1] + "b" if tag == "wrongUUID" else uuid, "encryption": "none"}
            outbounds.append({"protocol": "vless", "tag": tag,
                              "settings": {"vnext": [{"address": "127.0.0.1", "port": node_port, "users": [account]}]},
                              "streamSettings": {"network": "xhttp", "security": "tls", "tlsSettings": {
                                  "serverName": "wrong.test" if tag == "wrongSNI" else "outer.test",
                                  "alpn": ["http/1.1"] if tag == "packetH1" else ["h2", "h3"]},
                                  "xhttpSettings": {"host": "front.test", "path": "test bench?flag=1", "mode": mode}}})
        config = root / "client.json"
        config.write_text(json.dumps({"outbounds": outbounds + [{"tag": "drop", "protocol": "blackhole"}],
                                     "routing": {"rules": [{"type": "field", "network": "tcp",
                                                            "outboundTag": "drop"}]}}))
        with patch.dict(os.environ, {"SSL_CERT_FILE": str(cert)}):
            self.start("--xray-config", str(config), "--node-url", f"https://127.0.0.1:{https.server_port}/probe",
                       "--node-interval", "60", "--node-timeout", "5")

        def measurements(snapshot):
            return {tag: row["members"][0]["https"] for tag, row in fixtures.rows(snapshot).items()
                    if row.get("members") and "https" in row["members"][0]}

        snapshot = self.wait_for(lambda s: len(measurements(s)) == len(modes) and
                                 all(m["state"] in ("ok", "error", "unsupported", "timeout")
                                     for m in measurements(s).values()), timeout=20)
        self.stop()
        self.process = None
        for tag, m in measurements(snapshot).items():
            with self.subTest(tag=tag):
                self.assertEqual(m["source"], "node_https")
                if tag in ("wrongUUID", "wrongSNI"):
                    self.assertEqual(m["state"], "error", m)
                    self.assertEqual(m["detail"], "xhttp_session_failed", m)
                else:
                    self.assertEqual((m["state"], m.get("http_code")), ("ok", 204), m)
        self.assertEqual(visits, ["/probe"] * 5)
        self.assertEqual(len(tls_connections), 1, "HTTP/2 download and uploads should share a TLS connection")
        self.assertNotIn(uuid, self.output.read_text())

        # Same VLESS credentials and destination socket, different origin TLS
        # name. Only the outer XHTTP session can complete successfully.
        self.api.names = ["packetH2"]
        self.api.connected = [fixtures.assignment("packetH2", 2)]
        self.output.unlink()
        with patch.dict(os.environ, {"SSL_CERT_FILE": str(cert)}):
            self.start("--xray-config", str(config), "--node-url", f"https://localhost:{https.server_port}/probe",
                       "--node-interval", "60", "--node-timeout", "5")
        bad_origin = self.wait_for(lambda s: measurements(s).get("packetH2", {}).get("state") == "error")
        self.assertEqual(measurements(bad_origin)["packetH2"]["detail"], "https_tls_error")
        self.assertEqual(visits, ["/probe"] * 5)
