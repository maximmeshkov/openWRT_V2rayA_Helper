"""Optional loopback integration. Set V2RAYA_HELPER and V2RAYA_TEST_XRAY
to the native helper and Xray 25.10.15 binaries before unittest discovery."""
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
        for id_, (tag, mode) in enumerate(modes.items(), 1):
            self.api.servers.append(fixtures.profile(id_, tag, f"127.0.0.1:{port}", "vless(xhttp+tls)"))
            self.api.connected.append(fixtures.assignment(tag, id_))
            account = {"id": uuid[:-1] + "b" if tag == "wrongUUID" else uuid, "encryption": "none"}
            outbounds.append({"protocol": "vless", "tag": tag,
                              "settings": {"vnext": [{"address": "127.0.0.1", "port": port, "users": [account]}]},
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
                else:
                    self.assertEqual((m["state"], m.get("http_code")), ("ok", 204), m)
        self.assertEqual(visits, ["/probe"] * 5)
        self.assertNotIn(uuid, self.output.read_text())
