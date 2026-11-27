"""The env subcommand reports the v2rayA build and never invents a core."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
import subprocess
import threading
import unittest
from unittest.mock import patch


class VersionOnly(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"code": "SUCCESS", "data": {"version": "2.5.16", "variant": "V2rayaCore"}}).encode()
        self.send_response(200 if self.path == "/api/version" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class EnvironmentTest(unittest.TestCase):
    def env(self, api):
        output = subprocess.run([os.environ["V2RAYA_HELPER"], "env", api, "/nonexistent/config.json"],
                                capture_output=True, text=True, timeout=20, check=True).stdout
        return json.loads(output)

    def test_reports_version_and_decisions_without_a_core(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), VersionOnly)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with patch.dict(os.environ, {"V2RAYA_HELPER_ALLOW_UNVERIFIED": "2.5.16"}):
            report = self.env(f"http://127.0.0.1:{server.server_address[1]}")
        self.assertEqual((report["version"], report["variant"]), ("2.5.16", "V2rayaCore"))
        self.assertNotIn("core", report)
        self.assertEqual(report["features"]["routing_save"], {"state": "opted_in"})
        self.assertEqual(report["features"]["switch"]["state"], "denied")
        self.assertIn("v2rayA 2.5.16", report["features"]["switch"]["reason"])
        self.assertIsInstance(report["peer_check"], bool)

    def test_unreachable_v2raya_reports_no_version(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        report = self.env(f"http://127.0.0.1:{port}")
        self.assertEqual(set(report), {"peer_check"})


if __name__ == "__main__":
    unittest.main()
