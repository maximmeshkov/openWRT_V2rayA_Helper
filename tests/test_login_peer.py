"""Verify that an automatic local client sends no HTTP to a foreign peer."""
import errno
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from threading import Event, Thread
import unittest


class IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class LoginPeer(unittest.TestCase):
    def test_ipv6_foreign_listener_does_not_receive_credentials_or_requests(self):
        dialed = Event()
        empty_connections, requests = [], []

        class ForeignListener(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def handle_one_request(self):
                super().handle_one_request()
                if self.raw_requestline == b"":
                    empty_connections.append(1)
                    if len(empty_connections) >= 3:
                        dialed.set()

            def respond(self, status, reply):
                body = json.dumps(reply).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                requests.append(("GET", self.path))
                self.respond(401, {"code": "UNAUTHORIZED"})

            def do_POST(self):
                requests.append(("POST", self.path))
                self.respond(403, {"code": "UNAUTHORIZED"})

        try:
            server = IPv6Server(("::1", 0), ForeignListener)
        except OSError as error:
            if error.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL, errno.EPROTONOSUPPORT):
                self.skipTest("IPv6 loopback is unavailable")
            raise
        with server, tempfile.TemporaryDirectory() as directory:
            Thread(target=server.serve_forever, daemon=True).start()
            try:
                work = Path(directory)
                login, token = work / "login.json", work / "token"
                login.write_text(json.dumps({"username": "fixture", "password": "private-fixture-password"}))
                token.write_text("rejected-fixture-token\n")
                login.chmod(0o600)
                token.chmod(0o600)
                previous_token = token.read_bytes()
                previous_file = token.stat()
                command = [os.environ["V2RAYA_HELPER"], "--api", f"http://[::1]:{server.server_port}",
                           "--login-file", login, "--token-file", token, "--output", work / "status.json",
                           "--interval", "1", "--timeout", "2"]
                with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as helper:
                    try:
                        self.assertTrue(dialed.wait(10), "monitor did not retry the verified transport")
                        self.assertEqual(requests, [], "the foreign IPv6 listener received HTTP")
                        self.assertIsNone(helper.poll())
                    finally:
                        helper.terminate()
                        try:
                            helper.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            helper.kill()
                            helper.wait(timeout=5)
                self.assertEqual(token.read_bytes(), previous_token)
                stored = token.stat()
                self.assertEqual((stored.st_ino, stored.st_mtime_ns), (previous_file.st_ino, previous_file.st_mtime_ns))
            finally:
                server.shutdown()
