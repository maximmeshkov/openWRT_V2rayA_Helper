"""Run the native monitor against local v2rayA and Observatory HTTP fixtures."""
import json
import os
from pathlib import Path
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import tempfile
import threading
import time
import unittest


def profile(number, name, address, net):
    return {"id": number, "name": name, "address": address, "net": net}


def assignment(outbound, number, sub=None, selected=False):
    return {
        "outbound": outbound,
        "id": number,
        "_type": "server" if sub is None else "subscriptionServer",
        "sub": 0 if sub is None else sub,
        "selected": selected,
    }


def rows(snapshot):
    return {row["name"]: row for row in snapshot["outbounds"]}


def server_state(snapshot, tag):
    members = rows(snapshot).get(tag, {}).get("members", [])
    return members[0]["server"]["state"] if members else None


class APIFixture:
    def __init__(self):
        self.lock = threading.Lock()
        self.names = ["proxy"]
        self.servers = []
        self.subscriptions = []
        self.connected = None
        self.running = True
        self.paused = None
        self.token = None
        self.error_reply = None
        self.metrics = {}
        self.on_touch = None
        self.touch_count = 0
        self.observatory_auth = []
        self.paths = []

        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                with fixture.lock:
                    fixture.paths.append(self.path)
                    status, payload = fixture.reply(self.path, self.headers.get("Authorization"))
                    body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.http.server_port)

    def reply(self, path, header):
        if path == "/debug/vars":
            self.observatory_auth.append(header)
            return 200, {"observatory": self.metrics, "secret": "metrics-private"}
        if path not in ("/ui/api/outbounds", "/ui/api/touch"):
            return 404, {}
        if self.token and header != "Bearer " + self.token:
            return 401, {"code": "FAIL", "message": "authorization-private"}
        if self.error_reply:
            return self.error_reply
        if path.endswith("/outbounds"):
            data = {"outbounds": self.names}
        else:
            self.touch_count += 1
            if self.on_touch:
                self.on_touch(self.touch_count)
            data = {
                "running": self.running,
                "touch": {"servers": self.servers, "subscriptions": self.subscriptions,
                          "connectedServer": self.connected},
            }
            if self.paused is not None:
                data["networkPaused"] = self.paused
        return 200, {"code": "SUCCESS", "data": data, "message": None}

    def close(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()


class MonitorHarness(unittest.TestCase):
    def setUp(self):
        self.api = APIFixture()
        self.addCleanup(self.api.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name, "status.json")
        self.binary = os.environ["V2RAYA_HELPER"]
        self.process = None
        self.addCleanup(self.stop)
        self.sockets = []
        for listening in (True, False):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            if listening:
                sock.listen(64)
            self.sockets.append(sock)
            self.addCleanup(sock.close)
        self.open_port, self.closed_port = [f"127.0.0.1:{s.getsockname()[1]}" for s in self.sockets]

    def start(self, *extra):
        self.process = subprocess.Popen(
            [self.binary, "--api", self.api.url + "/ui/", "--output", str(self.output),
             "--mark", "0", "--interval", "1", "--timeout", "1", "--workers", "4", *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def stop(self):
        if self.process is None:
            return
        self.process.terminate()
        try:
            _, stderr = self.process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()
            self.fail("monitor did not stop")
        self.assertEqual(self.process.returncode, 0, stderr)

    def wait_for(self, predicate, timeout=7):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            if self.output.exists():
                last = json.loads(self.output.read_text())
                if predicate(last):
                    return last
            if self.process.poll() is not None:
                self.fail("monitor exited before publishing the expected snapshot")
            time.sleep(0.02)
        self.fail(f"timed out, last snapshot was {last}")

    def single(self):
        self.api.servers = [profile(1, "Node A", self.open_port, "vless(tcp+reality)")]
        self.api.connected = [assignment("proxy", 1)]


class MonitorTest(MonitorHarness):
    def test_members_empty_group_selected_and_udp(self):
        self.api.names = ["proxy", "Group", "Empty", "Ambiguous"]
        self.api.servers = [profile(1, "Server", self.open_port, "socks5"),
                            profile(2, "TCP-looking alias", self.open_port, "trojan")]
        self.api.subscriptions = [
            {"servers": [], "address": "subscription-private-1"},
            {"servers": [profile(1, "UDP", self.open_port, "wireguard"),
                         profile(2, "Stream", self.open_port, "vmess(ws+tls)")],
             "address": "subscription-private-2"},
        ]
        self.api.connected = [assignment("", 1), assignment("Group", 2, 1, True),
                              assignment("Group", 1, 1), assignment("Ambiguous", 2)]
        self.start()
        snapshot = self.wait_for(lambda d: server_state(d, "proxy") == "ok")
        items = rows(snapshot)
        self.assertEqual(set(items), set(self.api.names))
        self.assertEqual(items["Empty"]["members"], [])
        self.assertEqual(items["proxy"]["members"][0]["server"]["detail"], "local_tcp")
        self.assertEqual(items["proxy"]["route"]["state"], "unknown")
        members = items["Group"]["members"]
        self.assertEqual([(m["name"], m["selected"], m["transport"], m["server"]["state"]) for m in members],
                         [("Stream", True, "tcp", "ok"), ("UDP", False, "udp", "unsupported")])
        self.assertEqual(server_state(snapshot, "Ambiguous"), "unsupported")
        self.assertNotIn("subscription-private", self.output.read_text())
        self.assertEqual(set(self.api.paths), {"/ui/api/outbounds", "/ui/api/touch"})

    def test_switch_during_probe_drops_old_sample_and_tracks_count(self):
        self.single()

        def switch_on_recheck(number):
            if number == 2:
                self.api.servers = [profile(1, "Node B", self.closed_port, "socks5")]

        self.api.on_touch = switch_on_recheck
        self.start()
        changed = self.wait_for(lambda d: rows(d).get("proxy", {}).get("members", []) and
                                rows(d)["proxy"]["members"][0]["name"] == "Node B")
        self.assertEqual(server_state(changed, "proxy"), "pending")
        self.sockets[0].settimeout(1)
        conn, _ = self.sockets[0].accept()  # Old endpoint really did receive the probe.
        conn.close()
        self.wait_for(lambda d: server_state(d, "proxy") == "refused")
        with self.api.lock:
            self.api.names.append("Another")
        self.wait_for(lambda d: rows(d).get("Another", {}).get("members") == [])
        with self.api.lock:
            self.api.names = ["proxy"]
            self.api.connected = None
        self.wait_for(lambda d: set(rows(d)) == {"proxy"} and rows(d)["proxy"]["members"] == [])

    def test_stale_token_refresh_and_inconsistent_references(self):
        self.single()
        self.api.token = "initial-token"
        token = Path(self.tmp.name, "token")
        token.write_text(self.api.token + "\n")
        self.start("--token-file", str(token))
        self.wait_for(lambda d: server_state(d, "proxy") == "ok")
        with self.api.lock:
            self.api.token = "rotated-token"
        stale = self.wait_for(lambda d: d["state"] == "stale" and "authorization" in d["message"])
        self.assertEqual(set(rows(stale)), {"proxy"})
        self.assertNotIn("authorization-private", self.output.read_text())
        token.write_text(self.api.token + "\n")
        self.wait_for(lambda d: d["state"] == "ok" and server_state(d, "proxy") == "ok")
        with self.api.lock:
            self.api.error_reply = 200, {"code": "FAIL", "message": "private-upstream-message"}
        stale = self.wait_for(lambda d: d["state"] == "stale" and "busy" in d["message"])
        self.assertNotIn("private-upstream-message", json.dumps(stale))
        with self.api.lock:
            self.api.error_reply = None
            self.api.connected = [assignment("proxy", 100)]
        stale = self.wait_for(lambda d: d["state"] == "stale" and "inconsistent" in d["message"])
        self.assertEqual(rows(stale)["proxy"]["members"][0]["name"], "Node A")
        with self.api.lock:
            self.api.connected = None
        self.wait_for(lambda d: d["state"] == "ok" and rows(d)["proxy"]["members"] == [])

    def test_stopped_core_publishes_inventory_without_probing(self):
        self.single()
        self.api.running = False
        self.start()
        self.wait_for(lambda d: d["state"] == "stopped")
        with self.api.lock:
            self.api.running = True
            self.api.paused = True
            self.api.names.append("After pause")
        self.wait_for(lambda d: d["state"] == "stopped" and "After pause" in rows(d))
        self.sockets[0].settimeout(0.15)
        with self.assertRaises(socket.timeout):
            self.sockets[0].accept()

    def test_observatory_fresh_cached_success_omitted_false_and_errors(self):
        self.single()
        self.api.names.append("Group")
        self.api.servers.append(profile(2, "Node B", self.open_port, "socks5"))
        self.api.connected.extend([assignment("Group", 1, selected=True), assignment("Group", 2)])
        self.api.token = "private-jwt"
        token = Path(self.tmp.name, "jwt")
        token.write_text(self.api.token)
        self.start("--observatory", self.api.url + "/debug/vars",
                   "--observatory-max-age", "3", "--token-file", str(token))
        self.wait_for(lambda d: server_state(d, "proxy") == "ok")
        # Wait for the first assignment's timestamp to precede the sample.
        initial_second = int(time.time())
        while int(time.time()) == initial_second:
            time.sleep(0.02)
        with self.api.lock:
            self.api.metrics["proxy"] = {"outbound_tag": "proxy", "alive": True, "delay": 42,
                                         "last_try_time": int(time.time())}
            self.api.metrics["Group"] = {"outbound_tag": "Group", "alive": True, "delay": 22,
                                         "last_try_time": int(time.time())}
        route = lambda d: rows(d)["proxy"]["route"]
        snapshot = self.wait_for(lambda d: route(d).get("ms") == 42)
        self.assertEqual(route(snapshot)["state"], "ok")
        self.assertEqual(rows(snapshot)["Group"]["route"]["state"], "unknown")
        self.wait_for(lambda d: route(d)["state"] == "unknown")
        with self.api.lock:
            self.api.metrics["proxy"] = {"outbound_tag": "proxy", "delay": 99999999,
                                         "last_error_reason": "metrics-private", "last_try_time": int(time.time())}
        self.wait_for(lambda d: route(d)["state"] == "failed")
        self.assertNotIn("metrics-private", self.output.read_text())
        self.assertNotIn("private-jwt", self.output.read_text())
        self.assertEqual(set(self.api.observatory_auth), {None})
        with self.api.lock:
            self.api.metrics["proxy"] = {"outbound_tag": "other", "alive": True,
                                         "delay": 22, "last_try_time": int(time.time())}
        self.wait_for(lambda d: route(d)["state"] == "unknown")

    def test_only_loopback_metrics_allowed(self):
        result = subprocess.run([self.binary, "--observatory", "http://example.invalid/debug/vars"],
                                capture_output=True, timeout=2)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("example.invalid", result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
