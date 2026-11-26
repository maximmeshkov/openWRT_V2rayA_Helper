"""Use a local v2rayA and authenticated SOCKS stand-in to verify failover."""
import json
import os
from pathlib import Path
from socketserver import StreamRequestHandler, ThreadingTCPServer
import subprocess
from threading import Thread
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from test_independent_nodes import NodeFixture
from test_monitor import assignment, profile, rows


class FailoverRunner(NodeFixture):
    def setUp(self):
        super().setUp()
        self.settings = Path(self.tmp.name, "failover.json")
        self.token_file = Path(self.tmp.name, "token")
        self.token_file.write_text("fixture-failover-token\n")
        self.version = "2.2.7.4"
        self.share_password = "correct"
        self.reserve_port = self.port
        self.posts = []
        previous_reply = self.api.reply
        fixture = self

        def reply(path, auth):
            url = urlsplit(path)
            if url.path == "/ui/api/version":
                return 200, {"code": "SUCCESS", "data": {"version": self.version, "variant": "Xray"}}
            if url.path == "/ui/api/sharingAddress":
                if auth != "Bearer fixture-failover-token":
                    return 401, {"code": "UNAUTHORIZED"}
                target = json.loads(parse_qs(url.query)["touch"][0])
                if target != {"_type": "server", "id": 2}:
                    return 404, {"code": "FAIL"}
                return 200, {"code": "SUCCESS", "data": {
                    "sharingAddress": f"socks5://fixture:{self.share_password}@127.0.0.1:{self.reserve_port}"}}
            return previous_reply(path, auth)

        self.api.reply = reply
        self.api.token = "fixture-failover-token"

        def post(handler):
            data = json.loads(handler.rfile.read(int(handler.headers["Content-Length"])))
            auth = handler.headers.get("Authorization")
            with fixture.api.lock:
                fixture.posts.append((handler.path, auth, data, len(fixture.auth_failures), len(fixture.seen)))
                expected = {"_type": "server", "id": 2, "outbound": "media"}
                if handler.path != "/ui/api/connection" or data != expected or auth != "Bearer fixture-failover-token":
                    status, payload = 400, {"code": "FAIL"}
                else:
                    fixture.active_locked(2, "correct")
                    status, payload = previous_reply("/ui/api/touch", auth)
            body = json.dumps(payload).encode()
            handler.send_response(status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)

        self.api.http.RequestHandlerClass.do_POST = post
        with self.api.lock:
            self.nodes = [dict(profile(number, name, f"127.0.0.1:{self.port}", "socks5"), _type="server")
                          for number, name in enumerate(("Primary", "Reserve"), 1)]
            self.api.servers = self.nodes[:]
            self.api.names = ["media"]
            self.active_locked(1, "wrong")

    def active_locked(self, number, password):
        update = self.config.with_suffix(".new")
        update.write_text(json.dumps({"outbounds": [{
            "tag": "media", "protocol": "socks", "settings": {"servers": [{
                "address": "127.0.0.1", "port": self.port,
                "users": [{"user": "fixture", "pass": password}],
            }]},
        }], "routing": {"rules": []}}))
        update.replace(self.config)
        self.api.connected = [assignment("media", number)]

    def choose_policy(self, mode):
        command = [self.binary, "failover", "context", self.api.url + "/ui/",
                   self.token_file, self.settings]
        context = json.loads(subprocess.check_output(command, text=True, timeout=10))
        self.assertTrue(context["ok"], context)
        self.reserve = next(node["key"] for node in context["nodes"] if node["name"] == "Reserve")
        self.write_policy(mode)

    def write_policy(self, mode):
        update = self.settings.with_suffix(".new")
        update.write_text(json.dumps({"policies": [{
            "outbound": "media", "mode": mode, "candidates": [self.reserve], "failures": 3,
        }]}))
        update.replace(self.settings)

    def start_runner(self):
        with patch.dict(os.environ, SSL_CERT_FILE=self.cert):
            self.start("--token-file", str(self.token_file), "--node-url", "https://check.invalid/generate_204",
                       "--node-interval", "1", "--node-timeout", "2", "--xray-config", str(self.config),
                       "--failover-file", str(self.settings))

    def test_only_switches_after_failures_and_a_confirmed_reserve(self):
        self.choose_policy("outage")
        self.start_runner()

        def recovered(snapshot):
            members = rows(snapshot).get("media", {}).get("members", [])
            return self.posts and members and members[0]["name"] == "Reserve" and members[0]["https"]["state"] == "ok"

        self.wait_for(recovered, timeout=15)
        self.assertEqual(len(self.posts), 1)
        path, auth, target, active_failures, reserve_successes = self.posts[0]
        self.assertEqual((path, auth, target), ("/ui/api/connection", "Bearer fixture-failover-token",
                         {"_type": "server", "id": 2, "outbound": "media"}))
        self.assertGreaterEqual(active_failures, 3)
        self.assertGreaterEqual(reserve_successes, 1)
        self.assertNotIn("fixture-failover-token", self.output.read_text())

    def test_queue_delay_preserves_distinct_failures_for_a_working_reserve(self):
        class HangingSocks(StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(4)
                try:
                    if self.rfile.read(1) == b"\x05":
                        self.rfile.read()
                except OSError:
                    pass

        slow = ThreadingTCPServer(("127.0.0.1", 0), HangingSocks)
        slow.daemon_threads = True
        self.addCleanup(slow.server_close)
        self.addCleanup(slow.shutdown)
        Thread(target=slow.serve_forever, daemon=True).start()
        slow_port = slow.server_address[1]
        names = ["media", "work", "video", "chat"]
        with self.api.lock:
            outbounds = [{"tag": name, "protocol": "socks", "settings": {"servers": [{
                "address": "127.0.0.1", "port": slow_port,
                "users": [{"user": "fixture", "pass": "correct"}],
            }]}} for name in names]
            self.config.write_text(json.dumps({"outbounds": outbounds, "routing": {"rules": []}}))
            self.nodes[0]["address"] = f"127.0.0.1:{slow_port}"
            self.api.names = names
            self.api.connected = [assignment(name, 1) for name in names]

        healthy = subprocess.check_output([
            "curl", "--silent", "--show-error", "--fail", "--max-time", "5", "--cacert", self.cert,
            "--noproxy", "", "--proxy", f"socks5h://fixture:correct@127.0.0.1:{self.port}",
            "--output", os.devnull, "--write-out", "%{http_code}", "https://check.invalid/generate_204",
        ], text=True, timeout=8)
        self.assertEqual(healthy, "204")
        self.seen.clear()

        self.choose_policy("outage")
        with patch.dict(os.environ, SSL_CERT_FILE=self.cert):
            self.start("--workers", "2", "--token-file", str(self.token_file),
                       "--node-url", "https://check.invalid/generate_204", "--node-interval", "1",
                       "--node-timeout", "2", "--xray-config", str(self.config),
                       "--failover-file", str(self.settings))

        failures = set()

        def collect(snapshot):
            members = rows(snapshot).get("media", {}).get("members", [])
            if members and members[0]["name"] == "Primary":
                sample = members[0]["https"]
                if sample.get("detail") in ("https_timeout", "dns_or_probe_timeout"):
                    failures.add(sample["checked_at"])
            if len(failures) < 3:
                self.assertFalse(self.posts, "switch before three separately completed active failures")
            return len(failures) >= 3

        self.wait_for(collect, timeout=25)

        def restored(snapshot):
            members = rows(snapshot).get("media", {}).get("members", [])
            return members and members[0]["name"] == "Reserve" and members[0]["https"].get("http_code") == 204

        try:
            self.wait_for(restored, timeout=7)
        except AssertionError as error:
            raise AssertionError(f"no recovery after distinct failures at {sorted(failures)}: {error}") from error
        self.assertEqual(len(self.posts), 1)
        self.assertGreaterEqual(self.posts[0][4], 1, "reserve was not verified before the switch")

    def test_seven_unreachable_reserves_allow_inventory_updates_between_checks(self):
        snapshots = []
        status_path = self.output

        class UnresponsiveReserve(StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(4)
                try:
                    if self.rfile.read(1) == b"\x05":
                        snapshots.append(status_path.stat().st_mtime_ns)
                        self.rfile.read()
                except OSError:
                    pass

        slow = ThreadingTCPServer(("127.0.0.1", 0), UnresponsiveReserve)
        slow.daemon_threads = True
        self.addCleanup(slow.server_close)
        self.addCleanup(slow.shutdown)
        Thread(target=slow.serve_forever, daemon=True).start()
        self.reserve_port = slow.server_address[1]
        names = ["media", "ai", "work", "video", "chat", "manual", "local"]
        with self.api.lock:
            self.nodes[1]["address"] = f"127.0.0.1:{self.reserve_port}"
            self.api.names = names
            self.api.connected = [assignment(name, 1) for name in names]
            config = json.loads(self.config.read_text())
            config["outbounds"] = [dict(config["outbounds"][0], tag=name) for name in names]
            self.config.write_text(json.dumps(config))
        self.choose_policy("outage")
        policy = json.loads(self.settings.read_text())["policies"][0]
        self.settings.write_text(json.dumps({"policies": [dict(policy, outbound=name) for name in names]}))
        history = self.settings.with_suffix(".latency")
        with patch.dict(os.environ, SSL_CERT_FILE=self.cert):
            self.start("--workers", "7", "--token-file", str(self.token_file),
                       "--node-url", "https://check.invalid/generate_204", "--node-interval", "1",
                       "--node-timeout", "2", "--xray-config", str(self.config), "--failover-file",
                       str(self.settings), "--latency-file", str(history))
        self.wait_for(lambda _: len(snapshots) >= 2, timeout=15)
        self.assertGreater(snapshots[1], snapshots[0], "two reserve timeouts ran without an inventory cycle")

        def all_outbounds_checked(_):
            if not history.exists():
                return False
            for name in names:
                result = subprocess.check_output([self.binary, "latency", history, name], text=True, timeout=4)
                if not any(sample["state"] == "timeout" and sample["role"] == "reserve"
                           for sample in json.loads(result)["samples"]):
                    return False
            return True

        self.wait_for(all_outbounds_checked, timeout=40)
        self.assertFalse(self.posts)

    def test_disabled_missing_and_failing_reserves_do_not_switch(self):
        self.choose_policy("off")
        self.start_runner()
        self.wait_for(lambda _: len(self.auth_failures) >= 4, timeout=15)
        self.assertFalse(self.posts)
        self.assertFalse(any("sharingAddress" in path for path in self.api.paths))

        with self.api.lock:
            self.api.servers = self.nodes[:1]
        previous = len(self.auth_failures)
        self.write_policy("outage")
        self.wait_for(lambda _: len(self.auth_failures) >= previous + 4, timeout=15)
        self.assertFalse(self.posts)

        with self.api.lock:
            self.share_password = "wrong"
            self.api.servers = self.nodes[:]
        self.wait_for(lambda _: any("sharingAddress" in path for path in self.api.paths), timeout=15)
        previous = len(self.auth_failures)
        self.wait_for(lambda _: len(self.auth_failures) >= previous + 3, timeout=15)
        self.assertFalse(self.posts)

    def test_disabling_policy_while_reserve_is_probed_prevents_switch(self):
        self.choose_policy("outage")
        self.hold.set()
        self.start_runner()
        self.assertTrue(self.waiting.wait(15), "the reserve was never probed")
        self.write_policy("off")
        self.release.set()
        previous = len(self.auth_failures)
        self.wait_for(lambda _: len(self.auth_failures) >= previous + 2, timeout=15)
        self.assertFalse(self.posts)
