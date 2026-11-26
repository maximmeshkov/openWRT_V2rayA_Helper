"""Follow v2rayA's positional references through changes to the server catalogue."""
import json
import os
import subprocess
from urllib.parse import parse_qs, quote, urlsplit
from unittest.mock import patch

from test_independent_nodes import NodeFixture
from test_latency_history import history, node_args
from test_monitor import assignment, profile, rows


class CatalogueLifecycle(NodeFixture):
    def setUp(self):
        super().setUp()
        self.token = self.tmp_path("token")
        self.token.write_text("lifecycle-private-api-token\n")
        self.api.token = "lifecycle-private-api-token"
        self.history_file = self.tmp_path("latency.json")
        self.policy_file = self.tmp_path("failover.json")
        self.route_lock = self.tmp_path("route.lock")
        self.early_feed = "https://fixture.invalid/early?access=private-early-token"
        self.main_feed = "https://fixture.invalid/main?access=private-main-token"
        self.posts = []
        self.shares = []
        self.links = {}
        base_reply = self.api.reply
        fixture = self

        def reply(path, auth):
            url = urlsplit(path)
            if url.path == "/ui/api/version":
                return 200, {"code": "SUCCESS", "data": {"version": "2.2.7.4", "variant": "Xray"}}
            if auth != "Bearer " + fixture.api.token:
                return 401, {"code": "UNAUTHORIZED"}
            if url.path == "/ui/api/routingA":
                return 200, {"code": "SUCCESS", "data": {"routingA": "default: direct\n"}}
            if url.path == "/ui/api/sharingAddress":
                target = json.loads(parse_qs(url.query)["touch"][0])
                fixture.shares.append(target)
                ref = (target.get("sub"), target["id"])
                link = fixture.links.get(ref)
                if link is None:
                    return 404, {"code": "FAIL"}
                return 200, {"code": "SUCCESS", "data": {"sharingAddress": link}}
            return base_reply(path, auth)

        def post(handler):
            request = json.loads(handler.rfile.read(int(handler.headers["Content-Length"])))
            with fixture.api.lock:
                fixture.posts.append(request)
                ref = (request.get("sub"), request["id"])
                valid = (
                    handler.path == "/ui/api/connection" and
                    handler.headers.get("Authorization") == "Bearer " + fixture.api.token and
                    fixture.links.get(ref) is not None
                )
                if valid:
                    fixture.set_active_locked(ref[0], ref[1], "correct")
                    status, response = base_reply("/ui/api/touch", handler.headers.get("Authorization"))
                else:
                    status, response = 400, {"code": "FAIL"}
            body = json.dumps(response).encode()
            handler.send_response(status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)

        self.api.reply = reply
        self.api.http.RequestHandlerClass.do_POST = post

    def tmp_path(self, name):
        return self.config.with_name(name)

    def install_catalogue(self, manual, subscriptions):
        links = {}

        def servers(items, sub):
            result = []
            kind = "server" if sub is None else "subscriptionServer"
            for number, (name, password) in enumerate(items, 1):
                result.append(dict(profile(number, name, f"127.0.0.1:{self.port}", "socks5"), _type=kind))
                links[sub, number] = (
                    f"socks5://fixture:{quote(password)}@127.0.0.1:{self.port}#{quote(name)}"
                )
            return result

        self.api.servers = servers(manual, None)
        self.api.subscriptions = [
            {"id": number + 1, "_type": "subscription", "address": address,
             "servers": servers(items, number)}
            for number, (address, items) in enumerate(subscriptions)
        ]
        self.links = links
        self.api.names = ["proxy"]

    def set_active_locked(self, sub, number, password):
        outbounds = []
        self.api.connected = []
        if number is not None:
            self.api.connected = [assignment("proxy", number, sub=sub)]
            outbounds = [{
                "tag": "proxy", "protocol": "socks", "settings": {"servers": [{
                    "address": "127.0.0.1", "port": self.port,
                    "users": [{"user": "fixture", "pass": password}],
                }]},
            }]
        new = self.config.with_suffix(".new")
        new.write_text(json.dumps({"outbounds": outbounds, "routing": {"rules": []}}))
        new.replace(self.config)

    def command(self, endpoint, action, request=None):
        location = self.policy_file if endpoint == "failover" else self.route_lock
        reply = subprocess.check_output(
            [self.binary, endpoint, action, self.api.url + "/ui/", self.token, location],
            input=json.dumps(request) if request is not None else "",
            text=True, timeout=10,
        )
        for secret in ("lifecycle-private-api-token", "private-early-token", "private-main-token"):
            self.assertNotIn(secret, reply)
        return json.loads(reply)

    def catalogue(self):
        response = self.command("failover", "context")
        self.assertTrue(response["ok"], response)
        self.assertTrue(response["can_switch"], response)
        return response

    def save_policy(self, key):
        return self.command("failover", "save", {"policy": {
            "outbound": "proxy", "mode": "outage", "candidates": [key],
            "failure_method": "consecutive", "failures": 3, "allow_restart": True,
        }})

    def start_monitor(self, interval=1):
        with patch.dict(os.environ, SSL_CERT_FILE=self.cert):
            self.start("--token-file", str(self.token), "--failover-file", str(self.policy_file),
                       *node_args(self, self.history_file, interval))

    def wait_member(self, name, state):
        def check(snap):
            members = rows(snap).get("proxy", {}).get("members", [])
            return (snap["state"] == "ok" and members and members[0]["name"] == name and
                    members[0]["https"]["state"] == state)
        return self.wait_for(check, timeout=15)

    def samples(self):
        if not self.history_file.exists():
            return []
        return history(self, self.history_file, "proxy")["samples"]

    @staticmethod
    def names_to_keys(context):
        return {node["name"]: node["key"] for node in context["nodes"]}

    def test_catalogue_keys_survive_position_changes_and_stale_reserve_is_rejected(self):
        with self.api.lock:
            self.install_catalogue([("Old manual", "correct"), ("Manual", "correct")], [
                (self.early_feed, [("Old subscription", "correct")]),
                (self.main_feed, [("Primary", "correct"), ("Reserve", "correct")]),
            ])
            self.set_active_locked(1, 1, "correct")
        original = self.names_to_keys(self.catalogue())
        saved = self.save_policy(original["Reserve"])
        self.assertTrue(saved["ok"], saved)
        client = self.existing_client()
        self.start_monitor(interval=2)
        self.wait_member("Primary", "ok")
        self.wait_for(lambda _: bool(self.samples()))
        first = self.samples()[0]

        # This refresh moves the active node and reserve within the feed.
        # The prior subscription and manual node are deleted, moving the
        # remaining positions. A new third subscription and manual node arrive.
        with self.api.lock:
            self.install_catalogue([("Manual", "correct"), ("New manual", "correct")], [
                (self.main_feed, [("New subscription", "correct"),
                                  ("Reserve", "correct"), ("Primary", "correct")]),
                (self.early_feed + "&new=1", [("New feed member", "correct")]),
            ])
            self.api.connected = [assignment("proxy", 3, sub=0)]
        updated = self.catalogue()
        keys = self.names_to_keys(updated)
        self.assertEqual(keys["Manual"], original["Manual"])
        self.assertEqual(keys["Primary"], original["Primary"])
        self.assertEqual(keys["Reserve"], original["Reserve"])
        self.assertEqual(set(keys) - set(original), {"New manual", "New subscription", "New feed member"})
        self.assertEqual(set(original) - set(keys), {"Old subscription", "Old manual"})
        self.assertEqual(updated["policies"][0]["candidates"], [keys["Reserve"]])
        self.wait_for(lambda _: any(s["at"] > first["at"] for s in self.samples()))
        refreshed = self.samples()

        # A new node occupies the reserve's removed position. The saved
        # selection must not become permission to switch to that node.
        with self.api.lock:
            self.install_catalogue([("Manual", "correct"), ("New manual", "correct")], [
                (self.main_feed, [("New subscription", "correct"),
                                  ("Replacement", "correct"), ("Primary", "correct")]),
            ])
        latest = self.catalogue()
        self.assertNotIn(keys["Reserve"], self.names_to_keys(latest).values())
        self.assertIn(keys["Reserve"], latest["policies"][0]["candidates"])
        rejected = self.save_policy(keys["Reserve"])
        self.assertFalse(rejected["ok"], rejected)
        self.assertFalse(self.posts)
        client.write(b"same connection after catalogue changes\n")
        self.assertEqual(client.readline(), b"same connection after catalogue changes\n")
        self.assertEqual({sample["series"] for sample in refreshed}, {first["series"]},
                         "the same active profile acquired a new chart series after its indexes moved")

    def test_manual_update_after_server_deletion_preserves_history_and_routing_edit_guard(self):
        with self.api.lock:
            self.install_catalogue([("Before", "correct"), ("Primary", "correct")], [])
            self.set_active_locked(None, 2, "correct")
        self.start_monitor(interval=30)
        self.wait_member("Primary", "ok")
        self.wait_for(lambda _: any(s["server"] == "Primary" and s["state"] == "ok" for s in self.samples()))
        before = next(s for s in self.samples() if s["server"] == "Primary")
        route = self.command("routing", "context")
        self.assertTrue(route["ok"], route)
        old_key = self.names_to_keys(self.catalogue())["Primary"]
        self.assertTrue(any(item["name"] == "proxy" and item["available"] for item in route["outbounds"]))

        # An earlier server disappears and the active server's credentials
        # rotate. The saved identity follows the active server, while the new
        # configuration gets a separate chart series.
        with self.api.lock:
            self.install_catalogue([("Primary", "rotated-secret")], [])
            self.set_active_locked(None, 1, "rotated-secret")
        self.wait_member("Primary", "error")
        self.wait_for(lambda _: any(s["state"] == "error" for s in self.samples()))
        after = next(s for s in self.samples() if s["state"] == "error")
        self.assertNotEqual(before["series"], after["series"])
        self.assertEqual(after["server"], "Primary")
        self.assertNotIn("ms", after)
        self.assertIn(before, self.samples())
        self.assertEqual(self.names_to_keys(self.catalogue())["Primary"], old_key)
        self.assertNotIn("rotated-secret", self.history_file.read_text())

        with self.api.lock:
            self.install_catalogue([("Changed", "correct")], [])
            self.set_active_locked(None, 1, "correct")
        self.wait_member("Changed", "ok")
        self.wait_for(lambda _: any(s["server"] == "Changed" for s in self.samples()))
        restored = next(s for s in self.samples() if s["server"] == "Changed")
        self.assertNotEqual(restored["series"], after["series"])
        self.assertEqual(restored["state"], "ok")
        self.assertNotIn(old_key, self.names_to_keys(self.catalogue()).values())

        with self.api.lock:
            self.install_catalogue([], [])
            self.set_active_locked(None, None, None)
        self.wait_for(lambda s: s["state"] == "ok" and not rows(s)["proxy"]["members"])
        blocked = self.command("routing", "preview", {
            "kind": "domain", "value": "example.org", "outbound": "proxy",
            "before_line": 0, "revision": route["revision"],
        })
        self.assertFalse(blocked["ok"], blocked)
        self.assertIn(before, self.samples())
        self.assertIn(after, self.samples())
        self.assertIn(restored, self.samples())
        self.assertFalse(self.posts)

    def test_refresh_during_reserve_probe_never_switches_to_reused_index(self):
        with self.api.lock:
            self.install_catalogue([("Active", "wrong")], [
                (self.early_feed, [("Other", "correct")]),
                (self.main_feed, [("Reserve", "correct")]),
            ])
            self.set_active_locked(None, 1, "wrong")
        key = self.names_to_keys(self.catalogue())["Reserve"]
        saved = self.save_policy(key)
        self.assertTrue(saved["ok"], saved)
        self.hold.set()
        self.start_monitor()
        self.assertTrue(self.waiting.wait(15), "the selected reserve was not probed")
        with self.api.lock:
            self.install_catalogue([("Active", "wrong")], [
                (self.early_feed, [("Other", "correct")]),
                (self.main_feed, [("Substitute", "correct")]),
            ])
        self.release.set()
        failed_checks = len(self.auth_failures)
        self.wait_for(lambda _: len(self.auth_failures) >= failed_checks + 2, timeout=12)
        self.assertFalse(self.posts)
        self.assertNotIn(key, self.names_to_keys(self.catalogue()).values())
        self.assertEqual(self.catalogue()["policies"][0]["candidates"], [key])
        before = {"_type": "subscriptionServer", "id": 1, "sub": 1}
        self.assertIn(before, self.shares)
        self.assertTrue(all(share == before for share in self.shares))

        # The original reserve returns under a fresh subscription index and
        # server position. Only a new successful probe may authorize the POST.
        with self.api.lock:
            self.install_catalogue([("Active", "wrong")], [
                (self.main_feed, [("Substitute", "correct"), ("Reserve", "correct")]),
            ])
        self.wait_member("Reserve", "ok")
        self.assertEqual(self.posts, [
            {"_type": "subscriptionServer", "outbound": "proxy", "id": 2, "sub": 0},
        ])
        self.assertIn({"_type": "subscriptionServer", "id": 2, "sub": 0}, self.shares)

    def test_successful_reserve_probe_cannot_switch_after_active_credentials_recover(self):
        with self.api.lock:
            self.install_catalogue([("Primary", "wrong")], [
                (self.main_feed, [("Reserve", "correct")]),
            ])
            self.set_active_locked(None, 1, "wrong")
        keys = self.names_to_keys(self.catalogue())
        saved = self.save_policy(keys["Reserve"])
        self.assertTrue(saved["ok"], saved)
        self.hold.set()
        self.start_monitor()
        self.assertTrue(self.waiting.wait(15), "the selected reserve was not probed")
        self.assertGreaterEqual(len(self.auth_failures), 3)

        # Credentials recover on the assigned node as the reserve completes
        # its probe. All public catalogue keys and references remain equal.
        with self.api.lock:
            self.install_catalogue([("Primary", "correct")], [
                (self.main_feed, [("Reserve", "correct")]),
            ])
            self.set_active_locked(None, 1, "correct")
        try:
            self.assertEqual(self.names_to_keys(self.catalogue()), keys)
        finally:
            self.release.set()

        def post_or_recovered(snap):
            members = rows(snap).get("proxy", {}).get("members", [])
            return self.posts or (members and members[0]["name"] == "Primary" and
                                  members[0]["https"]["state"] == "ok")

        result = self.wait_for(post_or_recovered, timeout=12)
        self.assertFalse(self.posts, "the old failure streak authorized a switch after credential recovery")
        primary = rows(result)["proxy"]["members"][0]
        self.assertEqual(primary["name"], "Primary")
        self.assertEqual(primary["https"]["http_code"], 204)
