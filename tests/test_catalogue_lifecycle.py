"""Follow v2rayA's positional references through changes to the server catalogue."""
import json
import os
from pathlib import Path
import subprocess
import time
from socketserver import ThreadingTCPServer
from threading import Thread
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
        self.after_switch = None
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
                    fixture.set_active_locked(ref[0], ref[1], "correct", request["outbound"])
                    status, response = base_reply("/ui/api/touch", handler.headers.get("Authorization"))
                    if fixture.after_switch:
                        fixture.after_switch(request["outbound"])
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

    def another_proxy_port(self):
        socks = ThreadingTCPServer(("127.0.0.1", 0), self.socks.RequestHandlerClass)
        socks.daemon_threads = True
        self.addCleanup(socks.server_close)
        self.addCleanup(socks.shutdown)
        Thread(target=socks.serve_forever, daemon=True).start()
        return socks.server_address[1]

    def install_catalogue(self, manual, subscriptions, *, remarks=None, ports=None):
        links = {}

        def servers(items, sub):
            result = []
            kind = "server" if sub is None else "subscriptionServer"
            for number, (name, password) in enumerate(items, 1):
                port = (ports or {}).get(name, self.port)
                result.append(dict(profile(number, name, f"127.0.0.1:{port}", "socks5"), _type=kind))
                links[sub, number] = (
                    f"socks5://fixture:{quote(password)}@127.0.0.1:{port}#{quote(name)}"
                )
            return result

        self.api.servers = servers(manual, None)
        self.api.subscriptions = [
            {"id": number + 1, "_type": "subscription", "address": address,
             "remarks": (remarks or {}).get(address, ""),
             "servers": servers(items, number)}
            for number, (address, items) in enumerate(subscriptions)
        ]
        self.links = links
        self.api.names = ["proxy"]

    def set_active_locked(self, sub, number, password, tag="proxy"):
        config = json.loads(self.config.read_text()) if self.config.exists() else {"routing": {"rules": []}}
        outbounds = [out for out in config.get("outbounds", []) if out["tag"] != tag]
        self.api.connected = [ref for ref in self.api.connected or [] if ref["outbound"] != tag]
        if number is not None:
            self.api.connected.append(assignment(tag, number, sub=sub))
            outbounds.append({
                "tag": tag, "protocol": "socks", "settings": {"servers": [{
                    "address": "127.0.0.1", "port": urlsplit(self.links[sub, number]).port,
                    "users": [{"user": "fixture", "pass": password}],
                }]},
            })
        new = self.config.with_suffix(".new")
        config["outbounds"] = outbounds
        new.write_text(json.dumps(config))
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

    def save_subscription_policy(self, subscription, candidates=(), *, exclusions=None):
        policy = {
            "outbound": "proxy", "mode": "outage", "candidates": list(candidates),
            "subscriptions": [subscription], "failures": 3, "allow_restart": True,
        }
        if exclusions is not None:
            policy["exclusions"] = exclusions
        return self.command("failover", "save", {"policy": policy})

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

    def test_subscription_selection_follows_live_feed_without_reusing_its_old_index(self):
        manual = [("Primary", "wrong"), ("Unselected manual", "correct")]
        unrelated = (self.early_feed, [("Unselected reserve", "correct")])
        with self.api.lock:
            self.install_catalogue(manual, [unrelated, (self.main_feed, [("Old reserve", "wrong")])],
                                   remarks={self.main_feed: "My selected feed"})
            self.set_active_locked(None, 1, "wrong")

        original = self.catalogue()["subscriptions"]
        selected = next(item for item in original if item["name"] == "My selected feed")
        key = selected["key"]
        self.assertRegex(key, r"^[0-9a-f]{32}$")
        self.assertEqual(selected["count"], 1)
        self.assertTrue(self.save_subscription_policy(key)["ok"])
        stored = self.catalogue()["policies"][0]
        self.assertEqual((stored["subscriptions"], stored["candidates"]), ([key], []))
        self.assertNotIn(self.main_feed, self.policy_file.read_text())

        old_reserve = {"_type": "subscriptionServer", "id": 1, "sub": 1}
        self.start_monitor()
        self.wait_for(lambda _: old_reserve in self.shares, timeout=16)
        self.assertTrue(all(share == old_reserve for share in self.shares))
        self.assertFalse(self.posts)

        # A healthy node in a different subscription now occupies exactly the
        # old reserve's position. It must not inherit permission from the feed.
        with self.api.lock:
            self.install_catalogue(manual, [unrelated, (self.early_feed + "&replacement=1", [
                ("Old reserve", "correct"),
            ])])
            share_count = len(self.shares)
        unavailable = self.catalogue()
        self.assertNotIn(key, {feed["key"] for feed in unavailable["subscriptions"]})
        self.assertEqual(unavailable["policies"][0]["subscriptions"], [key])
        self.assertFalse(self.save_subscription_policy(key)["ok"])
        previous_failures = len(self.auth_failures)
        self.wait_for(lambda _: len(self.auth_failures) >= previous_failures + 3, timeout=12)
        self.assertEqual(len(self.shares), share_count)
        self.assertFalse(self.posts)

        # The chosen feed returns under a different label and index with a
        # newly added server. The saved key still applies to this new member.
        self.hold.set()
        with self.api.lock:
            self.install_catalogue(manual, [(self.main_feed, [("New reserve", "correct")]), unrelated],
                                   remarks={self.main_feed: "Renamed selected feed"})
        updated = self.catalogue()
        self.assertIn({"key": key, "name": "Renamed selected feed", "count": 1}, updated["subscriptions"])
        self.assertEqual(updated["policies"][0]["subscriptions"], [key])
        self.assertTrue(self.waiting.wait(15), "new feed member did not receive its HTTPS probe")
        self.assertFalse(self.posts, "the new member was assigned before its probe completed")
        self.release.set()
        final = self.wait_member("New reserve", "ok")
        self.assertEqual(rows(final)["proxy"]["members"][0]["https"]["http_code"], 204)
        self.assertEqual(self.posts, [{"_type": "subscriptionServer", "outbound": "proxy", "id": 1, "sub": 0}])
        self.assertTrue(all(share == {"_type": "subscriptionServer", "id": 1, "sub": 0}
                            for share in self.shares[share_count:]))

    def test_subscription_selection_keeps_individually_selected_reserves(self):
        with self.api.lock:
            self.install_catalogue([("Primary", "wrong"), ("Manual reserve", "correct")],
                                   [(self.main_feed, [])])
            self.set_active_locked(None, 1, "wrong")
        original = self.catalogue()
        subscription = original["subscriptions"][0]["key"]
        manual = self.names_to_keys(original)["Manual reserve"]
        self.assertTrue(self.save_subscription_policy(subscription, [manual])["ok"])
        stored = self.catalogue()["policies"][0]
        self.assertEqual((stored["subscriptions"], stored["candidates"]), ([subscription], [manual]))
        self.start_monitor()
        self.wait_member("Manual reserve", "ok")
        self.assertEqual(self.posts, [{"_type": "server", "outbound": "proxy", "id": 2}])

    def test_endpoint_exclusions_override_both_sources_across_catalogue_refresh(self):
        blocked_port = self.another_proxy_port()
        excluded_endpoint = f"127.0.0.1:{blocked_port}"
        unavailable_endpoint = "192.0.2.210:443"
        manual = [("Primary", "wrong"), ("Unselected manual", "correct"),
                  ("Blocked manual", "correct")]
        unrelated = (self.early_feed, [("Unselected subscription member", "correct")])
        with self.api.lock:
            self.install_catalogue(manual, [unrelated, (self.main_feed, [("Blocked member", "correct")])],
                                   remarks={self.main_feed: "Selected feed"},
                                   ports={"Blocked manual": blocked_port, "Blocked member": blocked_port})
            self.set_active_locked(None, 1, "wrong")
        original = self.catalogue()
        self.assertTrue(original["supports_exclusions"])
        nodes = {node["name"]: node for node in original["nodes"]}
        for name in ("Blocked manual", "Blocked member"):
            self.assertEqual(nodes[name]["endpoint"], excluded_endpoint)
        subscription = next(item["key"] for item in original["subscriptions"]
                            if item["name"] == "Selected feed")
        manual_key = nodes["Blocked manual"]["key"]
        saved = self.save_subscription_policy(subscription, [manual_key],
                                              exclusions=[excluded_endpoint, unavailable_endpoint])
        self.assertTrue(saved["ok"], saved)
        self.assertCountEqual(self.catalogue()["policies"][0]["exclusions"],
                              [excluded_endpoint, unavailable_endpoint])

        self.start_monitor()
        self.wait_for(lambda _: len(self.auth_failures) >= 4, timeout=15)
        self.assertFalse(self.shares, "excluded endpoints must be skipped before profile export")
        self.assertFalse(self.posts)

        self.hold.set()
        try:
            with self.api.lock:
                self.install_catalogue([manual[0], manual[2]], [(self.main_feed, [
                    ("Renamed blocked member", "correct"), ("Allowed new member", "correct"),
                ]), unrelated], ports={"Blocked manual": blocked_port, "Renamed blocked member": blocked_port})
            updated = self.catalogue()
            nodes_after = {node["name"]: node for node in updated["nodes"]}
            self.assertEqual(nodes_after["Blocked manual"]["key"], manual_key)
            self.assertNotEqual(nodes_after["Renamed blocked member"]["key"], nodes["Blocked member"]["key"])
            self.assertEqual(nodes_after["Renamed blocked member"]["endpoint"], excluded_endpoint)
            self.assertCountEqual(updated["policies"][0]["exclusions"], [excluded_endpoint, unavailable_endpoint])
            self.assertTrue(self.waiting.wait(15), "allowed new member did not reach its HTTPS check")
            self.assertFalse(self.posts, "the allowed member was assigned before its probe completed")
        finally:
            self.release.set()
        final = self.wait_member("Allowed new member", "ok")
        self.assertEqual(rows(final)["proxy"]["members"][0]["https"]["http_code"], 204)
        self.assertEqual(self.posts, [{"_type": "subscriptionServer", "outbound": "proxy", "id": 2, "sub": 0}])
        self.assertTrue(self.shares)
        self.assertTrue(all(share == {"_type": "subscriptionServer", "id": 2, "sub": 0} for share in self.shares),
                        self.shares)

    def test_catalogue_normalizes_endpoint_spellings(self):
        addresses = {
            "Domain": ("reserve.EXAMPLE.:0443", "reserve.example:443"),
            "IPv4": ("127.0.0.1:443", "127.0.0.1:443"),
            "IPv4-mapped IPv6": ("[::ffff:127.0.0.1]:443", "127.0.0.1:443"),
            "IPv6": ("[2001:0DB8:0:0::0001]:443", "[2001:db8::1]:443"),
            "Octal IPv4": ("0177.0.0.01:443", None),
            "Hex IPv4": ("0x7f000001:443", None),
        }
        with self.api.lock:
            self.install_catalogue([("Primary", "wrong"), *((name, "correct") for name in addresses)], [])
            self.set_active_locked(None, 1, "wrong")
            for server in self.api.servers[1:]:
                server["address"] = addresses[server["name"]][0]
        nodes = {node["name"]: node for node in self.catalogue()["nodes"]}
        self.assertEqual({name: nodes[name].get("endpoint") for name in addresses},
                         {name: endpoint for name, (_, endpoint) in addresses.items()})

    def test_exclusion_saved_during_reserve_probe_prevents_switch(self):
        reserve_port = self.another_proxy_port()
        with self.api.lock:
            self.install_catalogue([("Primary", "wrong")], [(self.main_feed, [("Reserve", "correct")])],
                                   ports={"Reserve": reserve_port})
            self.set_active_locked(None, 1, "wrong")
        subscription = self.catalogue()["subscriptions"][0]["key"]
        original = self.save_subscription_policy(subscription)
        self.assertTrue(original["ok"], original)
        self.hold.set()
        self.start_monitor()
        try:
            self.assertTrue(self.waiting.wait(15), "reserve never reached the HTTPS check")
            self.assertFalse(self.posts)
            self.assertEqual(self.shares, [{"_type": "subscriptionServer", "id": 1, "sub": 0}])
            excluded_endpoint = f"127.0.0.1:{reserve_port}"
            saved = self.save_subscription_policy(subscription, exclusions=[excluded_endpoint])
            self.assertTrue(saved["ok"], saved)
            self.assertEqual(self.catalogue()["policies"][0]["exclusions"], [excluded_endpoint])
        finally:
            self.release.set()
        previous_failures = len(self.auth_failures)
        self.wait_for(lambda _: len(self.auth_failures) >= previous_failures + 2, timeout=12)
        self.assertFalse(self.posts, "an in-flight successful probe overrode the newly saved exclusion")
        self.assertEqual(self.shares, [{"_type": "subscriptionServer", "id": 1, "sub": 0}])

    def test_candidate_export_cannot_redirect_probe_to_an_excluded_endpoint(self):
        blocked_port = self.another_proxy_port()
        with self.api.lock:
            self.install_catalogue([("Primary", "wrong")], [(self.main_feed, [("Reserve", "correct")])])
            self.set_active_locked(None, 1, "wrong")
            self.links[0, 1] = f"socks5://fixture:correct@127.0.0.1:{blocked_port}#Reserve"
        catalogue = self.catalogue()
        self.assertEqual(next(node["endpoint"] for node in catalogue["nodes"] if node["name"] == "Reserve"),
                         f"127.0.0.1:{self.port}")
        saved = self.save_subscription_policy(catalogue["subscriptions"][0]["key"],
                                              exclusions=[f"127.0.0.1:{blocked_port}"])
        self.assertTrue(saved["ok"], saved)
        self.start_monitor()
        target = {"_type": "subscriptionServer", "id": 1, "sub": 0}
        self.wait_for(lambda _: target in self.shares, timeout=15)
        previous_failures = len(self.auth_failures)
        self.wait_for(lambda _: len(self.auth_failures) >= previous_failures + 2, timeout=12)
        self.assertFalse(self.seen, "an exported profile generated traffic to the excluded endpoint")
        self.assertFalse(self.posts)

    def test_subscription_becoming_ambiguous_during_probe_cannot_switch(self):
        manual = [("Primary", "wrong")]
        selected = (self.main_feed, [("Verified reserve", "correct")])
        with self.api.lock:
            self.install_catalogue(manual, [selected])
            self.set_active_locked(None, 1, "wrong")
        original = self.catalogue()
        key = original["subscriptions"][0]["key"]
        reserve = self.names_to_keys(original)["Verified reserve"]
        saved = self.save_subscription_policy(key)
        self.assertTrue(saved["ok"], saved)
        self.hold.set()
        self.start_monitor()
        self.assertTrue(self.waiting.wait(15), "reserve never reached the HTTPS check")
        try:
            # The exact node key and its share URI remain valid. Only the
            # subscription itself becomes ambiguous while the probe runs.
            with self.api.lock:
                self.install_catalogue(manual, [selected, (self.main_feed, [("Other reserve", "correct")])])
            current = self.catalogue()
            self.assertEqual(current["subscriptions"], [])
            self.assertEqual(self.names_to_keys(current)["Verified reserve"], reserve)
            self.assertEqual(current["policies"][0]["subscriptions"], [key])
            self.assertFalse(self.save_subscription_policy(key)["ok"])
        finally:
            self.release.set()
        previous_failures = len(self.auth_failures)
        self.wait_for(lambda _: len(self.auth_failures) >= previous_failures + 2, timeout=12)
        self.assertFalse(self.posts, "the successful probe from the ambiguous source authorized a switch")

    def test_qualified_outbound_is_rechecked_after_switch_and_router_cooldown(self):
        self.check_cooldown_followup(rotate_media=False)

    def test_qualified_outbound_restarts_streak_if_its_core_profile_changes(self):
        self.check_cooldown_followup(rotate_media=True)

    def expire_cooldown(self):
        marker = self.policy_file.with_suffix(".json.last")
        fields = marker.read_text().split()
        expired = int(time.time()) - 1
        replacement = f"{expired - 60} {expired}\n"
        if fields[0] == "v2":
            _, boot, wall, seconds, boot_time = fields
            attempted, cooldown, boot_ns = map(int, (wall, seconds, boot_time))
            self.assertEqual(boot, Path("/proc/sys/kernel/random/boot_id").read_text().strip())
            self.assertEqual(cooldown, 60)
            self.assertGreater(attempted, 0)
            now_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            self.assertLessEqual(boot_ns, now_ns)
            self.assertGreater(boot_ns + cooldown * 1_000_000_000, now_ns)
            expired_boot_ns = now_ns - (cooldown + 1) * 1_000_000_000
            if expired_boot_ns > 0:
                replacement = f"v2 {boot} {expired - cooldown} {cooldown} {expired_boot_ns}\n"
        else:
            attempted, unblock = map(int, fields)
            self.assertEqual(unblock - attempted, 60)
            self.assertGreater(unblock, time.time())
        temp = marker.with_suffix(".tmp")
        temp.write_text(replacement)
        temp.replace(marker)

    def check_cooldown_followup(self, rotate_media):
        with self.api.lock:
            self.install_catalogue([
                ("Primary", "wrong"), ("Secondary", "wrong"), ("Healthy", "correct"), ("Disabled", "wrong"),
                ("Proxy reserve", "correct"), ("Media reserve", "correct"), ("Other reserve", "correct"),
            ], [])
            self.api.names.extend(["media", "healthy", "disabled"])
            for index, (tag, password) in enumerate([
                ("proxy", "wrong"), ("media", "wrong"), ("healthy", "correct"), ("disabled", "wrong"),
            ], 1):
                self.set_active_locked(None, index, password, tag)

        keys = self.names_to_keys(self.catalogue())
        for tag, mode, reserve in [
            ("proxy", "outage", "Proxy reserve"), ("media", "outage", "Media reserve"),
            ("healthy", "outage", "Other reserve"), ("disabled", "off", "Other reserve"),
        ]:
            saved = self.command("failover", "save", {"policy": {
                "outbound": tag, "mode": mode, "candidates": [keys[reserve]],
                "failure_method": "consecutive", "failures": 3, "allow_restart": True, "cooldown_seconds": 60,
            }})
            self.assertTrue(saved["ok"], saved)

        def edit_media_during_first_switch(tag):
            # The catalogue and assignment are unchanged, but the exact Xray
            # profile for media now contains different credentials.
            if tag == "proxy":
                self.set_active_locked(None, 2, "wrong-after-edit", "media")

        if rotate_media:
            self.after_switch = edit_media_during_first_switch

        def media_errors():
            if not self.history_file.exists():
                return []
            return [sample for sample in history(self, self.history_file, "media")["samples"]
                    if sample["state"] == "error" and sample["server"] == "Secondary"]

        self.start_monitor(interval=3)
        self.wait_for(lambda _: bool(media_errors()))
        before = media_errors()[0]["series"]
        self.wait_member("Proxy reserve", "ok")
        self.wait_for(lambda _: any(sample["series"] != before for sample in media_errors()))
        self.assertEqual([request["outbound"] for request in self.posts], ["proxy"])

        # Simulate waiting for the global cooldown, without skipping the second outbound's fresh check.
        self.expire_cooldown()

        final = self.wait_for(lambda s: rows(s)["media"]["members"][0]["name"] == "Media reserve", timeout=16)
        self.assertEqual([request["outbound"] for request in self.posts], ["proxy", "media"])
        fresh_failures = [sample for sample in media_errors() if sample["series"] != before]
        self.assertGreaterEqual(len(fresh_failures), 1)
        if rotate_media:
            self.assertGreaterEqual(len(fresh_failures), 3, "the edited outbound reused its previous failures")
        else:
            self.assertLess(len(fresh_failures), 3, "the unchanged outbound restarted its failure count")
        for tag, name in [("proxy", "Proxy reserve"), ("healthy", "Healthy"), ("disabled", "Disabled")]:
            self.assertEqual(rows(final)[tag]["members"][0]["name"], name)

    def test_qualified_later_outbound_gets_a_turn_before_the_first_switches_again(self):
        with self.api.lock:
            self.install_catalogue([
                ("Primary", "wrong"), ("Secondary", "wrong"),
                ("Proxy reserve A", "correct"), ("Proxy reserve B", "correct"),
                ("Media reserve", "correct"),
            ], [])
            self.api.names.append("media")
            self.set_active_locked(None, 1, "wrong", "proxy")
            self.set_active_locked(None, 2, "wrong", "media")

        keys = self.names_to_keys(self.catalogue())
        for tag, reserves in [("proxy", ["Proxy reserve A", "Proxy reserve B"]), ("media", ["Media reserve"])]:
            saved = self.command("failover", "save", {"policy": {
                "outbound": tag, "mode": "outage", "candidates": [keys[name] for name in reserves],
                "failure_method": "consecutive", "failures": 3, "allow_restart": True, "cooldown_seconds": 60,
            }})
            self.assertTrue(saved["ok"], saved)

        def fail_first_reserve_after_assignment(tag):
            if tag == "proxy":
                selected = next(ref for ref in self.api.connected if ref["outbound"] == tag)
                if selected["id"] == 3:
                    # The first reserve passes its isolated probe but fails after assignment.
                    self.set_active_locked(None, selected["id"], "wrong-when-assigned", tag)

        self.after_switch = fail_first_reserve_after_assignment
        self.start_monitor()
        self.wait_for(lambda _: self.posts, timeout=15)
        self.assertEqual([request["outbound"] for request in self.posts], ["proxy"])

        def both_failed_after_switch(_):
            proxy = [sample for sample in history(self, self.history_file, "proxy")["samples"]
                     if sample["server"] == "Proxy reserve A" and sample["role"] == "active" and
                     sample["state"] == "error"]
            if len(proxy) < 3:
                return False
            media = [sample for sample in history(self, self.history_file, "media")["samples"]
                     if sample["server"] == "Secondary" and sample["state"] == "error" and
                     sample["at"] >= proxy[0]["at"]]
            return len(media) >= 3

        self.wait_for(both_failed_after_switch, timeout=15)
        self.assertEqual([request["outbound"] for request in self.posts], ["proxy"])
        self.expire_cooldown()

        def media_restored(snap):
            return any(member["name"] == "Media reserve" and member["https"]["state"] == "ok"
                       for member in rows(snap).get("media", {}).get("members", []))

        self.wait_for(media_restored, timeout=15)
        self.assertEqual([(request["outbound"], request["id"]) for request in self.posts],
                         [("proxy", 3), ("media", 5)])
        self.expire_cooldown()

        restored = self.wait_member("Proxy reserve B", "ok")
        self.assertEqual(rows(restored)["proxy"]["members"][0]["https"]["http_code"], 204)
        self.assertEqual([(request["outbound"], request["id"]) for request in self.posts],
                         [("proxy", 3), ("media", 5), ("proxy", 4)])

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

    def test_successful_reserve_probe_cannot_switch_after_active_endpoint_recovers(self):
        primary_proxy = ThreadingTCPServer(("127.0.0.1", 0), self.socks.RequestHandlerClass,
                                          bind_and_activate=False)
        primary_proxy.daemon_threads = True
        self.addCleanup(primary_proxy.server_close)
        primary_proxy.server_bind()
        with self.api.lock:
            self.install_catalogue([("Primary", "correct")], [(self.main_feed, [("Reserve", "correct")])],
                                   ports={"Primary": primary_proxy.server_address[1]})
            self.set_active_locked(None, 1, "correct")
        config_before = self.config.read_bytes()
        saved = self.save_policy(self.names_to_keys(self.catalogue())["Reserve"])
        self.assertTrue(saved["ok"], saved)
        self.hold.set()
        self.start_monitor()
        self.assertTrue(self.waiting.wait(15), "the reserve was never probed while the primary endpoint was down")

        try:
            primary_proxy.server_activate()
            Thread(target=primary_proxy.serve_forever, daemon=True).start()
            self.addCleanup(primary_proxy.shutdown)
            self.assertEqual(self.config.read_bytes(), config_before)
        finally:
            self.release.set()

        def post_or_recovered(snap):
            members = rows(snap).get("proxy", {}).get("members", [])
            return self.posts or (members and members[0]["name"] == "Primary" and
                                  members[0]["https"]["state"] == "ok")

        result = self.wait_for(post_or_recovered, timeout=12)
        self.assertFalse(self.posts, "the reserve triggered a switch after the unchanged primary endpoint recovered")
        self.assertEqual(self.config.read_bytes(), config_before)
        primary = rows(result)["proxy"]["members"][0]
        self.assertEqual(primary["https"]["http_code"], 204)
