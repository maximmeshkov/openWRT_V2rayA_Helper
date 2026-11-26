"""Verify the routing command against an isolated v2rayA HTTP fixture."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

from test_monitor import assignment, profile


DOCUMENT = (
    "# Existing rules\r\n"
    "outbound:custom=socks(address:127.0.0.1,port:1080,user:foo,pass:fixture-secret)\r\n"
    "domain(domain: internal.example) -> direct\r\n"
    "default: proxy"
)


class RoutingEditorTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.token = Path(temp.name, "token")
        self.token.write_text("fixture-routing-token\n")
        self.lock = Path(temp.name, "write.lock")
        self.version = "2.2.7.4"
        self.document = DOCUMENT
        self.requests = []
        self.writes = []
        self.routing_reads = 0
        self.change_before_read = None
        self.connected = [assignment("proxy", 1), assignment("media", 1)]
        case = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, status, data=None):
                response = {"code": "SUCCESS", "data": data} if status == 200 else {"code": "FAIL"}
                body = json.dumps(response, ensure_ascii=False).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def authenticated(self):
                return self.headers.get("Authorization") == "Bearer fixture-routing-token"

            def do_GET(self):
                case.requests.append(("GET", self.path, self.headers.get("Authorization")))
                if self.path == "/ui/api/version":
                    self.reply(200, {"version": case.version})
                    return
                if not self.authenticated():
                    self.reply(401)
                    return
                if self.path == "/ui/api/routingA":
                    case.routing_reads += 1
                    if case.routing_reads == case.change_before_read:
                        case.document += "\r\n# Changed in the v2rayA UI"
                    self.reply(200, {"routingA": case.document})
                elif self.path == "/ui/api/outbounds":
                    self.reply(200, {"outbounds": ["proxy", "media", "unassigned"]})
                elif self.path == "/ui/api/touch":
                    self.reply(200, {
                        "running": True,
                        "touch": {
                            "servers": [profile(1, "Node", "127.0.0.1:1", "socks5")],
                            "subscriptions": [],
                            "connectedServer": case.connected,
                        },
                    })
                else:
                    self.reply(404)

            def do_PUT(self):
                case.requests.append(("PUT", self.path, self.headers.get("Authorization")))
                if not self.authenticated():
                    self.reply(401)
                    return
                if self.path != "/ui/api/routingA":
                    self.reply(404)
                    return
                length = int(self.headers["Content-Length"])
                data = json.loads(self.rfile.read(length))
                case.writes.append((self.headers.get("Content-Type"), data))
                case.document = data["routingA"]
                self.reply(200)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def command(self, action, request=None):
        proc = subprocess.run(
            [os.environ["V2RAYA_HELPER"], "routing", action,
             f"http://127.0.0.1:{self.server.server_port}/ui/", self.token, self.lock],
            input=json.dumps(request) if request is not None else "",
            capture_output=True, text=True, timeout=10, check=True,
        )
        self.assertNotIn("fixture-secret", proc.stdout + proc.stderr)
        self.assertNotIn("fixture-routing-token", proc.stdout + proc.stderr)
        return json.loads(proc.stdout)

    def request(self, **overrides):
        context = self.command("context")
        self.assertTrue(context["ok"], context)
        request = {
            "kind": "domain",
            "value": "example.org",
            "outbound": "media",
            "before_line": 0,
            "revision": context["revision"],
        }
        request.update(overrides)
        return request

    def test_context_and_preview_are_read_only(self):
        context = self.command("context")
        self.assertTrue(context["ok"], context)
        self.assertTrue(context["can_save"])
        self.assertEqual(context["version"], "2.2.7.4")
        self.assertEqual({row["name"]: row["available"] for row in context["outbounds"]},
                         {"proxy": True, "media": True, "unassigned": False,
                          "direct": True, "block": True})
        self.assertEqual(context["positions"], [{"line": 3, "label": "domain(domain: internal.example) -> direct"}])
        self.assertEqual(context["positions_total"], 1)
        request = self.request(before_line=3)
        preview = self.command("preview", request)
        self.assertTrue(preview["ok"], preview)
        self.assertEqual(preview["rule"], "domain(domain: example.org) -> media")
        self.assertEqual(preview["before_line"], 3)
        self.assertEqual(self.document, DOCUMENT)
        self.assertFalse(self.writes)
        for verb, path, auth in self.requests:
            self.assertEqual(verb, "GET")
            self.assertEqual(auth, None if path.endswith("/version") else "Bearer fixture-routing-token")

    def test_positions_keep_actual_quoted_rules_and_skip_non_rules(self):
        regex = 'domain(regexp: "[()]#пример") && port(443) -> proxy'
        ipv6 = 'ip("2001:db8::/32") -> media'
        self.document = (f"{DOCUMENT}\r\n"
                         f"\t # {regex}\r\n"
                         f"  {regex}\t \r\n"
                         f"\t{ipv6} ")
        context = self.command("context")
        self.assertTrue(context["ok"], context)
        self.assertEqual(context["positions"][1:], [{"line": 6, "label": regex}, {"line": 7, "label": ipv6}])
        self.assertEqual(context["positions_total"], 3)
        request = self.request(before_line=6)
        preview = self.command("preview", request)
        self.assertTrue(preview["ok"], preview)
        saved = self.command("save", request)
        self.assertTrue(saved["ok"], saved)
        self.assertIn(f'{preview["rule"]}\r\n  {regex}\t \r\n', self.document)

    def test_long_position_labels_preserve_utf8_and_outbound_within_rpc_budget(self):
        rule = 'domain(regexp: "' + ('ё💡' * 400) + '") -> media'
        self.document = (rule + "\n") * 401
        context = self.command("context")
        self.assertTrue(context["ok"], context)
        self.assertEqual(context["positions_total"], 401)
        self.assertEqual(len(context["positions"]), 400)
        self.assertEqual(context["positions"][-1]["line"], 400)
        for position in context["positions"]:
            label = position["label"]
            self.assertLessEqual(len(label.encode()), 2048)
            self.assertNotIn("\ufffd", label)
            self.assertTrue(label.startswith('domain(regexp: "ё💡'))
            self.assertTrue(label.endswith('") -> media'))
            self.assertIn(" … ", label)

    def test_save_preserves_existing_rules_and_refuses_stale_preview(self):
        request = self.request(before_line=3)
        self.assertTrue(self.command("preview", request)["ok"])
        self.document += "\r\n# Concurrent change"
        self.assertFalse(self.command("save", request)["ok"])
        self.assertFalse(self.writes)
        request = self.request(before_line=3)
        result = self.command("save", request)
        self.assertTrue(result["ok"], result)
        prefix, rest = self.document.split("domain(domain: example.org) -> media\r\n", 1)
        self.assertEqual(prefix + rest, DOCUMENT + "\r\n# Concurrent change")
        self.assertEqual(self.writes, [("application/json", {"routingA": self.document})])
        writes = [(path, auth) for verb, path, auth in self.requests if verb == "PUT"]
        self.assertEqual(writes, [("/ui/api/routingA", "Bearer fixture-routing-token")])

    def test_rejects_disabled_outbounds_and_write_on_newer_version(self):
        for outbound in ("unassigned", "removed"):
            with self.subTest(outbound=outbound):
                request = self.request(outbound=outbound)
                self.assertFalse(self.command("preview", request)["ok"])
                self.assertFalse(self.command("save", request)["ok"])
        request = self.request()
        self.connected = [assignment("proxy", 1)]
        self.assertFalse(self.command("save", request)["ok"])
        self.version = "2.5.10"
        context = self.command("context")
        self.assertTrue(context["ok"], context)
        self.assertFalse(context["can_save"])
        request = self.request(outbound="direct")
        self.assertTrue(self.command("preview", request)["ok"])
        self.assertFalse(self.command("save", request)["ok"])
        self.assertEqual(self.document, DOCUMENT)
        self.assertFalse(self.writes)

    def test_save_rechecks_routing_a_immediately_before_put(self):
        request = self.request()
        self.change_before_read = self.routing_reads + 2

        result = self.command("save", request)

        self.assertFalse(result["ok"], result)
        self.assertEqual(self.document, DOCUMENT + "\r\n# Changed in the v2rayA UI")
        self.assertFalse(self.writes)
