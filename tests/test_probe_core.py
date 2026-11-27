"""HTTPS checks through a separate probe core, with a fake core binary.

The helper must start its own core with the server's outbound, reach the
control site through it, keep the server's socket mark, count a server the
core cannot reach as failed, and leave no core process behind."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time
from unittest.mock import patch

from test_monitor import MonitorHarness, assignment, profile, rows

UUID = "00000000-0000-4000-9000-000000000001"

FAKE_CORE = r'''#!{python}
import json, os, socket, sys, threading
routes = json.load(open({routes!r}))
config = json.load(sys.stdin)
with open({record!r}, "a") as out:
    out.write(json.dumps({{"argv": sys.argv[1:], "pid": os.getpid(), "env": sorted(os.environ),
                          "config": config}}) + "\n")

def pipe(source, target):
    try:
        while data := source.recv(65536):
            target.sendall(data)
    except OSError:
        pass
    for end in (source, target):
        try:
            end.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

def relay(conn, reachable):
    stream = conn.makefile("rb")
    try:
        stream.read(stream.read(2)[1])
        conn.sendall(b"\x05\x00")
        kind = stream.read(4)[3]
        stream.read(stream.read(1)[0] if kind == 3 else 4)
        stream.read(2)
        # Like Xray: SOCKS succeeds at once, the server connection fails later.
        conn.sendall(b"\x05\x00\x00\x01" + bytes(6))
        if not reachable:
            conn.close()
            return
        origin = socket.create_connection(("127.0.0.1", routes["origin"]))
        threading.Thread(target=pipe, args=(origin, conn), daemon=True).start()
        pipe(conn, origin)
    except (OSError, IndexError):
        conn.close()

def serve(listener, outbound):
    server = (outbound["settings"].get("vnext") or outbound["settings"].get("servers"))[0]
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=relay, args=(conn, server["port"] not in routes["dead"]), daemon=True).start()

for inbound, outbound in zip(config["inbounds"], config["outbounds"]):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((inbound["listen"], inbound["port"]))
    listener.listen(16)
    threading.Thread(target=serve, args=(listener, outbound), daemon=True).start()
threading.Event().wait()
'''


class ProbeCoreTest(MonitorHarness):
    def setUp(self):
        super().setUp()
        root = Path(self.tmp.name)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=check.invalid", "-addext", "subjectAltName=DNS:check.invalid",
                        "-keyout", key, "-out", cert], check=True, stderr=subprocess.DEVNULL)
        self.cert = str(cert)

        class Origin(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(204 if self.path == "/generate_204" else 404)
                self.send_header("Connection", "close")
                self.end_headers()

            def log_message(self, *args):
                pass

        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        origin.socket = context.wrap_socket(origin.socket, server_side=True)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        self.addCleanup(origin.server_close)
        self.addCleanup(origin.shutdown)

        self.live_port, self.dead_port = 40001, 40002
        routes, self.record = root / "routes.json", root / "core-calls.jsonl"
        routes.write_text(json.dumps({"origin": origin.server_address[1], "dead": [self.dead_port]}))
        self.core = root / "fake-core"
        self.core.write_text(FAKE_CORE.format(python=sys.executable, routes=str(routes), record=str(self.record)))
        self.core.chmod(0o755)
        self.config = root / "config.json"

    def calls(self):
        return [json.loads(line) for line in self.record.read_text().splitlines()] if self.record.exists() else []

    def test_checks_go_through_a_separate_core_that_leaves_nothing_behind(self):
        def vless(tag, port, **stream):
            return {"tag": tag, "protocol": "vless", "settings": {"vnext": [
                {"address": "127.0.0.1", "port": port, "users": [{"id": UUID, "encryption": "none"}]}]},
                "streamSettings": {"network": "tcp", "security": "reality", **stream}}
        self.config.write_text(json.dumps({"outbounds": [
            vless("live", self.live_port, sockopt={"mark": 77}), vless("dead", self.dead_port)], "routing": {}}))
        self.api.names = ["live", "dead"]
        self.api.servers = [profile(1, "Live", f"127.0.0.1:{self.live_port}", "vless(tcp+reality)"),
                            profile(2, "Dead", f"127.0.0.1:{self.dead_port}", "vless(tcp+reality)")]
        self.api.connected = [assignment("live", 1), assignment("dead", 2)]

        def https(snapshot, tag):
            members = rows(snapshot).get(tag, {}).get("members", [])
            return members[0].get("https", {}) if members else {}

        with patch.dict(os.environ, SSL_CERT_FILE=self.cert):
            self.start("--node-url", "https://check.invalid/generate_204", "--node-code", "204",
                       "--node-timeout", "3", "--node-interval", "1", "--xray-config", str(self.config),
                       "--probe-core", str(self.core))
        snapshot = self.wait_for(lambda s: https(s, "live").get("state") == "ok" and
                                 https(s, "dead").get("state") == "error", timeout=20)
        self.assertEqual(https(snapshot, "live")["http_code"], 204)

        first = self.calls()[0]
        self.assertEqual(first["argv"], ["run", "-c", "stdin:"])
        self.assertNotIn("XRAY_LOCATION_CONFDIR", first["env"])
        config = first["config"]
        self.assertEqual(config["log"], {"loglevel": "none"})
        self.assertEqual({inbound["listen"] for inbound in config["inbounds"]}, {"127.0.0.1"})
        self.assertEqual({inbound["protocol"] for inbound in config["inbounds"]}, {"socks"})
        outbounds = {out["settings"]["vnext"][0]["port"]: out for out in config["outbounds"]}
        # The server's own mark stays; a server without one gets the helper's (0 here).
        self.assertEqual(outbounds[self.live_port]["streamSettings"]["sockopt"], {"mark": 77})
        self.assertNotIn("sockopt", outbounds[self.dead_port]["streamSettings"])
        for rule in config["routing"]["rules"]:
            self.assertEqual(rule["inboundTag"][0].replace("in", "out"), rule["outboundTag"])

        self.stop()
        deadline = time.monotonic() + 5
        alive = {call["pid"] for call in self.calls()}
        while alive and time.monotonic() < deadline:
            alive = {pid for pid in alive if os.path.exists(f"/proc/{pid}") and
                     Path(f"/proc/{pid}/stat").read_text().split(")")[-1].split()[0] != "Z"}
            time.sleep(0.05)
        self.assertEqual(alive, set(), "a probe core outlived its batch")

    def test_plain_proxies_need_no_core(self):
        self.config.write_text(json.dumps({"outbounds": [{"tag": "proxy", "protocol": "socks", "settings": {
            "servers": [{"address": "127.0.0.1", "port": self.live_port}]}}], "routing": {}}))
        self.api.servers = [profile(1, "Socks", f"127.0.0.1:{self.live_port}", "socks5")]
        self.api.connected = [assignment("proxy", 1)]
        self.start("--node-url", "https://check.invalid/generate_204", "--node-timeout", "1",
                   "--node-interval", "1", "--xray-config", str(self.config), "--probe-core", str(self.core))
        self.wait_for(lambda s: rows(s).get("proxy", {}).get("members", [{}])[0].get("https", {}).get("state")
                      not in (None, "pending"), timeout=10)
        self.assertEqual(self.calls(), [])
