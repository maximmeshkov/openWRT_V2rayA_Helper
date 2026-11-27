"""Match synthetic v2rayA inventory against independent snapshots of generated Xray config."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipIf(os.environ.get("V2RAYA_TEST_SYSROOT"), "native profile parser tests")
class NodeProfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        src = Path(__file__).resolve().parents[1] / "src"
        driver = root / "driver.c"
        driver.write_text(r'''
#include "node_profile.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 5) return 2;
    struct member members[] = {
        {.name = "One", .address = argv[2], .display_net = argv[3]},
        {.name = argv[4], .address = argv[2], .display_net = argv[3]}
    };
    struct outbound o = {.name = "my-out", .members = members, .count = *argv[4] ? 2 : 1};
    struct node_profile p;
    json_object *config = node_config_read(argv[1]);
    const char *err = node_profile_parse(config, &o, members, &p);
    // Deliberately print only the public error, method and non-secret booleans.
    if (err) puts(err);
    else printf("ok %s %d %d\n", (const char *[]){"socks","http","https","core"}[p.kind],
                p.has_mark && p.mark == 128, *p.username && *p.password);
    json_object_put(config);
    return 0;
}
''')
        cls.binary = root / "driver"
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-I", src, driver,
                        src / "inventory.c", src / "capability.c", src / "node_profile.c", src / "node_key.c", "-lcurl", "-ljson-c",
                        "-o", cls.binary], check=True)
        cls.config = root / "config.json"

    def setUp(self):
        self.proxy = {"tag": "my-out", "protocol": "socks", "settings": {"servers": [
            {"address": "::1", "port": 1080, "users": [{"user": "fixture-only", "pass": "fixture-only"}]}]},
            "streamSettings": {"sockopt": {"mark": 128}}}
        self.xhttp = {"tag": "my-out", "protocol": "vless", "settings": {"vnext": [
            {"address": "node.invalid", "port": 443, "users": [
                {"id": "00000000-0000-4000-9000-000000000001", "encryption": "none"}]}]},
            "streamSettings": {"network": "xhttp", "security": "tls", "sockopt": {"mark": 128},
                               "xhttpSettings": {"path": "/example/path"},
                               "tlsSettings": {"allowInsecure": False, "alpn": ["h2", "h3"],
                                               "serverName": "test.invalid", "fingerprint": "firefox"}}}

    def parse(self, outbounds, endpoint="[::1]:1080", net="socks5", other="", routing=None):
        self.config.write_text(json.dumps({"outbounds": outbounds, "routing": routing or {}}))
        return subprocess.check_output([self.binary, self.config, endpoint, net, other], text=True).strip()

    def test_authenticated_proxies_and_rotation(self):
        self.assertEqual(self.parse([self.proxy]), "ok socks 1 1")
        server = self.proxy["settings"]["servers"][0]
        server.update(address="proxy.invalid", port=8443)
        self.assertEqual(self.parse([self.proxy]), "profile endpoint differs from v2rayA")
        self.assertTrue(self.parse([self.proxy], endpoint="proxy.invalid:8443").startswith("ok socks"))
        self.proxy["protocol"] = "http"
        self.assertTrue(self.parse([self.proxy], endpoint="proxy.invalid:8443", net="http").startswith("ok http "))
        self.proxy["streamSettings"].update(network="tcp", security="tls", tlsSettings={"serverName": "proxy.invalid"})
        self.assertEqual(self.parse([self.proxy], endpoint="proxy.invalid:8443", net="https"), "ok https 1 1")

    def test_what_libcurl_cannot_reproduce_goes_to_the_core(self):
        # A plain proxy runs natively only when libcurl can reach it exactly as configured.
        for root, key, value in [
            (("streamSettings",), "security", "tls"), (("streamSettings",), "tlsSettings", {}),
            (("streamSettings",), "network", "ws"), ((), "mux", {"enabled": True}),
            (("settings", "servers", 0), "version", "4"),
            (("settings", "servers", 0, "users", 0), "user", "private\0truncated"),
        ]:
            with self.subTest(key=key):
                config = copy.deepcopy(self.proxy)
                target = config
                for sub in root:
                    target = target[sub]
                target[key] = value
                self.assertEqual(self.parse([config]), "ok core 0 0")
        self.assertEqual(self.parse([self.proxy], net="http"), "ok core 0 0")

    def test_core_runs_any_protocol_at_the_reported_endpoint(self):
        self.assertEqual(self.parse([self.xhttp], "node.invalid:443", "vless(xhttp+tls)"), "ok core 0 0")
        trojan = {"tag": "my-out", "protocol": "trojan", "settings": {"servers": [
            {"address": "node.invalid", "port": 443, "password": "fixture-only"}]},
            "streamSettings": {"network": "grpc", "security": "reality"}}
        shadowsocks = {"tag": "my-out", "protocol": "shadowsocks", "settings": {"servers": [
            {"address": "node.invalid", "port": 443, "method": "aes-256-gcm", "password": "fixture-only"}]}}
        for config in (trojan, shadowsocks):
            with self.subTest(protocol=config["protocol"]):
                self.assertEqual(self.parse([config], "node.invalid:443", "any"), "ok core 0 0")
        for root, key, value in [
            ((), "mux", {"enabled": True}), (("streamSettings", "tlsSettings"), "pinnedPeerCertSha256", "x"),
            (("streamSettings", "xhttpSettings"), "downloadSettings", {}),
            (("settings", "vnext", 0, "users", 0), "flow", "xtls-rprx-vision"),
        ]:
            with self.subTest(key=key):
                config = copy.deepcopy(self.xhttp)
                target = config
                for sub in root:
                    target = target[sub]
                target[key] = value
                self.assertEqual(self.parse([config], "node.invalid:443", "vless(xhttp+tls)"), "ok core 0 0")

    def test_core_refuses_chains_and_other_endpoints(self):
        for root, key, value, error in [
            ((), "proxySettings", {"tag": "chain"}, "proxy chains are unsupported"),
            (("streamSettings", "sockopt"), "dialerProxy", "other", "proxy chains are unsupported"),
            (("settings", "vnext", 0), "port", 444, "profile endpoint differs from v2rayA"),
        ]:
            with self.subTest(key=key):
                config = copy.deepcopy(self.xhttp)
                target = config
                for sub in root:
                    target = target[sub]
                target[key] = value
                self.assertEqual(self.parse([config], "node.invalid:443", "vless(xhttp+tls)"), error)
        self.xhttp["settings"]["vnext"].append(self.xhttp["settings"]["vnext"][0])
        self.assertEqual(self.parse([self.xhttp], "node.invalid:443", "vless(xhttp+tls)"),
                         "outbound has no single server")

    def test_ambiguous_profiles(self):
        self.assertFalse(self.parse([self.proxy, self.proxy]).startswith("ok"))
        users = self.proxy["settings"]["servers"][0]["users"]
        users.append(users[0])
        self.assertEqual(self.parse([self.proxy]), "ok core 0 0")
        users.pop()
        self.proxy["settings"]["servers"].append(self.proxy["settings"]["servers"][0])
        self.assertFalse(self.parse([self.proxy]).startswith("ok"))

    def test_match_group_by_named_member_not_order_or_routing_rules(self):
        self.proxy["tag"] = "『One』"
        routing = {"rules": [{"type": "field", "domain": ["example.net"], "outboundTag": "SomethingElse"}],
                   "balancers": [{"tag": "my-out", "selector": ["『Two』", "『One』"]}]}
        self.assertTrue(self.parse([self.proxy], other="Two", routing=routing).startswith("ok socks"))
        routing["rules"].clear()
        self.assertTrue(self.parse([self.proxy], other="Two", routing=routing).startswith("ok socks"))
        self.assertFalse(self.parse([self.proxy], other="One", routing=routing).startswith("ok"))
        routing["balancers"][0]["selector"].pop()
        self.assertFalse(self.parse([self.proxy], other="Two", routing=routing).startswith("ok"))


if __name__ == "__main__":
    unittest.main()
