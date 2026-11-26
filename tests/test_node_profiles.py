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
    else printf("ok %s %d %d %d %d %d\n",
                (const char *[]){"socks","http","https","xhttp"}[p.kind],
                p.http_version, p.allow_insecure, p.has_mark && p.mark == 128,
                *p.fingerprint != 0, *p.username && *p.password);
    json_object_put(config);
    return 0;
}
''')
        cls.binary = root / "driver"
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-I", src, driver,
                        src / "inventory.c", src / "node_profile.c", "-lcurl", "-ljson-c",
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
        self.assertEqual(self.parse([self.proxy]), "ok socks 0 0 1 0 1")
        server = self.proxy["settings"]["servers"][0]
        server.update(address="proxy.invalid", port=8443)
        self.assertFalse(self.parse([self.proxy]).startswith("ok"))
        self.assertTrue(self.parse([self.proxy], endpoint="proxy.invalid:8443").startswith("ok socks"))
        self.assertFalse(self.parse([self.proxy], endpoint="proxy.invalid:8443", net="http").startswith("ok"))
        self.proxy["protocol"] = "http"
        self.assertTrue(self.parse([self.proxy], endpoint="proxy.invalid:8443", net="http").startswith("ok http "))
        self.proxy["streamSettings"].update(network="tcp", security="tls", tlsSettings={"serverName": "proxy.invalid"})
        self.assertEqual(self.parse([self.proxy], endpoint="proxy.invalid:8443", net="https"), "ok https 0 0 1 0 1")
        tls = self.proxy["streamSettings"]["tlsSettings"]
        tls["allowInsecure"] = True
        self.assertEqual(self.parse([self.proxy], endpoint="proxy.invalid:8443", net="https"),
                         "HTTPS proxy with allowInsecure is unsupported")
        tls["allowInsecure"] = False
        self.proxy["streamSettings"]["tlsSettings"]["serverName"] = "other.invalid"
        self.assertFalse(self.parse([self.proxy], endpoint="proxy.invalid:8443", net="https").startswith("ok"))

    def test_plain_proxy_never_ignores_transport_or_account_settings(self):
        for root, key, value in [
            (("streamSettings",), "security", "tls"), (("streamSettings",), "tlsSettings", {}),
            (("streamSettings",), "network", "ws"),
            (("streamSettings", "sockopt"), "dialerProxy", "other"),
            (("settings", "servers", 0), "version", "4"),
            (("settings", "servers", 0, "users", 0), "user", "private\0truncated"),
        ]:
            with self.subTest(key=key):
                config = copy.deepcopy(self.proxy)
                target = config
                for sub in root:
                    target = target[sub]
                target[key] = value
                self.assertFalse(self.parse([config]).startswith("ok"))

    def test_xhttp_and_alpn(self):
        def run():
            return self.parse([self.xhttp], "node.invalid:443", "vless(xhttp+tls)")
        tls = self.xhttp["streamSettings"]["tlsSettings"]
        self.assertEqual(run(), "ok xhttp 2 0 1 1 0")
        xhttp = self.xhttp["streamSettings"]["xhttpSettings"]
        xhttp["path"] = "test bench?flag=1"
        self.assertEqual(run(), "ok xhttp 2 0 1 1 0")
        xhttp["path"] = "test?unsafe=raw space"
        self.assertFalse(run().startswith("ok"))
        xhttp["path"] = "/test"
        tls.update(alpn=["http/1.1"], allowInsecure=True)
        self.assertEqual(run(), "ok xhttp 1 1 1 1 0")
        xhttp["mode"] = "stream-up"
        self.assertFalse(run().startswith("ok"))
        xhttp["mode"] = "packet-up"
        tls["alpn"] = ["h3"]
        self.assertFalse(run().startswith("ok"))
        self.assertFalse(self.parse([self.xhttp], "node.invalid:443", "vmess(xhttp+tls)").startswith("ok"))

    def test_unimplemented_profile_features_stay_unknown(self):
        for root, key, value in [
            ((), "proxySettings", {"tag": "chain"}), ((), "mux", {"enabled": True}),
            (("streamSettings", "sockopt"), "dialerProxy", "other"),
            (("streamSettings", "tlsSettings"), "pinnedPeerCertSha256", "fixture-only"),
            (("streamSettings", "xhttpSettings"), "downloadSettings", {}),
            (("settings", "vnext", 0, "users", 0), "flow", "xtls-rprx-vision"),
            (("settings", "vnext", 0, "users", 0), "id", "bad-uuid"),
            (("settings", "vnext", 0), "port", 444),
        ]:
            with self.subTest(key=key):
                config = copy.deepcopy(self.xhttp)
                target = config
                for sub in root:
                    target = target[sub]
                target[key] = value
                error = self.parse([config], "node.invalid:443", "vless(xhttp+tls)")
                self.assertFalse(error.startswith("ok"))
                self.assertNotIn("fixture-only", error)

    def test_ambiguous_profiles(self):
        self.assertFalse(self.parse([self.proxy, self.proxy]).startswith("ok"))
        users = self.proxy["settings"]["servers"][0]["users"]
        users.append(users[0])
        self.assertFalse(self.parse([self.proxy]).startswith("ok"))
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
