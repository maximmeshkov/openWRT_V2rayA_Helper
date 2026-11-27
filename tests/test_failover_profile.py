"""Turn v2rayA 2.2.x share exports into the outbound its Configuration() builds."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import urlencode


UUID = "00000000-0000-4000-9000-000000000001"


def vless(**query):
    """V2Ray.ExportToURL for vless: url.Values.Encode of the non-empty fields."""
    return f"vless://{UUID}@edge.test:443?{urlencode(query)}#Display%20Only"


def vmess(**fields):
    """V2Ray.ExportToURL for vmess: unpadded base64 of the server object's JSON."""
    server = {"ps": "Display Only", "add": "edge.test", "port": "443", "id": UUID, "aid": "0", "scy": "auto",
              "net": "tcp", "type": "none", "host": "", "path": "", "tls": "", "allowInsecure": False,
              "quicSecurity": "", "v": "2", "protocol": "vmess", **fields}
    return "vmess://" + base64.b64encode(json.dumps(server).encode()).decode().rstrip("=")


def vnext(user, **stream):
    return {"tag": "candidate", "protocol": stream.pop("protocol", "vless"), "settings": {"vnext": [
        {"address": "edge.test", "port": 443, "users": [user]}]}, "streamSettings": stream}


VLESS_USER = {"id": UUID, "encryption": "none"}
VMESS_USER = {"id": UUID, "alterId": 0, "security": "auto"}


@unittest.skipIf(os.environ.get("V2RAYA_TEST_SYSROOT"), "native profile parser tests")
class FailoverProfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = tempfile.TemporaryDirectory()
        cls.addClassCleanup(scratch.cleanup)
        root = Path(scratch.name)
        src = Path(__file__).resolve().parents[1] / "src"
        driver = root / "driver.c"
        driver.write_text(r'''
#include "failover_profile.h"
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct failover_profile candidate = {0};
    const char *error = failover_profile_parse(argv[1], &candidate);
    if (error) {
        if (candidate.storage || candidate.node.host) return 3;
        puts(error);
    } else {
        const struct node_profile *p = &candidate.node;
        json_object *out = json_object_array_get_idx(json_object_object_get(candidate.storage, "outbounds"), 0);
        printf("ok %s %s %d %d\n%s\n", (const char *[]){"socks5", "http", "https", "core"}[p->kind], p->host,
               p->port, *p->username && *p->password, json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN));
    }
    failover_profile_clear(&candidate);
    return 0;
}
''')
        cls.binary = root / "driver"
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-I", src, driver,
                        src / "inventory.c", src / "capability.c", src / "node_profile.c", src / "node_key.c",
                        src / "failover_profile.c", "-lcurl", "-ljson-c", "-o", cls.binary], check=True)

    def check(self, uri):
        return subprocess.check_output([self.binary, uri], text=True).strip()

    def outbound(self, uri, kind="core"):
        head, _, body = self.check(uri).partition("\n")
        self.assertTrue(head.startswith(f"ok {kind} "), head)
        return json.loads(body)

    def test_vless_transports_and_security(self):
        self.assertEqual(self.outbound(vless(type="tcp", security="reality", flow="xtls-rprx-vision", sni="front.test",
                                             allowInsecure="false", fp="chrome", pbk="PUBLIC", sid="ab", spx="/")),
                         vnext({**VLESS_USER, "flow": "xtls-rprx-vision"}, network="tcp", security="reality",
                               realitySettings={"serverName": "front.test", "fingerprint": "chrome", "show": False,
                                                "publicKey": "PUBLIC", "shortId": "ab", "spiderX": "/"}))
        self.assertEqual(self.outbound(vless(type="ws", security="tls", path="/ws", host="cdn.test",
                                             alpn="h2, http/1.1", allowInsecure="true")),
                         vnext(VLESS_USER, network="ws", wsSettings={"path": "/ws", "headers": {"Host": "cdn.test"}},
                               security="tls", tlsSettings={"allowInsecure": True, "serverName": "cdn.test",
                                                            "alpn": ["h2", "http/1.1"], "fingerprint": ""}))
        self.assertEqual(self.outbound(vless(type="grpc", serviceName="svc", security="tls", sni="front.test")),
                         vnext(VLESS_USER, network="grpc", grpcSettings={"serviceName": "svc"}, security="tls",
                               tlsSettings={"serverName": "front.test", "fingerprint": ""}))
        self.assertEqual(self.outbound(vless(type="xhttp", path="/x", security="none")),
                         vnext(VLESS_USER, network="xhttp", xhttpSettings={"path": "/x"}))
        self.assertEqual(self.outbound(vless(type="kcp", headerType="wechat-video", seed="s", security="none"))
                         ["streamSettings"]["kcpSettings"]["seed"], "s")

    def test_vmess_json_export(self):
        self.assertEqual(self.outbound(vmess(net="ws", host="cdn.test", path="/ws", tls="tls", sni="front.test")),
                         vnext(VMESS_USER, protocol="vmess", network="ws",
                               wsSettings={"path": "/ws", "headers": {"Host": "cdn.test"}}, security="tls",
                               tlsSettings={"serverName": "front.test", "fingerprint": ""}))
        tcp = self.outbound(vmess(type="http", host="a.test,b.test", path="x,/y"))["streamSettings"]["tcpSettings"]
        self.assertEqual(tcp["header"]["request"]["path"], ["/x", "/y"])
        self.assertEqual(tcp["header"]["request"]["headers"]["Host"], ["a.test", "b.test"])
        # ParseVmessURL treats a host that starts with "/" as the path.
        self.assertEqual(self.outbound(vmess(net="ws", host="/only-path"))["streamSettings"]["wsSettings"],
                         {"path": "/only-path", "headers": {"Host": ""}})

    def test_trojan_and_shadowsocks(self):
        self.assertEqual(self.outbound("trojan://secret@edge.test:443?type=grpc&serviceName=svc&sni=front.test#N"),
                         {"tag": "candidate", "protocol": "trojan", "settings": {"servers": [
                             {"address": "edge.test", "port": 443, "password": "secret"}]},
                          "streamSettings": {"network": "grpc", "security": "tls", "grpcSettings": {"serviceName": "svc"},
                                             "tlsSettings": {"serverName": "front.test", "allowInsecure": False}}})
        ws = self.outbound("trojan://secret@edge.test:443?type=ws&path=%2Fws&host=cdn.test&allowInsecure=1")
        self.assertEqual(ws["streamSettings"]["tlsSettings"], {"serverName": "edge.test", "allowInsecure": True})
        user = base64.urlsafe_b64encode(b"AES-256-GCM:pass:word").decode().rstrip("=")
        self.assertEqual(self.outbound(f"ss://{user}@[2001:db8::1]:8388#N"),
                         {"tag": "candidate", "protocol": "shadowsocks", "settings": {"servers": [
                             {"address": "2001:db8::1", "port": 8388, "method": "aes-256-gcm", "password": "pass:word"}]}})

    def test_plain_proxies_stay_native(self):
        self.assertEqual(self.check("socks5://[2001:db8::1]:1080#Synthetic").splitlines()[0], "ok socks5 2001:db8::1 1080 0")
        self.assertEqual(self.check("https://user+%40name:pass%3A%2Fword@proxy.test:443").splitlines()[0],
                         "ok https proxy.test 443 1")
        self.assertEqual(self.check("http://proxy.test:8080#Synthetic").splitlines()[0], "ok http proxy.test 8080 0")
        # libcurl cannot send a user name with a colon; the core can.
        self.assertTrue(self.check("http://a%3Ab:a@proxy.test:8080").startswith("ok core "))

    def test_rejects_what_the_probe_core_cannot_run(self):
        rc4 = base64.urlsafe_b64encode(b"rc4-md5:x").decode().rstrip("=")
        aes = base64.urlsafe_b64encode(b"aes-256-gcm:x").decode().rstrip("=")
        cases = [
            ("ssr://abc", "unsupported catalog protocol"),
            ("trojan-go://secret@edge.test:443", "unsupported catalog protocol"),
            ("tuic://u:p@edge.test:443", "unsupported catalog protocol"),
            (f"ss://{rc4}@edge.test:8388", "unsupported shadowsocks cipher"),
            (f"ss://{aes}@edge.test:8388?plugin=simple-obfs", "shadowsocks plugins are unsupported"),
            (vless(type="foo", security="none"), "unsupported catalog transport"),
            (vless(type="tcp", security="none").replace(UUID, "short-id"), "unsupported catalog account"),
            (vless(type="tcp", extra="1"), "invalid catalog profile URL"),
            (vless(type="tcp", allowInsecure="1"), "invalid catalog profile URL"),
            ("vmess://not-base64!", "invalid catalog profile URL"),
            (vmess(add=""), "invalid catalog profile URL"),
            ("socks4://proxy.test:1080", "unsupported catalog protocol"),
            ("socks5://user%00name:a@proxy.test:1080", "invalid catalog profile URL"),
            ("socks5://user@proxy.test:1080", "invalid catalog profile URL"),
            ("http://proxy.test:8080/path", "invalid catalog profile URL"),
            ("https://proxy.test", "invalid catalog profile URL"),
            ("socks5://[fe80::1%25wan]:1080", "invalid catalog profile URL"),
        ]
        for uri, error in cases:
            with self.subTest(uri=uri):
                self.assertEqual(self.check(uri), error)


if __name__ == "__main__":
    unittest.main()
