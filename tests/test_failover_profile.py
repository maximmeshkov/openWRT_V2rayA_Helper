"""Check native candidate profiles against v2rayA 2.2.7.4 share formats."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


UUID = "00000000-0000-4000-9000-000000000001"
VLESS = f"vless://{UUID}@edge.test:443?security=tls&sni=front.test&type=xhttp"


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
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct failover_profile candidate = {0};
    const char *error = failover_profile_parse(argv[1], &candidate);
    if (error) {
        if (candidate.storage || candidate.node.host) return 3;
        puts(error);
    } else {
        const struct node_profile *p = &candidate.node;
        printf("ok %s %s %d %d %d %s %s %s %d %d\n",
            (const char *[]){"socks5", "http", "https", "vless"}[p->kind],
            p->host, p->port, p->http_version, p->allow_insecure, p->sni,
            p->mode, p->fingerprint, !strcmp(p->path,"/foo +/bar?x=y&a=b"),
            !strcmp(p->username,"user+@name") && !strcmp(p->password,"pass:/word"));
    }
    failover_profile_clear(&candidate);
    return 0;
}
''')
        cls.binary = root / "driver"
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-I", src, driver,
                        src / "inventory.c", src / "node_profile.c", src / "failover_profile.c",
                        "-lcurl", "-ljson-c", "-o", cls.binary], check=True)

    def check(self, uri):
        return subprocess.check_output([self.binary, uri], text=True).strip()

    def test_xhttp_with_default_http2_and_plain_tls(self):
        self.assertEqual(self.check(VLESS + "#Display%20Only"),
                         "ok vless edge.test 443 2 0 front.test packet-up  0 0")
        self.assertEqual(self.check(VLESS + "&alpn=h2%2C+h3&fp=firefox"
                                   "&path=%2Ffoo+%2B%2Fbar%3Fx%3Dy%26a%3Db"),
                         "ok vless edge.test 443 2 0 front.test packet-up firefox 1 0")
        self.assertEqual(self.check(VLESS + "&alpn=http%2F1.1&allowInsecure=true"),
                         "ok vless edge.test 443 1 1 front.test packet-up  0 0")

    def test_simple_proxy_export(self):
        self.assertEqual(self.check("socks5://[2001:db8::1]:1080#Synthetic"),
                         "ok socks5 2001:db8::1 1080 0 0    0 0")
        self.assertEqual(self.check("https://user+%40name:pass%3A%2Fword@proxy.test:443"),
                         "ok https proxy.test 443 0 0 proxy.test   0 1")
        self.assertEqual(self.check("http://proxy.test:8080#Synthetic"),
                         "ok http proxy.test 8080 0 0    0 0")

    def test_rejects_unsupported_or_ambiguous_profiles(self):
        cases = [
            (VLESS.replace("&sni=front.test", ""), "catalog XHTTP profile has no explicit TLS server name"),
            (VLESS.replace("security=tls", "security=reality"), "unsupported catalog VLESS transport"),
            (VLESS.replace("type=xhttp", "type=ws"), "unsupported catalog VLESS transport"),
            (VLESS + "&flow=xtls-rprx-vision", "unsupported catalog VLESS transport"),
            (VLESS + "&alpn=h3", "unsupported XHTTP ALPN"),
            (VLESS + "&alpn=h2,h3e", "unsupported XHTTP ALPN"),
            (VLESS + "&type=xhttp", "invalid catalog profile URL"),
            (VLESS + "&extra=true", "invalid catalog profile URL"),
            (VLESS + "&host=discarded.test", "invalid catalog profile URL"),
            (VLESS + "&allowInsecure=1", "invalid catalog profile URL"),
            (VLESS + "&path=%00", "invalid catalog profile URL"),
            (VLESS + "&path=%GG", "invalid catalog profile URL"),
            (VLESS.replace(UUID, "arbitrary-identifier"), "unsupported VLESS account"),
            ("socks4://proxy.test:1080", "unsupported catalog protocol"),
            ("socks5://user%00name:a@proxy.test:1080", "invalid catalog profile URL"),
            ("socks5://user@proxy.test:1080", "invalid catalog profile URL"),
            ("socks5://a%3Ab:a@proxy.test:1080", None),
            ("http://a%3Ab:a@proxy.test:8080", "unsupported proxy credentials"),
            ("http://proxy.test:8080/path", "invalid catalog profile URL"),
            ("http://proxy.test:8080/path/..", "invalid catalog profile URL"),
            ("https://proxy.test", "invalid catalog profile URL"),
            ("socks5://[fe80::1%25wan]:1080", "invalid catalog profile URL")
        ]
        for uri, error in cases:
            with self.subTest(error=error):
                result = self.check(uri)
                if error is None:
                    self.assertTrue(result.startswith("ok socks5 "))
                else:
                    self.assertEqual(result, error)
