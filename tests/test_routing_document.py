"""Check the RoutingA form's literal serialization and byte-preserving insertion."""
import ctypes
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class RoutingPosition(ctypes.Structure):
    _fields_ = [("line", ctypes.c_size_t), ("text", ctypes.c_void_p), ("length", ctypes.c_size_t)]


@unittest.skipIf(os.environ.get("V2RAYA_TEST_SYSROOT"), "native RoutingA parser tests")
class RoutingDocumentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = tempfile.TemporaryDirectory()
        cls.addClassCleanup(scratch.cleanup)
        src = Path(__file__).resolve().parents[1] / "src"
        library = Path(scratch.name) / "routing_document.so"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared",
                        "-fPIC", src / "routing_document.c", "-o", library], check=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.free = ctypes.CDLL(None).free
        cls.free.argtypes = [ctypes.c_void_p]
        cls.free.restype = None
        cls.lib.routing_build_rule.argtypes = [ctypes.c_char_p] * 3 + [
            ctypes.POINTER(ctypes.c_void_p)]
        cls.lib.routing_build_rule.restype = ctypes.c_char_p
        cls.lib.routing_can_insert_before.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        cls.lib.routing_can_insert_before.restype = ctypes.c_int
        cls.lib.routing_list_positions.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(RoutingPosition), ctypes.c_size_t]
        cls.lib.routing_list_positions.restype = ctypes.c_size_t
        cls.lib.routing_insert_rule.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                               ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p)]
        cls.lib.routing_insert_rule.restype = ctypes.c_char_p

    def result(self, operation, *parameters):
        output = ctypes.c_void_p()
        error = operation(*parameters, ctypes.byref(output))
        try:
            if error:
                self.assertIsNone(output.value)
                return error.decode(), None
            self.assertIsNotNone(output.value)
            return None, ctypes.string_at(output)
        finally:
            self.free(output)

    def build(self, kind, value, outbound=b"Telega"):
        return self.result(self.lib.routing_build_rule, kind, value, outbound)

    def insert(self, source, rule, line):
        return self.result(self.lib.routing_insert_rule, source, rule, line)

    def test_build_rules(self):
        for kind, value, expected in [
            (b"contains", b"XRay", b"domain(contains: xray)"),
            (b"domain", b"Example.ORG.", b"domain(domain: example.org)"),
            (b"full", b"localhost", b"domain(full: localhost)"),
            (b"ip", b"203.0.113.0/24", b"ip(203.0.113.0/24)"),
            (b"ip", b"2001:db8::/32", b'ip("2001:db8::/32")'),
            (b"geosite", b"category-ads@cn", b"domain(geosite: category-ads@cn)"),
            (b"geoip", b"!private", b"ip(geoip: !private)"),
            (b"regexp", rb"(^|\.)example\.org$", rb'domain(regexp: "(^|\.)example\.org$")'),
            (b"regexp", b'^x"y$', b"""domain(regexp: '^x"y$')""")
        ]:
            with self.subTest(kind=kind, value=value):
                self.assertEqual(self.build(kind, value),
                                 (None, expected + b" -> Telega"))

    def test_invalid_input_cannot_add_other_statements(self):
        for kind, value, tag, error in [
            (b"domain", b"x\ndefault: direct", b"proxy", "invalid_domain"),
            (b"domain", b"example.org\r", b"proxy", "invalid_domain"),
            (b"domain", b"*.example.org", b"proxy", "invalid_domain"),
            (b"domain", b"f" * 64 + b".example", b"proxy", "invalid_domain"),
            (b"full", b"https://example.org", b"proxy", "invalid_domain"),
            (b"full", b"bad-.example.org", b"proxy", "invalid_domain"),
            (b"contains", b"x) -> block", b"proxy", "invalid_domain"),
            (b"contains", b"x", b"12", "invalid_outbound_name"),
            (b"contains", b"x", b"other-rule", "invalid_outbound_name"),
            (b"contains", b"x", b"proxy\nip(8.8.8.8) -> block", "invalid_outbound_name"),
            (b"ip", b"203.0.113.1/33", b"proxy", "invalid_ip_or_cidr"),
            (b"ip", b"2001:db8::/129", b"proxy", "invalid_ip_or_cidr"),
            (b"ip", b"203.0.113.1/", b"proxy", "invalid_ip_or_cidr"),
            (b"ip", b"203.0.113.1/2/1", b"proxy", "invalid_ip_or_cidr"),
            (b"geosite", b"ads@", b"block", "invalid_geo_list"),
            (b"geoip", b"cn@attr", b"proxy", "invalid_geo_list"),
            (b"regexp", b"$$routed_via$$", b"proxy", "invalid_regexp_literal"),
            (b"regexp", b'\"\'\\n"\'', b"proxy", "invalid_regexp_literal"),
            (b"regexp", b"x\n^^", b"proxy", "invalid_regexp_literal"),
            (b"fake", b"x", b"proxy", "invalid_match_type")
        ]:
            with self.subTest(kind=kind, value=value, tag=tag):
                self.assertEqual(self.build(kind, value, tag), (error, None))

    def test_only_standalone_rules_can_be_insertion_points(self):
        source = (b"# description -> proxy\r\n"
                  b"outbound: httpout = http(address: 127.0.0.1, user: 'pass')\r\n"
                  b"\r\n"
                  b"default: proxy\r\n"
                  b"  domain(regexp: \"->(x)\") && port(443) -> proxy  \r\n"
                  b" ip(203.0.113.0/24) -> direct")
        rule = b"domain(contains: test) -> proxy"
        rows = source.split(b"\r\n")
        for line in range(1, len(rows) + 1):
            self.assertEqual(bool(self.lib.routing_can_insert_before(source, line)), line in (5, 6))
        positions = (RoutingPosition * 2)()
        self.assertEqual(self.lib.routing_list_positions(source, positions, 1), 2)
        self.assertEqual([position.line for position in positions], [5, 0])
        self.assertEqual(self.lib.routing_list_positions(source, positions, 2), 2)
        self.assertEqual([position.line for position in positions], [5, 6])
        self.assertEqual([ctypes.string_at(position.text, position.length) for position in positions],
                         [row.strip() for row in rows[4:]])
        self.assertEqual(self.insert(source, rule, 2), ("invalid_insertion_point", None))
        self.assertEqual(self.insert(source, rule, 7), ("invalid_insertion_point", None))
        self.assertEqual(self.insert(source, rule, 5),
                         (None, b"\r\n".join(rows[:4] + [rule] + rows[4:])))
        self.assertEqual(self.insert(source, rule, 6),
                         (None, b"\r\n".join(rows[:5] + [rule] + rows[5:])))

    def test_append_keeps_existing_bytes_and_line_endings(self):
        rule = b"domain(full: example.org) -> block"
        cases = [
            (b"", rule + b"\n"),
            (b"default: proxy", b"default: proxy\n" + rule),
            (b"# comment\n", b"# comment\n" + rule + b"\n"),
            (b"default: proxy\r\n\r\n", b"default: proxy\r\n\r\n" + rule + b"\r\n"),
            (b"default: proxy\r\n# no final newline", b"default: proxy\r\n# no final newline\r\n" + rule),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(self.insert(source, rule, 0), (None, expected))
        self.assertEqual(self.insert(b"", b"default: direct", 0), ("invalid_rule", None))
        self.assertEqual(self.insert(b"", rule + b"\nip(8.8.8.8) -> block", 0),
                         ("invalid_rule", None))
