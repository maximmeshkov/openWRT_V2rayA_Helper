"""Which v2rayA builds may receive which changes, and what an opt-in covers."""
import ctypes as C
from ctypes.util import find_library
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SWITCH, ROUTING_SAVE, CORE_START, REDIRECT_RESTORE = range(4)
DENIED, VERIFIED, OPTED_IN = range(3)
OPT_IN = "V2RAYA_HELPER_ALLOW_UNVERIFIED"


class CapabilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        build = tempfile.TemporaryDirectory()
        cls.addClassCleanup(build.cleanup)
        stub = Path(build.name, "api_stub.c")
        # capability_check_api reads /api/version through inventory.c; only the decision is tested here.
        stub.write_text("#include <json-c/json.h>\n#include <stddef.h>\n"
                        "struct v2raya_api;\n"
                        "json_object *v2raya_api_version_data(const struct v2raya_api *a, char *e, size_t n)\n"
                        "{ (void)a; (void)e; (void)n; return NULL; }\n")
        library = Path(build.name, "capability.so")
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                        "-I", root / "src", root / "src/capability.c", stub, "-o", library, "-ljson-c"], check=True)
        cls.lib = C.CDLL(str(library))
        cls.jsonc = C.CDLL(find_library("json-c"))
        cls.jsonc.json_tokener_parse.argtypes = [C.c_char_p]
        cls.jsonc.json_tokener_parse.restype = C.c_void_p
        cls.jsonc.json_object_put.argtypes = [C.c_void_p]
        cls.lib.capability_decide.argtypes = [C.c_void_p, C.c_int, C.c_char_p, C.c_size_t]
        cls.lib.capability_decide.restype = C.c_int

    def decide(self, version, variant, feature):
        data = self.jsonc.json_tokener_parse(json.dumps({"version": version, "variant": variant, "lite": 0}).encode())
        reason = C.create_string_buffer(160)
        try:
            return self.lib.capability_decide(data, feature, reason, len(reason)), reason.value.decode()
        finally:
            self.jsonc.json_object_put(data)

    @patch.dict(os.environ, {OPT_IN: ""})
    def test_openwrt_builds_with_xray_are_verified(self):
        for version in ("2.2.6.7", "2.2.7.3", "2.2.7.4", "2.2.7.5"):
            for feature in (SWITCH, ROUTING_SAVE, CORE_START, REDIRECT_RESTORE):
                self.assertEqual(self.decide(version, "Xray", feature)[0], VERIFIED, (version, feature))

    @patch.dict(os.environ, {OPT_IN: ""})
    def test_v2ray_core_keeps_routing_but_not_core_dependent_changes(self):
        self.assertEqual(self.decide("2.2.7.4", "V2Ray", ROUTING_SAVE)[0], VERIFIED)
        for feature in (SWITCH, CORE_START, REDIRECT_RESTORE):
            result, reason = self.decide("2.2.7.4", "V2Ray", feature)
            self.assertEqual(result, DENIED)
            self.assertIn("v2rayA 2.2.7.4 with the V2Ray core", reason)

    @patch.dict(os.environ, {OPT_IN: ""})
    def test_unverified_version_is_read_only(self):
        for feature in (SWITCH, ROUTING_SAVE, CORE_START, REDIRECT_RESTORE):
            self.assertEqual(self.decide("2.5.16", "V2rayaCore", feature)[0], DENIED)
        self.assertEqual(self.decide("2.5.16", "V2rayaCore", SWITCH)[1],
                         "automatic server switching is not verified for v2rayA 2.5.16 with the V2rayaCore core")

    def test_opt_in_names_one_version_and_skips_version_specific_internals(self):
        with patch.dict(os.environ, {OPT_IN: "2.5.16"}):
            self.assertEqual(self.decide("2.5.16", "V2rayaCore", ROUTING_SAVE)[0], OPTED_IN)
            self.assertEqual(self.decide("2.5.16", "V2rayaCore", CORE_START)[0], OPTED_IN)
            # 2.3 and later add a connected server to the outbound instead of replacing it.
            self.assertEqual(self.decide("2.5.16", "V2rayaCore", SWITCH)[0], DENIED)
            self.assertEqual(self.decide("2.5.16", "V2rayaCore", REDIRECT_RESTORE)[0], DENIED)
            self.assertEqual(self.decide("2.5.15", "V2rayaCore", ROUTING_SAVE)[0], DENIED)
        with patch.dict(os.environ, {OPT_IN: "2.2.8"}):
            self.assertEqual(self.decide("2.2.8", "Xray", SWITCH)[0], OPTED_IN)
            self.assertEqual(self.decide("2.2.8", "V2Ray", SWITCH)[0], DENIED)

    @patch.dict(os.environ, {OPT_IN: ""})
    def test_missing_version_denies_and_missing_core_limits(self):
        for document, feature, expected in ((b'{"variant": "Xray"}', ROUTING_SAVE, DENIED),
                                            (b'{"version": "2.2.7.4"}', ROUTING_SAVE, VERIFIED),
                                            (b'{"version": "2.2.7.4"}', SWITCH, DENIED)):
            data = self.jsonc.json_tokener_parse(document)
            reason = C.create_string_buffer(160)
            self.assertEqual(self.lib.capability_decide(data, feature, reason, len(reason)), expected, document)
            self.jsonc.json_object_put(data)
        self.assertEqual(self.decide("2.2.7.4", "", CORE_START)[1],
                         "starting a crashed core is not verified for v2rayA 2.2.7.4 with the unknown core")


if __name__ == "__main__":
    unittest.main()
