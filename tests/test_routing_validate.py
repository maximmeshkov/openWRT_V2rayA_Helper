"""Offline validation, with the real Xray cases enabled by V2RAYA_TEST_XRAY."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


@unittest.skipIf(os.environ.get("V2RAYA_TEST_SYSROOT"), "native RoutingA validation tests")
class RoutingValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = tempfile.TemporaryDirectory()
        cls.addClassCleanup(scratch.cleanup)
        cls.scratch = Path(scratch.name)
        src = Path(__file__).resolve().parents[1] / "src"
        caller = cls.scratch / "validate.c"
        caller.write_text('#include "routing_validate.h"\n'
                          'int main(int argc, char **argv) {\n'
                          '    return argc != 6 || !routing_validate_advanced(argv[2], argv[3], core_kind_of(argv[1]),\n'
                          '                                                   argv[4], argv[5]);\n'
                          '}\n')
        cls.validator = cls.scratch / "validate"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", src, caller,
                        src / "routing_validate.c", src / "core_kind.c", "-ljson-c", "-o", cls.validator], check=True)

    def validate(self, kind, value, core, assets, env=None, variant="Xray"):
        result = subprocess.run([self.validator, variant, kind, value, core, assets], capture_output=True,
                                env=env, timeout=7)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))
        return result.returncode

    @unittest.skipUnless(os.environ.get("V2RAYA_TEST_XRAY"), "requires a local Xray 25.10.15 test binary")
    def test_xray_checks_real_geodata_and_regexp(self):
        core = Path(os.environ["V2RAYA_TEST_XRAY"]).absolute()
        assets = Path(os.environ.get("V2RAYA_TEST_ASSETS", core.parent)).absolute()
        self.assertIn("Xray 25.10.15 ", subprocess.check_output([core, "version"], text=True))
        confdir = self.scratch / "unrelated-configs"
        confdir.mkdir()
        (confdir / "broken.json").write_text("not a config")
        env = dict(os.environ, XRAY_LOCATION_CONFDIR=str(confdir), XRAY_LOCATION_ASSET=str(confdir))
        for kind, value, expected in (
            ("regexp", r"(^|\.)example\.org$", 0),
            ("regexp", "[", 1),
            ("geoip", "!private", 0),
            ("geoip", "missing-helper-test-tag", 1),
            ("geosite", "google", 0),
            ("geosite", "missing-helper-test-tag", 1),
            ("geosite", "google@missing-helper-test-attribute", 1),
        ):
            with self.subTest(kind=kind, value=value):
                self.assertEqual(self.validate(kind, value, core, assets, env), expected)
        self.assertEqual(self.validate("geoip", "private", core, confdir), 1)
        self.assertEqual(self.validate("geosite", "google", core, confdir), 1)

    def test_each_core_gets_its_own_check_command_and_asset_variable(self):
        record = self.scratch / "core-call"
        core = self.scratch / "fake-core"
        # The check runs with only the asset variable in its environment.
        core.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" "$XRAY_LOCATION_ASSET|$V2RAY_LOCATION_ASSET" > {record}\n'
                        '/bin/cat > /dev/null\n')
        core.chmod(0o755)
        for variant, arguments, assets in (
            ("Xray", "run -test -c stdin:", f"{self.scratch}|"),
            ("V2rayaCore", "run -test -c stdin:", f"{self.scratch}|"),
            ("V2Ray", "test -format=json -c /dev/stdin", f"|{self.scratch}"),
        ):
            with self.subTest(variant=variant):
                record.unlink(missing_ok=True)
                self.assertEqual(self.validate("regexp", "example", core, self.scratch, variant=variant), 0)
                self.assertEqual(record.read_text().splitlines(), [arguments, assets])
        record.unlink()
        self.assertEqual(self.validate("regexp", "example", core, self.scratch, variant="Unknown"), 1)
        self.assertFalse(record.exists())

    def test_bounded_child_cleanup_and_output(self):
        marker = self.scratch / "pid"
        code = self.scratch / "frozen.c"
        code.write_text('#include <stdio.h>\n#include <unistd.h>\n'
                        'int main(void) {\n'
                        f'    FILE *out = fopen({json.dumps(str(marker))}, "w");\n'
                        '    if (!out) return 2;\n'
                        '    fprintf(out, "%ld\\n", (long)getpid()); fclose(out);\n'
                        '    puts("private test output"); fflush(stdout);\n'
                        '    fputs("private test diagnostics", stderr);\n'
                        '    for (;;) pause();\n'
                        '}\n')
        frozen = self.scratch / "frozen"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", code, "-o", frozen], check=True)
        start = time.monotonic()
        self.assertEqual(self.validate("regexp", "example", frozen, self.scratch), 1)
        self.assertLess(time.monotonic() - start, 5.5)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(marker.read_text()), 0)
