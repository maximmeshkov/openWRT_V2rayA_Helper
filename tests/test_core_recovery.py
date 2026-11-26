"""Run the Xray recovery state machine and its checkpoint with a controlled API."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "linux", "recovery checkpoint reads Linux boot and namespace IDs")
class CoreRecoveryBudget(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tests = Path(__file__).resolve().parent
        src = tests.parent / "src"
        build = tempfile.TemporaryDirectory()
        cls.addClassCleanup(build.cleanup)
        cls.fixture = Path(build.name, "recovery-fixture")
        recovery = os.environ.get("V2RAYA_TEST_CORE_RECOVERY_SOURCE", src / "core_recovery.c")
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-I", src,
                        tests / "core_recovery_fixture.c", recovery, src / "recovery_checkpoint.c", src / "boot_id.c",
                        src / "private_state.c", "-o", cls.fixture, "-ljson-c"], check=True, timeout=30)

    def check_scenario(self, scenario):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([self.fixture, scenario, Path(directory, "recovery.state")],
                                    capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_preflight_veto_does_not_delay_the_next_confirmed_outage(self):
        self.check_scenario("veto")

    def test_uncertain_post_keeps_its_cooldown_after_restart(self):
        self.check_scenario("uncertain")

    def test_attempt_cap_survives_changing_sentinel_ports(self):
        self.check_scenario("rotate-port")

    def test_occupied_api_port_becoming_fixed_vetoes_start_without_using_budget(self):
        self.check_scenario("busy-port-veto")

    def test_secondary_port_occupied_at_final_check_does_not_consume_attempt(self):
        self.check_scenario("secondary-port-veto")

    def test_unverified_start_socket_does_not_consume_attempt(self):
        self.check_scenario("foreign-peer-veto")
