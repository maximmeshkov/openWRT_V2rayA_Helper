"""Exercise the daemon's latency history through its read-only command."""
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import test_failover_runner as failover_fixture
from test_independent_nodes import NodeFixture


def history(runner, path, outbound=None):
    command = [runner.binary, "latency", str(path)]
    if outbound is not None:
        command.append(outbound)
    return json.loads(subprocess.check_output(command, text=True, timeout=8))


def node_args(runner, path, interval):
    return ["--node-url", "https://check.invalid/generate_204", "--node-code", "204",
            "--node-interval", str(interval), "--node-timeout", "3",
            "--xray-config", str(runner.config), "--latency-file", str(path)]


class LatencyHistory(NodeFixture):
    def test_existing_readings_are_deduplicated_and_keep_their_server(self):
        tag, other = "Основной выход", "Other"
        secret = "fixture-private-latency-password"
        path = Path(self.tmp.name, "latency.json")
        self.configure([(tag, 1, "correct"), (other, 3, "correct")])
        with patch.dict(os.environ, SSL_CERT_FILE=self.cert):
            self.start(*node_args(self, path, 30))

        def samples():
            return history(self, path, tag)["samples"] if path.exists() else []

        self.wait_for(lambda _: any(sample["state"] == "ok" for sample in samples()), timeout=15)
        first = samples()
        self.assertEqual(len(first), 1)
        self.assertEqual((first[0]["server"], first[0]["role"]), ("Profile 1", "active"))
        self.assertGreaterEqual(first[0]["ms"], 0)
        self.assertIsInstance(first[0]["at"], int)
        self.assertTrue(first[0]["series"])

        rediscovery_target = self.api.touch_count + 4
        self.wait_for(lambda _: self.api.touch_count >= rediscovery_target, timeout=8)
        self.assertEqual(samples(), first)
        listed = history(self, path)
        self.assertEqual(set(listed["outbounds"]), {tag, other})
        self.assertEqual(listed["samples"], [])
        self.assertGreaterEqual(listed["router_unix"], first[0]["at"])
        reply = subprocess.check_output([self.binary, "latency-rpc", str(path)],
                                        input=json.dumps({"outbound": tag}, ensure_ascii=False),
                                        text=True, timeout=8)
        self.assertEqual(json.loads(reply)["samples"], first)

        self.configure([(tag, 2, secret), (other, 3, "correct")])
        self.wait_for(lambda _: any(sample["server"] == "Profile 2" and
                                    sample["state"] == "error" for sample in samples()), timeout=15)
        recorded = samples()
        new = [sample for sample in recorded if sample["server"] == "Profile 2"]
        self.assertIn(first[0], recorded)
        self.assertEqual(len(new), 1)
        self.assertEqual((new[0]["role"], new[0]["state"]), ("active", "error"))
        self.assertGreaterEqual(new[0]["at"], first[0]["at"])
        self.assertNotEqual(new[0]["series"], first[0]["series"])
        self.assertNotIn("ms", new[0])
        self.assertTrue(all(sample["server"] != "Profile 3" for sample in recorded))
        self.assertNotIn(secret, path.read_text())

        self.hold.set()
        self.configure([(tag, 4, "correct"), (other, 3, "correct")])
        self.wait_for(lambda _: any(sample["server"] == "Profile 4" and
                                    sample["state"] == "timeout" for sample in samples()), timeout=15)
        timed_out = next(sample for sample in samples() if sample["server"] == "Profile 4")
        self.assertNotIn("ms", timed_out)

        before_restart = samples()
        self.release.set()
        self.stop()
        self.process = None
        self.configure([(tag, 5, "correct"), (other, 3, "correct")])
        with patch.dict(os.environ, SSL_CERT_FILE=self.cert):
            self.start(*node_args(self, path, 30))
        self.wait_for(lambda _: any(sample["server"] == "Profile 5" and
                                    sample["state"] == "ok" for sample in samples()), timeout=15)
        after_restart = samples()
        for sample in before_restart:
            self.assertIn(sample, after_restart)


class ReserveLatencyHistory(unittest.TestCase):
    def test_confirmed_reserve_has_its_own_reading(self):
        runner = failover_fixture.FailoverRunner()
        self.addCleanup(lambda: self.assertTrue(runner.doCleanups()))
        runner.setUp()
        path = Path(runner.tmp.name, "latency.json")
        runner.choose_policy("off")
        policy = {"outbound": "media", "mode": "outage", "candidates": [runner.reserve],
                  "failures": 3, "failure_method": "window", "failure_window_minutes": 5,
                  "allow_restart": True}
        command = [runner.binary, "failover", "save", runner.api.url + "/ui/",
                   runner.token_file, runner.settings]
        saved = json.loads(subprocess.check_output(command, input=json.dumps({"policy": policy}),
                                                   text=True, timeout=10))
        self.assertTrue(saved["ok"], saved)
        saved_policy = json.loads(runner.settings.read_text())["policies"][0]
        self.assertEqual((saved_policy["failure_method"], saved_policy["failure_window_minutes"]),
                         ("window", 5))
        with patch.dict(os.environ, SSL_CERT_FILE=runner.cert):
            runner.start("--token-file", str(runner.token_file),
                         "--failover-file", str(runner.settings), *node_args(runner, path, 1))

        def after_switch(_):
            if not runner.posts or not path.exists():
                return False
            timeline = history(runner, path, "media")["samples"]
            return any(sample["server"] == "Reserve" and sample["state"] == "ok"
                       and sample["role"] == "active" for sample in timeline)

        runner.wait_for(after_switch, timeout=20)
        samples = history(runner, path, "media")["samples"]
        failed = [sample for sample in samples if sample["server"] == "Primary"
                  and sample["state"] == "error" and sample["role"] == "active"]
        reserves = [sample for sample in samples if sample["server"] == "Reserve"
                    and sample["state"] == "ok" and sample["role"] == "reserve"]
        self.assertGreaterEqual(len(failed), 3)
        self.assertEqual(len({sample["at"] for sample in failed}), len(failed))
        self.assertTrue(all("ms" not in sample for sample in failed))
        self.assertEqual(len(reserves), 1)
        self.assertGreaterEqual(reserves[0]["ms"], 0)
        self.assertEqual(len(runner.posts), 1)
        self.assertNotIn("fixture-failover-token", path.read_text())
