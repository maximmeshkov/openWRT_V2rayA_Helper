"""Exercise failover thresholds, candidate confirmation and local policy storage."""
import ctypes as C
from ctypes.util import find_library
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


class Policy(C.Structure):
    _fields_ = [("mode", C.c_int), ("failures", C.c_uint), ("max_ms", C.c_uint),
                ("cooldown", C.c_uint), ("start", C.c_uint), ("end", C.c_uint),
                ("outbound", C.c_char_p), ("candidates", C.c_void_p),
                ("failure_method", C.c_int), ("failure_window_minutes", C.c_uint),
                ("subscriptions", C.c_void_p), ("exclusions", C.c_void_p)]


class Sample(C.Structure):
    _fields_ = [("id", C.c_char_p), ("state", C.c_int), ("ms", C.c_long),
                ("checked", C.c_long), ("subscription", C.c_char_p), ("endpoint", C.c_char_p)]


class Streak(C.Structure):
    _fields_ = [("id", C.c_char * 97), ("checked", C.c_long),
                ("failed", C.c_uint), ("slow", C.c_uint), ("latest", C.c_int),
                ("window_count", C.c_uint), ("failure_times", C.c_long * 30)]


NOW = 1735689600
UNKNOWN, OK, FAILED = range(3)
CONSECUTIVE, WINDOW = range(2)


class FailoverPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        build = tempfile.TemporaryDirectory()
        cls.addClassCleanup(build.cleanup)
        library = Path(build.name, "failover.so")
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-shared", "-fPIC", root / "src/failover_policy.c", "-o", library, "-ljson-c"],
                       check=True)
        cls.lib = C.CDLL(str(library))
        cls.jsonc = C.CDLL(find_library("json-c"))
        cls.jsonc.json_tokener_parse.argtypes = [C.c_char_p]
        cls.jsonc.json_tokener_parse.restype = C.c_void_p
        cls.jsonc.json_object_put.argtypes = [C.c_void_p]
        cls.lib.failover_policy_parse.argtypes = [C.c_void_p, C.POINTER(Policy)]
        cls.lib.failover_policy_parse.restype = C.c_int
        cls.lib.failover_settings_read.argtypes = [C.c_char_p]
        cls.lib.failover_settings_read.restype = C.c_void_p
        cls.lib.failover_settings_write.argtypes = [C.c_char_p, C.c_void_p]
        cls.lib.failover_settings_write.restype = C.c_int
        inputs = [C.POINTER(Policy), C.POINTER(Sample), C.POINTER(Streak)]
        timing = [C.c_long, C.c_long, C.c_long]
        cls.lib.failover_record.argtypes = [inputs[2], inputs[0], inputs[1], *timing[:2]]
        cls.lib.failover_record.restype = None
        cls.lib.failover_policy_ready.argtypes = inputs + timing
        cls.lib.failover_policy_ready.restype = C.c_int
        cls.lib.failover_policy_choose.argtypes = inputs + [C.POINTER(Sample), C.c_size_t] + timing
        cls.lib.failover_policy_choose.restype = C.c_char_p
        cls.lib.failover_policy_confirmed.argtypes = inputs + [C.POINTER(Sample), C.c_long] + timing
        cls.lib.failover_policy_confirmed.restype = C.c_int

    def setUp(self):
        previous = os.environ.get("TZ")
        os.environ["TZ"] = "UTC0"
        time.tzset()

        def restore_timezone():
            if previous is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = previous
            time.tzset()

        self.addCleanup(restore_timezone)

    def json(self, data):
        obj = self.jsonc.json_tokener_parse(json.dumps(data).encode())
        self.assertIsNotNone(obj)
        self.addCleanup(self.jsonc.json_object_put, obj)
        return obj

    def policy(self, expected=0, **opts):
        entry = {"outbound": "media", "mode": "outage", "candidates": ["main", "preferred", "other"]}
        entry.update(opts)
        result = Policy()
        self.assertEqual(self.lib.failover_policy_parse(self.json(entry), C.byref(result)), expected, entry)
        return result

    def record(self, p, streak, sample, now=NOW):
        self.lib.failover_record(C.byref(streak), C.byref(p), C.byref(sample), now, 120)

    def ready(self, p, streak, sample, now=NOW, age=86400):
        return self.lib.failover_policy_ready(C.byref(p), C.byref(sample), C.byref(streak), now, 120, age)

    def chosen(self, p, streak, sample, *candidates, now=NOW, age=86400):
        return self.lib.failover_policy_choose(C.byref(p), C.byref(sample), C.byref(streak),
                                               (Sample * len(candidates))(*candidates), len(candidates),
                                               now, 120, age)

    def confirmed(self, p, streak, active, reserve, checked, now, maximum_age=4, cooldown=86400):
        return self.lib.failover_policy_confirmed(C.byref(p), C.byref(active), C.byref(streak), C.byref(reserve),
                                                  checked, now, maximum_age, cooldown)

    def streak(self, p, state=FAILED, ms=0, now=NOW):
        streak = Streak()
        for offset in (60, 30, 0):
            sample = Sample(b"main", state, ms, now - offset)
            self.record(p, streak, sample, now)
        return streak, sample

    def test_failure_requires_distinct_confirmed_samples_and_viable_candidate(self):
        p = self.policy()
        self.assertEqual((p.failures, p.cooldown), (3, 900))
        self.assertEqual((p.failure_method, p.failure_window_minutes), (CONSECUTIVE, 10))
        streak = Streak()
        failure = Sample(b"main", FAILED, 0, NOW - 60)
        for _ in range(3):
            self.record(p, streak, failure)
        self.assertEqual(streak.failed, 1)
        self.assertFalse(self.ready(p, streak, failure))

        streak, failure = self.streak(p)
        self.assertTrue(self.ready(p, streak, failure))
        candidates = (Sample(b"main", OK, 10, NOW), Sample(b"unchecked", OK, 5, NOW),
                      Sample(b"preferred", OK, 30, NOW - 1), Sample(b"other", UNKNOWN, 0, NOW))
        self.assertIsNone(self.chosen(p, streak, failure, *candidates))
        self.assertEqual(self.chosen(p, streak, failure, *candidates,
                                     Sample(b"preferred", OK, 80, NOW),
                                     Sample(b"other", OK, 50, NOW)), b"other")

        self.record(p, streak, Sample(b"main", UNKNOWN, 0, NOW))
        self.assertFalse(self.ready(p, streak, failure))
        self.record(p, streak, Sample(b"new-main", FAILED, 0, NOW))
        self.assertEqual(streak.failed, 1)

    def test_waiting_in_queue_keeps_consecutive_failures_but_requires_a_fresh_result(self):
        p = self.policy()
        streak = Streak()
        sample = Sample(b"main", FAILED, 0, NOW)
        self.record(p, streak, sample)
        for previous_count in (1, 2):
            later = sample.checked + 150
            self.record(p, streak, sample, later)
            self.assertEqual(streak.failed, previous_count)
            self.assertFalse(self.ready(p, streak, sample, now=later))
            sample = Sample(b"main", FAILED, 0, later)
            self.record(p, streak, sample, later)
        self.assertTrue(self.ready(p, streak, sample, now=sample.checked))
        self.assertFalse(self.ready(p, streak, sample, now=sample.checked + 150))
        self.record(p, streak, Sample(b"main", UNKNOWN, 0, sample.checked + 151), sample.checked + 151)
        self.assertEqual(streak.failed, 0)

    def test_fresh_confirmation_allows_attempt_after_original_result_ages(self):
        p = self.policy()
        streak, active = self.streak(p)
        reserve = Sample(b"preferred", OK, 3000, NOW + 3)
        self.assertTrue(self.confirmed(p, streak, active, reserve, NOW + 6, NOW + 6))
        self.assertFalse(self.confirmed(p, streak, active, reserve, NOW + 2, NOW + 6))
        self.assertFalse(self.confirmed(p, streak, active, reserve, NOW + 6, NOW + 8))
        self.assertFalse(self.confirmed(p, streak, active, reserve, NOW + 7, NOW + 6))
        self.assertFalse(self.confirmed(p, streak, active, reserve, NOW + 6, NOW + 6, cooldown=15))
        self.assertEqual((streak.failed, streak.checked), (3, NOW))

    def test_confirmation_does_not_extend_a_configured_failure_window(self):
        p = self.policy(failure_method="window", failure_window_minutes=1)
        streak = Streak()
        for offset in (58, 29, 0):
            active = Sample(b"main", FAILED, 0, NOW - offset)
            self.record(p, streak, active, NOW - offset)
        reserve = Sample(b"preferred", OK, 3000, NOW + 1)
        self.assertTrue(self.confirmed(p, streak, active, reserve, NOW + 2, NOW + 2))
        self.assertFalse(self.confirmed(p, streak, active, reserve, NOW + 3, NOW + 3))
        self.assertEqual(streak.window_count, 3)

    def test_rolling_window_counts_distinct_failures_with_recoveries(self):
        p = self.policy(failure_method="window", failure_window_minutes=3)
        self.assertEqual((p.failure_method, p.failure_window_minutes), (WINDOW, 3))
        streak = Streak()
        for offset, state in [(-120, FAILED), (-90, OK), (-60, FAILED), (-30, OK), (0, FAILED)]:
            sample = Sample(b"main", state, 0, NOW + offset)
            self.record(p, streak, sample, NOW + offset)
            self.record(p, streak, sample, NOW + offset)
        self.assertEqual(streak.window_count, 3)
        self.assertEqual(streak.failed, 1)
        self.assertTrue(self.ready(p, streak, sample))
        self.assertFalse(self.ready(p, streak, sample, now=NOW + 61))

        recovered = Sample(b"main", OK, 30, NOW + 1)
        self.record(p, streak, recovered, NOW + 1)
        self.assertEqual(streak.window_count, 3)
        self.assertFalse(self.ready(p, streak, recovered, now=NOW + 1))
        self.assertFalse(self.ready(p, streak, sample, now=NOW + 1))
        unknown = Sample(b"main", UNKNOWN, 0, NOW + 2)
        self.record(p, streak, unknown, NOW + 2)
        self.assertFalse(self.ready(p, streak, unknown, now=NOW + 2))
        changed = Sample(b"new-main", FAILED, 0, NOW + 3)
        self.record(p, streak, changed, NOW + 3)
        self.assertFalse(self.ready(p, streak, changed, now=NOW + 3))

    def test_subscription_candidates_require_selected_source_and_probe_confirmation(self):
        p = self.policy(candidates=[], subscriptions=["chosen-feed"])
        streak, failure = self.streak(p)
        self.assertTrue(self.ready(p, streak, failure))
        self.assertIsNone(self.chosen(p, streak, failure,
                                      Sample(b"main", OK, 1, NOW, b"chosen-feed"),
                                      Sample(b"old", OK, 2, NOW - 1, b"chosen-feed"),
                                      Sample(b"other", OK, 3, NOW, b"other-feed"),
                                      Sample(b"manual", OK, 4, NOW),
                                      Sample(b"failed", FAILED, 5, NOW, b"chosen-feed")))
        self.assertEqual(self.chosen(p, streak, failure,
                                     Sample(b"new", OK, 6, NOW, b"chosen-feed")), b"new")

        union = self.policy(candidates=["manual"], subscriptions=["chosen-feed"])
        streak, failure = self.streak(union)
        self.assertEqual(self.chosen(union, streak, failure,
                                     Sample(b"new", OK, 6, NOW, b"chosen-feed"),
                                     Sample(b"manual", OK, 4, NOW)), b"manual")

    def test_exclusions_veto_explicit_and_subscribed_candidates_by_endpoint(self):
        p = self.policy(candidates=["manual", "unknown"], subscriptions=["feed"],
                        exclusions=["skip.example:443", "[2001:db8::1]:1080"])
        streak, failure = self.streak(p)
        unsuitable = (
            Sample(b"manual", OK, 1, NOW, None, b"skip.example:443"),
            Sample(b"renamed", OK, 2, NOW, b"feed", b"skip.example:443"),
            Sample(b"duplicate", OK, 3, NOW, b"feed", b"[2001:db8::1]:1080"),
            Sample(b"unknown", OK, 4, NOW),
            Sample(b"malformed", OK, 5, NOW, b"feed", b"invalid-address"),
        )
        self.assertIsNone(self.chosen(p, streak, failure, *unsuitable))
        self.assertEqual(self.chosen(p, streak, failure, *unsuitable,
                                     Sample(b"ready", OK, 6, NOW, b"feed", b"skip.example:8443")), b"ready")

        cleared = self.policy(candidates=["unknown"], exclusions=[])
        streak, failure = self.streak(cleared)
        self.assertEqual(self.chosen(cleared, streak, failure, Sample(b"unknown", OK, 4, NOW)), b"unknown")

    def test_scheduled_rolling_window_keeps_only_the_latest_thirty_failures(self):
        p = self.policy(mode="scheduled", start="23:58", end="00:01", failures=30,
                        failure_method="window", failure_window_minutes=1)
        streak = Streak()
        for offset in range(-39, 1):
            sample = Sample(b"main", FAILED, 0, NOW + offset)
            self.record(p, streak, sample, NOW + offset)
        self.assertEqual(streak.window_count, 30)
        self.assertEqual(streak.failure_times[0], NOW - 29)
        self.assertTrue(self.ready(p, streak, sample, now=NOW + 31))
        self.assertFalse(self.ready(p, streak, sample, now=NOW + 32))

        for offset in range(30, 60):
            sample = Sample(b"main", FAILED, 0, NOW + offset)
            self.record(p, streak, sample, NOW + offset)
        self.assertTrue(self.ready(p, streak, sample, now=NOW + 59))
        self.assertFalse(self.ready(p, streak, sample, now=NOW + 60))

    def test_scheduled_slow_threshold_requires_improving_candidate_and_window(self):
        p = self.policy(mode="scheduled", start="23:00", end="06:00", max_ms=300)
        streak, active = self.streak(p, OK, 420)
        self.assertTrue(self.ready(p, streak, active))
        self.assertFalse(self.ready(p, streak, active, age=5))
        self.assertTrue(self.ready(p, streak, active, age=900))
        self.assertIsNone(self.chosen(p, streak, active, Sample(b"preferred", OK, 320, NOW)))
        self.assertEqual(self.chosen(p, streak, active, Sample(b"preferred", OK, 250, NOW)), b"preferred")

        midday = NOW + 12 * 3600
        streak, active = self.streak(p, OK, 420, now=midday)
        self.assertFalse(self.ready(p, streak, active, now=midday))
        p = self.policy(mode="outage", max_ms=300)
        streak, active = self.streak(p, OK, 420)
        self.assertFalse(self.ready(p, streak, active))

    def test_scheduled_slow_answers_and_failures_add_up(self):
        p = self.policy(mode="scheduled", start="23:00", end="06:00", max_ms=300)
        streak = Streak()
        for offset, state, ms in ((60, OK, 420), (30, FAILED, 0), (0, OK, 420)):
            active = Sample(b"main", state, ms, NOW - offset)
            self.record(p, streak, active)
        self.assertEqual((streak.failed, streak.slow), (0, 3))
        self.assertTrue(self.ready(p, streak, active))
        p = self.policy(mode="outage", max_ms=300)
        streak = Streak()
        for offset, state, ms in ((60, OK, 420), (30, FAILED, 0), (0, OK, 420)):
            self.record(p, streak, Sample(b"main", state, ms, NOW - offset))
        self.assertEqual((streak.failed, streak.slow), (0, 0))

    def test_settings_reject_invalid_policies_and_keep_prior_file(self):
        for overrides in ({"mode": "reboot"}, {"failures": 1}, {"failures": 31},
                          {"failure_method": "sliding"}, {"failure_method": None},
                          {"failure_window_minutes": 0}, {"failure_window_minutes": 181},
                          {"failure_window_minutes": "10"}, {"candidates": ["same", "same"]},
                          {"subscriptions": None}, {"subscriptions": "feed"},
                          {"subscriptions": ["same", "same"]},
                          {"subscriptions": list(map(str, range(65)))},
                          {"exclusions": None}, {"exclusions": "skip.example:443"},
                          {"exclusions": ["skip.example:443", "skip.example:443"]},
                          {"exclusions": ["Skip.Example:443"]}, {"exclusions": ["skip.example:0443"]},
                          {"exclusions": ["0x7f000001:443"]}, {"exclusions": ["0x7f.0.0.1:443"]},
                          {"exclusions": ["https://skip.example:443"]}, {"exclusions": ["skip.example:65536"]},
                          {"exclusions": [f"host{i}.example:443" for i in range(65)]},
                          {"mode": "scheduled", "start": "24:00", "end": "06:00"},
                          {"mode": "scheduled", "start": "05:00", "end": "05:00"}):
            with self.subTest(overrides=overrides):
                self.policy(expected=-1, **overrides)
        off = self.policy(mode="off")
        streak, active = self.streak(off)
        self.assertFalse(self.ready(off, streak, active))
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp, "settings.json")
            path = os.fsencode(settings)
            empty = self.lib.failover_settings_read(path)
            self.assertTrue(empty)
            self.jsonc.json_object_put(empty)
            good = {"policies": [{"outbound": "Медиа", "mode": "off", "candidates": []}]}
            self.assertEqual(self.lib.failover_settings_write(path, self.json(good)), 0)
            self.assertEqual(json.loads(settings.read_text()), good)
            self.assertEqual(settings.stat().st_mode & 0o777, 0o600)
            round_trip = self.lib.failover_settings_read(path)
            self.assertTrue(round_trip)
            self.jsonc.json_object_put(round_trip)
            self.assertEqual(self.lib.failover_settings_write(path, self.json({"policies": good["policies"] * 2})), -1)
            self.assertEqual(json.loads(settings.read_text()), good)
            good["policies"][0]["exclusions"] = ["192.0.2.1:443", "[2001:db8::1]:1080"]
            self.assertEqual(self.lib.failover_settings_write(path, self.json(good)), 0)
            round_trip = self.lib.failover_settings_read(path)
            self.assertTrue(round_trip)
            self.jsonc.json_object_put(round_trip)
            self.assertEqual(json.loads(settings.read_text()), good)
            settings.write_bytes(b'{"policies":[{"outbound":"\xc0\xaf","mode":"off","candidates":[]}]}')
            self.assertFalse(self.lib.failover_settings_read(path))
            settings.write_text("{")
            self.assertFalse(self.lib.failover_settings_read(path))
