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
                ("outbound", C.c_char_p), ("candidates", C.c_void_p)]


class Sample(C.Structure):
    _fields_ = [("id", C.c_char_p), ("state", C.c_int), ("ms", C.c_long),
                ("checked", C.c_long)]


class Streak(C.Structure):
    _fields_ = [("id", C.c_char * 97), ("checked", C.c_long),
                ("failed", C.c_uint), ("slow", C.c_uint)]


NOW = 1735689600
UNKNOWN, OK, FAILED = range(3)


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

    def ready(self, p, streak, sample, now=NOW, last=0):
        return self.lib.failover_policy_ready(C.byref(p), C.byref(sample), C.byref(streak), now, 120, last)

    def chosen(self, p, streak, sample, *candidates, now=NOW, last=0):
        return self.lib.failover_policy_choose(C.byref(p), C.byref(sample), C.byref(streak),
                                               (Sample * len(candidates))(*candidates), len(candidates),
                                               now, 120, last)

    def streak(self, p, state=FAILED, ms=0, now=NOW):
        streak = Streak()
        for offset in (60, 30, 0):
            sample = Sample(b"main", state, ms, now - offset)
            self.record(p, streak, sample, now)
        return streak, sample

    def test_failure_requires_distinct_confirmed_samples_and_viable_candidate(self):
        p = self.policy()
        self.assertEqual((p.failures, p.cooldown), (3, 900))
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

    def test_scheduled_slow_threshold_requires_improving_candidate_and_window(self):
        p = self.policy(mode="scheduled", start="23:00", end="06:00", max_ms=300)
        streak, active = self.streak(p, OK, 420)
        self.assertTrue(self.ready(p, streak, active))
        self.assertFalse(self.ready(p, streak, active, last=NOW - 5))
        self.assertTrue(self.ready(p, streak, active, last=NOW - 900))
        self.assertIsNone(self.chosen(p, streak, active, Sample(b"preferred", OK, 320, NOW)))
        self.assertEqual(self.chosen(p, streak, active, Sample(b"preferred", OK, 250, NOW)), b"preferred")

        midday = NOW + 12 * 3600
        streak, active = self.streak(p, OK, 420, now=midday)
        self.assertFalse(self.ready(p, streak, active, now=midday))
        p = self.policy(mode="outage", max_ms=300)
        streak, active = self.streak(p, OK, 420)
        self.assertFalse(self.ready(p, streak, active))

    def test_settings_reject_invalid_policies_and_keep_prior_file(self):
        for overrides in ({"mode": "reboot"}, {"failures": 1}, {"candidates": ["same", "same"]},
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
            good = {"policies": [{"outbound": "media", "mode": "off", "candidates": []}]}
            self.assertEqual(self.lib.failover_settings_write(path, self.json(good)), 0)
            self.assertEqual(json.loads(settings.read_text()), good)
            self.assertEqual(settings.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.lib.failover_settings_write(path, self.json({"policies": good["policies"] * 2})), -1)
            self.assertEqual(json.loads(settings.read_text()), good)
            settings.write_text("{")
            self.assertFalse(self.lib.failover_settings_read(path))
