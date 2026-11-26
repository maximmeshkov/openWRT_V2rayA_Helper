"""Exercise failover cooldown across per-process Linux clock steps."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_failover_runner as failover_fixture


INITIAL_WALL_OFFSET = 2 * 3600
NANOSECONDS_PER_SECOND = 1_000_000_000


CLOCK_OVERRIDE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int clock_gettime(clockid_t clock, struct timespec *value)
{
    int (*original)(clockid_t, struct timespec *) = dlsym(RTLD_NEXT, "clock_gettime");
    int status = original(clock, value);
    if (status || (clock != CLOCK_REALTIME && clock != CLOCK_BOOTTIME)) return status;
    const char *path = getenv("V2RAYA_TEST_CLOCK_OFFSETS");
    FILE *offsets = path ? fopen(path, "r") : NULL;
    if (offsets) {
        long long wall, elapsed;
        if (fscanf(offsets, "%lld %lld", &wall, &elapsed) == 2)
            value->tv_sec += clock == CLOCK_REALTIME ? wall : elapsed;
        fclose(offsets);
    }
    return status;
}

time_t time(time_t *result)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now)) return (time_t)-1;
    if (result) *result = now.tv_sec;
    return now.tv_sec;
}
"""


@unittest.skipUnless(sys.platform == "linux" and not os.environ.get("V2RAYA_TEST_SYSROOT") and shutil.which("cc"),
                     "clock override requires a native Linux helper and compiler")
class FailoverClock(unittest.TestCase):
    def prepare_monitor(self, cooldown_seconds):
        fixture = failover_fixture.FailoverRunner()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.choose_policy("outage")
        settings = json.loads(fixture.settings.read_text())
        settings["policies"][0]["cooldown_seconds"] = cooldown_seconds
        fixture.settings.write_text(json.dumps(settings))

        directory = fixture.settings.parent
        source, library = directory / "clock.c", directory / "clock.so"
        offsets = directory / "clock.offsets"
        source.write_text(CLOCK_OVERRIDE)
        subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                        source, "-o", library, "-ldl"], check=True, timeout=15)
        self.set_clock(offsets)
        return fixture, library, offsets

    @staticmethod
    def set_clock(offsets, wall_offset=0, elapsed_offset=0):
        # The test CA's validity starts at real wall time. Both simulated times
        # must remain within its validity period so TLS can qualify a reserve.
        update = offsets.with_suffix(".new")
        update.write_text(f"{INITIAL_WALL_OFFSET + wall_offset} {elapsed_offset}\n")
        update.replace(offsets)

    @staticmethod
    def start_monitor(fixture, library, offsets):
        with patch.dict(os.environ, LD_PRELOAD=str(library), V2RAYA_TEST_CLOCK_OFFSETS=str(offsets)):
            fixture.start_runner()

    def run_clock_step(self, wall_offset, elapsed_offset):
        fixture, library, offsets = self.prepare_monitor(cooldown_seconds=60)
        self.start_monitor(fixture, library, offsets)
        fixture.wait_for(lambda _: len(fixture.posts) == 1, timeout=15)
        fixture.wait_for(lambda snap: any(
            out["name"] == "media" and any(member["name"] == "Reserve" and member["https"]["state"] == "ok"
                                           for member in out["members"])
            for out in snap.get("outbounds", [])), timeout=12)

        self.set_clock(offsets, wall_offset, elapsed_offset)
        previous_failures = len(fixture.auth_failures)
        with fixture.api.lock:
            fixture.active_locked(1, "wrong")
        fixture.wait_for(lambda _: len(fixture.posts) >= 2 or len(fixture.auth_failures) >= previous_failures + 5,
                         timeout=15)
        return len(fixture.posts)

    def test_forward_wall_step_does_not_end_the_cooldown_early(self):
        self.assertEqual(self.run_clock_step(wall_offset=3600, elapsed_offset=0), 1)

    def test_backward_wall_step_cannot_block_switch_after_elapsed_cooldown(self):
        self.assertEqual(self.run_clock_step(wall_offset=-3600, elapsed_offset=61), 2)

    def run_different_boot(self, saved_duration, current_duration):
        fixture, library, offsets = self.prepare_monitor(current_duration)
        current_boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        previous_boot = "00000000-0000-0000-0000-000000000001"
        if previous_boot == current_boot:
            previous_boot = "00000000-0000-0000-0000-000000000002"
        marker = fixture.settings.with_suffix(".json.last")
        attempt_wall = int(time.time()) + INITIAL_WALL_OFFSET - 3600
        marker.write_text(f"v2 {previous_boot} {attempt_wall} {saved_duration} {1800 * NANOSECONDS_PER_SECOND}\n")
        real_uptime = int(time.clock_gettime(time.CLOCK_BOOTTIME))
        self.set_clock(offsets, elapsed_offset=120 - real_uptime)
        self.start_monitor(fixture, library, offsets)
        fixture.wait_for(lambda _: fixture.posts or len(fixture.auth_failures) >= 5, timeout=12)
        self.assertFalse(fixture.posts, "only the shorter cross-boot pause had elapsed")

        self.set_clock(offsets, elapsed_offset=910 - real_uptime)
        fixture.wait_for(lambda _: len(fixture.posts) == 1, timeout=12)
        self.assertEqual(fixture.posts[0][2]["outbound"], "media")

    def test_cross_boot_cooldown_honors_longer_previous_policy(self):
        self.run_different_boot(saved_duration=900, current_duration=60)

    def test_cross_boot_cooldown_honors_longer_current_policy(self):
        self.run_different_boot(saved_duration=60, current_duration=900)

    def test_future_legacy_marker_migrates_under_lock_and_survives_restart(self):
        import fcntl

        fixture, library, offsets = self.prepare_monitor(cooldown_seconds=60)
        marker = fixture.settings.with_suffix(".json.last")
        future = int(time.time()) + INITIAL_WALL_OFFSET + 3600
        legacy_record = f"{future} {future + 60}\n"
        marker.write_text(legacy_record)
        with fixture.settings.with_suffix(".json.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.start_monitor(fixture, library, offsets)
            fixture.wait_for(lambda _: fixture.posts or len(fixture.auth_failures) >= 4, timeout=12)
            self.assertFalse(fixture.posts)
            self.assertEqual(marker.read_text(), legacy_record, "migration bypassed the failover lock")

        fixture.wait_for(lambda _: marker.read_text().startswith("v2 "))
        converted = marker.read_text()
        _, boot, _, duration, _ = converted.split()
        self.assertEqual(boot, Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        self.assertEqual(int(duration), 60)
        fixture.stop()
        fixture.output.unlink()
        self.set_clock(offsets, elapsed_offset=30)
        previous_failures = len(fixture.auth_failures)
        self.start_monitor(fixture, library, offsets)
        fixture.wait_for(lambda _: fixture.posts or len(fixture.auth_failures) >= previous_failures + 4, timeout=12)
        self.assertFalse(fixture.posts, "restart unlocked the migrated cooldown early")
        self.assertEqual(marker.read_text(), converted, "restart reset the migrated cooldown")

        self.set_clock(offsets, elapsed_offset=61)
        fixture.wait_for(lambda _: len(fixture.posts) == 1, timeout=12)
