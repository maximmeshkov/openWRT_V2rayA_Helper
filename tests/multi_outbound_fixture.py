"""Scenario for multiple selected outputs on a real isolated v2rayA and Xray."""

from pathlib import Path
from socketserver import ThreadingTCPServer
from threading import Thread
import time


ROUTES = {"proxy": "first.invalid", "video": "second.invalid", "stay": "healthy.invalid"}
FAILED_ROUTES = ("proxy", "video")
MINIMUM_PAUSE = 60


class MultiOutboundFixture:
    def __init__(self, stack, node):
        def listener():
            server = stack.enter_context(ThreadingTCPServer(("127.0.0.1", 0), node.socks.RequestHandlerClass))
            server.daemon_threads = True
            Thread(target=server.serve_forever, daemon=True).start()
            stack.callback(server.shutdown)
            return server

        self.primary = {route: node.socks if route == "proxy" else listener() for route in ROUTES}
        self.reserve = {route: listener() for route in ROUTES}

    def configure(self, call):
        for route in ROUTES:
            if route != "proxy":
                call("POST", "outbound", {"outbound": route})
            for kind, nodes in (("primary", self.primary), ("reserve", self.reserve)):
                port = nodes[route].server_address[1]
                call("POST", "import", {"url": f"socks5://fixture:correct@127.0.0.1:{port}#{route}-{kind}"})
        self.ids = {server["name"]: server["id"] for server in call("GET", "touch")["touch"]["servers"]}
        for route in ROUTES:
            call("POST", "connection", {"_type": "server", "id": self.ids[f"{route}-primary"], "outbound": route})

    def save_policies(self, rpc, target):
        nodes = rpc("failover", "context", *target)["nodes"]
        keys = {node["name"]: node["key"] for node in nodes}
        for route in ROUTES:
            rpc("failover", "save", *target, body={"policy": {
                "outbound": route, "mode": "outage", "allow_restart": True,
                "candidates": [keys[f"{route}-reserve"]], "failures": 3, "cooldown_seconds": MINIMUM_PAUSE,
            }})

    def exercise(self, call, rpc, policy_file, history_file, client, snapshot, xray_pid, wait):
        def selected():
            state = call("GET", "touch", allow_busy=True)
            if state is None:
                return None
            assert state["running"], "v2rayA lost running state"
            refs = state["touch"]["connectedServer"]
            assert len(refs) == len(ROUTES) and all(ref["_type"] == "server" for ref in refs)
            return {ref["outbound"]: ref["id"] for ref in refs}

        def samples(route, server, role, state, since):
            return {sample["at"] for sample in rpc("latency", history_file, route)["samples"]
                    if sample["server"] == f"{route}-{server}" and sample["role"] == role
                    and sample["state"] == state and sample["at"] >= since}

        def reaches(route):
            return client.https(timeout=.6, host=ROUTES[route])

        def attempt():
            fields = Path(f"{policy_file}.last").read_text().split()
            if fields[0] == "v2":
                _, boot, wall, seconds, boot_time = fields
                assert boot == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                started, pause, boot_ns = map(int, (wall, seconds, boot_time))
                assert 0 < boot_ns <= time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            else:
                started, unblocks = map(int, fields)
                pause, boot_ns = unblocks - started, None
            assert pause == MINIMUM_PAUSE
            return started, pause, boot_ns

        def all_measured():
            rows = {out["name"]: out["members"] for out in snapshot().get("outbounds", [])}
            return all(len(rows.get(route, [])) == 1 and rows[route][0]["https"]["state"] == "ok"
                       for route in ROUTES)

        initial = {route: self.ids[f"{route}-primary"] for route in ROUTES}
        assert selected() == initial
        original_pid = xray_pid()
        wait(all_measured, "fresh HTTPS results for all three original outbounds")
        assert all(reaches(route) for route in ROUTES), "isolated LAN did not reach all three routed hosts"

        first_fault = int(time.time())
        for route in FAILED_ROUTES:
            self.primary[route].reject_auth = True
        assert not any(reaches(route) for route in FAILED_ROUTES) and reaches("stay")

        def first_switch():
            current = selected()
            return current if current is not None and current != initial else None

        changed = wait(first_switch, "first stock v2rayA assignment changed", 25)
        switched = [route for route in ROUTES if changed[route] != initial[route]]
        assert len(switched) == 1 and switched[0] in FAILED_ROUTES
        first = switched[0]
        second, = set(FAILED_ROUTES) - {first}
        assert changed[first] == self.ids[f"{first}-reserve"]
        first_record = attempt()
        first_observed = time.monotonic()
        first_attempt, pause, first_boot_ns = first_record
        assert first_attempt >= first_fault
        wait(lambda: xray_pid() not in (None, original_pid) and reaches(first) and reaches("stay"),
             "LAN returned on first reserve and healthy outbound")
        first_pid = xray_pid()
        assert len(samples(first, "primary", "active", "error", first_fault)) >= 3
        wait(lambda: samples(second, "primary", "active", "error", first_attempt + 1),
             "new HTTPS failure of second outbound after the first's switch")
        assert len(samples(second, "primary", "active", "error", first_fault)) >= 3
        assert selected() == changed and xray_pid() == first_pid and not reaches(second)
        print(f"Multi-outbound: {first} switched, fresh failures on {second} waited, healthy assignment unchanged",
              flush=True)

        restored_at = int(time.time())
        self.primary[second].reject_auth = False
        wait(lambda: reaches(second) and samples(second, "primary", "active", "ok", restored_at),
             "second primary recovered during the common cooldown")
        while time.monotonic() < first_observed + pause + 2:
            assert attempt() == first_record, "another switch began during the common cooldown"
            assert selected() == changed and xray_pid() == first_pid
            assert reaches(second) and reaches("stay")
            time.sleep(1)
        after_pause = int(time.time())
        wait(lambda: samples(second, "primary", "active", "ok", after_pause),
             "fresh successful check on the second outbound after the pause")
        assert selected() == changed and xray_pid() == first_pid and attempt() == first_record
        print(f"Multi-outbound: recovered {second} retained its original assignment past the 60-second pause",
              flush=True)

        second_fault = int(time.time())
        self.primary[second].reject_auth = True
        assert not reaches(second)
        expected = {**changed, second: self.ids[f"{second}-reserve"]}
        wait(lambda: selected() == expected and xray_pid() not in (None, first_pid) and
             all(reaches(route) for route in ROUTES), "second fresh failure restored LAN through its own reserve", 25)
        elapsed = time.monotonic() - first_observed
        second_attempt, _, second_boot_ns = attempt()
        assert (first_boot_ns is None) == (second_boot_ns is None)
        if second_boot_ns is not None:
            elapsed = (second_boot_ns - first_boot_ns) / 1_000_000_000
        assert second_attempt >= second_fault and elapsed >= MINIMUM_PAUSE
        assert len(samples(second, "primary", "active", "error", second_fault)) >= 3
        assert samples(second, "reserve", "reserve", "ok", second_fault)
        print(f"Multi-outbound: {second} switched after three new failures, {elapsed:.1f}s after "
              f"{first}; all LAN hosts reached HTTPS 204 and healthy assignment stayed in place", flush=True)
