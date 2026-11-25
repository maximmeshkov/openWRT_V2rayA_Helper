"""Privileged Linux integration test. Usage: sudo python3 tests/netns_probe.py BINARY"""
import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from test_monitor import APIFixture, assignment, profile, server_state


def listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    return sock


@contextlib.contextmanager
def monitor(binary, api, path, *options):
    proc = subprocess.Popen([binary, "--api", api.url + "/ui", "--output", path,
                             "--interval", "1", "--timeout", "1", *options])
    try:
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise AssertionError("monitor did not exit normally")
        if proc.returncode:
            raise AssertionError(f"monitor exited with status {proc.returncode}")


def counter(name):
    result = subprocess.check_output(["nft", "-j", "list", "counter", "inet",
                                      "v2raya_probe_test", name])
    for item in json.loads(result)["nftables"]:
        if item.get("counter", {}).get("name") == name:
            return item["counter"]["packets"]
    raise AssertionError(f"nftables did not return the {name} counter")


def wait_for_state(proc, path, state, tick):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError("monitor exited early")
        tick()
        if path.exists():
            data = json.loads(path.read_text())
            if server_state(data, "proxy") == state:
                return data["outbounds"][0]["members"][0]["server"]
        time.sleep(0.05)
    raise AssertionError(f"monitor did not publish {state}")


def isolated_test(binary, original_netns):
    # This assertion runs before *any* link or firewall change. The parent
    # keeps its network namespace open and passes that descriptor via unshare.
    if os.path.samestat(os.fstat(original_netns), os.stat("/proc/self/ns/net")):
        raise RuntimeError("refusing to change the caller's networking")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    with contextlib.ExitStack() as stack:
        tmp = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        api = APIFixture()
        stack.callback(api.close)
        target = stack.enter_context(listener())
        port = target.getsockname()[1]
        api.servers = [profile(1, "TCP target", f"127.0.0.1:{port}", "socks5")]
        api.connected = [assignment("proxy", 1)]
        rules = f"""
table inet v2raya_probe_test {{
    counter rejected {{ }}
    counter passed {{ }}
    chain output {{
        type filter hook output priority filter; policy accept;
        ip daddr 127.0.0.1 tcp dport {port} tcp flags & (syn | ack) == syn meta mark != 0x80 counter name rejected reject with tcp reset
        ip daddr 127.0.0.1 tcp dport {port} tcp flags & (syn | ack) == syn meta mark 0x80 counter name passed accept
    }}
}}
"""
        subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True)
        service = stack.enter_context(listener())
        client = stack.enter_context(socket.create_connection(service.getsockname(), timeout=1))
        peer = stack.enter_context(service.accept()[0])
        peer.settimeout(1)
        exchanges = 0

        def exchange():
            nonlocal exchanges
            payload = bytes([exchanges % 256])
            client.sendall(payload)
            if peer.recv(1) != payload:
                raise AssertionError("application connection lost request")
            peer.sendall(payload)
            if client.recv(1) != payload:
                raise AssertionError("application connection lost response")
            exchanges += 1

        # Keep using this exact TCP connection for both runs.
        exchange()
        status = tmp / "unmarked.json"
        with monitor(binary, api, status, "--mark", "0") as proc:
            wait_for_state(proc, status, "refused", exchange)
        rejected = counter("rejected")
        if not rejected or counter("passed"):
            raise AssertionError("unmarked control did not hit the rejection rule")

        status = tmp / "default.json"
        with monitor(binary, api, status) as proc:
            result = wait_for_state(proc, status, "ok", exchange)
            if result["detail"] != "local_tcp":
                raise AssertionError("unexpected transport")
            target.setblocking(False)
            accepted = 0
            deadline = time.monotonic() + 10
            while accepted < 3 and time.monotonic() < deadline:
                exchange()
                try:
                    conn, _ = target.accept()
                except BlockingIOError:
                    time.sleep(0.05)
                else:
                    conn.close()
                    accepted += 1
            if accepted != 3 or counter("passed") < 3 or counter("rejected") != rejected:
                raise AssertionError("expected three accepted default-mark probes")
        exchange()
        print(f"Unmarked SYN rejected; {accepted} default-mark TCP probes accepted. "
              f"One application connection completed {exchanges} request/reply exchanges.")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[2] == "--isolated":
        isolated_test(sys.argv[1], int(sys.argv[3]))
    elif len(sys.argv) == 2:
        binary = Path(sys.argv[1]).resolve(strict=True)
        with open("/proc/self/ns/net", "rb", buffering=0) as ns:
            args = ["unshare", "--net", "--", sys.executable, __file__,
                    str(binary), "--isolated", str(ns.fileno())]
            sys.exit(subprocess.run(args, pass_fds=(ns.fileno(),)).returncode)
    else:
        sys.exit(__doc__)
