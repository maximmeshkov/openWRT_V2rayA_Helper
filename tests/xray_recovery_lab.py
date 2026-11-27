"""Opt-in crash/recovery test with real, isolated v2rayA and Xray on Linux."""
import argparse
from contextlib import ExitStack, contextmanager, suppress
import errno
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
from socketserver import ThreadingTCPServer
import stat
import struct
import subprocess
import sys
import tempfile
from threading import Thread
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from multi_outbound_fixture import MultiOutboundFixture, ROUTES
from test_independent_nodes import NodeFixture
from tproxy_fixture import (CLIENT, DESTINATION, NAMESPACES, ROUTER, TRANSPARENT_PORT, TransparentClient,
                            prepare_router, run_isolated, transparent_config)


FIXTURE_LOGIN = {"username": "fixture", "password": "isolated-lab-pass"}
REJECTED_TOKEN = "isolated-rejected-fixture-token"
ASSIGNED_MANAGEMENT = {"ipv4": ROUTER, "ipv6": "fd55:2e70:2117::99"}
SOCKS_UDP6_CASES = ("socks-udp6", "socks-udp6-disabled", "socks-udp6-shared")
REDIRECT_IPV6_CASES = ("redirect-tcp6", "redirect-udp6")
REDIRECT_CASES = ("redirect-tcp", "redirect-udp", *REDIRECT_IPV6_CASES, "redirect-http-control")
REDIRECT_ROUTER_IPV6 = "2001:db8:37::1"
REDIRECT_CLIENT_IPV6 = "2001:db8:37::2"
REDIRECT_DESTINATION_IPV6 = "2001:db8:42::42"
INBOUND_PORT_CASES = ("http-v4", "http-v6", "socks-udp", *SOCKS_UDP6_CASES, "fixed-api",
                      "http-udp-control", "http-lan-control", "http-lan-sharing", *REDIRECT_CASES)
STOP_RACE_CASES = ("naive", "dormant-after", "dormant-cleanup", "dormant-failed-delete", "tproxy-route")


class StockLanClient(TransparentClient):
    def configure_ipv6(self):
        subprocess.run(["ip", "-6", "addr", "add", f"{REDIRECT_ROUTER_IPV6}/64",
                        "dev", "lab-router", "nodad"], check=True, timeout=5)
        subprocess.run([*self.enter, "ip", "-6", "addr", "add", f"{REDIRECT_CLIENT_IPV6}/64",
                        "dev", "lab-client", "nodad"], check=True, timeout=5)
        subprocess.run([*self.enter, "ip", "-6", "route", "add", f"{REDIRECT_DESTINATION_IPV6}/128",
                        "via", REDIRECT_ROUTER_IPV6, "dev", "lab-client"], check=True, timeout=5)

    def https_ipv6(self, timeout=2):
        reply = subprocess.run([*self.enter, "curl", "-q", "--ipv6", "--silent", "--max-time", str(timeout),
                                "--resolve", f"check.invalid:443:[{REDIRECT_DESTINATION_IPV6}]",
                                "--cacert", self.cert, "--output", "/dev/null", "--write-out", "%{http_code}",
                                "https://check.invalid/generate_204"], capture_output=True, text=True,
                               timeout=4, env=self.env)
        return reply.returncode == 0 and reply.stdout == "204"

    def _packets(self):
        result = subprocess.run(["iptables", "-w", "2", "-t", "nat", "-L", "TP_RULE", "-nvx"],
                                capture_output=True, text=True, timeout=5)
        if result.returncode:
            # The stock process removes this chain on an unexpected core exit.
            assert "No chain" in result.stderr or "does not exist" in result.stderr, result.stderr
            return 0
        return next((int(fields[0]) for line in result.stdout.splitlines() if
                     len(fields := line.split()) > 2 and fields[2] == "REDIRECT"), 0)


def replace_private_file(path, contents):
    temporary = path.with_suffix(".next")
    temporary.touch(mode=0o600, exist_ok=False)
    temporary.write_text(contents)
    temporary.replace(path)


def file_revision(path):
    state = path.stat()
    return state.st_dev, state.st_ino, state.st_mtime_ns, state.st_ctime_ns


def nft_generation():
    # NFNL_SUBSYS_NFTABLES wraps NFT_MSG_GETGEN / NFT_MSG_NEWGEN on NETLINK_NETFILTER.
    netfilter, subsystem, get_generation, new_generation, generation_id = 12, 10, 16, 15, 1
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, netfilter) as channel:
        channel.settimeout(3)
        channel.bind((0, 0))
        port, _ = channel.getsockname()
        request = struct.pack("=IHHII", 20, subsystem << 8 | get_generation, 1, 1, port) + bytes(4)
        channel.sendto(request, (0, 0))
        data, sender = channel.recvfrom(4096)
    size, response, _, sequence, addressed_port = struct.unpack_from("=IHHII", data)
    assert sender == (0, 0) and response == subsystem << 8 | new_generation
    assert sequence == 1 and addressed_port == port and size == len(data)
    offset = 20
    while offset + 4 <= size:
        length, kind = struct.unpack_from("=HH", data, offset)
        assert 4 <= length <= size - offset
        if kind & 0x3fff == generation_id:
            assert length == 8
            return struct.unpack_from("!I", data, offset + 4)[0]
        offset += (length + 3) & ~3
    raise AssertionError("the nftables generation response omitted NFTA_GEN_ID")


def configure_stop_race(work, env, mode):
    hook = work / "stock-stop-latch.sh"
    hook.write_text("""#!/bin/sh
case " $* " in
  *" --stage=pre-stop "*) if [ -f "$LAB_STOP_ARMED" ]; then
    : > "$LAB_STOP_ENTERED"
    count=0
    while [ ! -f "$LAB_STOP_RELEASED" ] && [ "$count" -lt 240 ]; do
      sleep 0.05
      count=$((count+1))
    done
  fi ;;
esac
exit 0
""")
    hook.chmod(0o700)

    tool_dir = work / "stop-tools"
    tool_dir.mkdir()
    real_nft = shutil.which("nft")
    assert real_nft, "stock nft is required for the REDIRECT Stop-race test"
    wrapper = tool_dir / "nft"
    wrapper.write_text("""#!/bin/sh
if [ "$*" = "delete table inet v2raya" ] && [ -f "$LAB_STOP_ARMED" ]; then
  if [ "$LAB_STOP_CASE" = "dormant-failed-delete" ]; then
    printf '%s\\n' 42 > "$LAB_NFT_DELETE_RC"
    printf '%s\\n' "fixture-forced nft deletion failure" >&2
    exit 42
  fi
  "$LAB_NFT_COMMAND" "$@"
  rc=$?
  printf '%s\\n' "$rc" > "$LAB_NFT_DELETE_RC"
  exit "$rc"
fi
exec "$LAB_NFT_COMMAND" "$@"
""")
    wrapper.chmod(0o700)
    env.update(PATH=f"{tool_dir}:{env['PATH']}", LAB_STOP_CASE=mode, LAB_NFT_COMMAND=real_nft,
               LAB_STOP_ARMED=str(work / "stop.arm"), LAB_STOP_ENTERED=str(work / "stop.entered"),
               LAB_STOP_RELEASED=str(work / "stop.release"), LAB_NFT_DELETE_RC=str(work / "stock-delete.rc"))
    return hook, real_nft


def loopback_ports(count):
    with ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]


def wait(check, description, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (OSError, json.JSONDecodeError):
            pass
        time.sleep(.1)
    raise AssertionError("timed out waiting for " + description)


def terminate(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def owned_xray(pid, owner, binary, config):
    proc = Path("/proc", str(pid))
    try:
        args = (proc / "cmdline").read_bytes().split(b"\0")
        ppid = int((proc / "stat").read_text().rsplit(")", 1)[1].split()[1])
        return (ppid == owner and (proc / "exe").resolve(strict=True) == binary and
                b"run" in args and os.fsencode(f"--config={config}") in args)
    except OSError:
        return False


def run_case(args, recover, check_authorization=False, auto_login=None):
    transparent_lan = getattr(args, "transparent_lan", False)
    late_wan = getattr(args, "late_wan", False)
    slow_reserve_failover = getattr(args, "slow_reserve_failover", False)
    server_failover = getattr(args, "server_failover", False) or slow_reserve_failover or late_wan
    multi_outbound_failover = getattr(args, "multi_outbound_failover", False)
    cold_start = getattr(args, "cold_start", False)
    early_crash = getattr(args, "early_xray_crash", False)
    ipv6_management = getattr(args, "ipv6_management", False)
    assigned_management = getattr(args, "assigned_management", None)
    local_management = ipv6_management or bool(assigned_management)
    owner_restart_dynamic = getattr(args, "owner_restart_dynamic", False)
    without_socks = getattr(args, "without_socks", False) or local_management or owner_restart_dynamic
    inbound_port_case = getattr(args, "inbound_port_case", None)
    ingress_loss = getattr(args, "ingress_loss", None)
    stock_redirect = inbound_port_case in REDIRECT_CASES or bool(ingress_loss)
    nft_redirect = ingress_loss == "nftables"
    stock_tproxy = args.tproxy_ingress_loss
    stock_transparent = stock_redirect or stock_tproxy
    helper_restart = getattr(args, "helper_restart", False)
    use_recovery_state = helper_restart and not getattr(args, "without_recovery_state", False)
    with ExitStack() as stack:
        if transparent_lan or owner_restart_dynamic:
            prepare_router(args.namespace_origin)
        work = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="v2raya-xray-recovery-")))
        if local_management:
            # The production login guard verifies every ancestor and the peer executable's owner.
            assert Path("/").stat().st_uid == os.geteuid() and work.parent.stat().st_uid == os.geteuid(), (
                "private login lab requires an outer root mapped into its isolated user namespace"
            )
        os.environ["V2RAYA_HELPER"] = str(args.helper)
        node = NodeFixture()
        stack.callback(node.doCleanups)
        if multi_outbound_failover:
            node.https_hosts = (*node.https_hosts, *ROUTES.values())
        node.setUp()
        if multi_outbound_failover:
            multiple = MultiOutboundFixture(stack, node)
        if server_failover:
            # Both SOCKS endpoints use the same TLS response and shared outage switch.
            reserve_handler = node.socks.RequestHandlerClass
            if slow_reserve_failover:
                primary_timeouts, reserve_ready_at = [], []

                class StallingPrimary(node.socks.RequestHandlerClass):
                    def handle(self):
                        if not getattr(self.server, "stall", False):
                            return super().handle()
                        self.connection.settimeout(8)
                        try:
                            if self.rfile.read(1) == b"\x05":
                                started = time.monotonic()
                                with suppress(OSError):
                                    self.rfile.read()
                                elapsed = time.monotonic() - started
                                if elapsed >= 3.75:
                                    primary_timeouts.append((started, elapsed))
                        except OSError:
                            pass

                class SlowReserve(node.socks.RequestHandlerClass):
                    def handle(self):
                        time.sleep(3.3)
                        reserve_ready_at.append(time.monotonic())
                        super().handle()

                node.socks.RequestHandlerClass = StallingPrimary
                reserve_handler = SlowReserve
            reserve = stack.enter_context(ThreadingTCPServer(("127.0.0.1", 0), reserve_handler))
            reserve.daemon_threads = True
            Thread(target=reserve.serve_forever, daemon=True).start()
            stack.callback(reserve.shutdown)
        runtime = work / "runtime"
        runtime.mkdir()
        config_dir = work / "config"
        config_dir.mkdir()
        config = config_dir / "config.json"
        api_port, socks_port, http_port, pac_port, reserve_port = loopback_ports(5)
        address = f"127.0.0.1:{api_port}"
        xray_api_port = socks_port if getattr(args, "fixed_xray_api_port", False) else 0
        if inbound_port_case == "fixed-api":
            xray_api_port = reserve_port
        if local_management:
            management_ipv6 = ipv6_management or assigned_management == "ipv6"
            management_host = "::1" if ipv6_management else ASSIGNED_MANAGEMENT[assigned_management]
            if assigned_management:
                client = TransparentClient(stack, node.cert, wait, terminate)
                if management_ipv6:
                    subprocess.run(["ip", "-6", "addr", "add", f"{management_host}/128", "dev", "lab-router", "nodad"],
                                   check=True, timeout=5)
            family = socket.AF_INET6 if management_ipv6 else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.bind((management_host, 0))
                management_port = probe.getsockname()[1]
            xray_api_port = api_port if api_port != management_port else socks_port
            host = f"[{management_host}]" if management_ipv6 else management_host
            address = f"{host}:{management_port}"
        env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), SSL_CERT_FILE=node.cert)
        if args.allow_unverified:
            env["V2RAYA_HELPER_ALLOW_UNVERIFIED"] = args.allow_unverified
        if owner_restart_dynamic:
            env["V2RAYA_IPV6_SUPPORT"] = "off"
            env.pop("V2RAYA_V2RAY_CONFDIR", None)
        log = stack.enter_context((work / "v2raya.log").open("w+"))
        extra = []
        if stock_transparent:
            # The router fixture already runs in a private mount namespace.
            resolver = work / "resolv.conf"
            resolver.write_text("nameserver 127.0.0.1\n")
            subprocess.run(["mount", "--bind", resolver, "/etc/resolv.conf"], check=True, timeout=5)
            stack.callback(subprocess.run, ["umount", "/etc/resolv.conf"], check=True, timeout=5)
            client = StockLanClient(stack, node.cert, wait, terminate)
            subprocess.run(["ip", "route", "add", "default", "via", CLIENT, "dev", "lab-router"],
                           check=True, timeout=5)
            if inbound_port_case in REDIRECT_IPV6_CASES:
                subprocess.run(["ip", "-6", "addr", "add", REDIRECT_ROUTER_IPV6 + "/64",
                                "dev", "lab-router", "nodad"], check=True, timeout=5)
            assert not client._https(.25), "the client reached the test site directly"
            if (args.restore_ingress or args.ingress_table_loss or stock_tproxy) and args.ingress_dual_family:
                client.configure_ipv6()
                assert not client.https_ipv6(.25), "the IPv6 client reached the test site directly"
            env.update(V2RAYA_NFTABLES_SUPPORT="auto" if nft_redirect else "off",
                       V2RAYA_IPV6_SUPPORT="on" if args.ingress_dual_family else "off")
        elif transparent_lan:
            fragment = work / "xray-fragments"
            transparent_config(fragment, ROUTES if multi_outbound_failover else None)
            extra = ["--v2ray-confdir", fragment]
        if not stock_transparent:
            extra.append("--lite")
        if inbound_port_case in SOCKS_UDP6_CASES:
            extra += ["--ipv6-support", "off" if inbound_port_case == "socks-udp6-disabled" else "on"]
        if args.ingress_stop_race:
            hook, real_nft = configure_stop_race(work, env, args.ingress_stop_race)
            extra.extend(["--core-hook", hook])

        def start_daemon():
            return subprocess.Popen([args.v2raya, "--address", address,
                                     "--config", config_dir, "--v2ray-bin", args.xray,
                                     "--v2ray-assetsdir", args.assets, "--log-disable-color", *extra],
                                    env=env, stdout=log, stderr=log)

        daemon = start_daemon()
        stack.callback(lambda: terminate(daemon))
        opener = build_opener(ProxyHandler({}))
        token = ""

        def call(method, endpoint, payload=None, *, allow_busy=False, bearer=None, timeout=4):
            assert daemon.poll() is None, "isolated v2rayA exited"
            headers = {"Content-Type": "application/json"}
            supplied_token = token if bearer is None else bearer
            if supplied_token:
                headers["Authorization"] = f"Bearer {supplied_token}"
            body = json.dumps(payload).encode() if payload is not None else None
            with opener.open(Request(f"http://{address}/api/{endpoint}", data=body,
                                     headers=headers, method=method), timeout=timeout) as response:
                result = json.load(response)
            if allow_busy and result == {"code": "FAIL", "message": "the last request is being processed", "data": None}:
                return None
            assert result["code"] == "SUCCESS", (method, endpoint, result["code"], result.get("message"))
            return result.get("data")

        def xray_pid():
            children = set()
            for thread in Path("/proc", str(daemon.pid), "task").iterdir():
                try:
                    children.update(map(int, (thread / "children").read_text().split()))
                except FileNotFoundError:
                    continue
            matches = [pid for pid in children if owned_xray(pid, daemon.pid, args.xray, config)]
            assert len(matches) <= 1, "multiple laboratory Xray processes matched"
            return next(iter(matches), None)

        def via_xray():
            response = subprocess.run(["curl", "--silent", "--max-time", "2", "--noproxy", "",
                                       "--proxy", f"socks5h://127.0.0.1:{socks_port}",
                                       "--cacert", node.cert, "--output", "/dev/null",
                                       "--write-out", "%{http_code}", "https://check.invalid/generate_204"],
                                      capture_output=True, text=True, timeout=3)
            return response.returncode == 0 and response.stdout == "204"

        version = wait(lambda: call("GET", "version"), "laboratory v2rayA API")
        assert (version["version"], version["variant"]) == (args.expect_version, args.expect_variant), version
        if stock_transparent:
            assert not version["lite"], "stock transparent proxy requires full v2rayA"
        token = call("POST", "account", FIXTURE_LOGIN)["token"]
        def stop_core():
            with suppress(OSError, AssertionError):
                call("DELETE", "v2ray")
        stack.callback(stop_core)
        token_file = work / "token"

        invalid_file = auto_login in ("insecure", "symlink")
        wrong_login = auto_login == "wrong"
        if auto_login != "bootstrap":
            replace_private_file(token_file, REJECTED_TOKEN if invalid_file or wrong_login else token)
        initial_token = file_revision(token_file) if auto_login == "recover" else None
        if auto_login or local_management:
            login_file = work / "login.json"
            if auto_login == "symlink":
                target = work / "private-login.json"
                replace_private_file(target, json.dumps(FIXTURE_LOGIN))
                login_file.symlink_to(target)
            else:
                credentials = dict(FIXTURE_LOGIN)
                if wrong_login:
                    credentials["password"] = "isolated-incorrect-password"
                replace_private_file(login_file, json.dumps(credentials))
                if invalid_file:
                    login_file.chmod(0o644)

        if inbound_port_case in ("http-lan-sharing", "socks-udp6-shared") or stock_transparent:
            settings = call("GET", "setting")["setting"]
            settings["portSharing"] = not stock_transparent
            if stock_transparent:
                settings.update(transparent="proxy", transparentType="tproxy" if stock_tproxy else "redirect",
                                antiPollution="closed")
            settings["ipforward"] = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
            call("PUT", "setting", settings)
        call("PUT", "ports", {"socks5": 0 if without_socks else socks_port,
                              "http": 0 if without_socks else http_port,
                              "httpWithPac": 0 if without_socks else pac_port,
                              "socks5WithPac": 0, "vmess": 0, "api": {"port": xray_api_port}})
        if multi_outbound_failover:
            multiple.configure(call)
        else:
            call("POST", "import", {"url": f"socks5://fixture:correct@127.0.0.1:{node.port}#Lab"})
            if server_failover:
                call("POST", "import", {"url": f"socks5://fixture:correct@127.0.0.1:{reserve.server_address[1]}#Reserve"})
            call("POST", "connection", {"_type": "server", "id": 1, "outbound": "proxy"})
        if not call("GET", "touch")["running"]:
            call("POST", "v2ray", {})
        former = wait(xray_pid, "owned Xray")
        client_https = via_xray
        if stock_transparent:
            client_https = client._https if (nft_redirect or stock_tproxy) else client.https
        elif transparent_lan:
            if not assigned_management:
                client = TransparentClient(stack, node.cert, wait, terminate)
            client.enable_interception()
            client_https = client.https
        if not owner_restart_dynamic:
            wait(client_https, "client HTTPS 204 through the real Xray ingress")

        status_file = work / "status.json"
        recovery_state = work / "recovery.state"
        helper_log = stack.enter_context((work / "helper.log").open("w+"))
        flags = ["--recover-xray"] if recover else []
        if args.restore_ingress:
            flags.append("--restore-lan-redirect")
        if args.restart_ingress_helper:
            redirect_state = work / "redirect.state"
            flags.extend(["--redirect-state", redirect_state])
        if auto_login or local_management:
            flags.extend(["--login-file", login_file])
        if (use_recovery_state or cold_start or early_crash or without_socks or inbound_port_case or
                late_wan or ingress_loss or stock_tproxy):
            flags.extend(["--recovery-state", recovery_state])
        if server_failover or multi_outbound_failover:
            policy_file, history_file = work / "failover.json", work / "latency.json"
            flags.extend(["--failover-file", policy_file, "--latency-file", history_file])

            def helper_rpc(*command, body=None):
                data = subprocess.check_output([args.helper, *command], text=True, env=env, timeout=8,
                                               input=json.dumps(body) if body is not None else None)
                result = json.loads(data)
                assert result.get("ok", True), result
                return result

            policy_target = [f"http://{address}", token_file, policy_file]
            if multi_outbound_failover:
                flags.extend(["--workers", str(len(ROUTES))])
                multiple.save_policies(helper_rpc, policy_target)
            else:
                catalogue = helper_rpc("failover", "context", *policy_target)
                reserve_key = next(item["key"] for item in catalogue["nodes"] if item["name"] == "Reserve")
                helper_rpc("failover", "save", *policy_target, body={"policy": {
                    "outbound": "proxy", "mode": "outage", "allow_restart": True,
                    "candidates": [reserve_key], "failures": 3,
                }})
        helper_command = [args.helper, "--api", f"http://{address}", "--token-file", token_file,
                          "--interval", "1", "--timeout", "2", "--mark", "0"]
        if (not stock_transparent or ingress_loss or stock_tproxy) and not owner_restart_dynamic:
            helper_command.extend(["--node-interval", "1", "--node-timeout", "4" if slow_reserve_failover else "2",
                                   "--node-url", "https://check.invalid/generate_204"])
        helper_command.extend(flags)

        def start_helper(output=status_file, logs=helper_log, config_file=config):
            command = [*helper_command, "--output", output, "--xray-config", config_file]
            process = subprocess.Popen(command, env=env, stdout=logs, stderr=logs)
            stack.callback(terminate, process)
            return process

        def snapshot():
            assert helper.poll() is None, "helper exited"
            return json.loads(status_file.read_text())

        def monitor_https(state):
            snap = snapshot()
            def matches(reading):
                return reading.get("state") == state or (
                    state == "timeout" and reading.get("detail") == "https_timeout")
            return any(matches(member.get("https", {}))
                       for row in snap.get("outbounds", []) if row["name"] == "proxy"
                       for member in row.get("members", []))

        def arm():
            if stock_redirect:
                # Use the real client for REDIRECT. QEMU user mode may reject the
                # generated outbound SO_MARK that the optional helper probe uses.
                wait(lambda: snapshot().get("state") == "ok" and recovery_state.exists() and client_https(),
                     "healthy recovery checkpoint and real LAN HTTPS")
            else:
                wait(lambda: snapshot().get("state") == "ok" and monitor_https("ok"),
                     "warm independent HTTPS measurement")

        def client_unavailable():
            return not (client_https(.25) if transparent_lan else client_https())

        def independent_probe():
            for row in snapshot().get("outbounds", []):
                if row["name"] != "proxy":
                    continue
                for member in row["members"]:
                    sample = member.get("https", {})
                    checked = sample.get("checked_at")
                    if not checked:
                        continue
                    if sample.get("state") == "ok" and sample.get("http_code") == 204:
                        return checked, "independent HTTPS 204"
                    if (args.allow_unavailable_node_probe and sample.get("state") == "error" and
                            sample.get("detail") == "https_mark_error"):
                        return checked, "independent https_mark_error"
            return None

        def wait_new_measurement(since):
            def fresh():
                sample = independent_probe()
                return sample if sample and sample[0] > since else None
            return wait(fresh, "a new independent HTTPS reading")

        @contextmanager
        def paused_stock_stop():
            stop_arm = work / "stop.arm"
            stop_entered = work / "stop.entered"
            stop_release = work / "stop.release"
            outcomes = []

            def stop_api():
                try:
                    outcomes.append(call("DELETE", "v2ray", timeout=12))
                except Exception as error:
                    outcomes.append(error)

            stop_arm.touch()
            stop_thread = Thread(target=stop_api, daemon=True)
            stop_thread.start()
            try:
                wait(stop_entered.exists, "stock Stop after firewall cleanup and before closing Xray", timeout=5)
                assert call("GET", "touch", allow_busy=True) is None
                yield
            finally:
                stop_release.touch()
                stop_thread.join(timeout=6)
                stop_arm.unlink()
            assert len(outcomes) == 1 and isinstance(outcomes[0], dict) and not outcomes[0]["running"], outcomes

        def stock_stop_race_case():
            mode = args.ingress_stop_race
            table = ["table", "inet", "v2raya"]
            table_header = "table inet v2raya {"
            delete_result = work / "stock-delete.rc"

            def nft(*arguments, **options):
                return subprocess.run([real_nft, *arguments], text=True, capture_output=True, timeout=4, **options)

            def table_flags():
                listed = nft("-j", "list", *table)
                if listed.returncode:
                    assert "No such file or directory" in listed.stderr, listed.stderr
                    return None
                entry, = (item["table"] for item in json.loads(listed.stdout)["nftables"] if "table" in item)
                flags = entry.get("flags", [])
                return {flags} if isinstance(flags, str) else set(flags)

            assert xray_pid() == former and client_https() and via_xray()
            config_revision = file_revision(config)
            backup = nft("list", *table, check=True).stdout
            assert backup.count(table_header) == 1 and table_flags() == set()
            dormant = backup.replace(table_header, table_header + "\n    flags dormant", 1)
            nft("delete", *table, check=True)
            assert table_flags() is None and client_unavailable() and via_xray() and xray_pid() == former
            if mode in ("dormant-cleanup", "dormant-failed-delete"):
                nft("-f", "-", input=dormant, check=True)
                assert table_flags() == {"dormant"} and client_unavailable() and via_xray()

            before_touch = nft_generation()
            assert call("GET", "touch")["running"] and nft_generation() == before_touch
            with paused_stock_stop():
                assert delete_result.is_file(), "stock Stop did not invoke its exact nft delete command"
                delete_rc = int(delete_result.read_text())
                at_pause = nft_generation()
                assert xray_pid() == former and via_xray() and file_revision(config) == config_revision
                assert client_unavailable()
                print(f"Stop race {mode}: last successful touch at generation {before_touch}, "
                      f"stock nft delete returned {delete_rc}, pre-stop generation {at_pause}", flush=True)

                if mode in ("naive", "dormant-after"):
                    assert delete_rc != 0 and table_flags() is None and before_touch == at_pause
                    nft("-f", "-", input=backup if mode == "naive" else dormant, check=True)
                    if mode == "dormant-after":
                        assert table_flags() == {"dormant"} and client_unavailable() and via_xray()
                        assert call("GET", "touch", allow_busy=True) is None
                        nft("delete", *table, check=True)
                        assert table_flags() is None
                        print("Stop race: staged dormant table stayed inactive; fresh busy touch prevented activation",
                              flush=True)
                elif mode == "dormant-cleanup":
                    assert delete_rc == 0 and table_flags() is None and before_touch != at_pause
                    print("Stop race: stock cleanup removed the staged table and advanced nftables generation",
                          flush=True)
                else:
                    assert delete_rc == 42 and table_flags() == {"dormant"} and before_touch == at_pause
                    nft("add", *table, check=True)

                active_republication = mode in ("naive", "dormant-failed-delete")
                if active_republication:
                    wait(client_https, "unsafe activation reopened LAN before stock Stop returned")
                    assert table_flags() == set() and xray_pid() == former
                    print("Stop race: an earlier successful touch and unchanged generation admitted unsafe activation",
                          flush=True)
            assert xray_pid() is None and not call("GET", "touch")["running"] and client_unavailable()
            if active_republication:
                assert table_flags() == set(), "the stock Stop unexpectedly removed the late active table"
                print("Stop race: stock Stop killed Xray while the late active REDIRECT table remained", flush=True)
                nft("delete", *table, check=True)
            assert table_flags() is None

        def tproxy_ingress_case():
            probes = {"ipv4": client_https}
            if args.ingress_dual_family:
                probes["ipv6"] = client.https_ipv6

            def status(broken=None, reason=None):
                current = snapshot()
                if current.get("state") != "ok":
                    return False
                if args.expect_no_tproxy_status:
                    return "lan_ingress" not in current
                ingress = current.get("lan_ingress", {})
                if (ingress.get("mode"), ingress.get("backend")) != ("tproxy", "iptables"):
                    return False
                for family in ("ipv4", "ipv6"):
                    expected_reason = reason if family == broken else None
                    expected = "attached" if family in probes and family != broken else "unknown"
                    if expected_reason:
                        expected = "missing"
                    if ingress.get(family) != expected or ingress.get(f"{family}_reason") != expected_reason:
                        return False
                return True

            def kernel_state():
                state = {}
                for family in probes:
                    layer = "-6" if family == "ipv6" else "-4"
                    iptables = "ip6tables-save" if family == "ipv6" else "iptables-save"
                    rules = subprocess.check_output([iptables, "-t", "mangle"], text=True, timeout=5)
                    policy = subprocess.check_output(["ip", layer, "-j", "rule", "show"], text=True, timeout=5)
                    route = subprocess.run(["ip", layer, "-j", "route", "show", "table", "100"],
                                           capture_output=True, text=True, timeout=5)
                    if route.returncode:
                        assert "FIB table does not exist" in route.stderr, route.stderr
                    state[family] = ([line for line in rules.splitlines() if line.startswith("-A ")],
                                     json.loads(policy), [] if route.returncode else json.loads(route.stdout))
                return state

            def all_lan_up():
                return all(https() for https in probes.values())

            def only_lan_family_down(broken):
                return all(https(.35) == (family != broken) for family, https in probes.items())

            for command in ("iptables", "ip6tables") if args.ingress_dual_family else ("iptables",):
                assert "(nf_tables)" in subprocess.check_output([command, "--version"], text=True, timeout=5)
            wait(lambda: status() and all_lan_up(), "stock iptables-nft TPROXY and LAN HTTPS on each enabled family")
            check_recovery_record()
            previous_config = file_revision(config)
            previous_recovery = file_revision(recovery_state)
            core_stat = Path("/proc", str(former), "stat")
            started = core_stat.read_text().rsplit(")", 1)[1].split()[19]
            original_kernel = kernel_state()

            if args.ingress_stop_race == "tproxy-route":
                route = ["local", "0.0.0.0/0", "dev", "lo", "table", "100"]
                subprocess.run(["ip", "-4", "route", "del", *route], check=True, timeout=5)
                wait(lambda: status("ipv4", "local_route_missing") and only_lan_family_down("ipv4"),
                     "one real LAN route failure before Stop")
                assert call("GET", "touch")["running"] and via_xray() and xray_pid() == former
                with paused_stock_stop():
                    after_cleanup = kernel_state()
                    assert all("-A PREROUTING -j TP_PRE" not in rules and not routes and
                               not any(entry.get("fwmark") == "0x40" for entry in policy)
                               for rules, policy, routes in after_cleanup.values())
                    assert via_xray() and xray_pid() == former and file_revision(config) == previous_config
                    subprocess.run(["ip", "-4", "route", "add", *route], check=True, timeout=5)
                    assert client_unavailable()
                wait(lambda: xray_pid() is None and snapshot().get("state") == "stopped", "stock TPROXY Stop")
                expected = dict(after_cleanup)
                rules, policy, _ = after_cleanup["ipv4"]
                expected["ipv4"] = (rules, policy, original_kernel["ipv4"][2])
                assert kernel_state() == expected, "only the late IPv4 route should remain after Stop"
                assert client_unavailable()
                call("POST", "v2ray", {}, timeout=12)
                assert wait(xray_pid, "new Xray through ordinary stock Start") != former
                wait(lambda: status() and all_lan_up(), "ordinary Start returned real LAN HTTPS")
                assert kernel_state() == original_kernel
                print("TPROXY Stop race: late local route survived Stop; ordinary Start rebuilt the stock kernel state",
                      flush=True)
                return

            healthy_at, _ = wait(independent_probe, "initial independent HTTPS on stock TPROXY")
            unrelated = ["priority", "1000", "fwmark", "0x80/0x80", "table", "4242"]
            subprocess.run(["ip", "-4", "rule", "add", *unrelated], check=True, timeout=5)
            try:
                wait_new_measurement(healthy_at)
                assert status() and all_lan_up() and xray_pid() == former
            finally:
                subprocess.run(["ip", "-4", "rule", "del", *unrelated], check=True, timeout=5)
            assert kernel_state() == original_kernel
            print("Ingress TPROXY: unrelated IPv4 PBR mark left all enabled LAN families working", flush=True)

            with ExitStack() as pbr:
                blackhole = ["blackhole", f"{DESTINATION}/32", "table", "4242"]
                overlapping = ["priority", "1000", "fwmark", "0x40/0xc0", "table", "4242"]
                for kind, entry in (("route", blackhole), ("rule", overlapping)):
                    subprocess.run(["ip", "-4", kind, "add", *entry], check=True, timeout=5)
                    pbr.callback(subprocess.run, ["ip", "-4", kind, "del", *entry], check=True, timeout=5)
                wait(lambda: status("ipv4") and only_lan_family_down("ipv4"),
                     "earlier matching PBR interrupts only IPv4 without claiming a deleted stock object")
                assert via_xray() and xray_pid() == former
            wait(lambda: status() and all_lan_up(), "real LAN HTTPS after removing the test PBR override")
            assert kernel_state() == original_kernel
            print("Ingress TPROXY: matching earlier PBR interrupted IPv4 with each stock object still present",
                  flush=True)

            for family in probes:
                layer = "-6" if family == "ipv6" else "-4"
                iptables = "ip6tables" if family == "ipv6" else "iptables"
                faults = (
                    ("hook_missing", [iptables, "-w", "2", "-t", "mangle"], "-D", "-I", ["PREROUTING", "-j", "TP_PRE"]),
                    ("policy_missing", ["ip", layer, "rule"], "del", "add", ["fwmark", "0x40/0xc0", "table", "100"]),
                    ("local_route_missing", ["ip", layer, "route"], "del", "add",
                     ["local", "::/0" if family == "ipv6" else "0.0.0.0/0", "dev", "lo", "table", "100"]),
                )
                for reason, command, remove, add, entry in faults:
                    subprocess.run([*command, remove, *entry], check=True, timeout=5)
                    try:
                        checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        changed_kernel = kernel_state()
                        assert changed_kernel[family] != original_kernel[family]
                        wait(lambda: only_lan_family_down(family), f"actual LAN {family} isolated fault for {reason}")
                        wait(lambda: status(family, reason), f"snapshot diagnoses {family} {reason}")
                        for _ in range(2):
                            checked_at, evidence = wait_new_measurement(checked_at)
                            assert status(family, reason) and only_lan_family_down(family) and via_xray()
                            assert kernel_state() == changed_kernel and xray_pid() == former
                        assert call("GET", "touch")["running"]
                    finally:
                        subprocess.run([*command, add, *entry], check=True, timeout=5)
                    wait(lambda: status() and all_lan_up(), f"real LAN HTTPS returned after restoring only {reason}")
                    assert kernel_state() == original_kernel
                    assert xray_pid() == former and core_stat.read_text().rsplit(")", 1)[1].split()[19] == started
                    assert file_revision(config) == previous_config and file_revision(recovery_state) == previous_recovery
                    result = "previous helper omitted status" if args.expect_no_tproxy_status else "reason reported"
                    print(f"Ingress TPROXY {family} {reason}: {result} while real LAN was down and {evidence}; "
                          "manual single-object restoration returned LAN with the same Xray", flush=True)

        def ingress_loss_case():
            nonlocal helper

            def status(expected):
                current = snapshot()
                if current.get("state") != "ok":
                    return False
                if args.expect_no_ingress_status:
                    return "lan_ingress" not in current
                ingress = current.get("lan_ingress", {})
                if args.ingress_dual_family and ingress.get("ipv6") != expected:
                    return False
                return (ingress.get("mode"), ingress.get("backend"), ingress.get("ipv4")) == (
                    "redirect", ingress_loss, expected)

            def nft_objects(*target):
                output = subprocess.check_output(["nft", "-j", "list", *target], text=True, timeout=5)
                return json.loads(output)["nftables"]

            def stock_jump(rule):
                return (bool(rule) and (rule["family"], rule["table"], rule["chain"]) ==
                        ("inet", "v2raya", "tp_pre") and
                        any(expr.get("jump", {}).get("target") == "tp_rule" for expr in rule["expr"]))

            def nft_jump_handles():
                return [item["rule"]["handle"] for item in nft_objects("chain", "inet", "v2raya", "tp_pre")
                        if stock_jump(item.get("rule"))]

            def nft_rules_without_jump_handle():
                rules = nft_objects("ruleset")
                jump, = (item["rule"] for item in rules if stock_jump(item.get("rule")))
                del jump["handle"]
                return rules

            if nft_redirect:
                handle, = nft_jump_handles()
                remove = ["nft", "delete", "rule", "inet", "v2raya", "tp_pre", "handle", str(handle)]
                families = "{ ipv4, ipv6 }" if args.ingress_dual_family else "ipv4"
                restore = ["nft", "add", "rule", "inet", "v2raya", "tp_pre",
                           "meta", "nfproto", families, "meta", "l4proto", "tcp", "jump", "tp_rule"]
                present = nft_jump_handles
            else:
                table = ["iptables", "-w", "2", "-t", "nat"]
                jump = ["PREROUTING", "-p", "tcp", "-j", "TP_PRE"]
                remove = [*table, "-D", *jump]
                restore = [*table, "-I", *jump]

                def present():
                    result = subprocess.run([*table, "-C", *jump], capture_output=True, timeout=5)
                    assert result.returncode in (0, 1), result.stderr
                    return result.returncode == 0

            assert present(), "stock REDIRECT attachment was not present before the test"
            assert isinstance(former, int) and former > 0 and xray_pid() == former
            wait(independent_probe, "an independent probe before unhooking LAN traffic")
            wait(lambda: status("attached") and client_https(), "stock REDIRECT active with real LAN HTTPS")
            original_config = file_revision(config)
            check_recovery_record()
            original_recovery = file_revision(recovery_state)
            if args.restore_ingress or args.ingress_table_loss:
                def lan_https():
                    return client_https() and (not args.ingress_dual_family or client.https_ipv6())

                def lan_unavailable():
                    return client_unavailable() and (not args.ingress_dual_family or not client.https_ipv6(.25))

                wait(lan_https, "real LAN HTTPS over every enabled address family")
                core_stat = Path("/proc", str(former), "stat")
                old_generation = core_stat.read_text().rsplit(")", 1)[1].split()[19]

                if args.ingress_table_loss:
                    def stock_table_present():
                        return any((item.get("table", {}).get("family"), item.get("table", {}).get("name")) ==
                                   ("inet", "v2raya") for item in nft_objects("ruleset"))

                    def table_without_handles(name):
                        objects = nft_objects("table", "inet", name)
                        for item in objects:
                            for value in item.values():
                                value.pop("handle", None)
                        return objects

                    def table_loss_status():
                        current = snapshot()
                        if current.get("state") != "ok":
                            return False
                        if args.expect_no_table_loss_status:
                            return "lan_ingress" not in current
                        ingress = current.get("lan_ingress", {})
                        expected_v6 = "missing" if args.ingress_dual_family else "unknown"
                        return (ingress.get("mode"), ingress.get("backend"), ingress.get("reason"),
                                ingress.get("ipv4"), ingress.get("ipv6")) == (
                                    "redirect", "nftables", "table_missing", "missing", expected_v6)

                    before_fw4, _ = wait(independent_probe, "independent HTTPS before the fw4 control")
                    subprocess.run(["nft", "-f", "-"], text=True, input="""
table inet fw4 {
    chain lab_unrelated {
        return
    }
}
""", check=True, timeout=5)
                    wait_new_measurement(before_fw4)
                    assert stock_table_present() and status("attached") and lan_https() and xray_pid() == former
                    unrelated = nft_objects("table", "inet", "fw4")
                    print("Ingress nftables: an unrelated inet fw4 edit left stock REDIRECT attached and LAN working",
                          flush=True)

                    original_table = table_without_handles("v2raya")
                    backup = subprocess.check_output(["nft", "list", "table", "inet", "v2raya"], text=True, timeout=5)
                    subprocess.run(["nft", "delete", "table", "inet", "v2raya"], check=True, timeout=5)
                    try:
                        kernel_without_table = nft_objects("ruleset")
                        assert not stock_table_present()
                        wait(lan_unavailable, "actual LAN HTTPS loss after removing the complete stock table")
                        wait(table_loss_status, "whole-table REDIRECT loss in the current helper snapshot")
                        checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        for _ in range(3):
                            checked_at, evidence = wait_new_measurement(checked_at)
                            assert table_loss_status() and lan_unavailable() and via_xray()
                            assert xray_pid() == former and call("GET", "touch")["running"]
                            assert nft_objects("ruleset") == kernel_without_table and not stock_table_present()
                        family = "IPv4 and IPv6" if args.ingress_dual_family else "IPv4"
                        diagnosis = ("the previous helper omitted ingress status" if args.expect_no_table_loss_status
                                     else "the helper reported table_missing")
                        print(f"Ingress nftables table loss ({family}): {diagnosis} with fresh {evidence}; "
                              "stock table stayed absent and Xray stayed running", flush=True)
                    finally:
                        if not stock_table_present():
                            subprocess.run(["nft", "-f", "-"], input=backup, text=True, check=True, timeout=5)

                    wait(lambda: status("attached") and lan_https(), "live LAN after manual restoration of the table")
                    assert snapshot()["lan_ingress"].get("reason") != "table_missing"
                    assert table_without_handles("v2raya") == original_table and nft_objects("table", "inet", "fw4") == unrelated
                    assert xray_pid() == former and core_stat.read_text().rsplit(")", 1)[1].split()[19] == old_generation
                    assert file_revision(config) == original_config and file_revision(recovery_state) == original_recovery
                    print(f"Ingress nftables table loss ({family}): manual restoration returned LAN HTTPS 204 "
                          "with the same Xray and the same unrelated fw4 table", flush=True)
                    return

                original_rules = nft_rules_without_jump_handle()

                def detach_stock_jump():
                    subprocess.run(remove, check=True, timeout=5)
                    assert not present()
                    wait(lan_unavailable, "real LAN HTTPS down after nftables attachment removal")
                    assert xray_pid() == former and call("GET", "touch")["running"] and via_xray()

                if args.restart_ingress_helper:
                    def private_witness():
                        info = redirect_state.lstat()
                        return (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
                                info.st_uid == os.geteuid() and info.st_size > 0)

                    wait(private_witness, "the warm helper wrote its private REDIRECT witness")
                    old_helper = helper.pid
                    terminate(helper)
                    assert helper.poll() is not None and private_witness()
                    if args.without_redirect_state:
                        redirect_state.unlink()
                    if args.stale_redirect_state:
                        config_next = config.with_suffix(".lab-next")
                        config_next.write_bytes(config.read_bytes())
                        config_next.chmod(stat.S_IMODE(config.stat().st_mode))
                        config_next.replace(config)
                        new_revision = file_revision(config)
                        assert new_revision[:2] != original_config[:2], "fixture kept the same config inode"
                        original_config = new_revision
                    status_file.unlink()
                    detach_stock_jump()
                    restarted_at = time.monotonic()
                    helper = start_helper()
                    assert helper.pid != old_helper, "the replacement helper must be a new process"
                else:
                    # Exercise the custom-rule guard before a successful restore starts the cooldown.
                    subprocess.run(["nft", "add", "rule", "inet", "v2raya", "tp_pre",
                                    "ip", "daddr", "192.0.2.201", "return"], check=True, timeout=5)
                    subprocess.run(remove, check=True, timeout=5)
                    custom_handle, = (item["rule"]["handle"] for item in
                                      nft_objects("chain", "inet", "v2raya", "tp_pre") if "rule" in item)
                    custom_rules = nft_objects("ruleset")
                    wait(lambda: status("unknown") and lan_unavailable(), "unknown custom ingress remains detached")
                    for _ in range(4):
                        assert not present() and nft_objects("ruleset") == custom_rules
                        assert xray_pid() == former and via_xray() and lan_unavailable()
                        time.sleep(.7)
                    print("Ingress nftables: ambiguous custom rule and missing stock jump both stayed as configured",
                          flush=True)
                    subprocess.run([*remove[:-1], str(custom_handle)], check=True, timeout=5)
                    subprocess.run(restore, check=True, timeout=5)
                    handle, = present()
                    remove[-1] = str(handle)
                    wait(lambda: status("attached") and lan_https(), "stock witness after removing custom rule")
                    assert nft_rules_without_jump_handle() == original_rules

                    helper_fd = os.pidfd_open(helper.pid)
                    helper_stat = Path("/proc", str(helper.pid), "stat")
                    try:
                        signal.pidfd_send_signal(helper_fd, signal.SIGSTOP)
                        wait(lambda: helper_stat.read_text().rsplit(")", 1)[1].split()[0] == "T",
                             "only the test helper paused before removing the attachment")
                        detach_stock_jump()
                    finally:
                        signal.pidfd_send_signal(helper_fd, signal.SIGCONT)
                        os.close(helper_fd)

                wait(lambda: status("missing") and not present(),
                     "the helper observed an isolated missing stock jump before repairing it")
                if args.without_redirect_state or args.stale_redirect_state:
                    kernel_without_jump = nft_objects("ruleset")
                    wait(independent_probe, "working independent probe from the restarted helper")
                    for _ in range(5):
                        assert status("missing") and not present()
                        if args.without_redirect_state:
                            assert not redirect_state.exists()
                        assert nft_objects("ruleset") == kernel_without_jump
                        assert xray_pid() == former and lan_unavailable()
                        time.sleep(.7)
                    witness = "after replacing the generated config inode" if args.stale_redirect_state else "without the witness"
                    print(f"Ingress nftables: helper restart {witness} left the stock jump absent", flush=True)
                    subprocess.run(restore, check=True, timeout=5)
                    action = "manual rule restoration"
                elif args.restart_ingress_helper:
                    action = "the new helper restored the rule from the previous helper's witness"
                else:
                    action = "the helper restored the rule without manual action"
                wait(lambda: present() and status("attached") and lan_https(),
                     f"actual LAN HTTPS after {action}", timeout=20)
                recovered_after_restart = (
                    f" in {time.monotonic() - restarted_at:.2f}s"
                    if args.restart_ingress_helper and not (args.without_redirect_state or args.stale_redirect_state)
                    else "")
                restored_handle, = present()
                assert restored_handle != handle, "expected a replacement jump"
                assert nft_rules_without_jump_handle() == original_rules, "ruleset changed beyond the repaired jump"
                assert xray_pid() == former and core_stat.read_text().rsplit(")", 1)[1].split()[19] == old_generation
                assert call("GET", "touch")["running"] and via_xray()
                assert file_revision(config) == original_config and file_revision(recovery_state) == original_recovery
                print(f"Ingress nftables {'IPv4 and IPv6' if args.ingress_dual_family else 'IPv4-only'}: "
                      f"one stock jump and real LAN HTTPS 204 with the same Xray after {action}"
                      f"{recovered_after_restart}", flush=True)

                call("DELETE", "v2ray")
                wait(lambda: xray_pid() is None and snapshot().get("state") == "stopped",
                     "deliberate stock Stop after repairing the attachment")
                for _ in range(4):
                    assert not any(item.get("table", {}).get("name") == "v2raya"
                                   for item in nft_objects("ruleset")), "helper recreated stock rules after Stop"
                    assert xray_pid() is None and lan_unavailable()
                    time.sleep(.7)
                assert not call("GET", "touch")["running"]
                print("Ingress nftables: deliberate Stop stayed stopped with LAN attachment absent", flush=True)
                return

            subprocess.run(remove, check=True, timeout=5)
            try:
                detached_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                wait(client_unavailable, "LAN HTTPS stopped after removing only the PREROUTING attachment")
                def fresh_probe():
                    sample = independent_probe()
                    return sample if sample and sample[0] > detached_at and status("missing") else None

                _, evidence = wait(fresh_probe, "a fresh independent probe while LAN ingress is missing")
                assert not present(), "helper unexpectedly reattached the stock rule"
                assert client_unavailable() and xray_pid() == former and call("GET", "touch")["running"]
                assert via_xray(), "Xray no longer served its explicit SOCKS path during the LAN outage"
                assert file_revision(config) == original_config and file_revision(recovery_state) == original_recovery
                if args.expect_no_ingress_status:
                    print(f"Ingress {ingress_loss} baseline: LAN went down with an owned Xray and fresh {evidence}, "
                          "but the snapshot has no lan_ingress field", flush=True)
                else:
                    family = "IPv4 and IPv6" if args.ingress_dual_family else "IPv4"
                    print(f"Ingress {ingress_loss}: missing {family} attachment detected with an owned Xray "
                          f"and fresh {evidence}", flush=True)
            finally:
                if not present():
                    subprocess.run(restore, check=True, timeout=5)

            wait(lambda: status("attached") and client_https(),
                 "the original LAN route returned after manual restoration")
            assert present() and xray_pid() == former and call("GET", "touch")["running"]
            assert file_revision(config) == original_config and file_revision(recovery_state) == original_recovery
            print(f"Ingress {ingress_loss}: manual rule restoration returned real LAN HTTPS 204 "
                  "with the same Xray process", flush=True)

        def assignment(*, allow_busy=False):
            data = call("GET", "touch", allow_busy=allow_busy)
            if data is None:
                return None
            assert data["running"], "v2rayA lost its running state"
            selected, = data["touch"]["connectedServer"]
            assert selected["_type"] == "server" and selected["outbound"] == "proxy"
            return selected["id"]

        def reserve_samples(state):
            if not history_file.exists():
                return []
            return [sample for sample in helper_rpc("latency", history_file, "proxy")["samples"]
                    if sample["role"] == "reserve" and sample["server"] == "Reserve" and sample["state"] == state]

        def late_wan_case():
            nonlocal daemon, helper, token
            assert assignment() == 1 and xray_pid() == former and client_https()
            with ExitStack() as descriptors:
                core_fd = os.pidfd_open(former)
                descriptors.callback(os.close, core_fd)
                exited = select.poll()
                exited.register(core_fd, select.POLLIN)
                terminate(daemon)
                assert daemon.returncode == 0, "v2rayA did not exit cleanly"
                if not exited.poll(1000):
                    # A stock v2rayA exit can race its asynchronous Xray stop. Clean up only this
                    # pre-verified laboratory process before simulating the next boot.
                    with suppress(ProcessLookupError):
                        signal.pidfd_send_signal(core_fd, signal.SIGKILL)
                    assert exited.poll(5000), "the original laboratory Xray did not stop"
                    print("Late WAN: reaped a leftover Xray from the stopped test daemon", flush=True)

            rules = f"""
table ip recovery_lab_wan {{
    chain egress {{
        type filter hook output priority filter; policy accept;
        ip daddr 127.0.0.1 tcp dport {node.port} counter drop;
        ip daddr 127.0.0.1 tcp dport {reserve.server_address[1]} counter drop;
    }}
}}
"""
            subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True, timeout=5)
            try:
                daemon = start_daemon()
                wait(lambda: call("GET", "version"), "stock v2rayA booted with both upstreams blocked")
                token = call("POST", "login", FIXTURE_LOGIN)["token"]
                replace_private_file(token_file, token)
                boot_core = wait(xray_pid, "stock v2rayA restored the saved Xray assignment without WAN")
                assert boot_core != former and assignment() == 1 and client_unavailable()
                original_config = file_revision(config)
                helper = start_helper()
                wait(lambda: monitor_https("timeout") and len(reserve_samples("timeout")) >= 2,
                     "primary timeout and two unsuccessful reserve checks with WAN still unavailable", timeout=45)
                assert assignment() == 1 and xray_pid() == boot_core and client_unavailable()
                assert file_revision(config) == original_config
                assert not Path(f"{policy_file}.last").exists(), "helper reserved a switch during the WAN outage"
                nft = subprocess.check_output(["nft", "-j", "list", "chain", "ip", "recovery_lab_wan", "egress"],
                                              text=True, timeout=5)
                counters = [expr["counter"]["packets"] for item in json.loads(nft)["nftables"]
                            for expr in item.get("rule", {}).get("expr", []) if "counter" in expr]
                assert len(counters) == 2 and all(counters), "both upstreams must have observed dropped packets"
                print("Late WAN: stock Xray started from saved settings while both upstreams were blocked. "
                      "Failed reserve checks left its assignment and process intact", flush=True)
            finally:
                subprocess.run(["nft", "delete", "table", "ip", "recovery_lab_wan"], check=True, timeout=5)

            started = time.monotonic()
            wait(lambda: monitor_https("ok") and client_https(),
                 "original transparent LAN client recovered after upstream egress returned")
            restored_in = time.monotonic() - started
            for _ in range(4):
                assert assignment() == 1 and xray_pid() == boot_core and client_https()
                assert file_revision(config) == original_config and not Path(f"{policy_file}.last").exists()
                time.sleep(.5)
            print(f"Late WAN: original assignment and Xray served LAN HTTPS 204 after egress returned "
                  f"in {restored_in:.2f}s", flush=True)

        def failover_case():
            assert assignment() == 1
            node.hold.set()
            try:
                wait(lambda: len(reserve_samples("timeout")) >= 2, "two reserve timeouts during common HTTPS outage", 30)
                assert assignment() == 1 and xray_pid() == former, "shared target outage caused a failover"
                assert client_unavailable(), "the LAN client reached the held control site"
            finally:
                node.hold.clear()
                node.release.set()
            wait(lambda: monitor_https("ok") and client_https(), "common HTTPS target restored on the primary")
            assert assignment() == 1 and xray_pid() == former, "restoring the common target switched servers"
            print("Server failover: shared HTTPS target outage timed out on the reserve without restarting Xray", flush=True)

            node.socks.shutdown()
            started = time.monotonic()
            node.socks.server_close()
            assert client_unavailable(), "LAN client did not observe the loss of the primary SOCKS endpoint"
            wait(lambda: assignment(allow_busy=True) == 2 and xray_pid() not in (None, former) and client_https(),
                 "LAN HTTPS 204 through the reserve and the new Xray process", 30)
            assert reserve_samples("ok"), "reserve was not independently verified before the switch"
            assert helper.poll() is None, "monitor stopped after switching"
            print(f"Server failover: loss of the primary SOCKS endpoint restored real LAN HTTPS through the reserve "
                  f"in {time.monotonic() - started:.2f}s", flush=True)

        def slow_reserve_case():
            assert call("GET", "touch")["touch"]["connectedServer"][0]["id"] == 1
            assert client_https() and xray_pid() == former
            node.socks.stall = True
            assert client_unavailable(), "the LAN client did not time out on the primary"
            started = time.monotonic()

            def confirmed_reserve():
                if not history_file.exists():
                    return None
                history = helper_rpc("latency", history_file, "proxy")["samples"]
                failures = {item["at"] for item in history if item["role"] == "active" and
                            item["server"] == "Lab" and item["state"] in ("timeout", "error")}
                reserves = [item["ms"] for item in history if item["role"] == "reserve" and
                            item["server"] == "Reserve" and item["state"] == "ok"]
                # A separate periodic batch waits at least one second. The immediate
                # recheck starts while returning from a valid reserve measurement.
                confirmation = next((elapsed for at, elapsed in primary_timeouts if
                                     any(0 <= at - ready < 1 for ready in reserve_ready_at)), None)
                return (min(reserves), confirmation) if len(failures) >= 3 and confirmation and reserves else None

            reserve_ms, recheck = wait(confirmed_reserve,
                                       "three primary timeouts plus a fresh failed recheck and valid reserve", timeout=32)
            assert 3000 <= reserve_ms < 4000
            print(f"Slow reserve: fresh checks completed, reserve {reserve_ms} ms and primary still times out "
                  f"({recheck:.2f}s)", flush=True)

            def recovered_lan():
                current = call("GET", "touch", allow_busy=True)
                return (current and current["running"] and current["touch"]["connectedServer"][0]["id"] == 2 and
                        xray_pid() not in (None, former) and client.https(3.9))

            wait(recovered_lan, "automatic server switch restored stock LAN HTTPS through the slow reserve", timeout=10)
            print(f"Slow reserve: LAN HTTPS 204 through the selected reserve in "
                  f"{time.monotonic() - started:.2f}s after observing the outage", flush=True)

        def socks_refused():
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=.5):
                    return False
            except ConnectionRefusedError:
                return True

        def stays_down(message):
            # A killed core can lose its /proc cmdline a moment before its listening
            # socket closes. Let that socket go, then require the core to stay down.
            released = time.monotonic() + 1
            while not socks_refused() and time.monotonic() < released:
                time.sleep(.05)
            for _ in range(8):
                assert xray_pid() is None and socks_refused() and client_unavailable(), message
                time.sleep(.5)

        def cold_start_case():
            log_path = work / "v2raya.log"

            def shutdown():
                old_core = xray_pid()
                with ExitStack() as descriptors:
                    exited = select.poll()
                    if old_core:
                        descriptor = os.pidfd_open(old_core)
                        descriptors.callback(os.close, descriptor)
                        exited.register(descriptor, select.POLLIN)
                    terminate(helper)
                    terminate(daemon)
                    assert daemon.returncode == 0, "v2rayA did not exit cleanly"
                    assert not old_core or exited.poll(5000), "old Xray did not exit with v2rayA"
                assert socks_refused() and client_unavailable()

            def boot():
                nonlocal daemon, helper, token
                status_file.unlink(missing_ok=True)
                recovery_state.unlink(missing_ok=True)
                offset = log_path.stat().st_size
                daemon = start_daemon()
                helper = start_helper()
                wait(lambda: call("GET", "version"), "v2rayA API after a clean restart")
                try:
                    call("GET", "touch")
                except HTTPError as error:
                    if error.code != 401:
                        raise
                    token = call("POST", "login", FIXTURE_LOGIN)["token"]
                    replace_private_file(token_file, token)
                    print("Cold start: previous bearer was rejected; normal fixture login restored API access",
                          flush=True)
                return log_path.read_bytes()[offset:].decode()

            assert call("GET", "touch")["running"]
            shutdown()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
                occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                occupied.bind(("127.0.0.1", socks_port))
                occupied.listen(1)
                startup = boot()
                failure = [line for line in startup.splitlines() if "failed to start v2ray-core" in line]
                assert len(failure) == 1 and str(socks_port) in failure[0], startup
                assert not call("GET", "touch")["running"] and xray_pid() is None and client_unavailable()
                wait(lambda: snapshot().get("state") == "stopped", "helper reports stopped after boot failure")
                print(f"Cold start: {failure[0].split('failed to start v2ray-core: ', 1)[-1]}", flush=True)

            started = time.monotonic()
            stays_down("Xray recovered automatically after the boot conflict was removed")
            assert not call("GET", "touch")["running"] and snapshot().get("state") == "stopped"
            print(f"Cold start: no stock or helper retry in {time.monotonic() - started:.2f}s after the port became free",
                  flush=True)

            assert not call("DELETE", "v2ray")["running"], "v2rayA did not acknowledge Stop while the core was absent"
            shutdown()
            started = time.monotonic()
            startup = boot()
            assert "failed to start v2ray-core" not in startup
            wait(lambda: call("GET", "touch")["running"] and xray_pid() and client_https(),
                 "stock automatic start and LAN HTTPS after the next daemon restart")
            print(f"Cold start: next clean v2rayA launch restored LAN HTTPS in {time.monotonic() - started:.2f}s "
                  "despite successful Stop while Xray was absent", flush=True)

            call("DELETE", "v2ray")
            wait(lambda: not call("GET", "touch")["running"] and xray_pid() is None, "administrator stopped Xray")
            wait(lambda: snapshot().get("state") == "stopped", "helper observed the deliberate stop")
            shutdown()
            startup = boot()
            assert "the core was not running the last time v2rayA exited" in startup, startup
            wait(lambda: snapshot().get("state") == "stopped", "fresh helper respected the stopped state")
            started = time.monotonic()
            stays_down("next v2rayA launch undid the administrator's stop")
            assert not call("GET", "touch")["running"]
            print(f"Cold start: deliberate stop was preserved on the next launch ({time.monotonic() - started:.2f}s observed)",
                  flush=True)

        def early_crash_case(started):
            nonlocal helper
            wait(core_unavailable, "fresh helper published the missing Xray")
            if args.expect_no_early_recovery:
                stays_down("old helper unexpectedly recovered an unwitnessed startup crash")
                assert call("GET", "touch")["running"]
                print(f"Early Xray crash control: LAN remained down for {time.monotonic() - started:.2f}s "
                      "despite v2rayA running=true", flush=True)
                return

            def recovered_core():
                pid = xray_pid()
                return pid if pid not in (None, former) and client_https() else None

            restored = wait(recovered_core, "fresh helper restored client HTTPS via a new owned Xray process")
            arm()
            print(f"Early Xray crash: fresh helper recovered LAN HTTPS in {time.monotonic() - started:.2f}s", flush=True)

            # A different configuration with a spare port must not hide the live core from the guard.
            alternate = config_dir / "alternate.json"
            contents = json.loads(config.read_text())
            replaced = [entry for entry in contents["inbounds"]
                        if entry.get("protocol") == "socks" and entry.get("port") == socks_port]
            assert replaced, "the laboratory SOCKS listener is missing from the generated configuration"
            unused_port, = loopback_ports(1)
            for entry in replaced:
                entry["port"] = unused_port
            alternate.write_text(json.dumps(contents))
            terminate(helper)
            status_file.unlink()
            recovery_state.unlink(missing_ok=True)
            helper = start_helper(config_file=alternate)
            def live_child_veto():
                state = snapshot()
                return state.get("state") == "stale" and "could not rule out another process" in state.get("message", "")

            wait(live_child_veto, "recovery declined because v2rayA still owns a live child")
            for _ in range(8):
                assert xray_pid() == restored and client_https(), "alternate config disturbed the real working Xray"
                time.sleep(.5)
            print("Early Xray crash: mismatched config and spare SOCKS port did not restart healthy Xray", flush=True)

        def core_unavailable():
            state = snapshot()
            return state.get("state") == "stale" and "Xray" in state.get("message", "")

        def kill_core(pid):
            descriptor = os.pidfd_open(pid)
            try:
                assert owned_xray(pid, daemon.pid, args.xray, config), "crash target escaped the lab"
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            finally:
                os.close(descriptor)

        def kill_helper():
            assert helper.poll() is None, "helper already exited before the test"
            helper.kill()
            assert helper.wait(timeout=5) == -signal.SIGKILL
            status_file.unlink()

        def check_recovery_record():
            state = recovery_state.lstat()
            assert stat.S_ISREG(state.st_mode) and stat.S_IMODE(state.st_mode) == 0o600
            assert state.st_uid == os.geteuid() and state.st_nlink == 1

        def listener_open(port, address="127.0.0.1"):
            try:
                with socket.create_connection((address, port), timeout=.5):
                    return True
            except ConnectionRefusedError:
                return False

        def xray_api_listener():
            generated = json.loads(config.read_text())
            assert "LoggerService" in generated["api"]["services"] and generated["api"]["tag"] == "api-out"
            inbounds = generated["inbounds"]
            tags = {inbound["tag"] for inbound in inbounds}
            assert tags in ({"api-in"}, {"api-in_ipv4"}, {"api-in_ipv4", "api-in_ipv6"})
            port, = {inbound["port"] for inbound in inbounds}
            for inbound in inbounds:
                address = "::1" if inbound["tag"] == "api-in_ipv6" else "127.0.0.1"
                assert inbound["protocol"] == "dokodemo-door" and inbound["listen"] == address
                assert inbound["settings"]["address"] == "127.0.0.1"
                assert listener_open(port, address), "generated core API is not listening"
            assert any(set(rule.get("inboundTag", [])) == tags and rule.get("outboundTag") == "api-out"
                       for rule in generated["routing"]["rules"])
            return port, ", ".join(sorted(tags))

        def owner_restart_case():
            nonlocal daemon, token

            def process_identity(pid):
                fields = (Path("/proc", str(pid)) / "stat").read_text().rsplit(")", 1)[1].split()
                assert fields[0] not in ("X", "Z")
                return int(fields[1]), int(fields[19])

            def listener_inode(pid, port):
                owned = set()
                for fd in (Path("/proc", str(pid)) / "fd").iterdir():
                    with suppress(FileNotFoundError):
                        owned.add(os.readlink(fd))
                address = int.from_bytes(socket.inet_aton("127.0.0.1"), sys.byteorder)
                for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
                    fields = line.split()
                    if (fields[1] == f"{address:08X}:{port:04X}" and fields[3] == "0A" and
                            f"socket:[{fields[9]}]" in owned):
                        return int(fields[9])
                return None

            def sole_api():
                assert call("GET", "ports")["api"]["port"] == 0
                port, tags = xray_api_listener()
                assert tags in ("api-in", "api-in_ipv4"), tags
                return port

            wait(lambda: recovery_state.exists() and snapshot()["state"] == "ok",
                 "helper observed the original owned Xray")
            check_recovery_record()
            former_port = sole_api()
            former_inode = listener_inode(former, former_port)
            former_parent, former_started = process_identity(former)
            assert former_parent == daemon.pid and former_inode
            before_replacement = file_revision(config)
            daemon.kill()
            assert daemon.wait(timeout=5) == -signal.SIGKILL

            def original_orphan_unchanged():
                return (process_identity(former) == (os.getpid(), former_started) and
                        listener_inode(former, former_port) == former_inode)

            wait(original_orphan_unchanged, "old Xray reparented with its original listener")
            daemon = start_daemon()
            assert daemon.pid != former_parent
            wait(lambda: call("GET", "version"), "replacement v2rayA API")
            current = wait(xray_pid, "stock v2rayA started a new child")
            token = call("POST", "login", FIXTURE_LOGIN)["token"]
            replace_private_file(token_file, token)
            last_status = file_revision(status_file)
            wait(lambda: snapshot()["state"] == "ok" and file_revision(status_file) != last_status,
                 "helper read the replacement owner with its current bearer")
            current_port = sole_api()
            assert current != former and current_port != former_port and listener_inode(current, current_port)
            assert call("GET", "touch")["running"] and original_orphan_unchanged()
            assert file_revision(config) != before_replacement

            kill_core(current)
            wait(lambda: xray_pid() is None and not listener_open(current_port), "only the new Xray stopped")
            assert call("GET", "touch")["running"] and original_orphan_unchanged()
            started = time.monotonic()
            wait(core_unavailable, "helper detected the missing current child despite the old Xray", timeout=8)

            def restored_child():
                pid = xray_pid()
                if pid in (None, current, former):
                    return None
                inventory = call("GET", "touch", allow_busy=True)
                return pid if inventory and inventory["running"] else None

            restored = wait(restored_child, "helper restored a third Xray under the current v2rayA owner", timeout=8)
            restored_port = sole_api()
            assert restored_port != former_port and listener_inode(restored, restored_port)
            assert call("GET", "touch")["running"] and original_orphan_unchanged()
            print(f"Owner restart: new Xray API restored in {time.monotonic() - started:.2f}s with "
                  f"original Xray PID {former} and port {former_port} unchanged", flush=True)

            call("DELETE", "v2ray")
            wait(lambda: xray_pid() is None and snapshot()["state"] == "stopped", "helper recognized manual Stop")
            stopped_config = file_revision(config)
            for _ in range(7):
                assert not call("GET", "touch")["running"] and xray_pid() is None
                assert file_revision(config) == stopped_config and original_orphan_unchanged()
                time.sleep(.5)
            print("Owner restart: manual Stop stayed in force with the original orphan still alive", flush=True)

        def no_socks_case():
            initial_listener, tags = xray_api_listener()
            assert call("GET", "ports")["api"]["port"] == xray_api_port
            assert xray_pid() == former and client_https()
            print(f"No SOCKS: generated config has only stock Xray API ({tags}); transparent LAN returns HTTPS 204",
                  flush=True)
            if not args.expect_no_socks_recovery:
                check_recovery_record()
            call("DELETE", "v2ray")
            wait(lambda: not call("GET", "touch")["running"] and xray_pid() is None,
                 "Xray explicitly stopped when using only the core API listener")
            wait(lambda: snapshot().get("state") == "stopped", "helper observes the deliberate stop")
            assert not listener_open(initial_listener)
            stays_down("helper restarted deliberately stopped Xray without SOCKS")
            call("POST", "v2ray", {})
            before_crash = wait(xray_pid, "manual Xray restart without SOCKS")
            wait(client_https, "transparent LAN after a manual start")
            arm()
            crashed_listener, _ = xray_api_listener()
            if xray_api_port:
                assert crashed_listener == xray_api_port

            started = time.monotonic()
            with ExitStack() as fault:
                if not args.expect_no_socks_recovery:
                    helper_fd = os.pidfd_open(helper.pid)
                    fault.callback(os.close, helper_fd)
                    signal.pidfd_send_signal(helper_fd, signal.SIGSTOP)
                    fault.callback(signal.pidfd_send_signal, helper_fd, signal.SIGCONT)
                    wait(lambda: (Path("/proc", str(helper.pid), "stat").read_text().rsplit(")", 1)[1].split()[0]
                                  == "T"), "helper paused before the simulated listener conflict")
                kill_core(before_crash)
                wait(lambda: xray_pid() is None, "crashed Xray without SOCKS")
                assert call("GET", "touch")["running"] and not listener_open(crashed_listener) and client_unavailable()
                if not args.expect_no_socks_recovery:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as other:
                        other.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        other.bind(("127.0.0.1", crashed_listener))
                        other.listen(16)
                        before_config = file_revision(config)
                        before_checkpoint = file_revision(recovery_state)
                        signal.pidfd_send_signal(helper_fd, signal.SIGCONT)
                        if args.fixed_xray_api_port or args.manual_api_reallocation:
                            for _ in range(8):
                                assert xray_pid() is None and client_unavailable(), "occupied API port caused a restart"
                                time.sleep(.5)
                            assert file_revision(config) == before_config, "generated config changed despite no restart"
                            assert file_revision(recovery_state) == before_checkpoint, "watchdog reserved a start"
                            print(f"No SOCKS: occupied API suppressed the watchdog for "
                                  f"{time.monotonic() - started:.2f}s", flush=True)
                        if not args.fixed_xray_api_port:
                            started = time.monotonic()
                            if args.manual_api_reallocation:
                                call("POST", "v2ray", {})
                            else:
                                wait(core_unavailable, "helper detects absence despite the old API port listener")
                            wait(lambda: xray_pid() not in (None, before_crash) and client_https(),
                                 "new Xray restored LAN while the old API port was still occupied")
                            arm()
                            new_listener, _ = xray_api_listener()
                            assert new_listener != crashed_listener
                            assert other.getsockname()[1] == crashed_listener and listener_open(crashed_listener)
                            assert call("GET", "ports")["api"]["port"] == 0
                            check_recovery_record()
                            operation = "stock manual POST" if args.manual_api_reallocation else "automatic recovery"
                            print(f"No SOCKS: {operation} moved Xray API to a new port and restored LAN HTTPS "
                                  f"in {time.monotonic() - started:.2f}s while the old port remained occupied",
                                  flush=True)
                            return
                    started = time.monotonic()
            if args.expect_no_socks_recovery:
                stays_down("old helper recovered Xray without a SOCKS listener")
                assert call("GET", "touch")["running"] and snapshot().get("state") == "ok" and monitor_https("ok")
                print(f"No SOCKS control: LAN stayed down for {time.monotonic() - started:.2f}s while independent "
                      "HTTPS remained green and v2rayA reported running=true", flush=True)
                return

            wait(core_unavailable, "helper published Xray failure without SOCKS")
            wait(lambda: xray_pid() not in (None, before_crash) and client_https(),
                 "new owned Xray restored LAN HTTPS without SOCKS")
            arm()
            assert xray_api_listener()[0] == crashed_listener
            assert call("GET", "ports")["api"]["port"] == xray_api_port
            check_recovery_record()
            print(f"No SOCKS: fixed API recovered on the same port {time.monotonic() - started:.2f}s "
                  "after the old occupant released it", flush=True)

        def verify_inbound_port():
            case = inbound_port_case
            socks_case = case == "socks-udp" or case in SOCKS_UDP6_CASES
            redirect_inbound = stock_redirect and case != "redirect-http-control"
            lan_address = case in ("http-lan-control", "http-lan-sharing", *REDIRECT_CASES)
            fixed_port = socks_port if socks_case else http_port
            if case == "fixed-api":
                fixed_port = xray_api_port
            elif redirect_inbound:
                fixed_port = TRANSPARENT_PORT
            udp = socks_case or case in ("http-udp-control", "redirect-udp", "redirect-udp6")
            ipv6 = case == "http-v6" or case in (*SOCKS_UDP6_CASES, *REDIRECT_IPV6_CASES)
            holder_address = "::1" if ipv6 else "127.0.0.1"
            if lan_address:
                holder_address = REDIRECT_ROUTER_IPV6 if ipv6 else ROUTER
            should_wait = case not in ("http-udp-control", "http-lan-control", "socks-udp6-disabled",
                                       "redirect-http-control")
            generated = json.loads(config.read_text())["inbounds"]

            def owned_udp6_socket(pid):
                owned = set()
                for fd in Path("/proc", str(pid), "fd").iterdir():
                    with suppress(FileNotFoundError):
                        owned.add(os.readlink(fd))
                for line in Path("/proc/net/udp6").read_text().splitlines()[1:]:
                    fields = line.split()
                    address, port = fields[1].split(":", 1)
                    if int(port, 16) == fixed_port and f"socket:[{fields[9]}]" in owned:
                        assert fields[3] == "07", "expected a bound and unconnected IPv6 UDP socket"
                        if case == "socks-udp6-shared":
                            assert address == "0" * 32, "expected a wildcard IPv6 UDP socket"
                        return True
                return False

            if case == "fixed-api":
                assert call("GET", "ports")["api"]["port"] == fixed_port
                assert any(inbound["port"] == fixed_port and inbound["tag"] in ("api-in", "api-in_ipv4")
                           for inbound in generated)
            elif not redirect_inbound:
                protocol = "socks" if socks_case else "http"
                assert any(inbound["port"] == fixed_port and inbound["protocol"] == protocol
                           for inbound in generated)
            if lan_address:
                sharing = case == "http-lan-sharing"
                assert call("GET", "setting")["setting"]["portSharing"] is sharing
                listen = "0.0.0.0" if sharing or redirect_inbound else "127.0.0.1"
                assert any(inbound["port"] == fixed_port and inbound["listen"] == listen
                           for inbound in generated)
            if stock_redirect:
                transparent, = [inbound for inbound in generated if inbound["tag"] == "transparent"]
                assert transparent["listen"] == "0.0.0.0" and transparent["port"] == TRANSPARENT_PORT
                assert transparent["settings"]["network"] == "tcp,udp"
                assert transparent["streamSettings"]["sockopt"]["tproxy"] == "redirect"
                if ipv6:
                    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as probe:
                        probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        try:
                            probe.bind((holder_address, fixed_port))
                        except OSError as error:
                            assert error.errno == errno.EADDRINUSE
                        else:
                            raise AssertionError("stock Xray did not occupy the IPv6 LAN binding")
            if case in SOCKS_UDP6_CASES:
                active_udp6 = case != "socks-udp6-disabled"
                mirrors = [inbound for inbound in generated if inbound["tag"] == "socks_ipv6"]
                if case == "socks-udp6":
                    mirror, = mirrors
                    assert mirror["listen"] == "::1" and mirror["port"] == fixed_port and mirror["settings"]["udp"] is True
                else:
                    assert not mirrors
                if case == "socks-udp6-shared":
                    assert call("GET", "setting")["setting"]["portSharing"] is True
                    shared, = [inbound for inbound in generated if inbound["tag"] == "socks"]
                    assert shared["listen"] == "0.0.0.0" and shared["port"] == fixed_port and shared["settings"]["udp"] is True
                assert owned_udp6_socket(former) == active_udp6
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
                    probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    try:
                        probe.bind((holder_address, fixed_port))
                    except OSError as error:
                        assert active_udp6 and error.errno == errno.EADDRINUSE
                    else:
                        assert not active_udp6, "an exclusive socket could bind over the running UDP6 listener"
            assert xray_pid() == former and client_https()
            check_recovery_record()
            previous_config = file_revision(config)
            previous_checkpoint = file_revision(recovery_state)

            def restored():
                if xray_pid() in (None, former):
                    return False
                current = call("GET", "touch", allow_busy=True)
                return bool(current and current["running"] and client_https())

            with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET,
                               socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as holder:
                if ipv6:
                    holder.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                if not udp:
                    holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                helper_fd = os.pidfd_open(helper.pid)
                try:
                    signal.pidfd_send_signal(helper_fd, signal.SIGSTOP)
                    wait(lambda: Path("/proc", str(helper.pid), "stat").read_text()
                         .rsplit(")", 1)[1].split()[0] == "T", "helper paused before the listener conflict")
                    kill_core(former)
                    wait(lambda: xray_pid() is None and socks_refused() and client_unavailable(),
                         "Xray crashed, SOCKS TCP was free and client HTTPS was down")
                    assert call("GET", "touch")["running"], "stock v2rayA lost the intended running state"
                    holder.bind((holder_address, fixed_port))
                    if not udp:
                        holder.listen(16)
                finally:
                    signal.pidfd_send_signal(helper_fd, signal.SIGCONT)
                    os.close(helper_fd)

                started = time.monotonic()
                if not should_wait:
                    wait(restored, "LAN recovered while the unrelated socket stayed bound")
                    assert holder.getsockname()[:2] == (holder_address, fixed_port)
                    if case == "socks-udp6-disabled":
                        assert not owned_udp6_socket(xray_pid())
                    print(f"Inbound {case}: unrelated socket remained bound while LAN HTTPS recovered "
                          f"in {time.monotonic() - started:.2f}s", flush=True)
                    return

                wait(core_unavailable, "helper published the Xray outage")
                for _ in range(8):
                    current = call("GET", "touch", allow_busy=True)
                    assert current and current["running"], "helper sent a premature start request"
                    assert xray_pid() is None and client_unavailable(), "helper started Xray while the port was held"
                    assert file_revision(config) == previous_config, "helper caused the stock config to be rewritten"
                    assert file_revision(recovery_state) == previous_checkpoint, "helper reserved a start against the conflict"
                    time.sleep(.5)
                assert holder.getsockname()[:2] == (holder_address, fixed_port)
                print(f"Inbound {case}: waited {time.monotonic() - started:.2f}s with stock running intent "
                      "and no start reservation", flush=True)

            started = time.monotonic()
            wait(restored, "real LAN HTTPS 204 recovered automatically after the foreign socket closed")
            arm()
            check_recovery_record()
            if case == "fixed-api":
                assert call("GET", "ports")["api"]["port"] == fixed_port
                assert listener_open(fixed_port)
            if case in ("socks-udp6", "socks-udp6-shared"):
                assert owned_udp6_socket(xray_pid())
            print(f"Inbound {case}: automatic LAN HTTPS recovery in {time.monotonic() - started:.2f}s "
                  "after releasing the conflicting socket", flush=True)

        def start_core_and_arm():
            assert not call("GET", "touch")["running"]
            call("POST", "v2ray", {})
            pid = wait(xray_pid, "manually started Xray after the stopped case")
            wait(client_https, "client HTTPS 204 after a manual start")
            arm()
            check_recovery_record()
            return pid

        def wait_outage():
            wait(lambda: xray_pid() is None, "Xray child terminated while the helper is down")
            assert call("GET", "touch")["running"], "the upstream API did not retain running intent"
            assert socks_refused() and client_unavailable(), "Xray ingress or client unexpectedly remained up"

        def verify_single_state_writer():
            revision = file_revision(recovery_state)
            second_status = work / "second-status.json"
            second_log = work / "second-helper.log"
            with second_log.open("w") as log:
                second = start_helper(second_status, log)
                try:
                    wait(lambda: json.loads(second_status.read_text()).get("state") == "ok",
                         "working monitor alongside the owner of the recovery state")
                    assert second.poll() is None
                    assert "state file is unavailable" in second_log.read_text()
                    assert file_revision(recovery_state) == revision, "second helper rewrote shared state"
                finally:
                    terminate(second)
            print("Helper restart: a concurrent helper monitored without taking over the recovery state")

        def restart_case():
            nonlocal helper
            active_core = former
            if use_recovery_state:
                check_recovery_record()
                verify_single_state_writer()
                kill_helper()
                call("DELETE", "v2ray")
                wait(lambda: not call("GET", "touch")["running"] and xray_pid() is None,
                     "deliberate Xray stop while the helper is down")
                helper = start_helper()
                wait(lambda: snapshot().get("state") == "stopped", "deliberate stop after helper restart")
                stays_down("restarted helper undid the administrator's stop")
                active_core = start_core_and_arm()
                print("Helper restart: an administrator's stop while the helper was down was respected")

                kill_helper()
                former_state = work / "symlink-target.state"
                recovery_state.rename(former_state)
                former_revision = file_revision(former_state)
                recovery_state.symlink_to(former_state)
                kill_core(active_core)
                wait_outage()
                helper = start_helper()
                wait(core_unavailable, "published Xray failure with an invalid recovery state path")
                stays_down("a symlink supplied recovery state")
                assert recovery_state.is_symlink(), "helper replaced the symlink supplied as state"
                assert file_revision(former_state) == former_revision, "helper modified the symlink target"
                kill_helper()
                recovery_state.unlink()
                call("DELETE", "v2ray")
                helper = start_helper()
                wait(lambda: snapshot().get("state") == "stopped", "published stop after invalid state")
                active_core = start_core_and_arm()
                print("Helper restart: a symlink to the real recovery state was refused")

            kill_helper()
            kill_core(active_core)
            started = time.monotonic()
            wait_outage()
            helper = start_helper()
            wait(core_unavailable, "published Xray failure after the helper restarted")
            if not use_recovery_state:
                stays_down("the no-state control unexpectedly recovered Xray")
                print("Helper restart control: Xray and client HTTPS stayed down without saved recovery state")
                return
            def recovered_core():
                pid = xray_pid()
                return pid if pid not in (None, active_core) and client_https() else None

            active_core = wait(recovered_core, "new Xray process and client HTTPS 204 after both processes were killed")
            arm()
            client_kind = "transparent LAN" if transparent_lan else "SOCKS"
            print(f"Helper restart: {client_kind} HTTPS 204 returned in {time.monotonic() - started:.2f}s "
                  "with the same v2rayA process after both helper and Xray were killed")

            kill_helper()
            kill_core(active_core)
            wait_outage()
            helper = start_helper()
            wait(lambda: core_unavailable() and "before another start attempt" in snapshot().get("message", ""),
                 "a replacement helper observing the saved 60-second start cooldown")
            stays_down("a helper restart bypassed the Xray start cooldown")
            assert call("GET", "touch")["running"] and time.monotonic() - started < 60
            print("Helper restart: another crash during the cooldown did not reopen SOCKS or restore HTTPS")
            wait(recovered_core, "client HTTPS 204 after the recovery cooldown", timeout=75)
            elapsed = time.monotonic() - started
            assert elapsed >= 60, "the second recovery finished before the saved cooldown"
            print(f"Helper restart: {client_kind} HTTPS 204 returned after the cooldown ({elapsed:.2f}s since first crash)")

        def authorization_stale():
            state = snapshot()
            return state.get("state") == "stale" and "authoriz" in state.get("message", "").lower()

        def verify_private_token():
            mode = token_file.stat().st_mode & 0o777
            assert mode == 0o600, "the token is readable outside the helper account"
            renewed = token_file.read_text().strip()
            assert renewed not in ("", REJECTED_TOKEN), "token was not renewed"
            status_and_logs = status_file.read_text() + (work / "helper.log").read_text()
            assert not any(secret in status_and_logs for secret in (FIXTURE_LOGIN["password"], renewed, token)), (
                "login credentials or token leaked to the helper's status or logs"
            )

        def local_management_case():
            nonlocal former, helper
            name = f"Assigned {assigned_management.upper()} management" if assigned_management else "IPv6 management"
            baseline = args.expect_no_ipv6_recovery or args.expect_no_assigned_recovery
            assert listener_open(management_port, management_host) and not listener_open(management_port)
            if assigned_management and management_ipv6:
                assert not listener_open(management_port, "::1")
            watched, tags = xray_api_listener()
            assert watched == xray_api_port and watched != management_port
            assert xray_pid() == former and client_https()
            print(f"{name}: v2rayA listens on {management_host}; separate Xray API ({tags}); LAN HTTPS 204",
                  flush=True)
            if not baseline:
                check_recovery_record()
            elif assigned_management:
                diagnostics = (work / "helper.log").read_text()
                assert "Xray recovery disabled" in diagnostics and "login renewal disabled" in diagnostics
                assert not recovery_state.exists()

            if assigned_management and not baseline:
                call("DELETE", "v2ray")
                wait(lambda: xray_pid() is None and not call("GET", "touch")["running"] and
                     snapshot().get("state") == "stopped", "administrator stopped Xray before any recovery attempt")
                stopped_config = file_revision(config)
                stays_down("helper undid the administrator's Stop")
                assert file_revision(config) == stopped_config and not call("GET", "touch")["running"]
                call("POST", "v2ray", {})
                former = wait(xray_pid, "administrator restored Xray after the Stop control")
                wait(client_https, "real LAN HTTPS returned after the administrator's start")
                arm()
                assert xray_api_listener()[0] == watched
                print(f"{name}: explicit Stop remained in force until the administrator started Xray", flush=True)

            try:
                call("GET", "touch", bearer=REJECTED_TOKEN)
            except HTTPError as error:
                assert error.code == 401
            else:
                raise AssertionError("real v2rayA accepted the rejected fixture bearer")

            kill_helper()
            replace_private_file(token_file, REJECTED_TOKEN)
            kill_core(former)
            wait(lambda: xray_pid() is None and not listener_open(watched) and client_unavailable(),
                 "Xray process and listener disappeared and the client was down while the helper was absent")
            assert call("GET", "touch")["running"]
            if args.assigned_management_late:
                family_flag = "-6" if management_ipv6 else "-4"
                prefix = f"{management_host}/{128 if management_ipv6 else 24}"
                device = ["dev", "lab-router"]
                subprocess.run(["ip", family_flag, "addr", "del", prefix, *device], check=True, timeout=5)
            started = time.monotonic()
            helper = start_helper()
            if args.assigned_management_late:
                wait(lambda: snapshot().get("state") == "stale", "helper started before its management address existed")
                assert token_file.read_text() == REJECTED_TOKEN and xray_pid() is None
                assert not listener_open(watched), "helper started Xray before the management address was assigned"
                options = ["nodad"] if management_ipv6 else []
                subprocess.run(["ip", family_flag, "addr", "add", prefix, *device, *options], check=True, timeout=5)
                assert call("GET", "touch")["running"], "v2rayA did not retain running intent through address assignment"
                print(f"{name}: reattached the management address after the helper published a stale snapshot",
                      flush=True)
            if baseline:
                wait(authorization_stale, "old helper reports rejected authorization over the management endpoint")
                stays_down("old helper restored Xray via the management URL")
                assert token_file.read_text() == REJECTED_TOKEN and authorization_stale()
                print(f"{name} control: bearer remained rejected and LAN stayed down for "
                      f"{time.monotonic() - started:.2f}s", flush=True)
                return

            def renewed_token():
                value = token_file.read_text().strip()
                return value if value != REJECTED_TOKEN else None

            renewed = wait(renewed_token, "helper renewed the rejected bearer through the stock v2rayA endpoint")
            assert call("GET", "touch", bearer=renewed)["running"]
            verify_private_token()
            wait(lambda: xray_pid() not in (None, former) and client_https(),
                 "same v2rayA instance started a new Xray and recovered real LAN HTTPS")
            arm()
            assert xray_api_listener()[0] == watched
            print(f"{name}: trusted bearer renewed and LAN restored in {time.monotonic() - started:.2f}s "
                  "after restarting the helper and losing Xray", flush=True)
            if assigned_management:
                verify_login_peer(args, ipv6=management_ipv6, host=management_host)

        if late_wan:
            late_wan_case()
            return

        if early_crash:
            assert not recovery_state.exists()
            kill_core(former)
            wait(lambda: xray_pid() is None, "Xray crashed before helper startup")
            assert call("GET", "touch")["running"] and socks_refused() and client_unavailable()
            started = time.monotonic()
            helper = start_helper()
            early_crash_case(started)
            return

        helper = start_helper()
        if owner_restart_dynamic:
            owner_restart_case()
            return
        if invalid_file:
            wait(authorization_stale, "stale status with an insecure login file")
            for _ in range(6):
                assert authorization_stale() and token_file.read_text() == REJECTED_TOKEN
                time.sleep(.5)
            assert xray_pid() == former and client_https(), "insecure credentials disturbed working Xray"
            print(f"Automatic login: credentials file with {auto_login} attributes was refused")
            return

        if wrong_login:
            def login_rejections():
                return (work / "v2raya.log").read_text().count("wrong username or password")

            wait(login_rejections, "stock v2rayA rejecting the wrong credentials")
            wait(authorization_stale, "stale status after login rejection")
            for _ in range(6):
                assert login_rejections() == 1, "wrong credentials were retried without a cool-down"
                assert token_file.read_text() == REJECTED_TOKEN, "a rejected login changed the token"
                time.sleep(.5)
            assert xray_pid() == former and client_https(), "wrong credentials disturbed working Xray"
            print("Automatic login: one rejected login across multiple monitor cycles, working Xray unaffected")
            return

        if stock_tproxy:
            tproxy_ingress_case()
            return
        if ingress_loss:
            if args.ingress_stop_race:
                stock_stop_race_case()
            else:
                ingress_loss_case()
            return
        arm()
        if local_management:
            local_management_case()
            return
        if inbound_port_case:
            verify_inbound_port()
            return
        if without_socks:
            no_socks_case()
            return
        if cold_start:
            cold_start_case()
            return
        if server_failover:
            if slow_reserve_failover:
                slow_reserve_case()
            else:
                failover_case()
            return
        if multi_outbound_failover:
            multiple.exercise(call, helper_rpc, policy_file, history_file, client, snapshot, xray_pid, wait)
            return
        if helper_restart:
            restart_case()
            return
        if auto_login == "bootstrap":
            verify_private_token()
            assert xray_pid() == former and client_https(), "initial login disturbed working Xray"
            print("Automatic login: created a private token and kept working Xray running")
            return

        if recover and not check_authorization and not auto_login:
            node.hold.set()
            try:
                assert not client_https(), "held control website should not respond"
                wait(lambda: monitor_https("timeout") or monitor_https("error"), "helper HTTPS failure")
                assert xray_pid() == former, "site failure restarted healthy Xray"
            finally:
                node.hold.clear()
                node.release.set()
            wait(client_https, "control website recovery while Xray remains up")
            # Check intentional stop before a recovery cooldown could mask a bug.
            call("DELETE", "v2ray")
            wait(lambda: not call("GET", "touch")["running"] and xray_pid() is None, "intentional Xray stop")
            wait(lambda: snapshot().get("state") == "stopped", "published intentional stop")
            stays_down("manual stop was undone")
            call("POST", "v2ray", {})
            former = wait(xray_pid, "manually started Xray")
            wait(client_https, "manual startup of laboratory Xray")
            arm()

        if check_authorization:
            replace_private_file(token_file, REJECTED_TOKEN)
            wait(authorization_stale, "rejection of the helper's token")
            assert xray_pid() == former and client_https(), "authorization error disturbed the running Xray"

        if initial_token:
            # A valid manually supplied token should never trigger a login or rewrite.
            for _ in range(6):
                assert file_revision(token_file) == initial_token and not authorization_stale()
                time.sleep(.5)

        started = time.monotonic()
        with ExitStack() as fault:
            if auto_login == "recover":
                # Pause only this test helper so expiry and the crash are both visible
                # at its next iteration, then always resume it even on assertion failure.
                helper_fd = os.pidfd_open(helper.pid)
                fault.callback(os.close, helper_fd)
                signal.pidfd_send_signal(helper_fd, signal.SIGSTOP)
                fault.callback(signal.pidfd_send_signal, helper_fd, signal.SIGCONT)
                wait(lambda: (Path("/proc", str(helper.pid), "stat").read_text().rsplit(")", 1)[1].split()[0]
                              == "T"), "paused laboratory helper")
                replace_private_file(token_file, REJECTED_TOKEN)
            kill_core(former)
            if auto_login == "recover":
                wait(lambda: xray_pid() is None, "crashed laboratory Xray before credential renewal")
                assert token_file.read_text() == REJECTED_TOKEN and not client_https()
            if transparent_lan:
                wait(lambda: xray_pid() is None, "crashed laboratory Xray before checking LAN traffic")
                assert not client.https(.25), "LAN HTTPS remained available with the lab Xray stopped"

        if not recover:
            wait(lambda: xray_pid() is None, "default-off Xray crash")
            stays_down("default mode unexpectedly recovered Xray")
            assert call("GET", "touch")["running"], "upstream no longer reproduces stale running state"
            print("Default-off: stale upstream running state, Xray unavailable, helper stayed active")
            return

        if check_authorization:
            wait(lambda: xray_pid() is None, "Xray crash with rejected authorization")
            stays_down("Xray recovered while the helper's authorization was rejected")
            assert authorization_stale() and call("GET", "touch")["running"]
            print("Rejected authorization: helper remained stale and Xray stayed down after the crash")
            started = time.monotonic()
            replace_private_file(token_file, token)

        try:
            wait(core_unavailable, "published Xray failure instead of an independent HTTPS success")
        except AssertionError as error:
            state = snapshot()
            raise AssertionError(f"{error}; last state={state.get('state')}, message={state.get('message')}, "
                                 f"API running={call('GET', 'touch')['running']}, "
                                 f"Xray PID={xray_pid()}, client HTTPS={client_https()}") from error
        wait(lambda: xray_pid() not in (None, former) and client_https(),
             "automatic recovery of real Xray HTTPS traffic")
        wait(lambda: snapshot().get("state") == "ok" and monitor_https("ok"), "healthy published state")
        elapsed = time.monotonic() - started
        if transparent_lan:
            print(f"Transparent LAN: HTTPS 204 without proxy settings returned in {elapsed:.2f}s "
                  "after Xray crash")
            print("Transparent LAN: direct path control failed, nft counter increased for HTTPS, "
                  "website timeout and deliberate stop did not trigger recovery")
        elif auto_login == "recover":
            verify_private_token()
            print(f"Automatic login: replaced rejected token and restored Xray HTTPS 204 in {elapsed:.2f}s")
        elif check_authorization:
            print(f"Restored authorization: Xray HTTPS 204 recovered without helper restart in {elapsed:.2f}s")
        else:
            print(f"Enabled: Xray HTTPS 204 recovered without helper restart in {elapsed:.2f}s")
            print("Enabled: control-site timeout and intentional Xray stop did not trigger recovery")


def verify_login_peer(args, same_login_and_token=False, *, ipv6=False, host=None):
    class Impostor(BaseHTTPRequestHandler):
        requests = []
        attempted_login = False
        sent_authorization = False

        def log_message(self, *_):
            pass

        def respond(self, status, response):
            body = json.dumps(response).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.requests.append(self.path)
            if "Authorization" in self.headers:
                type(self).sent_authorization = True
            if self.path == "/api/version":
                self.respond(200, {"code": "SUCCESS", "data": {"version": "2.2.7.4", "variant": "Xray"}})
            else:
                self.respond(401, {"code": "UNAUTHORIZED"})

        def do_POST(self):
            type(self).attempted_login = True
            self.respond(403, {"code": "UNAUTHORIZED"})

    class ObservedHTTPServer(ThreadingHTTPServer):
        accepted = 0

        def get_request(self):
            accepted = super().get_request()
            self.accepted += 1
            return accepted

    class IPv6HTTPServer(ObservedHTTPServer):
        address_family = socket.AF_INET6

    with ExitStack() as stack:
        work = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="v2raya-foreign-listener-")))
        factory = IPv6HTTPServer if ipv6 else ObservedHTTPServer
        if host is None:
            host = "::1" if ipv6 else "127.0.0.1"
        server = stack.enter_context(factory((host, 0), Impostor))
        Thread(target=server.serve_forever, daemon=True).start()
        stack.callback(server.shutdown)
        login_file, token_file, snapshot = [work / name for name in ("login.json", "token", "status.json")]
        core_config, recovery_state = [work / name for name in ("config.json", "recovery.state")]
        login = json.dumps(FIXTURE_LOGIN)
        replace_private_file(login_file, login)
        if same_login_and_token:
            token_file = login_file
        else:
            replace_private_file(token_file, REJECTED_TOKEN)
        socks_port = next(port for port in loopback_ports(2) if port != server.server_port)
        replace_private_file(core_config, json.dumps({"inbounds": [
            {"tag": "socks", "protocol": "socks", "listen": "127.0.0.1", "port": socks_port}
        ]}))
        original_config = file_revision(core_config)
        address = f"[{host}]" if ipv6 else host
        helper = subprocess.Popen([args.helper, "--api", f"http://{address}:{server.server_port}",
                                   "--login-file", login_file, "--token-file", token_file,
                                   "--recover-xray", "--xray-config", core_config, "--recovery-state", recovery_state,
                                   "--output", snapshot, "--interval", "1", "--timeout", "2"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(terminate, helper)
        wait(lambda: json.loads(snapshot.read_text()).get("state") == "stale",
             "stale status against an untrusted listener")
        if same_login_and_token:
            # A credential document cannot be used as a bearer or trigger login.
            time.sleep(3.0)
            assert server.accepted == 0, "the helper attempted to connect with the credentials file as its token"
        else:
            wait(lambda: server.accepted >= 3, "multiple guarded TCP connections to an untrusted listener")
        assert not Impostor.requests, "the unrelated local listener received an HTTP request"
        assert not Impostor.sent_authorization, "the unrelated local listener received an authorization header"
        assert not Impostor.attempted_login, "the unrelated local listener received a POST"
        assert login_file.read_text() == login, "the original credentials changed"
        assert not recovery_state.exists(), "helper reserved a restart based on an unrelated local listener"
        assert file_revision(core_config) == original_config
        if same_login_and_token:
            result = "Automatic login: identical credentials and token paths were refused"
        else:
            assert token_file.read_text() == REJECTED_TOKEN, "rejected listener rewrote the token"
            family = "IPv6" if ipv6 else "IPv4"
            result = f"Automatic login: an unrelated local {family} listener accepted TCP without an HTTP request"
        assert helper.poll() is None, "authorization failure stopped the helper"
        print(result)


def run_management_lab(args):
    if os.geteuid() != 0:
        raise RuntimeError("run the private login lab from an outer root account for the mapped private user namespace")
    with tempfile.TemporaryDirectory(prefix="v2raya-ipv6-lab-assets-") as work:
        stage = Path(work)
        for name, source in (("v2raya", args.v2raya), ("xray", args.xray)):
            target = stage / name
            shutil.copyfile(source, target)
            target.chmod(0o500)
        for name in ("geoip.dat", "geosite.dat"):
            shutil.copyfile(args.assets / name, stage / name)
        arguments = ["--helper", str(args.helper), "--v2raya", str(stage / "v2raya"),
                     "--xray", str(stage / "xray"), "--assets", work]
        if args.assigned_management:
            arguments.extend(["--assigned-management", args.assigned_management])
        else:
            arguments.append("--ipv6-management")
        if args.expect_no_ipv6_recovery:
            arguments.append("--expect-no-ipv6-recovery")
        if args.expect_no_assigned_recovery:
            arguments.append("--expect-no-assigned-recovery")
        if args.assigned_management_late:
            arguments.append("--assigned-management-late")
        return run_isolated(Path(__file__).resolve(), arguments, allow_mapped_root=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("helper", "v2raya", "xray", "assets"):
        parser.add_argument("--" + name, type=lambda path: Path(path).resolve(strict=True), required=True)
    # The version lab runs each v2rayA build; --xray is then the core that build runs.
    parser.add_argument("--expect-version", default="2.2.7.4")
    parser.add_argument("--expect-variant", default="Xray")
    parser.add_argument("--expect-core", default="Xray 25.10.15 ", help="start of the core's version line")
    parser.add_argument("--allow-unverified", metavar="VERSION",
                        help="pass the helper's opt-in for this exact v2rayA version")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--baseline-only", action="store_true")
    modes.add_argument("--auto-login-only", action="store_true")
    modes.add_argument("--transparent-lan", action="store_true",
                       help="check client HTTPS via an isolated transparent IPv4 route")
    modes.add_argument("--server-failover", action="store_true",
                       help="exercise the real server switch and transparent LAN client connectivity")
    modes.add_argument("--slow-reserve-failover", action="store_true",
                       help="verify stock failover after a slow reserve and an active timeout near the freshness limit")
    modes.add_argument("--late-wan", action="store_true",
                       help="start with both upstreams blocked and restore LAN without restarting Xray")
    modes.add_argument("--ingress-loss", choices=("iptables", "nftables"),
                       help="remove the stock IPv4 REDIRECT ingress attachment while leaving Xray and egress alive")
    modes.add_argument("--tproxy-ingress-loss", action="store_true",
                       help="check independent loss of the stock iptables-nft hook, policy, and local route")
    modes.add_argument("--multi-outbound-failover", action="store_true",
                       help="check isolated LAN recovery and the shared pause across three v2rayA outbounds")
    modes.add_argument("--cold-start", action="store_true",
                       help="check v2rayA startup intent after an isolated Xray port conflict and a deliberate stop")
    modes.add_argument("--early-xray-crash", action="store_true",
                       help="crash real Xray before the isolated helper has observed it working")
    modes.add_argument("--without-socks", action="store_true",
                       help="test recovery using only the stock Xray API listener and transparent LAN")
    modes.add_argument("--ipv6-management", action="store_true",
                       help="recover over local IPv6 management and verify the peer before login")
    modes.add_argument("--assigned-management", choices=ASSIGNED_MANAGEMENT,
                       help="recover through a numeric IPv4 or IPv6 management address assigned to the lab router")
    modes.add_argument("--owner-restart-dynamic", action="store_true",
                       help="recover the current Xray with a previous owner's disjoint API listener still live")
    modes.add_argument("--inbound-port-case", choices=INBOUND_PORT_CASES,
                       help="verify a stock inbound collision or a nonconflicting socket with transparent LAN")
    parser.add_argument("--helper-restart", action="store_true",
                        help="kill and restart the helper around an isolated Xray outage")
    parser.add_argument("--without-recovery-state", action="store_true",
                        help="run the helper restart case with no saved recovery state")
    parser.add_argument("--expect-no-early-recovery", action="store_true",
                        help="verify the early Xray crash remains down on older helper versions")
    parser.add_argument("--expect-no-socks-recovery", action="store_true",
                        help="verify Xray without a SOCKS listener remains down on older helper versions")
    api_modes = parser.add_mutually_exclusive_group()
    api_modes.add_argument("--manual-api-reallocation", action="store_true",
                           help="prove that manual start can move an occupied automatic Xray API port")
    api_modes.add_argument("--fixed-xray-api-port", action="store_true",
                           help="verify that a fixed Xray API port blocks restoration until it is released")
    parser.add_argument("--expect-no-ipv6-recovery", action="store_true",
                        help="verify IPv6 management recovery and login are absent on older versions")
    parser.add_argument("--expect-no-assigned-recovery", action="store_true",
                        help="verify assigned-address management recovery and login are absent on older versions")
    parser.add_argument("--assigned-management-late", action="store_true",
                        help="restart the helper before the assigned management address is available")
    parser.add_argument("--expect-no-ingress-status", action="store_true",
                        help="verify that the previous helper cannot report a missing IPv4 REDIRECT attachment")
    parser.add_argument("--expect-no-tproxy-status", action="store_true",
                        help="verify that the previous helper omitted stock TPROXY ingress status")
    parser.add_argument("--allow-unavailable-node-probe", action="store_true",
                        help="allow a fresh https_mark_error under QEMU while still checking real LAN HTTPS")
    parser.add_argument("--ingress-dual-family", action="store_true",
                        help="verify attachment status for the stock dual-family nftables jump")
    parser.add_argument("--restore-ingress", action="store_true",
                        help="verify optional automatic restoration of the exact stock nftables attachment")
    parser.add_argument("--ingress-table-loss", action="store_true",
                        help="remove the whole stock nftables table instead of just the ingress jump")
    parser.add_argument("--ingress-stop-race", choices=STOP_RACE_CASES,
                        help="exercise a paused stock Stop with late REDIRECT table or TPROXY route publication")
    parser.add_argument("--expect-no-table-loss-status", action="store_true",
                        help="verify that the previous helper omitted ingress status after whole-table loss")
    parser.add_argument("--restart-ingress-helper", action="store_true",
                        help="remove the nftables attachment while the helper is stopped, then restart it")
    redirect_states = parser.add_mutually_exclusive_group()
    redirect_states.add_argument("--without-redirect-state", action="store_true",
                                 help="delete the attachment witness before restarting the helper")
    redirect_states.add_argument("--stale-redirect-state", action="store_true",
                                 help="keep the witness but replace the generated config inode before restarting")
    parser.add_argument("--namespace-origin", type=int, nargs=len(NAMESPACES), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.helper_restart and (args.baseline_only or args.auto_login_only or args.server_failover or
                                args.slow_reserve_failover or args.late_wan or args.ingress_loss or args.tproxy_ingress_loss or
                                args.multi_outbound_failover or
                                args.cold_start or args.early_xray_crash or args.without_socks or
                                args.ipv6_management or args.assigned_management or args.inbound_port_case or
                                args.owner_restart_dynamic):
        parser.error("--helper-restart may be combined only with --transparent-lan")
    if args.without_recovery_state and not args.helper_restart:
        parser.error("--without-recovery-state requires --helper-restart")
    if args.expect_no_early_recovery and not args.early_xray_crash:
        parser.error("--expect-no-early-recovery requires --early-xray-crash")
    if args.expect_no_socks_recovery and not args.without_socks:
        parser.error("--expect-no-socks-recovery requires --without-socks")
    if (args.manual_api_reallocation or args.fixed_xray_api_port) and (
            not args.without_socks or args.expect_no_socks_recovery):
        parser.error("Xray API port variants require --without-socks and a helper supporting that configuration")
    if args.expect_no_ipv6_recovery and not args.ipv6_management:
        parser.error("--expect-no-ipv6-recovery requires --ipv6-management")
    if args.expect_no_assigned_recovery and not args.assigned_management:
        parser.error("--expect-no-assigned-recovery requires --assigned-management")
    if args.assigned_management_late and (not args.assigned_management or args.expect_no_assigned_recovery):
        parser.error("--assigned-management-late requires --assigned-management on a helper supporting it")
    if args.expect_no_ingress_status and not args.ingress_loss:
        parser.error("--expect-no-ingress-status requires --ingress-loss")
    if args.expect_no_tproxy_status and not args.tproxy_ingress_loss:
        parser.error("--expect-no-tproxy-status requires --tproxy-ingress-loss")
    if args.allow_unavailable_node_probe and not (args.ingress_loss or args.tproxy_ingress_loss):
        parser.error("--allow-unavailable-node-probe requires --ingress-loss or --tproxy-ingress-loss")
    if args.ingress_dual_family and not (args.ingress_loss == "nftables" or args.tproxy_ingress_loss):
        parser.error("--ingress-dual-family requires --ingress-loss nftables or --tproxy-ingress-loss")
    if args.restore_ingress and (args.ingress_loss != "nftables" or args.expect_no_ingress_status):
        parser.error("--restore-ingress requires --ingress-loss nftables on a helper supporting it")
    if args.restart_ingress_helper and not args.restore_ingress:
        parser.error("--restart-ingress-helper requires --restore-ingress")
    if args.ingress_table_loss and (args.ingress_loss != "nftables" or
                                    args.restart_ingress_helper or args.expect_no_ingress_status):
        parser.error("--ingress-table-loss requires --ingress-loss nftables without other baseline or restart modes")
    if args.expect_no_table_loss_status and not args.ingress_table_loss:
        parser.error("--expect-no-table-loss-status requires --ingress-table-loss")
    if args.ingress_stop_race == "tproxy-route":
        if not args.tproxy_ingress_loss or args.expect_no_tproxy_status:
            parser.error("--ingress-stop-race tproxy-route requires --tproxy-ingress-loss")
    elif args.ingress_stop_race and (args.ingress_loss != "nftables" or args.ingress_dual_family or
                                    args.ingress_table_loss or args.restore_ingress or args.expect_no_ingress_status):
        parser.error("--ingress-stop-race requires --ingress-loss nftables without other ingress variants")
    if (args.without_redirect_state or args.stale_redirect_state) and not args.restart_ingress_helper:
        parser.error("redirect witness controls require --restart-ingress-helper")
    args.transparent_lan = (args.transparent_lan or args.server_failover or args.slow_reserve_failover or args.late_wan or
                            args.multi_outbound_failover or args.tproxy_ingress_loss or
                            args.cold_start or args.early_xray_crash or args.without_socks or args.ingress_loss or
                            args.ipv6_management or bool(args.assigned_management) or bool(args.inbound_port_case))
    isolated = args.transparent_lan or args.owner_restart_dynamic
    if isolated and args.namespace_origin is None:
        if args.ipv6_management or args.assigned_management:
            sys.exit(run_management_lab(args))
        sys.exit(run_isolated(Path(__file__).resolve(), sys.argv[1:]))
    if not isolated and (os.geteuid() == 0 or args.namespace_origin is not None):
        parser.error("run as an unprivileged user in a disposable Linux environment")
    version = subprocess.check_output([args.xray, "version"], text=True, timeout=5)
    assert version.splitlines()[0].startswith(args.expect_core), version.splitlines()[0]
    if isolated or args.helper_restart:
        run_case(args, recover=not (args.server_failover or args.slow_reserve_failover or args.multi_outbound_failover))
        if args.ipv6_management and not args.expect_no_ipv6_recovery:
            verify_login_peer(args, ipv6=True)
        return
    if not args.auto_login_only:
        run_case(args, recover=False)
        if not args.baseline_only:
            run_case(args, recover=True)
            run_case(args, recover=True, check_authorization=True)
    if not args.baseline_only:
        run_case(args, recover=False, auto_login="bootstrap")
        run_case(args, recover=False, auto_login="insecure")
        run_case(args, recover=False, auto_login="symlink")
        run_case(args, recover=False, auto_login="wrong")
        run_case(args, recover=True, auto_login="recover")
        verify_login_peer(args)
        verify_login_peer(args, same_login_and_token=True)


if __name__ == "__main__":
    main()
