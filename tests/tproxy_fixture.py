"""Disposable transparent IPv4 client path for the crash recovery lab."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys


NAMESPACES = ("user", "net", "mnt", "pid")
DESTINATION = "198.18.0.42"
ROUTER = "192.0.2.1"
CLIENT = "192.0.2.2"
TRANSPARENT_PORT = 52345


def run_isolated(script, arguments, *, allow_mapped_root=False):
    if os.geteuid() == 0 and not allow_mapped_root:
        raise RuntimeError("run the transparent lab from an unprivileged Linux account")
    with ExitStack() as stack:
        origins = [stack.enter_context(open(f"/proc/self/ns/{space}", "rb", buffering=0)).fileno()
                   for space in NAMESPACES]
        command = ["unshare", "--user", "--map-root-user", "--net", "--mount", "--pid", "--fork",
                   "--mount-proc", "--kill-child", "--propagation", "private", "--",
                   sys.executable, script, *arguments,
                   "--namespace-origin", *map(str, origins)]
        return subprocess.run(command, pass_fds=origins).returncode


def confirm_isolation(origins):
    if os.geteuid() != 0 or len(origins) != len(NAMESPACES):
        raise RuntimeError("the transparent lab needs new user, network, mount and PID namespaces")
    for original, space in zip(origins, NAMESPACES):
        if not os.readlink(f"/proc/self/fd/{original}").startswith(f"{space}:["):
            raise RuntimeError(f"invalid original {space} namespace descriptor")
        if os.path.samestat(os.fstat(original), os.stat(f"/proc/self/ns/{space}")):
            raise RuntimeError(f"refusing to change the caller's {space} namespace")
    for original in origins:
        os.close(original)


def command(*args, **options):
    return subprocess.run(args, check=True, timeout=5, **options)


def prepare_router(origins):
    confirm_isolation(origins)
    command("ip", "link", "set", "lo", "up")


def transparent_config(directory, routes=None):
    directory.mkdir()
    rules = [{"type": "field", "inboundTag": ["lab-transparent"], "domain": [f"full:{host}"],
              "outboundTag": route} for route, host in (routes or {}).items()]
    rules.append({"type": "field", "inboundTag": ["lab-transparent"], "outboundTag": "proxy"})
    content = {
        "inbounds": [{
            "tag": "lab-transparent",
            "port": TRANSPARENT_PORT,
            "listen": "0.0.0.0",
            "protocol": "dokodemo-door",
            "settings": {"network": "tcp", "followRedirect": True},
            "sniffing": {"enabled": True, "destOverride": ["tls"]},
            "streamSettings": {"sockopt": {"tproxy": "tproxy"}},
        }],
        "routing": {"rules": rules},
    }
    (directory / "99-transparent.json").write_text(json.dumps(content))


class TransparentClient:
    def __init__(self, stack, cert, wait, terminate):
        self.cert = cert
        client = subprocess.Popen(["unshare", "--net", "--", "sleep", "3600"])
        stack.callback(terminate, client)
        namespace = Path("/proc", str(client.pid), "ns", "net")
        wait(lambda: client.poll() is None and not os.path.samestat(namespace.stat(), os.stat("/proc/self/ns/net")),
             "separate client network namespace")
        self.enter = ["nsenter", f"--net={namespace}", "--"]
        command("ip", "link", "add", "lab-router", "type", "veth", "peer", "name", "lab-client")
        command("ip", "link", "set", "lab-client", "netns", str(client.pid))
        command("ip", "addr", "add", f"{ROUTER}/24", "dev", "lab-router")
        command("ip", "link", "set", "lab-router", "up")
        command(*self.enter, "ip", "link", "set", "lo", "up")
        command(*self.enter, "ip", "addr", "add", f"{CLIENT}/24", "dev", "lab-client")
        command(*self.enter, "ip", "link", "set", "lab-client", "up")
        command(*self.enter, "ip", "route", "add", f"{DESTINATION}/32", "via", ROUTER)
        self.env = {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy")}

    def _https(self, timeout=2, host="check.invalid"):
        reply = subprocess.run([*self.enter, "curl", "-q", "--silent", "--max-time", str(timeout),
                                "--resolve", f"{host}:443:{DESTINATION}", "--cacert", self.cert,
                                "--output", "/dev/null", "--write-out", "%{http_code}",
                                f"https://{host}/generate_204"], capture_output=True, text=True,
                               timeout=4, env=self.env)
        return reply.returncode == 0 and reply.stdout == "204"

    def enable_interception(self):
        assert not self._https(), "the client unexpectedly reached the destination directly"
        command("ip", "rule", "add", "priority", "100", "fwmark", "0x1/0x1", "lookup", "100")
        command("ip", "route", "add", "local", f"{DESTINATION}/32", "dev", "lo", "table", "100")
        rules = f"""
table ip recovery_lab {{
    counter lan_https {{ }}
    chain ingress {{
        type filter hook prerouting priority mangle; policy accept;
        iifname "lab-router" ip daddr {DESTINATION} tcp dport 443 counter name lan_https tproxy to :{TRANSPARENT_PORT} meta mark set 0x1 accept
    }}
}}
"""
        command("nft", "-f", "-", input=rules, text=True)

    def _packets(self):
        result = command("nft", "-j", "list", "counter", "ip", "recovery_lab", "lan_https",
                         capture_output=True)
        return next(item["counter"]["packets"] for item in json.loads(result.stdout)["nftables"]
                    if "counter" in item)

    def https(self, timeout=2, *, host="check.invalid"):
        before = self._packets()
        if not self._https(timeout, host):
            return False
        assert self._packets() > before, "HTTPS returned without reaching the transparent rule"
        return True
