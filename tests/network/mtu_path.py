"""Synthetic WireGuard path with an MTU black hole inside a disposable container."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

assert os.environ.get("SIRINVPN_POLICY_ISOLATED") == "1"
assert Path("/.dockerenv").exists()


def run(*args, data=None):
    return subprocess.run(args, input=data, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


if sys.argv[1] == "prepare":
    assert [link["ifname"] for link in json.loads(run("ip", "-j", "link"))] == ["lo"]
    run("ip", "link", "set", "lo", "up")
    run("ip", "netns", "add", "mtu-server")
    with tempfile.TemporaryDirectory() as directory:
        keys = [run("wg", "genkey"), run("wg", "genkey")]
        public = [run("wg", "pubkey", data=key).decode().strip() for key in keys]
        names = ["sirinvpn0", "mtu-peer0"]
        ports = [54000, 53000]
        for index, name in enumerate(names):
            private = Path(directory) / str(index)
            private.write_bytes(keys[index])
            private.chmod(0o600)
            run("ip", "link", "add", name, "type", "wireguard")
            run("wg", "set", name, "private-key", str(private), "listen-port", str(ports[index]),
                "peer", public[1-index], "allowed-ips", "10.77.0.0/24", "endpoint", "127.0.0.1:" + str(ports[1-index]))
    run("ip", "link", "set", "mtu-peer0", "netns", "mtu-server")
    run("ip", "address", "add", "10.77.0.2/24", "dev", "sirinvpn0")
    run("ip", "link", "set", "dev", "sirinvpn0", "mtu", "1420", "up")
    run("ip", "-n", "mtu-server", "link", "set", "lo", "up")
    run("ip", "-n", "mtu-server", "address", "add", "10.77.0.1/24", "dev", "mtu-peer0")
    run("ip", "-n", "mtu-server", "link", "set", "mtu-peer0", "up")
    run("ip", "netns", "exec", "mtu-server", "nft", "-f", "-", data=b"""
table inet mtu_fixture {
 chain input { type filter hook input priority filter; policy accept;
   ip protocol icmp meta length > 1300 drop
 }
}
""")
    run("ping", "-n", "-c", "1", "-W", "2", "10.77.0.1")
else:
    run("ip", "netns", "exec", "mtu-server", "nft", "add", "rule", "inet", "mtu_fixture", "input", "ip", "protocol", "icmp", "drop")
