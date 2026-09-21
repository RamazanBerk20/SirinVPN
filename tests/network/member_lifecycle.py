"""Synthetic peers only, inside an empty disposable network namespace."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(*args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE,
                          check=True).stdout


assert os.environ.get("SIRINVPN_POLICY_ISOLATED") == "1"
assert Path("/.dockerenv").exists()
if sys.argv[1] == "prepare":
    assert [entry["ifname"] for entry in json.loads(run("ip", "-j", "link"))] == ["lo"]
    data = json.load(sys.stdin)
    Path("/tmp/lifecycle-v6").write_text(data["server_ipv6"])
    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "sirinvpn0", "type", "wireguard")
    run("wg", "set", "sirinvpn0", "private-key", data["server_private_key_path"], "listen-port", "51820")
    server_public = run("wg", "show", "sirinvpn0", "public-key").decode().strip()
    run("ip", "address", "add", "10.77.0.1/24", "dev", "sirinvpn0")
    run("ip", "-6", "address", "add", data["server_ipv6"] + "/64", "dev", "sirinvpn0", "nodad")
    run("ip", "link", "set", "sirinvpn0", "up")
    run("nft", "-f", "-", data=b"""
add table inet sirinvpn_filter
add set inet sirinvpn_filter peer_communication4 { type ipv4_addr; }
add set inet sirinvpn_filter peer_communication6 { type ipv6_addr; }
add chain inet sirinvpn_filter port_forward
add table ip sirinvpn_nat
add chain ip sirinvpn_nat port_forward_prerouting
add chain ip sirinvpn_nat prerouting { type nat hook prerouting priority dstnat; policy accept; }
add rule ip sirinvpn_nat prerouting jump port_forward_prerouting
""")
    for device in data["devices"]:
        namespace = "member" + str(device["index"])
        run("ip", "netns", "add", namespace)
        run("ip", "link", "add", "client0", "type", "wireguard")
        run("wg", "set", "client0", "private-key", device["private_key_path"],
            "peer", server_public, "allowed-ips", "0.0.0.0/0,::/0", "endpoint", "127.0.0.1:51820")
        run("ip", "link", "set", "client0", "netns", namespace)
        run("ip", "-n", namespace, "link", "set", "lo", "up")
        run("ip", "-n", namespace, "address", "add", device["ipv4"] + "/24", "dev", "client0")
        run("ip", "-n", namespace, "-6", "address", "add", device["ipv6"] + "/64", "dev", "client0", "nodad")
        run("ip", "-n", namespace, "link", "set", "client0", "up")
else:
    destination = Path("/tmp/lifecycle-v6").read_text() if sys.argv[3] == "6" else "10.77.0.1"
    expected = sys.argv[4] == "open"
    deadline = time.monotonic() + (45 if expected else 1)
    while True:
        probe = subprocess.run(["ip", "netns", "exec", "member" + sys.argv[2], "ping",
                                "-c", "1", "-W", "1", destination], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        available = probe.returncode == 0
        if available == expected:
            break
        if time.monotonic() >= deadline:
            raise SystemExit(1)
