"""The container namespace is a subnet router run by the production helper. A plain
WireGuard VPS, a consuming peer and the router's LAN host live in disposable namespaces."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(*args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE,
                          check=True).stdout


def key():
    private = run("wg", "genkey").strip()
    return private.decode(), run("wg", "pubkey", data=private + b"\n").decode().strip()


def veth(left, left_address, namespace, right, right_address):
    run("ip", "link", "add", left, "type", "veth", "peer", "name", right)
    run("ip", "link", "set", right, "netns", namespace)
    run("ip", "address", "add", left_address, "dev", left)
    run("ip", "link", "set", left, "up")
    run("ip", "-n", namespace, "link", "set", "lo", "up")
    run("ip", "-n", namespace, "address", "add", right_address, "dev", right)
    run("ip", "-n", namespace, "link", "set", right, "up")


assert os.environ.get("SIRINVPN_POLICY_ISOLATED") == "1"
assert Path("/.dockerenv").exists()
if sys.argv[1] == "prepare":
    assert [entry["ifname"] for entry in json.loads(run("ip", "-j", "link"))] == ["lo"]
    # Docker makes /proc/sys read-only; expose only the namespaced network controls.
    run("mount", "--make-rprivate", "/")
    run("mount", "--bind", "/proc/sys/net", "/proc/sys/net")
    run("mount", "-o", "remount,bind,rw", "/proc/sys/net")
    run("ip", "link", "set", "lo", "up")
    # The one host setting a subnet router needs; the helper never changes it.
    run("sysctl", "-qw", "net.ipv4.ip_forward=1")
    for namespace in ("vps", "consumer", "lan"):
        run("ip", "netns", "add", namespace)
    veth("uplink0", "198.51.100.2/24", "vps", "eth0", "198.51.100.1/24")
    veth("lan0", "192.168.1.1/24", "lan", "eth0", "192.168.1.10/24")
    vps, router, consumer = key(), key(), key()
    directory = Path(sys.argv[2])
    for name, (private, _) in (("vps", vps), ("consumer", consumer)):
        (directory / name).write_text(private + "\n")
    run("ip", "netns", "exec", "vps", "sysctl", "-qw", "net.ipv4.ip_forward=1")
    run("ip", "-n", "vps", "link", "add", "wg0", "type", "wireguard")
    run("ip", "netns", "exec", "vps", "wg", "set", "wg0", "private-key", str(directory / "vps"),
        "listen-port", "51820",
        "peer", router[1], "allowed-ips", "10.77.0.2/32,192.168.1.0/24",
        "peer", consumer[1], "allowed-ips", "10.77.0.3/32")
    run("ip", "-n", "vps", "address", "add", "10.77.0.1/24", "dev", "wg0")
    run("ip", "-n", "vps", "link", "set", "wg0", "up")
    run("ip", "-n", "vps", "route", "add", "192.168.1.0/24", "dev", "wg0")
    # Born in the VPS namespace, so its socket reaches the VPS on loopback there.
    run("ip", "-n", "vps", "link", "add", "client0", "type", "wireguard")
    run("ip", "netns", "exec", "vps", "wg", "set", "client0", "private-key",
        str(directory / "consumer"), "peer", vps[1], "allowed-ips", "0.0.0.0/0",
        "endpoint", "127.0.0.1:51820", "persistent-keepalive", "1")
    run("ip", "-n", "vps", "link", "set", "client0", "netns", "consumer")
    run("ip", "-n", "consumer", "link", "set", "lo", "up")
    run("ip", "-n", "consumer", "address", "add", "10.77.0.3/24", "dev", "client0")
    run("ip", "-n", "consumer", "link", "set", "client0", "up")
    run("ip", "-n", "consumer", "route", "add", "192.168.1.0/24", "dev", "client0")
    print(json.dumps({"vps_public_key": vps[1], "router_private_key": router[0]}))
else:
    source, destination, expected = sys.argv[2], sys.argv[3], sys.argv[4] == "open"
    command = ["ping", "-c", "1", "-W", "1", destination]
    if source != "router":
        command = ["ip", "netns", "exec", source, *command]
    deadline = time.monotonic() + (45 if expected else 2)
    while True:
        probe = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if (probe.returncode == 0) == expected:
            break
        if time.monotonic() >= deadline:
            raise SystemExit(1)
