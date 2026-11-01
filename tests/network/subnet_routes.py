"""A VPS, a subnet router with its LAN, peers and an internet host, inside an empty
disposable network namespace. The VPS firewall mirrors the installer's forward chain."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(*args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE,
                          check=True).stdout


# The rules of crates/installer/src/install_script.rs that decide tunnel forwarding.
VPS_FIREWALL = b"""
table inet sirinvpn_filter {
  set peer_communication4 { type ipv4_addr; }
  set peer_communication6 { type ipv6_addr; }
  chain port_forward {
  }
  chain forward {
    type filter hook forward priority -20; policy accept;
    iifname "sirinvpn0" ip saddr 10.77.0.224/27 drop
    oifname "sirinvpn0" ip daddr 10.77.0.224/27 drop
    jump port_forward
    iifname "eth-test" oifname "sirinvpn0" ip daddr 10.77.0.0/24 ct mark 0x5356504e drop
    iifname "sirinvpn0" oifname "sirinvpn0" meta nfproto ipv4 ip saddr @peer_communication4 ip daddr @peer_communication4 accept
    iifname "sirinvpn0" oifname "sirinvpn0" drop
    iifname "sirinvpn0" meta nfproto ipv4 oifname "eth-test" accept
    iifname "eth-test" meta nfproto ipv4 oifname "sirinvpn0" ct state established,related accept
    iifname "eth-test" meta nfproto ipv4 oifname "sirinvpn0" drop
  }
}
table ip sirinvpn_nat {
  chain port_forward_prerouting {
  }
  chain prerouting {
    type nat hook prerouting priority dstnat - 10; policy accept;
    jump port_forward_prerouting
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.77.0.0/24 oifname "eth-test" masquerade
  }
}
"""


def peer(namespace, private_key, address, server_public, lan_route):
    run("ip", "netns", "add", namespace)
    run("ip", "link", "add", "client0", "type", "wireguard")
    run("wg", "set", "client0", "private-key", private_key, "peer", server_public,
        "allowed-ips", "0.0.0.0/0", "endpoint", "127.0.0.1:51820", "persistent-keepalive", "1")
    run("ip", "link", "set", "client0", "netns", namespace)
    run("ip", "-n", namespace, "link", "set", "lo", "up")
    run("ip", "-n", namespace, "address", "add", address + "/24", "dev", "client0")
    run("ip", "-n", namespace, "link", "set", "client0", "up")
    run("ip", "-n", namespace, "route", "add", "default", "dev", "client0")
    if lan_route:
        run("ip", "-n", namespace, "route", "add", "192.168.1.0/24", "dev", "client0")


def veth(left_namespace, left, left_address, right_namespace, right, right_address):
    run("ip", "link", "add", left, "type", "veth", "peer", "name", right)
    for namespace, name, address in ((left_namespace, left, left_address),
                                     (right_namespace, right, right_address)):
        prefix = ["ip"] if namespace is None else ["ip", "-n", namespace]
        if namespace is not None:
            run("ip", "link", "set", name, "netns", namespace)
            run(*prefix, "link", "set", "lo", "up")
        run(*prefix, "address", "add", address, "dev", name)
        run(*prefix, "link", "set", name, "up")


assert os.environ.get("SIRINVPN_POLICY_ISOLATED") == "1"
assert Path("/.dockerenv").exists()
if sys.argv[1] == "prepare":
    assert [entry["ifname"] for entry in json.loads(run("ip", "-j", "link"))] == ["lo"]
    data = json.load(sys.stdin)
    # Docker makes /proc/sys read-only; expose only the namespaced network controls.
    run("mount", "--make-rprivate", "/")
    run("mount", "--bind", "/proc/sys/net", "/proc/sys/net")
    run("mount", "-o", "remount,bind,rw", "/proc/sys/net")
    run("ip", "link", "set", "lo", "up")
    run("sysctl", "-qw", "net.ipv4.ip_forward=1")
    run("ip", "link", "add", "sirinvpn0", "type", "wireguard")
    run("wg", "set", "sirinvpn0", "private-key", data["server_private_key_path"], "listen-port", "51820")
    server_public = run("wg", "show", "sirinvpn0", "public-key").decode().strip()
    run("ip", "address", "add", "10.77.0.1/24", "dev", "sirinvpn0")
    run("ip", "link", "set", "sirinvpn0", "up")
    run("nft", "-f", "-", data=VPS_FIREWALL)
    # The VPS's external network, with one internet host behind it.
    run("ip", "netns", "add", "internet")
    veth(None, "eth-test", "203.0.113.1/24", "internet", "eth0", "203.0.113.50/24")
    # It answers any source, so a LAN packet that left the VPS unmasqueraded would come back.
    run("ip", "-n", "internet", "route", "add", "default", "via", "203.0.113.1")
    router = data["router"]
    peer("router", router["private_key_path"], router["ipv4"], server_public, False)
    # What the Linux helper does on a router: forward from the tunnel and masquerade.
    run("ip", "netns", "add", "lan")
    veth("router", "lan0", "192.168.1.1/24", "lan", "eth0", "192.168.1.10/24")
    run("ip", "netns", "exec", "router", "sysctl", "-qw", "net.ipv4.ip_forward=1")
    run("ip", "netns", "exec", "router", "nft", "-f", "-", data=b"""
table ip router_lan {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    iifname "client0" oifname "lan0" masquerade
  }
}
""")
    # A LAN host that tries to start connections into SirinVPN or out through the VPS.
    run("ip", "-n", "lan", "route", "add", "default", "via", "192.168.1.1")
    for device in data["peers"]:
        peer("member" + str(device["index"]), device["private_key_path"], device["ipv4"],
             server_public, True)
else:
    source, destination, expected = sys.argv[2], sys.argv[3], sys.argv[4] == "open"
    # Optional extra ping arguments, such as "-e <identifier>" to keep one conntrack flow.
    extra = sys.argv[5:]
    deadline = time.monotonic() + (45 if expected else 2)
    while True:
        probe = subprocess.run(["ip", "netns", "exec", source, "ping", "-c", "1", "-W", "1",
                                *extra, destination], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        if (probe.returncode == 0) == expected:
            break
        if time.monotonic() >= deadline:
            raise SystemExit(1)
