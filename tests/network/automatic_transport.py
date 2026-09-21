"""Private four-carrier lab, only inside a disposable container."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import tempfile

assert os.environ.get("SIRINVPN_POLICY_ISOLATED") == "1"
assert Path("/.dockerenv").exists()


def run(*args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE, check=True).stdout


if sys.argv[1] == "prepare":
    assert [i["ifname"] for i in json.loads(run("ip", "-j", "link"))] == ["lo"]
    config = json.load(sys.stdin)
    run("ip", "link", "set", "lo", "up")
    run("ip", "netns", "add", "auto-vps")
    run("ip", "link", "add", "eth-test", "type", "veth", "peer", "name", "uplink")
    run("ip", "link", "set", "uplink", "netns", "auto-vps")
    for prefix, link, v4, v6 in [((), "eth-test", "198.18.0.2", "fdba::2"),
                                 (("-n", "auto-vps"), "uplink", "198.18.0.1", "fdba::1")]:
        run("ip", *prefix, "link", "set", "lo", "up")
        run("ip", *prefix, "address", "add", v4 + "/24", "dev", link)
        run("ip", *prefix, "-6", "address", "add", v6 + "/64", "dev", link, "nodad")
        run("ip", *prefix, "link", "set", link, "up")
    run("ip", "route", "add", "default", "via", "198.18.0.1")
    run("ip", "-6", "route", "add", "default", "via", "fdba::1")
    server = ("ip", "netns", "exec", "auto-vps")
    run(*server, "ip", "link", "add", "sirinvpn0", "type", "wireguard")
    run(*server, "wg", "set", "sirinvpn0", "private-key", config["private_key"], "listen-port", "51820")
    run(*server, "ip", "address", "add", "10.77.0.1/24", "dev", "sirinvpn0")
    run(*server, "ip", "-6", "address", "add", config["ipv6"] + "/64", "dev", "sirinvpn0", "nodad")
    run(*server, "ip", "link", "set", "sirinvpn0", "up")
    run(*server, "nft", "-f", "-", data=b"""
add table inet sirinvpn_filter
add set inet sirinvpn_filter peer_communication4 { type ipv4_addr; }
add set inet sirinvpn_filter peer_communication6 { type ipv6_addr; }
add chain inet sirinvpn_filter port_forward
add table ip sirinvpn_nat
add chain ip sirinvpn_nat port_forward_prerouting
""")
elif sys.argv[1] == "delay-direct":
    run("tc", "qdisc", "add", "dev", "eth-test", "root", "handle", "1:", "prio")
    run("tc", "qdisc", "add", "dev", "eth-test", "parent", "1:3", "handle", "30:", "netem", "delay", "30ms")
    run("tc", "filter", "add", "dev", "eth-test", "protocol", "ip", "parent", "1:", "prio", "1", "u32",
        "match", "ip", "protocol", "17", "0xff", "match", "ip", "dport", "51820", "0xffff", "flowid", "1:3")
elif sys.argv[1] == "probe-isolation":
    config = json.load(sys.stdin)
    run("ip", "netns", "add", "probe-check")
    try:
        run("ip", "link", "add", "lease-test", "type", "wireguard")
        with tempfile.NamedTemporaryFile() as key:
            key.write(config["private_key"].encode()); key.flush()
            run("wg", "set", "lease-test", "private-key", key.name, "fwmark", "51820", "peer", config["server_public_key"],
                "endpoint", "198.18.0.1:51820", "allowed-ips", "0.0.0.0/0")
        run("ip", "link", "set", "lease-test", "netns", "probe-check")
        run("ip", "-n", "probe-check", "address", "add", "10.77.1.2/32", "dev", "lease-test")
        run("ip", "-n", "probe-check", "link", "set", "lease-test", "up")
        run("ip", "-n", "probe-check", "route", "add", "default", "dev", "lease-test")
        run("ip", "netns", "exec", "auto-vps", "sysctl", "-qw", "net.ipv4.ip_forward=1")
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("198.18.0.2", 19001)); receiver.settimeout(0.5)
        run("ip", "netns", "exec", "probe-check", "python3", __file__, "check-probe")
        try:
            receiver.recv(128)
        except TimeoutError:
            pass
        else:
            raise AssertionError("leased peer escaped the forwarding quarantine")
        receiver.close()
    finally:
        run("ip", "netns", "delete", "probe-check")
elif sys.argv[1] == "check-probe":
    run("ping", "-n", "-c", "1", "-W", "2", "10.77.0.1")
    for port in (8443, 19000):
        try:
            connection = socket.create_connection(("10.77.0.1", port), timeout=0.4)
        except OSError:
            pass
        else:
            connection.close()
            raise AssertionError("leased peer reached a private service")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"no forwarding", ("198.18.0.2", 19001))
elif sys.argv[1] == "serve":
    def tcp_connection(connection):
        with connection:
            while data := connection.recv(1024):
                connection.sendall(data)

    def serve(family, kind, port):
        sock = socket.socket(family, kind)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", port))
        if kind == socket.SOCK_STREAM:
            sock.listen()
            while True:
                connection, _ = sock.accept()
                threading.Thread(target=tcp_connection, args=(connection,), daemon=True).start()
        else:
            while True:
                data, peer = sock.recvfrom(4096)
                sock.sendto(data, peer)

    for family in (socket.AF_INET, socket.AF_INET6):
        for kind, port in ((socket.SOCK_STREAM, 19000), (socket.SOCK_DGRAM, 19000), (socket.SOCK_DGRAM, 53)):
            threading.Thread(target=serve, args=(family, kind, port), daemon=True).start()
    threading.Event().wait()
