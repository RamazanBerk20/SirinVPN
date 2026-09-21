"""Disposable-container packet probe; no host networking or external endpoints."""
import argparse
import json
import socket
import subprocess
import threading
import time


def probe(address, port, protocol="udp", mark=False):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(family, kind) as stream:
        stream.settimeout(0.25)
        if mark:
            stream.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 51820)
        try:
            stream.connect((address, port))
            stream.sendall(b"sirin-isolated-probe")
            return stream.recv(64) == b"sirin-isolated-probe"
        except (OSError, TimeoutError):
            return False


def serve():
    def listener(family, address, protocol, port):
        kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
        with socket.socket(family, kind) as server:
            if family == socket.AF_INET6:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((address, port))
            if protocol == "tcp":
                server.listen()
            while True:
                if protocol == "udp":
                    data, address = server.recvfrom(64)
                    server.sendto(data, address)
                else:
                    connection, _ = server.accept()
                    with connection:
                        connection.sendall(connection.recv(64))
    for address in ["203.0.113.8", "203.0.113.9", "10.20.0.8", "10.77.0.1", "2001:db8::8", "2001:db8::9"]:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        for protocol in ["udp", "tcp"]:
            for port in [53, 853, 3333, 51820, 443, 8888]:
                threading.Thread(target=listener, args=(family, address, protocol, port), daemon=True).start()
    while True:
        time.sleep(30)


def prepare():
    def ip(*args):
        subprocess.run(["ip", *args], check=True)
    ip("link", "set", "lo", "up")
    ip("netns", "add", "sirin-peer")
    ip("link", "add", "probe0", "type", "veth", "peer", "name", "probe1")
    ip("link", "set", "probe1", "netns", "sirin-peer")
    for namespace, device, end in [(None, "probe0", 7), ("sirin-peer", "probe1", 8)]:
        prefix = ["-n", namespace] if namespace else []
        ip(*prefix, "link", "set", "lo", "up")
        for address in [f"203.0.113.{end}/24", f"10.20.0.{end}/24", f"2001:db8::{end}/64"]:
            ip(*prefix, "address", "add", address, "dev", device)
        ip(*prefix, "link", "set", device, "up")
    ip("-n", "sirin-peer", "address", "add", "203.0.113.9/24", "dev", "probe1")
    ip("-n", "sirin-peer", "address", "add", "2001:db8::9/64", "dev", "probe1")
    ip("-n", "sirin-peer", "address", "add", "10.77.0.1/32", "dev", "probe1")
    ip("route", "add", "10.77.0.1/32", "via", "203.0.113.8")
    time.sleep(2)  # allow IPv6 duplicate-address detection before binding
    subprocess.Popen(["ip", "netns", "exec", "sirin-peer", "python3", __file__, "serve"],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    time.sleep(2)


def check(mode):
    expectations = []
    for address in ["203.0.113.8", "2001:db8::8"]:
        expectations.append((address, 3333, "udp", False, mode == "off"))
        for protocol in ["udp", "tcp"]:
            for port in [53, 853]:
                expectations.append((address, port, protocol, False, mode == "off"))
    expectations += [("10.20.0.8", 8888, "udp", False, mode in ["off", "lan", "selected"]),
                     ("10.20.0.8", 53, "udp", False, mode == "off"),
                     ("10.77.0.1", 3333, "udp", False, mode == "off"),
                     ("203.0.113.9", 3333, "udp", False, mode in ["off", "selected"]),
                     ("2001:db8::9", 3333, "udp", False, mode in ["off", "selected"]),
                     ("203.0.113.8", 51820, "udp", True, mode not in ["tcp", "handoff"]),
                     ("203.0.113.9", 51820, "udp", True, mode in ["off", "selected", "handoff"]),
                     ("203.0.113.8", 51820, "udp", False, mode == "off"),
                     ("203.0.113.8", 443, "tcp", True, mode in ["off", "tcp"]),
                     ("203.0.113.8", 443, "tcp", False, mode == "off")]
    for address, port, protocol, mark, expected in expectations:
        actual = probe(address, port, protocol, mark)
        assert actual == expected, (mode, address, port, protocol, mark, actual, expected)
    print(json.dumps({"policy": mode, "packet_checks": len(expectations)}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "serve", "off", "full", "lan", "selected", "tcp", "handoff"])
    args = parser.parse_args()
    if args.action == "prepare":
        prepare()
    elif args.action == "serve":
        serve()
    else:
        check(args.action)
