#!/usr/bin/env python3
"""Synthetic packet proof inside the disposable --network none test container."""
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import time

BASE = pathlib.Path("/tmp/sirinvpn-application-proof")
SCRIPT = pathlib.Path(__file__).resolve()


def run(*arguments):
    subprocess.run(arguments, check=True, stdout=subprocess.DEVNULL)


def publish(path, value):
    temporary = path.with_suffix(".new")
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


def wait_file(path, predicate=lambda value: True):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            value = json.loads(path.read_text())
            if predicate(value):
                return value
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(0.03)
    raise AssertionError(f"timed out waiting for {path.name}")


def dns_reply(data, label):
    cursor = 12
    while cursor < len(data) and data[cursor]:
        cursor += data[cursor] + 1
    end = cursor + 5
    if end > len(data):
        return b""
    kind = struct.unpack("!H", data[cursor + 1:cursor + 3])[0]
    tail = 42 if label == "vpn" else 41
    address = socket.inet_pton(socket.AF_INET, f"198.51.100.{tail}") if kind == 1 else None
    count = 1 if address else 0
    result = data[:2] + struct.pack("!HHHHH", 0x8180, 1, count, 0, 0) + data[12:end]
    if address:
        result += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + address
    return result


def listen(label):
    sockets = []
    def udp(family, port, address, dns=False):
        server = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.bind((address, port))
        sockets.append(server)
        def serve():
            while True:
                data, peer = server.recvfrom(4096)
                response = dns_reply(data, label) if dns else peer[0].encode() if data == b"source" else label.encode()
                server.sendto(response, peer)
        threading.Thread(target=serve, daemon=True).start()
    def tcp(port):
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen()
        sockets.append(server)
        def serve():
            while True:
                client, _ = server.accept()
                with client:
                    client.settimeout(0.5)
                    try:
                        data = client.recv(4096)
                        if port == 53 and len(data) > 2:
                            response = dns_reply(data[2:], label)
                            client.sendall(struct.pack("!H", len(response)) + response)
                        else:
                            client.sendall(label.encode())
                    except OSError:
                        pass
        threading.Thread(target=serve, daemon=True).start()
    udp(socket.AF_INET, 19000, "198.51.100.9")
    udp(socket.AF_INET6, 19000, "2001:db8:1::9")
    udp(socket.AF_INET, 53, "10.77.0.1" if label == "vpn" else "198.51.100.9", True)
    if label == "normal":
        udp(socket.AF_INET, 19000, "10.12.0.9")
        udp(socket.AF_INET, 53, "10.12.0.9", True)
    tcp(19001)
    tcp(53)
    tcp(853)
    publish(BASE / f"{label}-ready", True)
    threading.Event().wait()


def display_server():
    path = "/run/user/1000/wayland-proof"
    server = socket.socket(socket.AF_UNIX)
    server.bind(path)
    os.chown(path, 1000, 1000)
    server.listen()
    publish(BASE / "display-ready", True)
    while True:
        client, _ = server.accept()
        with client:
            client.sendall(b"display")


def background(arguments):
    return subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup():
    assert os.geteuid() == 0 and pathlib.Path("/.dockerenv").exists()
    # Docker makes /proc/sys read-only by default. Expose only this container's
    # namespaced network controls, with private mount propagation.
    run("mount", "--make-rprivate", "/")
    run("mount", "--bind", "/proc/sys/net", "/proc/sys/net")
    run("mount", "-o", "remount,bind,rw", "/proc/sys/net")
    run("sysctl", "-q", "-w", "net.ipv6.conf.default.accept_dad=0")
    BASE.mkdir(mode=0o700)
    publish(BASE / "initial-ipv6-forwarding",
            pathlib.Path("/proc/sys/net/ipv6/conf/all/forwarding").read_text().strip())
    os.chown(BASE, 1000, 1000)
    run("useradd", "--uid", "1000", "--user-group", "--home-dir", str(BASE), "--shell", "/bin/sh", "svapp-proof")
    for namespace in ["normal-proof", "vpn-proof"]:
        run("ip", "netns", "add", namespace)
        run("ip", "netns", "exec", namespace, "sysctl", "-q", "-w", "net.ipv6.conf.default.accept_dad=0")
        run("ip", "-n", namespace, "link", "set", "lo", "up")
    run("ip", "link", "add", "normal0", "type", "veth", "peer", "name", "normal-peer", "netns", "normal-proof")
    run("ip", "address", "add", "192.0.2.2/24", "dev", "normal0")
    run("ip", "-6", "address", "add", "2001:db8:ffff::2/64", "dev", "normal0", "nodad")
    run("ip", "link", "set", "normal0", "up")
    for family, address in [("-4", "192.0.2.1/24"), ("-4", "198.51.100.9/32"),
                            ("-4", "10.12.0.9/32"), ("-6", "2001:db8:ffff::1/64"), ("-6", "2001:db8:1::9/128")]:
        command = ["ip", "-n", "normal-proof", family, "address", "add", address, "dev", "normal-peer"]
        if family == "-6":
            command += ["nodad"]
        run(*command)
    run("ip", "-n", "normal-proof", "link", "set", "normal-peer", "up")
    run("ip", "netns", "exec", "normal-proof", "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1")
    run("ip", "route", "add", "default", "via", "192.0.2.1")
    run("ip", "-6", "route", "add", "default", "via", "2001:db8:ffff::1")
    pathlib.Path("/etc/resolv.conf").write_text("nameserver 198.51.100.9\noptions timeout:1 attempts:1\n")
    for name in ["/run/nscd", "/run/user/1000"]:
        pathlib.Path(name).mkdir(parents=True, exist_ok=True)
    os.chown("/run/user/1000", 1000, 1000)
    os.chmod("/run/user/1000", 0o700)
    pathlib.Path("/run/nscd/socket").touch()
    pathlib.Path("/run/user/1000/bus").touch()
def start_listeners():
    for label, namespace in [("normal", "normal-proof"), ("vpn", "vpn-proof")]:
        background(["ip", "netns", "exec", namespace, "python3", str(SCRIPT), "listen", label])
        wait_file(BASE / f"{label}-ready")
    background(["python3", str(SCRIPT), "display"])
    wait_file(BASE / "display-ready")
    assert exchange("198.51.100.9") == "normal", "baseline host IPv4 failed"
    deadline = time.monotonic() + 4
    baseline6 = None
    while baseline6 != "normal" and time.monotonic() < deadline:
        baseline6 = exchange("2001:db8:1::9")
    if baseline6 != "normal":
        for args in [["-6", "route", "get", "2001:db8:1::9"],
                     ["-6", "neigh"], ["-n", "normal-proof", "-6", "route"],
                     ["-n", "normal-proof", "-6", "neigh"],
                     ["-n", "normal-proof", "-6", "address", "show"],
                     ["-6", "address", "show", "dev", "normal0"]]:
            subprocess.run(["ip", *args], check=True)
    assert baseline6 == "normal", "baseline host IPv6 failed"


def exchange(address, port=19000, tcp=False, dns=False, source=False):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    message = b"source" if source else b"test"
    if dns:
        message = b"\x51\x52" + struct.pack("!HHHHH", 0x100, 1, 0, 0, 0)
        message += b"\x13application-routing\x07invalid\x00\x00\x01\x00\x01"
    try:
        with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
            client.settimeout(0.45)
            client.connect((address, port))
            client.sendall(struct.pack("!H", len(message)) + message if dns and tcp else message)
            response = client.recv(4096)
            return response.hex() if dns else response.decode()
    except OSError:
        return None


def resolved():
    return socket.getaddrinfo("application-routing.invalid", None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]


def app(name):
    # Evidence comes from the actual unprivileged process and private mount view.
    status = pathlib.Path("/proc/self/status").read_text()
    assert os.getuid() == os.geteuid() == 1000, status
    for key in ["CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"]:
        assert f"{key}:\t0000000000000000" in status, status
    assert "NoNewPrivs:\t1" in status
    assert not pathlib.Path("/run/nscd/socket").exists()
    assert not pathlib.Path("/run/user/1000/bus").exists()
    with socket.socket(socket.AF_UNIX) as display:
        display.connect("/run/user/1000/wayland-proof")
        assert display.recv(32) == b"display"
    namespace = os.readlink("/proc/self/ns/net")
    last = None
    while True:
        phase = wait_file(BASE / f"{name}-command", lambda value: value != last)
        last = phase
        if phase == "stop":
            return
        result = {"phase": phase, "namespace": namespace, "udp4": exchange("198.51.100.9"),
                  "udp6": exchange("2001:db8:1::9"), "tcp": exchange("198.51.100.9", 19001, True)}
        if phase in ["active", "reconnected", "rotated", "lan", "ipv4-only"]:
            result["dns"] = resolved()
            result["dns_tcp"] = exchange("10.77.0.1", 53, True, True)
            result["source4"] = exchange("198.51.100.9", source=True)
            result["source6"] = exchange("2001:db8:1::9", source=True)
        else:
            result["dns_blocked"] = exchange("198.51.100.9", 53, dns=True)
        if phase == "lan":
            result["lan"] = exchange("10.12.0.9")
            result["lan_dns"] = exchange("10.12.0.9", 53, dns=True)
            result["lan_dot"] = exchange("10.12.0.9", 853, True)
        publish(BASE / f"{name}-result", result)


def launch(name):
    request = {"server_id": pathlib.Path("/tmp/application-server-id").read_text(),
               "executable": "/usr/bin/python3", "arguments": [str(SCRIPT), "app", name],
               "environment": {"XDG_RUNTIME_DIR": "/run/user/1000", "WAYLAND_DISPLAY": "wayland-proof"}}
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PKEXEC_UID": "1000"}
    child = subprocess.Popen(["ip", "netns", "exec", "sirinvpn-apps", "/usr/lib/sirinvpn/sirinvpn-helper", "application-child"],
                             stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=environment)
    child.stdin.write(json.dumps(request).encode())
    child.stdin.close()


def probe(phase):
    initial_forwarding = json.loads((BASE / "initial-ipv6-forwarding").read_text())
    assert pathlib.Path("/proc/sys/net/ipv6/conf/all/forwarding").read_text().strip() == initial_forwarding, \
        "application routing changed global IPv6 forwarding"
    ipv6_supported = (initial_forwarding == "1" or
                      pathlib.Path("/proc/sys/net/ipv6/conf/default/force_forwarding").exists())
    ipv6_expected = ipv6_supported and phase != "ipv4-only"
    name = "lan" if phase in ["lan", "ipv4-only"] else "original"
    publish(BASE / f"{name}-command", phase)
    if phase in ["active", "lan"]:
        launch(name)
    result = wait_file(BASE / f"{name}-result", lambda value: value["phase"] == phase)
    if phase in ["active", "reconnected", "rotated", "lan", "ipv4-only"]:
        assert (result["udp4"], result["udp6"], result["tcp"]) == ("vpn", "vpn" if ipv6_expected else None, "vpn"), result
        assert result["dns"] == "198.51.100.42" and result["dns_tcp"], result
        assert result["source4"] == ("10.77.0.3" if phase == "rotated" else "10.77.0.2"), result
        assert result["source6"] == (None if not ipv6_expected else "fd77::3" if phase == "rotated" else "fd77::2"), result
    else:
        assert all(result[key] is None for key in ["udp4", "udp6", "tcp", "dns_blocked"]), result
    if phase == "active":
        publish(BASE / "original-namespace", result["namespace"])
    elif phase in ["reconnected", "rotated", "disconnected"]:
        assert result["namespace"] == json.loads((BASE / "original-namespace").read_text()), result
    if phase == "lan":
        assert result["lan"] == "normal" and result["lan_dns"] is None and result["lan_dot"] is None, result
    assert exchange("198.51.100.9") == "normal", "ordinary host traffic changed"
    assert exchange("2001:db8:1::9") == "normal", "ordinary host IPv6 changed"
    assert resolved() == "198.51.100.41", "ordinary host DNS changed"
    assert pathlib.Path("/run/nscd/socket").exists(), "host runtime was changed"
    assert pathlib.Path("/run/user/1000/bus").exists(), "host bus was changed"
    print(f"{phase}: packet routing, DNS and runtime isolation passed (IPv6 forwarding available: {ipv6_supported})", flush=True)


if __name__ == "__main__":
    {"setup": setup, "start": start_listeners, "listen": lambda: listen(sys.argv[2]), "display": display_server,
     "app": lambda: app(sys.argv[2]), "probe": lambda: probe(sys.argv[2])}[sys.argv[1]]()
