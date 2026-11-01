"""An IPv6-only VPS running the installer's firewall and Unbound DNS64 configuration, a member
on an IPv6-only network, and an internet with an IPv6 site, a DNS-over-TLS resolver and a
stand-in NAT64 gateway. No external network is used."""
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

assert os.environ.get("SIRINVPN_POLICY_ISOLATED") == "1"
assert Path("/.dockerenv").exists()

PREFIX = "64:ff9b::"
# What the NAT64 gateway at 64:ff9b::/96 would forward to the IPv4-only site 192.0.2.80.
GATEWAY = "64:ff9b::c000:250"
SITE6, SITE4, RESOLVER = "2001:db8:2::81", "192.0.2.81", "2001:db8:2::53"
VPS_UPLINK = "2001:db8:1::2"


def run(*args, data=None):
    return subprocess.run(args, input=data, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE).stdout


def read_exact(stream, length):
    result = b""
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError()
        result += chunk
    return result


def question(query):
    offset, labels = 12, []
    while query[offset]:
        size = query[offset]
        labels.append(query[offset + 1:offset + 1 + size].decode().lower())
        offset += size + 1
    kind = struct.unpack("!H", query[offset + 1:offset + 3])[0]
    return ".".join(labels), kind, query[12:offset + 5]


RECORDS = {("v4only.example.net", 1): "192.0.2.80", ("dual.example.net", 1): SITE4, ("dual.example.net", 28): SITE6}


def answer(query):
    name, kind, asked = question(query)
    value = RECORDS.get((name, kind))
    data = b""
    if value:
        packed = socket.inet_pton(socket.AF_INET6 if kind == 28 else socket.AF_INET, value)
        data = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 60, len(packed)) + packed
    else:
        # NOERROR without data for every other name and type, as for an IPv4-only site's AAAA.
        data = b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 60, 22) + b"\0\0" + struct.pack("!IIIII", 1, 60, 60, 60, 60)
    return query[:2] + struct.pack("!HHHHH", 0x8580, 1, 1 if value else 0, 0 if value else 1, 0) + asked + data


def serve(certificate, key):
    """Runs in the internet namespace."""
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate, key)

    def resolver(stream):
        try:
            with tls.wrap_socket(stream, server_side=True) as stream:
                while True:
                    query = read_exact(stream, struct.unpack("!H", read_exact(stream, 2))[0])
                    response = answer(query)
                    stream.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, EOFError, ValueError):
            pass

    def site(stream):
        with stream:
            stream.sendall(stream.getpeername()[0].encode())

    def listen(address, port, handle):
        server = socket.create_server((address, port), family=socket.AF_INET6 if ":" in address else socket.AF_INET)
        while True:
            stream, _ = server.accept()
            threading.Thread(target=handle, args=(stream,), daemon=True).start()

    for address, port, handle in [(RESOLVER, 853, resolver), (SITE6, 80, site),
                                  (GATEWAY, 80, site), (SITE4, 80, site)]:
        threading.Thread(target=listen, args=(address, port, handle), daemon=True).start()
    threading.Event().wait()


def query(server, name, kind):
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    request = struct.pack("!HHHHHH", 4242, 0x100, 1, 0, 0, 0) + labels + struct.pack("!HH", kind, 1)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as stream:
        stream.settimeout(3)
        stream.sendto(request, (server, 53))
        response = stream.recv(4096)
    assert response[3] & 15 == 0, response.hex()
    offset = 12 + len(labels) + 4
    found = []
    for _ in range(struct.unpack("!H", response[6:8])[0]):
        while response[offset] and response[offset] < 0xc0:
            offset += response[offset] + 1
        offset += 2 if response[offset] >= 0xc0 else 1
        record_type, _, _, length = struct.unpack("!HHIH", response[offset:offset + 10])
        rdata = response[offset + 10:offset + 10 + length]
        offset += 10 + length
        if record_type == kind:
            found.append(socket.inet_ntop(socket.AF_INET6 if kind == 28 else socket.AF_INET, rdata))
    return found


def fetch(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect((address, 80))
        return stream.recv(256).decode()


def veth(left, left_namespace, right, right_namespace, left_address, right_address):
    run("ip", "link", "add", left, "type", "veth", "peer", "name", right)
    for name, namespace, address in ((left, left_namespace, left_address),
                                     (right, right_namespace, right_address)):
        if namespace:
            run("ip", "link", "set", name, "netns", namespace)
        prefix = ["ip", "-n", namespace] if namespace else ["ip"]
        run(*prefix, "address", "add", address, "dev", name, "nodad")
        run(*prefix, "link", "set", name, "up")


if sys.argv[1:2] == ["serve"]:
    serve(sys.argv[2], sys.argv[3])

data = json.load(sys.stdin)
assert [link["ifname"] for link in json.loads(run("ip", "-j", "link"))] == ["lo"]
# Docker makes /proc/sys read-only; expose only the namespaced network controls.
run("mount", "--make-rprivate", "/")
run("mount", "--bind", "/proc/sys/net", "/proc/sys/net")
run("mount", "-o", "remount,bind,rw", "/proc/sys/net")
run("ip", "link", "set", "lo", "up")
for namespace in ("vps", "internet"):
    run("ip", "netns", "add", namespace)
    run("ip", "-n", namespace, "link", "set", "lo", "up")
    run("ip", "netns", "exec", namespace, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
run("ip", "netns", "exec", "vps", "sysctl", "-qw", "net.ipv4.ip_forward=1")

# The member's own network has only IPv6, like the VPS's.
veth("member-up", None, "inet-member", "internet", "2001:db8:3::2/64", "2001:db8:3::1/64")
run("ip", "-6", "route", "add", "default", "via", "2001:db8:3::1")
veth("vps-up", "vps", "inet-vps", "internet", VPS_UPLINK + "/64", "2001:db8:1::1/64")
run("ip", "-n", "vps", "-6", "route", "add", "default", "via", "2001:db8:1::1")
for address in (RESOLVER + "/128", SITE6 + "/128", GATEWAY + "/128", SITE4 + "/32"):
    run("ip", "-n", "internet", "address", "add", address, "dev", "lo", *(["nodad"] if ":" in address else []))
assert not json.loads(run("ip", "-n", "vps", "-j", "-4", "route", "show", "default"))

with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    os.chmod(directory, 0o755)
    key, certificate = directory / "key.pem", directory / "certificate.pem"
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=resolver.fixture", "-addext", "subjectAltName=DNS:resolver.fixture",
        "-keyout", str(key), "-out", str(certificate))
    server_key, member_key = (run("wg", "genkey").strip() for _ in range(2))
    keys = {}
    for name, private in (("server", server_key), ("member", member_key)):
        (directory / name).write_bytes(private + b"\n")
        keys[name] = run("wg", "pubkey", data=private + b"\n").decode().strip()

    # network.sh up and nftables.conf, as the installer writes them.
    run("ip", "-n", "vps", "link", "add", "sirinvpn0", "type", "wireguard")
    run("ip", "netns", "exec", "vps", "wg", "set", "sirinvpn0", "private-key", str(directory / "server"),
        "listen-port", "51820", "peer", keys["member"],
        "allowed-ips", f"10.77.0.2/32,{data['member_ipv6']}/128")
    run("ip", "-n", "vps", "address", "replace", "10.77.0.1/24", "dev", "sirinvpn0")
    run("ip", "-n", "vps", "-6", "address", "replace", data["server_ipv6"] + "/64", "dev", "sirinvpn0", "nodad")
    run("ip", "-n", "vps", "link", "set", "mtu", "1420", "up", "dev", "sirinvpn0")
    run("ip", "netns", "exec", "vps", "nft", "-f", "-", data=data["nftables"].encode())

    configuration = directory / "unbound.conf"
    configuration.write_text('server:\n  username: ""\n  chroot: ""\n  pidfile: ""\n'
                             f'  directory: "{directory}"\n'
                             + data["unbound"].replace("/etc/ssl/certs/ca-certificates.crt", str(certificate)) + "\n")
    run("unbound-checkconf", str(configuration))
    internet = subprocess.Popen(["ip", "netns", "exec", "internet", "python3", __file__, "serve",
                                 str(certificate), str(key)], stdin=subprocess.DEVNULL)
    unbound = subprocess.Popen(["ip", "netns", "exec", "vps", "unbound", "-d", "-c", str(configuration)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        # The member's WireGuard carrier is IPv6; inside it run both families.
        run("ip", "link", "add", "client0", "type", "wireguard")
        run("wg", "set", "client0", "private-key", str(directory / "member"), "peer", keys["server"],
            "allowed-ips", "0.0.0.0/0,::/0", "endpoint", f"[{VPS_UPLINK}]:51820", "persistent-keepalive", "1")
        run("ip", "address", "add", "10.77.0.2/32", "dev", "client0")
        run("ip", "-6", "address", "add", data["member_ipv6"] + "/128", "dev", "client0", "nodad")
        run("ip", "link", "set", "mtu", "1420", "up", "dev", "client0")
        run("ip", "route", "add", "default", "dev", "client0")
        for route in ("10.77.0.0/24", data["ipv6_cidr"], "2001:db8:2::/64", PREFIX + "/96"):
            run("ip", "route", "add", route, "dev", "client0")

        deadline = time.monotonic() + 10
        while True:
            try:
                assert query("10.77.0.1", "dual.example.net", 1) == [SITE4]
                break
            except (OSError, AssertionError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
        assert f"[{VPS_UPLINK}]:51820" in run("wg", "show", "client0", "endpoints").decode()
        for server in ("10.77.0.1", data["server_ipv6"]):
            # DNS64: an IPv4-only name gets an AAAA inside the NAT64 prefix; a real AAAA wins.
            assert query(server, "v4only.example.net", 28) == [GATEWAY], server
            assert query(server, "dual.example.net", 28) == [SITE6], server
            assert query(server, "v4only.example.net", 1) == ["192.0.2.80"], server
        print("Unbound DNS64 over DNS-over-TLS to an IPv6 resolver: synthesized only for IPv4-only names")

        # Members leave through the VPS's IPv6 uplink, masqueraded to its address.
        assert fetch(SITE6) == VPS_UPLINK
        assert fetch(GATEWAY) == VPS_UPLINK
        print("Member IPv6 and NAT64-prefix traffic leaves the IPv6-only VPS masqueraded")

        # IPv4 has no route out of the VPS: refused at once, not left to time out.
        started = time.monotonic()
        try:
            fetch(SITE4)
            raise AssertionError("IPv4 left an IPv6-only VPS")
        except OSError as error:
            assert not isinstance(error, TimeoutError), error
        assert time.monotonic() - started < 2
        print("Member IPv4 to the internet fails immediately with an unreachable error")
    finally:
        unbound.terminate()
        internet.terminate()
        _, errors = unbound.communicate(timeout=5)
        internet.wait(timeout=5)
        if unbound.returncode not in (0, -15):
            raise RuntimeError(errors.decode())
