"""Endpoint DNS and underlay probes inside the disposable policy container."""
import socket
import struct
import subprocess
import sys
import threading
import time
from policy_packets import probe


def exact(stream, length):
    result = b""
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError()
        result += chunk
    return result


def reply(query, tcp):
    offset, labels = 12, []
    while query[offset]:
        size = query[offset]
        labels.append(query[offset + 1:offset + 1 + size].decode("ascii"))
        offset += size + 1
    offset += 1
    kind, _ = struct.unpack("!HH", query[offset:offset + 4])
    question = query[12:offset + 4]
    name = ".".join(labels)
    transaction = struct.unpack("!H", query[:2])[0] ^ (1 if name.startswith("wrong.") else 0)
    truncated = name.startswith(("tcp.", "slow.")) and not tcp
    value = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6,
                             "203.0.113.8" if kind == 1 else "2001:db8::8")
    answer = b"" if truncated else b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 30, len(value)) + value
    header = struct.pack("!HHHHHH", transaction, 0x8380 if truncated else 0x8180, 1, 0 if truncated else 1, 0, 0)
    return header + question + answer, name.startswith("slow.")


def serve(address, tcp):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as server:
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.bind((address, 53))
        if tcp:
            server.listen(32)
        while True:
            if not tcp:
                query, peer = server.recvfrom(4096)
                server.sendto(reply(query, False)[0], peer)
            else:
                connection, _ = server.accept()

                def handle(connection):
                    with connection:
                        try:
                            length = struct.unpack("!H", exact(connection, 2))[0]
                            result, slow = reply(exact(connection, length), True)
                            framed = struct.pack("!H", len(result)) + result
                            if slow:
                                for byte in framed:
                                    connection.sendall(bytes([byte]))
                                    time.sleep(0.2)
                            else:
                                connection.sendall(framed)
                        except (OSError, EOFError):
                            pass
                threading.Thread(target=handle, args=(connection,), daemon=True).start()


def prepare():
    for address in ["203.0.113.53/24", "2001:db8::53/64"]:
        subprocess.run(["ip", "-n", "sirin-peer", "address", "add", address, "dev", "probe1"], check=True)
    time.sleep(2)
    subprocess.Popen(["ip", "netns", "exec", "sirin-peer", "python3", __file__, "serve"],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    time.sleep(0.2)


def check(controls):
    for address in ["203.0.113.8", "2001:db8::8"]:
        for protocol, port in [("udp", 3333), ("udp", 53), ("tcp", 53), ("tcp", 853), ("tcp", 443)]:
            assert not probe(address, port, protocol), (address, port, "unmarked leak")
    assert probe("2001:db8::8", 51820, "udp", True)
    assert probe("2001:db8::8", 443, "tcp", True)
    assert not probe("203.0.113.8", 51820, "udp", True)
    assert probe("203.0.113.9", 443, "tcp", True) == controls
    assert not probe("203.0.113.9", 3333, "udp", True)
    assert not probe("203.0.113.9", 443, "tcp", False)
    print("IPv6 endpoint: marked outer transport/control available; unmarked IPv4/IPv6/DNS blocked", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "prepare":
        prepare()
    elif sys.argv[1] == "serve":
        for address in ["203.0.113.53", "2001:db8::53"]:
            for tcp in [False, True]:
                threading.Thread(target=serve, args=(address, tcp), daemon=True).start()
        while True:
            time.sleep(30)
    else:
        check(sys.argv[1] == "controls")
