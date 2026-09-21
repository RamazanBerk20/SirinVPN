"""Real Unbound, private TCP and authenticated TLS resolvers; no external network."""
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


def run(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def read_exact(stream, length):
    result = b""
    while len(result) < length:
        data = stream.recv(length - len(result))
        if not data:
            raise EOFError()
        result += data
    return result


class Resolver:
    def __init__(self, address, tls):
        self.address = address
        self.tls = tls
        self.names = []  # Only synthetic fixture names, in memory.
        self.failing = False
        self.listener = socket.create_server((address, 853 if tls else 53))
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            stream, _ = self.listener.accept()
            threading.Thread(target=self.serve, args=(stream,), daemon=True).start()

    def serve(self, stream):
        try:
            if self.tls:
                stream = self.tls.wrap_socket(stream, server_side=True)
            stream.settimeout(4)
            with stream:
                while True:
                    size = struct.unpack("!H", read_exact(stream, 2))[0]
                    query = read_exact(stream, size)
                    offset = 12
                    labels = []
                    while query[offset]:
                        size = query[offset]
                        labels.append(query[offset+1:offset+1+size].decode())
                        offset += 1+size
                    self.names.append(".".join(labels))
                    question = query[12:offset+5]
                    flags = 0x8182 if self.failing else 0x8180
                    answer = b"" if self.failing else b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(self.address)
                    response = query[:2] + struct.pack("!HHHHH", flags, 1, 0 if self.failing else 1, 0, 0) + question + answer
                    stream.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, EOFError, ValueError):
            pass


def query(name):
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    request = struct.pack("!HHHHHH", 5341, 0x100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
    with socket.create_connection(("127.0.0.1", 1053), timeout=5) as stream:
        stream.sendall(struct.pack("!H", len(request)) + request)
        response = read_exact(stream, struct.unpack("!H", read_exact(stream, 2))[0])
    return response


server_lines, forwarding = json.load(sys.stdin)
assert [link["ifname"] for link in json.loads(run("ip", "-j", "link"))] == ["lo"]
run("ip", "link", "set", "lo", "up")
for address in ["10.61.0.1", "10.61.0.2", "10.61.0.3"]:
    run("ip", "address", "add", address + "/32", "dev", "lo")
with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    key = directory / "key.pem"
    certificate = directory / "certificate.pem"
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=resolver.fixture", "-addext", "subjectAltName=DNS:resolver.fixture",
        "-keyout", str(key), "-out", str(certificate))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate, key)
    default = Resolver("10.61.0.1", tls)
    private = Resolver("10.61.0.2", None)
    specific = Resolver("10.61.0.3", tls)
    configuration = directory / "unbound.conf"
    configuration.write_text('''server:
  interface: 127.0.0.1@1053
  access-control: 127.0.0.0/8 allow
  username: ""
  chroot: ""
  pidfile: ""
  use-syslog: no
  verbosity: 0
  logfile: ""
  do-not-query-localhost: no
  module-config: "iterator"
''' + server_lines.replace("/etc/ssl/certs/ca-certificates.crt", str(certificate)) + "\n" + forwarding + "\n")
    run("unbound-checkconf", str(configuration))
    unbound = subprocess.Popen(["unbound", "-d", "-c", str(configuration)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                response = query("outside.example")
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        assert response[-4:] == socket.inet_aton("10.61.0.1")
        assert query("printer.corp.home")[-4:] == socket.inet_aton("10.61.0.2")
        assert query("app.secure.corp.home")[-4:] == socket.inet_aton("10.61.0.3")
        assert query("nas.corp.home")[-4:] == socket.inet_aton("10.62.0.5")
        private.failing = True
        response = query("unavailable.corp.home")
        assert response[3] & 15 == 2, response.hex()
        assert all(not name.endswith("corp.home") for name in default.names), default.names
        assert all(not name.endswith("secure.corp.home") for name in private.names), private.names
        print("Unbound private split DNS, authenticated TLS, longest suffix, local overrides and no-fallback failure passed")
    finally:
        unbound.terminate()
        _, errors = unbound.communicate(timeout=5)
        if unbound.returncode not in (0, -15):
            raise RuntimeError(errors.decode())
