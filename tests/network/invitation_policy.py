"""Exercise real bootstrap and permanent WireGuard peers in a disposable container."""
import json
import os
from pathlib import Path
import subprocess
import sys


def run(*args, data=None):
    return subprocess.run(args, input=data, check=True, stdout=subprocess.PIPE).stdout


assert os.environ.get("SIRINVPN_POLICY_ISOLATED") == "1"
assert Path("/.dockerenv").exists()
data = json.load(sys.stdin)
if data["mode"] == "bootstrap":
    run("ip", "netns", "add", "outside")
    run("ip", "link", "add", "eth-test", "type", "veth", "peer", "name", "service0")
    run("ip", "link", "set", "service0", "netns", "outside")
    for namespace, interface, ipv4, ipv6 in [(None, "eth-test", "198.18.0.1", "fdba::1"), ("outside", "service0", "198.18.0.2", "fdba::2")]:
        prefix = ["ip"] + (["-n", namespace] if namespace else [])
        run(*prefix, "address", "add", ipv4 + "/24", "dev", interface)
        run(*prefix, "-6", "address", "add", ipv6 + "/64", "dev", interface, "nodad")
        run(*prefix, "link", "set", interface, "up")
    run("ip", "-n", "outside", "route", "add", "10.77.0.0/24", "via", "198.18.0.1")
    run("ip", "-n", "outside", "-6", "route", "add", "default", "via", "fdba::1")
    assert Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    assert Path("/proc/sys/net/ipv6/conf/all/forwarding").read_text().strip() == "1"
    listener = """import socket, threading, time
def listen(family, address, port):
 s=socket.socket(family); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((address,port)); s.listen()
 while True:
  c,_=s.accept(); c.close()
for family, address in [(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')]:
 for port in (8443,8444):
  threading.Thread(target=listen,args=(family,address,port),daemon=True).start()
time.sleep(120)
"""
    subprocess.Popen(["python3", "-c", listener], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["ip", "netns", "exec", "outside", "python3", "-c", listener], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

namespace = "invite-" + data["mode"]
run("ip", "netns", "add", namespace)
run("ip", "link", "add", "invite0", "type", "wireguard")
server_public = run("wg", "show", "sirinvpn0", "public-key").decode().strip()
run("wg", "set", "invite0", "private-key", data["key"], "peer", server_public,
    "allowed-ips", "0.0.0.0/0,::/0", "endpoint", "127.0.0.1:51820")
run("ip", "link", "set", "invite0", "netns", namespace)
run("ip", "-n", namespace, "link", "set", "lo", "up")
run("ip", "-n", namespace, "address", "add", data["ipv4"] + "/32", "dev", "invite0")
run("ip", "-n", namespace, "-6", "address", "add", data["ipv6"] + "/128", "dev", "invite0", "nodad")
run("ip", "-n", namespace, "link", "set", "invite0", "up")
run("ip", "-n", namespace, "route", "add", "default", "dev", "invite0")
run("ip", "-n", namespace, "-6", "route", "add", "default", "dev", "invite0")
checks = [("10.77.0.1", 8443, True), ("10.77.0.1", 8444, data["mode"] == "permanent"),
          (data["server_ipv6"], 8444, data["mode"] == "permanent"),
          ("198.18.0.2", 8443, data["mode"] == "permanent"), ("fdba::2", 8443, data["mode"] == "permanent")]
client = """import socket,sys,time
host,port,expected=sys.argv[1],int(sys.argv[2]),sys.argv[3]=='True'
deadline=time.monotonic()+(15 if expected else 1)
while True:
 try:
  socket.create_connection((host,port),timeout=1).close(); available=True
 except OSError: available=False
 if available==expected: break
 if time.monotonic()>=deadline: raise SystemExit(1)
"""
for host, port, expected in checks:
    run("ip", "netns", "exec", namespace, "python3", "-c", client, host, str(port), str(expected))
print(data["mode"], "IPv4/IPv6 input and forwarding checks passed")
