"""Synthetic endpoint handoff, in a disposable container with no host routes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(*args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE, check=True).stdout


assert os.environ.get("SIRINVPN_POLICY_ISOLATED") == "1"
assert Path("/.dockerenv").exists()
data = json.load(sys.stdin)
mode = sys.argv[1]
if mode == "prepare":
    run("python3", "tests/network/member_lifecycle.py", "prepare", data=json.dumps(data).encode())
    run("ip", "netns", "add", "outside")
    run("ip", "link", "add", "eth-test", "type", "veth", "peer", "name", "service0")
    run("ip", "link", "set", "service0", "netns", "outside")
    for ns, interface, v4, v6 in [(None, "eth-test", "198.18.0.1", "fdba::1"),
                                 ("outside", "service0", "198.18.0.2", "fdba::2")]:
        prefix = ["ip"] + (["-n", ns] if ns else [])
        run(*prefix, "address", "add", v4 + "/24", "dev", interface)
        run(*prefix, "-6", "address", "add", v6 + "/64", "dev", interface, "nodad")
        run(*prefix, "link", "set", interface, "up")
    run("ip", "-n", "outside", "route", "add", "10.77.0.0/24", "via", "198.18.0.1")
    run("ip", "-n", "outside", "-6", "route", "add", "default", "via", "fdba::1")
    run("ip", "-n", "member0", "route", "add", "default", "dev", "client0")
    run("ip", "-n", "member0", "-6", "route", "add", "default", "dev", "client0")
    listener = """import socket, threading, time
def listen(family, address, port):
 s=socket.socket(family); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((address,port)); s.listen()
 while True:
  c,_=s.accept(); c.close()
for family, address in [(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')]:
 for port in (53,8443,8444):
  threading.Thread(target=listen,args=(family,address,port),daemon=True).start()
time.sleep(120)
"""
    for prefix in [[], ["ip", "netns", "exec", "outside"]]:
        subprocess.Popen([*prefix, "python3", "-c", listener],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.2)
else:
    permitted = mode == "open"
    checks = [("10.77.0.1", 8443, True), ("10.77.0.1", 53, permitted),
              ("10.77.0.1", 8444, permitted), (data["server_ipv6"], 8444, permitted),
              ("198.18.0.2", 8443, permitted), ("fdba::2", 8443, permitted)]
    probe = """import socket,sys,time
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
        run("ip", "netns", "exec", "member0", "python3", "-c", probe, host, str(port), str(expected))
    print(mode, "IPv4/IPv6 control and data checks passed")
