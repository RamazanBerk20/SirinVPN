#!/usr/bin/env python3
"""A disposable, bounded VPS reachable only through host loopback from the emulator."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"vm"))
from lab import Lab,free_port

parser=argparse.ArgumentParser()
parser.add_argument("--output",type=Path,required=True)
parser.add_argument("--base",type=Path,default=Path(".cache/debian-13-genericcloud-amd64.qcow2"))
parser.add_argument("--duration",type=int,default=3600,choices=range(60,10801),metavar="SECONDS")
args=parser.parse_args()
args.output.mkdir(parents=True,exist_ok=False)
with Lab(args.output) as lab:
    ports=[free_port() for _ in range(3)]
    server=lab.guest(args.base,"android-vps",memory=1024,ipv6=False,
        forwarded_ports=[("udp",ports[0],ports[0]),("udp",ports[1],ports[1]),("tcp",ports[2],ports[2])])
    server.start()
    fingerprint=subprocess.check_output(["ssh-keygen","-lf",str(server.directory/"guest-host-key.pub")],text=True).split()[1]
    metadata={"fixture":server.run_id,"host":"10.0.2.2","ssh_port":server.port,"username":"sirin",
        "authentication":"private_key","host_key_sha256":fingerprint,"name":"Android isolated VPS",
        "private_key_source":str(server.key),"agent_socket":str(server.agent_path),
        "dns_upstream":{"mode":"recursive"},"private_dns_records":[],"replace_existing_installation":False,
        "transport":{"public_host":"10.0.2.2","wireguard_port":ports[0],"obfuscated_udp_port":ports[1],"tcp_tls_port":ports[2]}}
    (args.output/"fixture.json").write_text(json.dumps(metadata))
    print("Isolated VPS ready; temporary keys stay in its private fixture directory.",flush=True)
    deadline=time.monotonic()+args.duration
    while time.monotonic()<deadline and not (args.output/"stop-fixtures").exists():
        time.sleep(1)
    (args.output/"fixture.json").unlink(missing_ok=True)
