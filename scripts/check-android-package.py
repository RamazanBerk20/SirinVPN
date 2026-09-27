#!/usr/bin/env python3
"""Check the actual APK: ABIs, ELF load alignment, zip alignment and signature."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import zipfile

parser=argparse.ArgumentParser()
parser.add_argument("apk",type=Path)
parser.add_argument("--abis",default="arm64-v8a,x86_64")
parser.add_argument("--unsigned",action="store_true")
args=parser.parse_args()
sdk=Path(os.environ.get("ANDROID_HOME",str(Path.home()/"Android/Sdk")))
build=sdk/"build-tools/36.0.0"
expected=set(args.abis.split(","))
libraries=[]
payloads=[]
with zipfile.ZipFile(args.apk) as archive:
    declared=json.loads(archive.read("assets/server-payloads/sha256.json"))
    assert set(declared)=={"aarch64","x86_64"}, "Both VPS payload architectures are required"
    root=Path(__file__).resolve().parents[1]
    for architecture, expected_digest in declared.items():
        data=archive.read(f"assets/server-payloads/{architecture}/sirinvpn-server")
        digest=hashlib.sha256(data).hexdigest()
        source=root/f"target/server-payloads/{architecture}-unknown-linux-gnu/release/sirinvpn-server"
        assert data[:4]==b"\x7fELF" and digest==expected_digest
        with source.open("rb") as current:
            assert hashlib.file_digest(current,"sha256").hexdigest()==digest, "Bundled VPS payload differs from current build"
        payloads.append({"architecture":architecture,"size":len(data),"sha256":digest})
    for entry in archive.namelist():
        assert not any(word in entry.lower() for word in ("acceptance-invitation","acceptance-vps-input","screenshot-fixture","invite-code.txt")),entry
        if not entry.startswith("lib/") or not entry.endswith(".so"):continue
        data=archive.read(entry)
        assert data[:6]==b"\x7fELF\x02\x01",entry
        offset=struct.unpack_from("<Q",data,32)[0]
        size,count=struct.unpack_from("<HH",data,54)
        loads=[struct.unpack_from("<IIQQQQQQ",data,offset+i*size) for i in range(count)]
        alignments=[p[7] for p in loads if p[0]==1]
        assert alignments and all(a>=16384 for a in alignments),(entry,alignments)
        libraries.append({"path":entry,"load_alignments":alignments})
    actual={entry["path"].split('/')[1] for entry in libraries}
    assert actual==expected,(actual,expected)
    for abi in expected:
        assert {Path(e['path']).name for e in libraries if e['path'].split('/')[1]==abi} >= {
            'libsirinvpn_desktop_lib.so','libsirinvpn_android_runtime.so','libsirin_wireguard.so'}
subprocess.run([str(build/"zipalign"),"-c","-P","16","4",str(args.apk)],check=True,timeout=60)
badging=subprocess.check_output([str(build/"aapt2"),"dump","badging",str(args.apk)],timeout=60).decode()
assert "minSdkVersion:'29'" in badging and "targetSdkVersion:'36'" in badging
debuggable="application-debuggable" in badging
certificates=[]
if not args.unsigned:
    verified=subprocess.check_output([str(build/"apksigner"),"verify","--print-certs","--min-sdk-version","29",str(args.apk)],timeout=60).decode()
    certificates=[line.split(': ',1)[1] for line in verified.splitlines() if 'certificate SHA-256 digest:' in line]
    assert certificates, "APK signer certificate digest missing"
print(json.dumps({"apk":str(args.apk),"sha256":hashlib.file_digest(args.apk.open('rb'),'sha256').hexdigest(),
    "signed":not args.unsigned,"signer_certificate_sha256":certificates,"debuggable":debuggable,
    "signing_category":"development" if debuggable else "non-debuggable-unqualified",
    "min_sdk":29,"target_sdk":36,"page_alignment":16384,"libraries":libraries,"server_payloads":payloads},indent=2))
