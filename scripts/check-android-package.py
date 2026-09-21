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
with zipfile.ZipFile(args.apk) as archive:
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
subprocess.run([str(build/"zipalign"),"-c","-P","16","4",str(args.apk)],check=True)
if not args.unsigned:
    subprocess.run([str(build/"apksigner"),"verify","--min-sdk-version","29",str(args.apk)],check=True)
print(json.dumps({"apk":str(args.apk),"sha256":hashlib.file_digest(args.apk.open('rb'),'sha256').hexdigest(),
    "signed":not args.unsigned,"page_alignment":16384,"libraries":libraries},indent=2))
