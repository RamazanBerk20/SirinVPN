#!/usr/bin/env python3
"""Pinned advisory/license gate. Scanner failure is never a clean result.

Pass --android-lock after generating the reviewed Gradle runtime lockfile.
Results include informational findings; exceptions require explicit review.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
VERSION = "2.6.0"
DIGEST = "ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--android-lock", type=Path)
    args = parser.parse_args()
    subprocess.run([sys.executable, str(ROOT / "scripts/check-vendored.py")], check=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tool = ROOT / ".cache/remediation-tools/osv-scanner"
    if not tool.is_file():
        tool.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://github.com/google/osv-scanner/releases/download/v{VERSION}/osv-scanner_linux_amd64"
        with urllib.request.urlopen(url, timeout=90) as response:
            content = response.read(80 * 1024 * 1024 + 1)
        assert len(content) <= 80 * 1024 * 1024 and hashlib.sha256(content).hexdigest() == DIGEST
        temporary = tool.with_suffix(".download")
        with temporary.open("xb") as output:
            output.write(content)
        os.chmod(temporary, 0o755)
        temporary.replace(tool)
    with tool.open("rb") as executable:
        assert hashlib.file_digest(executable, "sha256").hexdigest() == DIGEST, "Scanner digest mismatch"
    paths = ["Cargo.lock", "apps/desktop/pnpm-lock.yaml", "apps/desktop/android/wireguard/go.mod"]
    if args.android_lock:
        assert args.android_lock.is_file(), "Required Android dependency lock is unavailable"
        paths.append(str(args.android_lock))
    command = [str(tool), "scan", "source", "--format", "json", "--output-file", str(args.output),
               "--config", str(ROOT / "osv-scanner.toml"), "--no-call-analysis", "rust", "--no-call-analysis", "go", "--all-packages",
               "--licenses=MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,Unicode-3.0,Unlicense,CC0-1.0,AGPL-3.0-only,Zlib,OpenSSL,BSL-1.0,0BSD,MIT-0,OFL-1.1,BlueOak-1.0.0"]
    for path in paths:
        command.extend(["--lockfile", path])
    return subprocess.run(command, cwd=ROOT, timeout=600, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
