#!/usr/bin/env python3
"""Validate workflow syntax, expressions and shell with pinned actionlint."""
import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / ".cache/remediation-tools/actionlint"
DIGEST = "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
ARCHIVE = TOOL.with_suffix(".tar.gz")


def main():
    shellcheck = shutil.which("shellcheck")
    assert shellcheck, "Required workflow validator shellcheck is missing"
    if not ARCHIVE.is_file():
        url = "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz"
        with urllib.request.urlopen(url, timeout=90) as response:
            content = response.read(16 * 1024 * 1024 + 1)
        assert len(content) <= 16 * 1024 * 1024 and hashlib.sha256(content).hexdigest() == DIGEST
        ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
        ARCHIVE.write_bytes(content)
    content = ARCHIVE.read_bytes()
    assert hashlib.sha256(content).hexdigest() == DIGEST, "Workflow validator digest mismatch"
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        member = archive.getmember("actionlint")
        assert member.isfile() and member.size < 32 * 1024 * 1024
        TOOL.write_bytes(archive.extractfile(member).read())
    TOOL.chmod(0o755)
    return subprocess.run([str(TOOL), "-shellcheck", shellcheck], cwd=ROOT, timeout=120, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
