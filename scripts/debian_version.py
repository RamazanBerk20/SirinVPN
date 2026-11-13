#!/usr/bin/env python3
"""Give a Tauri-built .deb the Debian spelling of its SemVer version.

Tauri writes the SemVer version into `Version:` unchanged. Debian reads
`1.0.0-rc.1` as upstream `1.0.0` with revision `rc.1`, which sorts after the
final `1.0.0`; `1.0.0~rc.1` sorts before it. The installed-package checks in
crates/release/src/linux_debian_update.rs (`debian_package_version`) expect the
same mapping. Only control.tar.* changes; data.tar.* keeps its exact bytes.

usage: debian_version.py PACKAGE.deb      rewrite Version: in place
       debian_version.py --print VERSION  print the Debian version
"""
import io
import json
from pathlib import Path
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?")


def debian_version(version: str) -> str:
    match = SEMVER.fullmatch(version)
    if not match or "-" in (match[4] or "") or "-" in (match[5] or ""):
        raise ValueError(f"{version} has no Debian package version")
    return version.replace("-", "~", 1)


def read_ar(data: bytes) -> list[tuple[bytes, bytes]]:
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    members, offset = [], 8
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise ValueError("malformed ar header")
        size = int(header[48:58])
        members.append((header, data[offset + 60:offset + 60 + size]))
        offset += 60 + size + (size & 1)
    return members


def write_ar(members: list[tuple[bytes, bytes]]) -> bytes:
    out = bytearray(b"!<arch>\n")
    for header, body in members:
        out += header[:48] + str(len(body)).ljust(10).encode() + header[58:60] + body
        if len(body) & 1:
            out += b"\n"
    return bytes(out)


def set_control_version(control_archive: bytes, version: str) -> bytes:
    source = tarfile.open(fileobj=io.BytesIO(control_archive), mode="r:gz")
    output = io.BytesIO()
    # Same member order, owners, modes and times; only the control text changes.
    with source, tarfile.open(fileobj=output, mode="w:gz", format=source.format) as target:
        for member in source.getmembers():
            body = source.extractfile(member).read() if member.isreg() else None
            if member.name.removeprefix("./") == "control":
                text, count = re.subn(r"(?m)^Version: .*$", f"Version: {version}", body.decode("utf-8"))
                if count != 1:
                    raise ValueError("control must have exactly one Version field")
                body = text.encode("utf-8")
                member.size = len(body)
            target.addfile(member, io.BytesIO(body) if body is not None else None)
    return output.getvalue()


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--print":
        print(debian_version(sys.argv[2]))
        return
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    package = Path(sys.argv[1])
    version = debian_version(json.loads((ROOT / "apps/desktop/src-tauri/tauri.conf.json").read_text())["version"])
    members = read_ar(package.read_bytes())
    names = [header[:16].rstrip(b" /") for header, _ in members]
    if names[:1] != [b"debian-binary"] or names.count(b"control.tar.gz") != 1:
        raise ValueError("expected debian-binary followed by control.tar.gz")
    members = [(h, set_control_version(b, version) if n == b"control.tar.gz" else b) for (h, b), n in zip(members, names)]
    temporary = package.with_name(package.name + ".tmp")
    temporary.write_bytes(write_ar(members))
    temporary.replace(package)


if __name__ == "__main__":
    assert debian_version("1.0.0-rc.1") == "1.0.0~rc.1" and debian_version("1.0.0") == "1.0.0"
    main()
