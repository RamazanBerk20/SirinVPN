#!/usr/bin/env python3
"""Verify the complete, reviewed GLib backport before using its advisory disposition."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def verify():
    provenance = json.loads((ROOT / "vendor/glib-upstream.json").read_text())
    source = ROOT / "vendor/glib"
    assert source.is_dir() and not source.is_symlink(), "Unexpected vendored root"
    digest = hashlib.sha256()
    for path in sorted(source.rglob("*")):
        assert not path.is_symlink(), "Unexpected vendored link"
        if path.is_dir():
            continue
        assert path.is_file() and not path.is_symlink(), "Unexpected vendored entry"
        name = path.relative_to(source).as_posix().encode()
        content = path.read_bytes()
        digest.update(name + b"\0" + str(len(content)).encode() + b"\0" + content)
    assert digest.hexdigest() == provenance["tree_sha256"], "Vendored GLib differs from the reviewed backport"
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
    assert workspace["patch"]["crates-io"]["glib"] == {"path": "vendor/glib"}
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    assert manifest["package"]["name"] == provenance["name"] == "glib"
    assert manifest["package"]["version"] == provenance["version"] == "0.18.5"
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    libraries = [p for p in lock["package"] if p["name"] == "glib"]
    assert len(libraries) == 1 and libraries[0]["version"] == "0.18.5"
    assert "source" not in libraries[0], "Registry GLib would bypass the backport"
    return provenance


if __name__ == "__main__":
    print("Verified GLib reviewed source-tree binding and Cargo path selection: "
          + verify()["tree_sha256"])
