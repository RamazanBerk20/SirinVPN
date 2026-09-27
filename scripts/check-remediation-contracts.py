#!/usr/bin/env python3
"""Check local compatibility, version, manifest and documentation contracts."""
import json
from pathlib import Path
import re
import subprocess
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def main():
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
    version = workspace["workspace"]["package"]["version"]
    for name in ["apps/desktop/package.json", "apps/desktop/src-tauri/tauri.conf.json"]:
        assert json.loads((ROOT / name).read_text())["version"] == version, name
    # The scanner cannot obtain registry license metadata for unpublished local crates.
    overrides = tomllib.loads((ROOT / "osv-scanner.toml").read_text())["PackageOverrides"]
    local = {p['name'] for p in tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
             if p['name'].startswith('sirinvpn-') and 'source' not in p}
    metadata = [p for p in overrides if p['name'] in local]
    assert {p['name'] for p in metadata} == local and len(metadata) == len(local)
    assert all(p['version'] == version and p['license']['override'] ==
               [workspace['workspace']['package']['license']] for p in metadata), 'Stale local license metadata'
    compatibility = json.loads((ROOT / "release/state-compatibility.json").read_text())
    names = [item["state"] for item in compatibility["states"]]
    assert names == sorted(set(names)), "Compatibility states must be unique and sorted"
    for item in compatibility["states"]:
        assert item["reads"]["minimum"] <= item["writes"]["minimum"] <= item["writes"]["maximum"] <= item["reads"]["maximum"]
    manifest = ET.parse(ROOT / "apps/desktop/android/src/main/AndroidManifest.xml")
    android = "{http://schemas.android.com/apk/res/android}"
    vpn = next(s for s in manifest.iter("service") if s.get(android + "name") == ".SirinVpnService")
    assert vpn.get(android + "process") == ":vpn"
    assert vpn.get(android + "stopWithTask") == "false"
    assert vpn.get(android + "permission") == "android.permission.BIND_VPN_SERVICE"
    # New/current remediation guidance must have real local targets. Historical
    # reports with explicitly local-only artifacts retain their original scope.
    schema = json.loads((ROOT / "docs/evidence-schema.json").read_text())
    assert schema["properties"]["schema_version"]["const"] == 1
    assert {"source", "result", "artifacts", "source_changed_during_run"} <= set(schema["required"])
    for name in ["docs/remediation.md", "docs/development.md", "docs/releases.md",
                 "docs/android/build-and-test.md", "SECURITY.md", "PRIVACY.md"]:
        path = ROOT / name
        if not path.exists():
            continue
        for target in re.findall(r"\]\(([^)]+)\)", path.read_text()):
            if "://" in target or target.startswith("#"):
                continue
            assert (path.parent / target.split("#")[0]).exists(), f"Broken local link in {name}"
    files = subprocess.check_output(["git", "ls-files", ".github/workflows"], cwd=ROOT).decode().splitlines()
    files += [str(p.relative_to(ROOT)) for p in (ROOT / ".github/workflows").glob("*.yml")]
    for name in set(files):
        text = (ROOT / name).read_text()
        assert "pull_request_target" not in text and "self-hosted" not in text, name
        for action in re.findall(r"uses:\s*([^\s#]+)", text):
            assert action.startswith("./") or re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), action
    print("Version, state compatibility, Android ownership and workflow pin contracts passed.")


if __name__ == "__main__":
    main()
