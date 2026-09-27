#!/usr/bin/env python3
"""Pinned advisory/license gate with bounded, reviewed advisory dispositions.

Pass --android-lock after generating the reviewed Gradle runtime lockfile.
Raw results retain every finding; see docs/dependency-policy.md for exceptions.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
VERSION = "2.6.0"
DIGEST = "ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108"
LICENSES = "MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,Unicode-3.0,Unlicense,CC0-1.0,AGPL-3.0-only,Zlib,OpenSSL,BSL-1.0,0BSD,MIT-0,OFL-1.1,BlueOak-1.0.0"

# Reviewed 2026-09-27. Exact IDs AND package versions only, never alias expansion.
# Rationale, scope, mitigation and removal criteria: docs/dependency-policy.md.
REVIEW_UNTIL = datetime.date(2026, 12, 27)
REVIEWS = {
    "RUSTSEC-2024-0429": ("crates.io", "glib", "0.18.5", "verified backport"),
    "GHSA-wrw7-89jp-8q8g": ("crates.io", "glib", "0.18.5", "verified backport"),
    "RUSTSEC-2024-0370": ("crates.io", "proc-macro-error", "1.0.4", "unmaintained"),
    "RUSTSEC-2025-0081": ("crates.io", "unic-char-property", "0.9.0", "unmaintained"),
    "RUSTSEC-2025-0075": ("crates.io", "unic-char-range", "0.9.0", "unmaintained"),
    "RUSTSEC-2025-0080": ("crates.io", "unic-common", "0.9.0", "unmaintained"),
    "RUSTSEC-2025-0100": ("crates.io", "unic-ucd-ident", "0.9.0", "unmaintained"),
    "RUSTSEC-2025-0098": ("crates.io", "unic-ucd-version", "0.9.0", "unmaintained"),
    "GO-2026-5932": ("Go", "golang.org/x/crypto", "0.56.0", "OpenPGP not imported"),
}


def verify_go_imports():
    """The OpenPGP disposition requires absence on both shipped Android ABIs."""
    directory = ROOT / "apps/desktop/android/wireguard"
    go = os.environ.get("GO_BIN", "go")
    version = next(line.split()[1] for line in (directory / "go.mod").read_text().splitlines()
                   if line.startswith("go "))
    actual = subprocess.check_output([go, "env", "GOVERSION"], cwd=directory, text=True, timeout=90).strip()
    assert actual == "go" + version, f"Use pinned Go {version} for dependency review"
    for arch in ("arm64", "amd64"):
        env = dict(os.environ, GOOS="android", GOARCH=arch, CGO_ENABLED="1", GOWORK="off")
        imports = subprocess.check_output([go, "list", "-mod=readonly", "-deps", "./..."],
                                          cwd=directory, env=env, text=True, timeout=90).splitlines()
        assert "org.sirinvpn/wireguard" in imports, "Incomplete Android import graph"
        assert not any(p == "golang.org/x/crypto/openpgp" or p.startswith("golang.org/x/crypto/openpgp/")
                       for p in imports), "OpenPGP is imported; GO-2026-5932 requires remediation"
        print(f"Android {arch}: checked {len(imports)} imports; OpenPGP absent")


def review_results(report, scanner_code, paths, today):
    """Classify only complete successful scans; leave the raw report untouched."""
    assert scanner_code in (0, 1), f"OSV scanner failed with exit code {scanner_code}"
    assert not report.get("experimental_generic_findings"), "Unreviewed generic scanner findings"
    results = report["results"]
    expected = {str((ROOT / path).resolve()) for path in paths}
    observed = {item["source"]["path"] for item in results}
    assert expected == observed and len(results) == len(expected), "Incomplete lockfile scan"
    assert report["experimental_config"]["licenses"]["allowlist"] == LICENSES.split(","), "License scan missing"
    reviewed, blocked = [], []
    for result in results:
        assert result["source"]["type"] == "lockfile" and result["packages"], "Empty lockfile scan"
        for item in result["packages"]:
            package = item["package"]
            identity = tuple(package[key] for key in ("ecosystem", "name", "version"))
            label = f"{package['ecosystem']}/{package['name']}@{package['version']}"
            if item.get("license_violations"):
                blocked.append(f"{label}: license policy violation")
            for advisory in item.get("vulnerabilities", []):
                review = REVIEWS.get(advisory["id"])
                accepted = review is not None and identity == review[:3] and today < REVIEW_UNTIL
                if accepted and review[3] == "unmaintained":
                    affected = [a for a in advisory["affected"] if a["package"]["name"] == package["name"]]
                    accepted = bool(affected) and all(a.get("database_specific", {}).get("informational")
                                                     == "unmaintained" for a in affected)
                    accepted = accepted and not advisory.get("severity")
                line = f"{label}: {advisory['id']}"
                if accepted:
                    reviewed.append(f"{line} — {review[3]} (review expires {REVIEW_UNTIL})")
                else:
                    blocked.append(line)
    assert bool(scanner_code) == bool(reviewed or blocked), "Scanner exit code and findings disagree"
    return reviewed, blocked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--android-lock", type=Path)
    args = parser.parse_args()
    assert not args.output.exists(), "Use a new output path; raw scan evidence is not overwritten"
    subprocess.run([sys.executable, str(ROOT / "scripts/check-vendored.py")], check=True)
    verify_go_imports()
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
               "--licenses=" + LICENSES]
    for path in paths:
        command.extend(["--lockfile", path])
    scanner_code = subprocess.run(command, cwd=ROOT, timeout=600, check=False).returncode
    assert scanner_code in (0, 1), f"OSV scanner failed with exit code {scanner_code}"
    report = json.loads(args.output.read_text())
    reviewed, blocked = review_results(report, scanner_code, paths, datetime.datetime.now(datetime.UTC).date())
    count = sum(len(result["packages"]) for result in report["results"])
    lines = [f"Dependency scan: {count} packages; {len(blocked)} blocking findings; {len(reviewed)} reviewed notices.",
             "", f"Raw OSV exit code: {scanner_code}. The JSON artifact retains every finding.", ""]
    lines.extend(f"- BLOCKING: {line}" for line in blocked)
    lines.extend(f"- REVIEWED: {line}" for line in reviewed)
    summary = "\n".join(lines) + "\n"
    args.output.with_suffix(".md").write_text(summary)
    print(summary)
    return int(bool(blocked))


if __name__ == "__main__":
    raise SystemExit(main())
