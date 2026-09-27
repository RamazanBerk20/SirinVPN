#!/usr/bin/env python3
"""Bound first-party source file size, excluding Git-ignored build products."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EXTENSIONS = {".rs", ".ts", ".tsx", ".css", ".kt", ".sh", ".py", ".mjs", ".js", ".c", ".h", ".ps1"}
LIMIT = 1000


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def inventory(reference=None):
    if reference:
        paths = git("ls-tree", "-r", "--name-only", "-z", reference)
    else:
        paths = git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
    files = []
    for name in sorted(set(paths.decode().split("\0"))):
        # This exact third-party tree is separately bound by check-vendored.py.
        if name.startswith("vendor/glib/"):
            continue
        path = ROOT / name
        if path.suffix not in EXTENSIONS or (not reference and not path.is_file()):
            continue
        source = git("show", f"{reference}:{name}") if reference else path.read_bytes()
        files.append({"path": name, "lines": len(source.splitlines())})
    return {
        "files": len(files),
        "lines": sum(item["lines"] for item in files),
        "over_limit": [item for item in files if item["lines"] > LIMIT],
        "largest": sorted(files, key=lambda item: item["lines"], reverse=True)[:30],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", help="Optional Git revision for comparison")
    parser.add_argument("--output", type=Path, help="Write the measured inventory as JSON")
    args = parser.parse_args()
    current = inventory()
    report = {"limit": LIMIT, "current": current}
    if args.baseline:
        report["baseline_revision"] = git("rev-parse", args.baseline).decode().strip()
        report["baseline"] = inventory(args.baseline)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Source inventory: {current['files']} files, {current['lines']} lines, "
          f"{len(current['over_limit'])} files over {LIMIT} lines.")
    for item in current["over_limit"]:
        print(f"{item['path']}: {item['lines']} lines", file=sys.stderr)
    return 1 if current["over_limit"] else 0


if __name__ == "__main__":
    sys.exit(main())
