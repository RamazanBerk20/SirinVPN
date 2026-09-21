#!/usr/bin/env python3
"""Import the finite desktop inventory; never infer verification from screenshots."""
import argparse
import hashlib
import html
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATUSES = {"missing", "implemented_unverified", "verified", "adapted", "platform_restriction"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=ROOT / "target/screenshot-catalog-2026-09-20")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--capture-evidence", type=Path,
                        help="Import Android presentation results without promoting runtime status")
    args = parser.parse_args()
    manifest = json.loads((args.catalog / "manifest.json").read_text())
    destination = ROOT / "docs/android/scenarios.json"
    previous = json.loads(destination.read_text()) if destination.exists() else {}
    records = previous.get("scenarios", {})
    for scenario in manifest["scenarios"]:
        key = f'{scenario["family"]}/{scenario["id"]}'
        records.setdefault(key, {
            "operation": scenario["description"],
            "family": scenario["family"],
            "desktop_images": [entry["path"] for entry in scenario["files"]],
            "commands": sorted(set(scenario.get("observed", {}).get("calls", []))),
            "fixture_state": scenario.get("state", {}),
            "roles": "Preserve backend authorization and the role/capability branches in fixture_state.",
            "source": "apps/desktop/src/api.ts",
            "android_approach": "Shared production UI and native service command adapter; see features.md.",
            "status": "missing",
            "evidence": [],
        })
    expected = {f'{s["family"]}/{s["id"]}' for s in manifest["scenarios"]}
    assert set(records) == expected, "Scenario inventory differs from the catalog"
    if args.capture_evidence:
        assert not args.check, "Import and check are separate operations"
        captures = {}
        for line in args.capture_evidence.read_text().splitlines():
            row = json.loads(line)
            captures[row["key"]] = row
        assert set(captures) == expected, "Presentation inventory differs from the catalog"
        sections = []
        for key, capture in captures.items():
            status = "passed" if capture["success"] else capture.get("disposition", "failed")
            for file in capture["files"]:
                path = (ROOT / file["path"]).resolve()
                assert path.is_relative_to(ROOT / "target/android-catalog-evidence"), path
                assert hashlib.sha256(path.read_bytes()).hexdigest() == file["sha256"], path
            records[key]["android_presentation"] = {
                "status": status, "scope": "Fictional presentation only; no runtime verification implied.",
                "bundle_sha256": capture["bundleSha256"], "serial": capture["serial"],
                "files": capture["files"],
                **({"adaptation": capture["adaptation"]} if "adaptation" in capture else {}),
                **({"error": capture["error"]} if "error" in capture else {}),
            }
            links = " ".join(f'<a href="{html.escape(str((ROOT / f["path"]).relative_to(args.capture_evidence.resolve().parent)))}">'
                             f'{html.escape(Path(f["path"]).name)}</a>' for f in capture["files"])
            sections.append(f'<section><h2>{html.escape(key)}</h2><p>Presentation: {html.escape(status)} · '
                            f'Runtime: {html.escape(records[key]["status"])}</p>'
                            f'<p>{html.escape(records[key].get("verification_scope", ""))}</p>'
                            f'<p>{html.escape(capture.get("adaptation", ""))}</p>{links}</section>')
        (args.capture_evidence.parent / "index.html").write_text(
            '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            '<title>SirinVPN Android presentation evidence</title>'
            '<style>body{font:16px system-ui;max-width:72rem;margin:2rem auto;padding:1rem;background:#040815;color:#dbeaff}'
            'a{color:#65d4ff;display:inline-block;margin:.4rem}section{border-top:1px solid #345;padding:1rem 0}'
            'h2{font-size:1.1rem}input{width:90%;padding:.7rem}</style>'
            '<h1>Android catalog evidence</h1><p>646 desktop scenarios. Fictional presentation captures '
            'are separate from real tunnel/native evidence. See docs/android/progress.md.</p>'
            '<label>Filter scenarios <input oninput="document.querySelectorAll(\'section\').forEach(s=>'
            's.hidden=!s.querySelector(\'h2\').textContent.includes(this.value))"></label>'
            + "\n".join(sections))
    for key, row in records.items():
        assert row["status"] in STATUSES, key
        if row["status"] in {"verified", "adapted", "platform_restriction"}:
            assert row["evidence"], f"No evidence for {key}"
        assert row["desktop_images"], key
    hashes = manifest["source_sha256"]
    result = {
        "catalog_revision": manifest["source_revision"],
        "catalog_source_sha256": hashes,
        "counts": manifest["counts"],
        "scenarios": records,
    }
    presentation = Counter(r["android_presentation"]["status"] for r in records.values()
                           if "android_presentation" in r)
    if presentation:
        result["android_presentation_counts"] = dict(presentation)
    if not args.check:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    changed = [name for name, sha in hashes.items() if not (ROOT / name).exists()
               or hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != sha]
    print(json.dumps({"scenarios": len(records), "source_differences": changed,
                      "statuses": {s: sum(r["status"] == s for r in records.values()) for s in sorted(STATUSES)}}))


if __name__ == "__main__":
    main()
