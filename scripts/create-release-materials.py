#!/usr/bin/env python3
"""Export locked build inputs and available publisher notices for candidate review.

This intentionally includes development and other-target dependencies. It does
not assert that each component is linked into every named artifact. Missing
publisher notices remain explicit review items; this is not a release approval.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tarfile
import tomllib
from urllib.parse import quote
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def notice(name):
    return PurePosixPath(name).name.lower().startswith(("license", "licence", "notice", "copying", "copyright"))


def safe_name(name):
    path = PurePosixPath(name)
    assert not path.is_absolute() and ".." not in path.parts and not any(c in name for c in "\\:\0")
    return path.as_posix()


def crate_notices(archive, expected):
    assert digest(archive) == expected, "Cargo archive checksum mismatch"
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            if member.isfile() and notice(member.name):
                name = safe_name(member.name)
                assert member.size <= 2 * 1024**2, "Oversized notice"
                yield name, source.extractfile(member).read()


def local_notices(directory):
    if directory.is_dir():
        for path in sorted(directory.iterdir()):
            if path.is_file() and not path.is_symlink() and notice(path.name):
                assert path.stat().st_size <= 2 * 1024**2
                yield path.name, path.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, action="append", required=True)
    args = parser.parse_args()
    assert all(path.is_file() for path in args.artifact)
    args.output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("evidence", ROOT / "scripts/record-evidence.py")
    evidence = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evidence)
    identity = evidence.source_identity()
    locked = {(p["name"], p["version"]): p for p in tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]}
    scan = json.loads(args.scan.read_text())
    components, index = [], []
    ecosystems = {"crates.io": "cargo", "npm": "npm", "Go": "golang", "Maven": "maven"}
    with zipfile.ZipFile(args.output / "publisher-notices.zip", "x", zipfile.ZIP_DEFLATED) as output:
        for result in scan["results"]:
            lockfile = Path(result["source"]["path"]).relative_to(ROOT).as_posix()
            for entry in result["packages"]:
                package = entry["package"]
                name, version, ecosystem = (package[key] for key in ["name", "version", "ecosystem"])
                namespace = name.replace(":", "/") if ecosystem == "Maven" else name
                reference = f"pkg:{ecosystems[ecosystem]}/{quote(namespace, safe='/')}@{quote(version, safe='')}"
                component = {"type": "library", "bom-ref": reference, "name": name, "version": version,
                             "purl": reference, "properties": [{"name": "sirin:lockfile", "value": lockfile}]}
                licenses = entry.get("licenses", [])
                if licenses and "UNKNOWN" not in licenses:
                    component["licenses"] = [{"expression": " OR ".join(f"({value})" for value in licenses)}]
                files = []
                if ecosystem == "crates.io":
                    item = locked[(name, version)]
                    if "checksum" in item:
                        archives = list((Path.home() / ".cargo/registry/cache").glob(f"*/{name}-{version}.crate"))
                        if archives:
                            files = list(crate_notices(archives[0], item["checksum"]))
                            component["hashes"] = [{"alg": "SHA-256", "content": item["checksum"]}]
                    elif name == "glib":
                        files = list(local_notices(ROOT / "vendor/glib"))
                        component["properties"].append({"name": "sirin:backport-provenance", "value": "vendor/glib-upstream.json"})
                    else:
                        files = [("LICENSE", (ROOT / "LICENSE").read_bytes())]
                elif ecosystem == "npm":
                    directories = (ROOT / "apps/desktop/node_modules/.pnpm").glob(name.replace("/", "+") + "@" + version + "*")
                    for directory in directories:
                        package_dir = directory / "node_modules" / name
                        metadata = package_dir / "package.json"
                        if metadata.is_file() and json.loads(metadata.read_text()).get("version") == version:
                            files = list(local_notices(package_dir))
                            break
                elif ecosystem == "Go":
                    directory = ROOT / ".cache/android-tools/go" if name == "stdlib" else Path.home() / "go/pkg/mod" / (name + "@v" + version.removeprefix("v"))
                    files = list(local_notices(directory))
                elif ecosystem == "Maven":
                    group, artifact = name.split(":")
                    directory = Path.home() / ".gradle/caches/modules-2/files-2.1" / group / artifact / version
                    for archive in sorted(directory.glob("*/*")):
                        if archive.suffix == ".pom":
                            files.append((archive.name, archive.read_bytes()))
                        elif archive.suffix in (".aar", ".jar"):
                            with zipfile.ZipFile(archive) as source:
                                for member in source.infolist():
                                    if not member.is_dir() and notice(member.filename):
                                        assert member.file_size <= 2 * 1024**2
                                        files.append((archive.name + "/" + safe_name(member.filename), source.read(member)))
                records = []
                for filename, content in files:
                    destination = quote(reference, safe="") + "/" + safe_name(filename)
                    output.writestr(destination, content)
                    records.append({"path": destination, "sha256": hashlib.sha256(content).hexdigest()})
                index.append({"component": reference, "licenses": licenses, "files": records,
                              "publisher_notice_found": any(notice(path) for path, _ in files)})
                components.append(component)
    for artifact in args.artifact:
        components.append({"type": "file", "bom-ref": "artifact:" + artifact.name, "name": artifact.name,
                           "hashes": [{"alg": "SHA-256", "content": digest(artifact)}]})
    root_ref = "sirin:locked-build-inputs"
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
           "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(),
                        "component": {"type": "application", "bom-ref": root_ref, "name": "SirinVPN build inputs", "version": "0.1.0"},
                        "properties": [{"name": "sirin:source_sha256", "value": identity["source_sha256"]},
                                       {"name": "sirin:scope", "value": __doc__.strip()}]},
           "components": components, "compositions": [{"aggregate": "incomplete", "assemblies": [root_ref]}]}
    (args.output / "build-inputs.cdx.json").write_text(json.dumps(bom, indent=2) + "\n")
    (args.output / "notice-index.json").write_text(json.dumps({"source": identity, "scope": __doc__.strip(), "packages": index}, indent=2) + "\n")
    missing = [row["component"] for row in index if not row["publisher_notice_found"]]
    (args.output / "remaining-notice-review.json").write_text(json.dumps(missing, indent=2) + "\n")
    print(f"Exported {len(index)} locked components; {len(missing)} require publisher-notice review. Inventory is not release approval.")


if __name__ == "__main__":
    main()
