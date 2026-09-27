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
import subprocess
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


def supplemental_notices(reference, binding, sources):
    row = sources.get(reference)
    if row is None:
        return [], None
    expected = row.get('crate_sha256', row.get('binary_sha256', row.get('package_json_sha256')))
    assert expected is not None and expected == binding, 'Supplemental notice belongs to different input bytes'
    files = []
    for item in row['files']:
        path = (ROOT / item['path']).resolve(strict=True)
        assert path.is_relative_to(ROOT / 'packaging/third-party') and path.is_file()
        assert digest(path) == item['sha256'], 'Supplemental publisher notice changed'
        basename = item.get('name') or item['url'].rsplit('/', 1)[1]
        name = safe_name('upstream/' + item['sha256'] + '/' + basename)
        files.append((name, path.read_bytes()))
    return files, row


def artifact_inputs(artifacts, components, android_inputs):
    """Conservative target-specific inputs, not a claim about retained symbols."""
    def cargo(target, packages):
        command = ['cargo', 'tree', '--locked', '--offline', '--target', target,
                   '-e', 'normal,no-proc-macro', '--prefix', 'none', '--format', '{p}']
        for package in packages:
            command.extend(['-p', package])
        lines = subprocess.check_output(command, cwd=ROOT, text=True, timeout=90).splitlines()
        return {'pkg:cargo/' + line.split()[0] + '@' + quote(line.split()[1][1:], safe='')
                for line in lines if line.strip()}

    frontend = set()
    def npm(tree):
        for name, package in tree.get('dependencies', {}).items():
            reference = 'pkg:npm/' + quote(name, safe='/') + '@' + quote(package['version'], safe='')
            if reference not in frontend:
                frontend.add(reference)
                npm(package)
    for tree in json.loads(subprocess.check_output(
            ['pnpm', '--dir', 'apps/desktop', 'list', '--prod', '--depth', 'Infinity', '--json'],
            cwd=ROOT, timeout=90)):
        npm(tree)
    server = cargo('x86_64-unknown-linux-gnu', ['sirinvpn-server'])
    server |= cargo('aarch64-unknown-linux-gnu', ['sirinvpn-server'])
    known = {row['bom-ref'] for row in components}
    android = {p for p in known if p.startswith('pkg:golang/')}
    if any(path.suffix == '.apk' for path in artifacts):
        assert android_inputs, 'Android materials require the resolved release runtime inventory'
        resolved = json.loads(android_inputs.read_text())
        assert resolved['lockfile_sha256'] == digest(ROOT / 'apps/desktop/android/gradle.lockfile')
        assert resolved['configuration'] == 'universalReleaseRuntimeClasspath' and resolved['artifacts']
        for row in resolved['artifacts']:
            group, name, version = row['component'].split(':')
            directory = Path.home() / '.gradle/caches/modules-2/files-2.1' / group / name / version
            matches = list(directory.glob('*/' + row['filename']))
            assert matches and all(digest(p) == row['sha256'] for p in matches), 'Resolved Android input changed'
            android.add('pkg:maven/' + group + '/' + name + '@' + quote(version, safe=''))
    results = []
    for artifact in artifacts:
        selected = set(frontend) | server
        if artifact.suffix == '.apk':
            with zipfile.ZipFile(artifact) as archive:
                abis = {p.split('/')[1] for p in archive.namelist() if p.startswith('lib/') and p.endswith('.so')}
            assert abis and abis <= {'arm64-v8a', 'x86_64'}, 'Unexpected Android ABI'
            for abi in abis:
                selected |= cargo({'arm64-v8a': 'aarch64-linux-android', 'x86_64': 'x86_64-linux-android'}[abi],
                                  ['sirinvpn-android-runtime', 'sirinvpn-desktop'])
            selected |= android
        elif artifact.suffix == '.exe':
            selected |= cargo('x86_64-pc-windows-gnullvm',
                              ['sirinvpn-desktop', 'sirinvpn-cli', 'sirinvpn-windows-service'])
        elif artifact.suffix in ('.deb', '.AppImage'):
            selected |= cargo('x86_64-unknown-linux-gnu', ['sirinvpn-desktop', 'sirinvpn-cli',
                              'sirinvpn-linux-helper', 'sirinvpn-release', 'sirinvpn-release-fetch'])
        else:
            raise ValueError('Unknown artifact type: ' + artifact.name)
        assert selected <= known, 'Artifact resolution contains inputs absent from the locked inventory'
        results.append({'filename': artifact.name, 'sha256': digest(artifact), 'size': artifact.stat().st_size,
                        'selected_inputs': sorted(selected), 'other_build_inputs': sorted(known-selected)})
    return {'scope': 'Target-specific normal Rust dependencies (without proc macros), production npm closure, '
                     'both embedded VPS targets; Android includes its resolved Maven artifacts and locked Go inputs. '
                     'This is a conservative input inventory: dead stripping/R8 may remove code, and '
                     'Maven metadata without an artifact stays in the full build inventory. AppImage system ELF provenance is embedded in '
                     'usr/share/doc/sirinvpn/system-notices/inventory.json. External SDK/runtime notices '
                     'and generated-code obligations require separate review.', 'artifacts': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, action="append", required=True)
    parser.add_argument("--android-inputs", type=Path)
    args = parser.parse_args()
    assert all(path.is_file() for path in args.artifact)
    args.output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("evidence", ROOT / "scripts/record-evidence.py")
    evidence = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evidence)
    identity = evidence.source_identity()
    locked = {(p["name"], p["version"]): p for p in tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]}
    sources = json.loads((ROOT / 'release/publisher-notice-sources.json').read_text())['components']
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
                files, supplemental = [], None
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
                    extra, supplemental = supplemental_notices(reference, item.get('checksum'), sources)
                    files.extend(extra)
                elif ecosystem == "npm":
                    directories = (ROOT / "apps/desktop/node_modules/.pnpm").glob(name.replace("/", "+") + "@" + version + "*")
                    for directory in directories:
                        package_dir = directory / "node_modules" / name
                        metadata = package_dir / "package.json"
                        if metadata.is_file() and json.loads(metadata.read_text()).get("version") == version:
                            files = list(local_notices(package_dir))
                            extra, supplemental = supplemental_notices(reference, digest(metadata), sources)
                            files.extend(extra)
                            break
                elif ecosystem == "Go":
                    directory = ROOT / ".cache/android-tools/go" if name == "stdlib" else Path.home() / "go/pkg/mod" / (name + "@v" + version.removeprefix("v"))
                    files = list(local_notices(directory))
                elif ecosystem == "Maven":
                    group, artifact = name.split(":")
                    directory = Path.home() / ".gradle/caches/modules-2/files-2.1" / group / artifact / version
                    bindings = {}
                    for archive in sorted(directory.glob("*/*")):
                        if archive.suffix == ".pom":
                            files.append((archive.name, archive.read_bytes()))
                        elif archive.suffix in (".aar", ".jar"):
                            bindings[archive.name] = digest(archive)
                            with zipfile.ZipFile(archive) as source:
                                for member in source.infolist():
                                    if not member.is_dir() and notice(member.filename):
                                        assert member.file_size <= 2 * 1024**2
                                        files.append((archive.name + "/" + safe_name(member.filename), source.read(member)))
                    extra, supplemental = supplemental_notices(reference, bindings, sources)
                    files.extend(extra)
                records = []
                for filename, content in files:
                    destination = quote(reference, safe="") + "/" + safe_name(filename)
                    output.writestr(destination, content)
                    records.append({"path": destination, "sha256": hashlib.sha256(content).hexdigest()})
                index.append({"component": reference, "licenses": licenses, "files": records,
                              "publisher_notice_found": any(notice(path) for path, _ in files),
                              "supplemental_provenance": supplemental})
                components.append(component)
    inventory = artifact_inputs(args.artifact, components, args.android_inputs)
    present = {row['component'] for row in index if row['publisher_notice_found']}
    for artifact in inventory['artifacts']:
        artifact['missing_selected_notices'] = sorted(set(artifact['selected_inputs']) - present)
        selected = set(artifact['selected_inputs'])
        rows = [row for row in index if row['component'] in selected]
        destination = args.output / (artifact['filename'] + '.notices.zip')
        with zipfile.ZipFile(args.output / 'publisher-notices.zip') as source, \
                zipfile.ZipFile(destination, 'x', zipfile.ZIP_DEFLATED) as notices:
            notices.writestr('inventory.json', json.dumps({'artifact': artifact,
                             'scope': inventory['scope'], 'components': rows}, indent=2) + '\n')
            for row in rows:
                for file in row['files']:
                    notices.writestr(file['path'], source.read(file['path']))
        artifact['notice_bundle_sha256'] = digest(destination)
    (args.output / 'artifact-inputs.json').write_text(json.dumps(inventory, indent=2) + '\n')
    for artifact in args.artifact:
        components.append({"type": "file", "bom-ref": "artifact:" + artifact.name, "name": artifact.name,
                           "hashes": [{"alg": "SHA-256", "content": digest(artifact)}]})
    root_ref = "sirin:locked-build-inputs"
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
           "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(),
                        "component": {"type": "application", "bom-ref": root_ref, "name": "SirinVPN build inputs", "version": tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']},
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
