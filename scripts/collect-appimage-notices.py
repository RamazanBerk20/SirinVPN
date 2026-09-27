#!/usr/bin/env python3
"""Bind bundled system ELF files to Debian packages and preserve their notices.

Run inside the same Debian builder that produced the AppDir, before repacking.
Application dependencies and the AppImage launcher/runtime are separate inputs.
An unidentified system library fails the collection instead of disappearing.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def build_id(path):
    result = subprocess.run(['readelf', '-n', str(path)], capture_output=True, text=True, check=True)
    found = re.search(r'Build ID: ([0-9a-f]+)', result.stdout)
    return found[1] if found else None


def package_source(path):
    result = subprocess.run(['dpkg-query', '-S', '*/' + path.name], capture_output=True, text=True)
    identity = build_id(path)
    matches = []
    for line in result.stdout.splitlines():
        package, separator, name = line.partition(': /')
        source = Path('/' + name)
        if not separator or not source.is_file():
            continue
        with source.open('rb') as original:
            elf = original.read(4) == b'\x7fELF'
        if elf:
            if (identity and build_id(source) == identity) or digest(source) == digest(path):
                matches.append((package, source))
    assert matches and len({p for p, _ in matches}) == 1, f'Unidentified or ambiguous system ELF: {path.name}'
    return matches[0]


def collect(appdir, output):
    own = {'usr/bin/sirinvpn', 'usr/bin/sirinvpn-desktop',
           'usr/lib/sirinvpn/sirinvpn-helper', 'usr/lib/sirinvpn/sirinvpn-server',
           'usr/lib/sirinvpn/sirinvpn-release', 'usr/lib/sirinvpn/sirinvpn-release-fetch'}
    report = {'scope': __doc__.strip(), 'files': [], 'packages': {}, 'separate_inputs': []}
    for path in sorted(appdir.rglob('*')):
        if not path.is_file() or path.is_symlink() or path.is_relative_to(output):
            continue
        with path.open('rb') as source:
            if source.read(4) != b'\x7fELF':
                continue
        name = path.relative_to(appdir).as_posix()
        if name in own or name == 'AppRun.wrapped':
            report['separate_inputs'].append({'path': name, 'sha256': digest(path)})
            continue
        package, original = package_source(path)
        report['files'].append({'path': name, 'sha256': digest(path), 'package': package,
                                'source_file': str(original), 'source_sha256': digest(original),
                                'build_id': build_id(path)})
        if package in report['packages']:
            continue
        fields = subprocess.check_output(
            ['dpkg-query', '-W', '-f=${Version}\t${source:Package}\t${source:Version}', package],
            text=True).split('\t')
        copyright_path = Path('/usr/share/doc') / package.split(':')[0] / 'copyright'
        assert copyright_path.is_file(), f'Missing Debian copyright file: {package}'
        content = copyright_path.read_bytes()
        assert len(content) < 2 * 1024**2
        destination = output / package / 'copyright'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        report['packages'][package] = dict(zip(('version', 'source_package', 'source_version'), fields))
        report['packages'][package]['copyright_sha256'] = digest(destination)
    assert report['files'], 'No bundled system libraries found'
    root = Path(__file__).resolve().parents[1]
    extra = json.loads((root / 'release/publisher-notice-sources.json').read_text())['appimage_notice_review']
    for item in extra['notices']:
        source = (root / item['path']).resolve(strict=True)
        assert source.is_relative_to(root / 'packaging/third-party') and digest(source) == item['sha256']
        if 'appdir_path' in item:
            assert digest(appdir / item['appdir_path']) == item['bundled_sha256'], 'Changed AppImage launcher/hook needs review'
        destination = output / 'appimage' / source.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    report['appimage_notice_review'] = extra
    shutil.copytree('/usr/share/common-licenses', output / 'common-licenses', dirs_exist_ok=True)
    (output / 'inventory.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('appdir', type=Path)
    args = parser.parse_args()
    appdir = args.appdir.resolve(strict=True)
    output = appdir / 'usr/share/doc/sirinvpn/system-notices'
    if output.exists():
        assert not output.is_symlink()
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    report = collect(appdir, output)
    print(f"Preserved notices for {len(report['files'])} bundled ELF files from {len(report['packages'])} Debian packages.")


if __name__ == '__main__':
    main()
