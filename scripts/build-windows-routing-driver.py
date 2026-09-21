#!/usr/bin/env python3
"""Build the WFP routing driver with an explicit Microsoft WDK and Clang/LLD.

This produces an unsigned driver. Windows kernel signing is a separate publisher
operation; the script never changes signature enforcement or installs a driver.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wdk', type=Path, required=True, help='Root containing Include/ and Lib/')
    parser.add_argument('--kit-version', default='10.0.28000.0')
    parser.add_argument('--clang', type=Path, required=True)
    parser.add_argument('--lld', type=Path, required=True)
    parser.add_argument('--architecture', choices=['x64', 'arm64'], default='x64')
    parser.add_argument('--output', type=Path, default=Path('target/windows-routing-driver'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    include = args.wdk.resolve() / 'Include' / args.kit_version
    libraries = args.wdk.resolve() / 'Lib' / args.kit_version / 'km' / args.architecture
    for path in [include / 'km/fwpsk.h', include / 'shared/fwpstypes.h', libraries / 'ntoskrnl.lib', libraries / 'fwpkclnt.lib']:
        if not path.is_file():
            parser.error(f'Missing matching WDK/SDK component: {path}')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    machine = 'x86_64' if args.architecture == 'x64' else 'aarch64'
    source = root / 'packaging/windows/routing-driver/driver.c'
    obj = output / 'routing.obj'
    binary = output / 'sirinvpn-app-routing.sys'
    command = [str(args.clang.resolve()), f'--target={machine}-pc-windows-msvc',
               '-c', str(source), '-o', str(obj), '-O2', '-ffreestanding', '-fno-stack-protector', '-funwind-tables',
               '-fms-extensions', '-fms-compatibility', '-D_KERNEL_MODE', '-DNDIS630', '-D_WIN32_WINNT=0x0A00',
               '-DNTDDI_VERSION=0x0A000000', '-D_AMD64_' if machine == 'x86_64' else '-D_ARM64_',
               '-Wall', '-Wextra', '-Werror', '-Wno-unknown-pragmas', '-Wno-ignored-attributes',
               '-Wno-pragma-pack']
    if machine == 'x86_64':
        command.append('-mno-red-zone')
    if os.name != 'nt':
        # Microsoft's headers assume a case-insensitive filesystem. Map their
        # original bytes through Clang's VFS without rewriting the SDK cache.
        def directory(path):
            return {'type': 'directory', 'name': path.name, 'contents': [
                directory(child) if child.is_dir() else {
                    'type': 'file', 'name': child.name, 'external-contents': str(child)
                } for child in sorted(path.iterdir())]}
        tree = directory(include)
        tree['name'] = str(include)
        overlay = output / 'sdk-headers.json'
        overlay.write_text(json.dumps({'version': 0, 'case-sensitive': False, 'roots': [tree]}))
        command.extend(['-ivfsoverlay', str(overlay)])
    for directory in ['km', 'km/crt', 'shared', 'um', 'ucrt']:
        command.extend(['-isystem', str(include / directory)])
    subprocess.run(command, check=True, cwd=root)
    subprocess.run([str(args.lld.absolute()), '/driver', '/subsystem:native', '/entry:DriverEntry',
                    '/nodefaultlib', '/dynamicbase', '/nxcompat', '/integritycheck', '/release',
                    f'/machine:{args.architecture}', f'/out:{binary}', str(obj),
                    str(libraries / 'ntoskrnl.lib'), str(libraries / 'fwpkclnt.lib')], check=True, cwd=root)
    print(binary)


if __name__ == '__main__':
    main()
