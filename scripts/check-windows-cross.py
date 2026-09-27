#!/usr/bin/env python3
"""Check Windows code on Linux with a project-local LLVM-MinGW toolchain."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", type=Path, default=root / ".cache/tools/llvm-mingw-20260826-ucrt-ubuntu-22.04-x86_64")
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--components", action="store_true", help="Build and stage service and CLI executables")
    operation.add_argument("--bundle", action="store_true", help="Build a desktop installer (debug unless --release)")
    operation.add_argument("--tests", action="store_true", help="Type-check Windows desktop, service and platform tests")
    parser.add_argument("--nsis", type=Path, default=root / ".cache/tools/nsis-3.11", help="Native NSIS installation used by --bundle")
    parser.add_argument("--wireguard-archive", type=Path, default=root / ".cache/tools/wireguard-nt-1.1.zip")
    parser.add_argument("--routing-driver", type=Path, default=root / "target/windows-routing-driver/sirinvpn-app-routing.sys")
    parser.add_argument("--clippy", action="store_true", help="Lint the selected Windows check targets with warnings denied")
    parser.add_argument("--release", action="store_true", help="Use release binaries for --components and --bundle")
    arguments = parser.parse_args()
    if arguments.release and not (arguments.components or arguments.bundle):
        parser.error("--release requires --components or --bundle")
    profile = "release" if arguments.release else "debug"
    cargo_profile = ["--release"] if arguments.release else []
    tauri_profile = [] if arguments.release else ["--debug"]
    binaries = arguments.toolchain.resolve() / "bin"
    if not (binaries / "x86_64-w64-mingw32-clang").is_file():
        parser.error("Pass --toolchain with a verified LLVM-MinGW installation")
    environment = os.environ.copy()
    environment["PATH"] = str(binaries) + os.pathsep + environment.get("PATH", "")
    environment.setdefault("CARGO_BUILD_JOBS", "2")
    environment["RUSTFLAGS"] = (environment.get("RUSTFLAGS", "") + " -C target-feature=+crt-static").strip()
    target = "x86_64-pc-windows-gnullvm"
    for name, binary in {
        "CC_x86_64_pc_windows_gnullvm": "x86_64-w64-mingw32-clang",
        "CXX_x86_64_pc_windows_gnullvm": "x86_64-w64-mingw32-clang++",
        "AR_x86_64_pc_windows_gnullvm": "llvm-ar",
        "RANLIB_x86_64_pc_windows_gnullvm": "llvm-ranlib",
        "CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER": "x86_64-w64-mingw32-clang",
    }.items():
        environment[name] = str(binaries / binary)
    if arguments.components:
        if not arguments.routing_driver.is_file():
            parser.error("Build --routing-driver with scripts/build-windows-routing-driver.py first")
        result = subprocess.call(["cargo", "build", *cargo_profile, "--locked", "--target", target,
                                  "-p", "sirinvpn-windows-service", "-p", "sirinvpn-cli"], cwd=root, env=environment)
        if result:
            return result
        destination = root / "apps/desktop/src-tauri/binaries/windows"
        destination.mkdir(parents=True, exist_ok=True)
        for name in ["sirinvpn-windows-service.exe", "sirinvpn.exe"]:
            shutil.copyfile(root / "target" / target / profile / name, destination / name)
        shutil.copyfile(arguments.routing_driver, destination / "sirinvpn-app-routing.sys")
        pins = json.loads((root / "packaging/windows/wireguard-nt.json").read_text())
        archive = arguments.wireguard_archive.read_bytes()
        if hashlib.sha256(archive).hexdigest() != pins["archive_sha256"]:
            raise ValueError("WireGuardNT archive differs from its pinned hash")
        with zipfile.ZipFile(arguments.wireguard_archive) as vendor:
            library = vendor.read("wireguard-nt/bin/amd64/wireguard.dll")
        if hashlib.sha256(library).hexdigest() != pins["dll_sha256"]["amd64"]:
            raise ValueError("WireGuardNT library differs from its pinned hash")
        (destination / "wireguard.dll").write_bytes(library)
        return 0
    if arguments.bundle:
        if not (arguments.nsis / "Bin" / "makensis").is_file():
            parser.error("Pass --nsis with a native NSIS 3.11 or newer installation")
        environment["PATH"] = str(arguments.nsis.resolve() / "Bin") + os.pathsep + environment["PATH"]
        result = subprocess.call(["pnpm", "exec", "tauri", "build", *tauri_profile, "--target", target,
                                  "--no-bundle", "--no-sign", "--ci"],
                                 cwd=root / "apps/desktop", env=environment)
        if result:
            return result
        # Tauri adds this loader automatically for -gnu, but its current bundler
        # does not recognize -gnullvm. Use the loader emitted by the locked SDK.
        configuration = {"bundle": {
            "resources": {f"../../../target/{target}/{profile}/WebView2Loader.dll": "WebView2Loader.dll"},
            "windows": {"nsis": {"compression": "zlib"}},
        }}
        return subprocess.call(["pnpm", "exec", "tauri", "bundle", *tauri_profile, "--target", target,
                                "--bundles", "nsis", "--config", json.dumps(configuration),
                                "--no-sign", "--ci"], cwd=root / "apps/desktop", env=environment)
    command = ["cargo", "clippy" if arguments.clippy else "check", "--locked", "--target", target,
               "-p", "sirinvpn-desktop", "-p", "sirinvpn-cli"]
    if arguments.tests:
        command.extend(["-p", "sirinvpn-windows-service", "-p", "sirinvpn-platform", "--tests"])
    if arguments.clippy:
        command.extend(["--", "-D", "warnings"])
    return subprocess.call(command, cwd=root, env=environment)


if __name__ == "__main__":
    raise SystemExit(main())
