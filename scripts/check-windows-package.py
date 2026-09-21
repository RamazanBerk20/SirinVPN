#!/usr/bin/env python3
"""Inspect an NSIS payload without executing its installer or Windows binaries."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile


SYSTEM_DLLS = {
    "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "cabinet.dll",
    "cfgmgr32.dll", "combase.dll", "comctl32.dll", "crypt32.dll", "cryptbase.dll",
    "dwmapi.dll", "fwpuclnt.dll", "gdi32.dll", "iphlpapi.dll", "kernel32.dll",
    "kernelbase.dll", "msvcrt.dll", "nci.dll", "netapi32.dll", "nsi.dll", "ntdll.dll",
    "ole32.dll", "oleaut32.dll", "rpcrt4.dll", "secur32.dll", "setupapi.dll",
    "shell32.dll", "shlwapi.dll", "user32.dll", "userenv.dll", "ucrtbase.dll",
    "uxtheme.dll", "version.dll", "wintrust.dll", "ws2_32.dll", "wtsapi32.dll",
}


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def matches_nsis_executable(packaged: Path, original: Path) -> bool:
    """Tauri patches UNK to NSS in the installer copy and restores the build file."""
    if packaged.stat().st_size != original.stat().st_size:
        return False
    differences = []
    offset = 0
    with original.open("rb") as source, packaged.open("rb") as payload:
        while before := source.read(1024 * 1024):
            after = payload.read(len(before))
            if before != after:
                for index, (left, right) in enumerate(zip(before, after)):
                    if left != right:
                        differences.append((offset + index, left, right))
                        if len(differences) > 3:
                            return False
            offset += len(before)
        if not differences:
            return True
        start = differences[0][0]
        if differences != [(start + i, left, right) for i, (left, right) in enumerate(zip(b"UNK", b"NSS"))]:
            return False
        prefix = b"__TAURI_BUNDLE_TYPE_VAR_"
        if start < len(prefix):
            return False
        source.seek(start - len(prefix))
        return source.read(len(prefix)) == prefix


def pe_machine(path: Path) -> int:
    with path.open("rb") as source:
        dos = source.read(64)
        if dos[:2] != b"MZ":
            raise ValueError(f"{path.name} is not a PE executable")
        source.seek(int.from_bytes(dos[60:64], "little"))
        pe = source.read(6)
        if pe[:4] != b"PE\0\0":
            raise ValueError(f"{path.name} has an invalid PE header")
        return int.from_bytes(pe[4:6], "little")


def inspect(arguments: argparse.Namespace, root: Path) -> None:
    package = arguments.package.resolve(strict=True)
    listing = subprocess.check_output(["7z", "l", "-slt", "-ba", str(package)], text=True)
    entries = []
    total = 0
    for block in listing.strip().split("\n\n"):
        values = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
        if "Path" not in values:
            continue
        name = values["Path"].replace("\\", "/")
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or ":" in name or "\0" in name:
            raise ValueError("The package contains an unsafe extraction path")
        size = int(values.get("Size") or 0)
        if size > 768 * 1024 * 1024:
            raise ValueError("An individual package member exceeds the inspection limit")
        total += size
        entries.append(name)
    if not entries or len(entries) > 128 or total > 2 * 1024 * 1024 * 1024:
        raise ValueError("The package exceeds the inspection limit")

    config_directory = root / "apps/desktop/src-tauri"
    configuration = json.loads((config_directory / "tauri.windows.conf.json").read_text())
    expected = {target: (config_directory / source).resolve()
                for source, target in configuration["bundle"]["resources"].items()}
    target_directory = root / "target" / arguments.target / arguments.profile
    expected["sirinvpn-desktop.exe"] = target_directory / "sirinvpn-desktop.exe"
    expected["$R8"] = expected["sirinvpn-windows-service.exe"]
    if arguments.target.endswith(("-gnu", "-gnullvm")):
        expected["WebView2Loader.dll"] = target_directory / "WebView2Loader.dll"
    if not set(expected).issubset(entries) or "uninstall.exe" not in entries:
        raise ValueError("A required installer payload is missing")

    with tempfile.TemporaryDirectory(prefix="windows-package-", dir=root / ".cache") as temporary:
        subprocess.run(["7z", "x", "-y", "-mmt=1", "-o" + temporary, str(package)],
                       check=True, stdout=subprocess.DEVNULL)
        directory = Path(temporary)
        for target, original in expected.items():
            if target == "sirinvpn-desktop.exe" and matches_nsis_executable(directory / target, original):
                continue
            if digest(directory / target) != digest(original):
                raise ValueError(f"The packaged {target} differs from the built source")
        machine = 0xaa64 if arguments.target.startswith("aarch64-") else 0x8664
        for name in ["sirinvpn-desktop.exe", "sirinvpn-windows-service.exe", "sirinvpn.exe", "wireguard.dll", "sirinvpn-app-routing.sys"]:
            if pe_machine(directory / name) != machine:
                raise ValueError(f"The packaged {name} has a different architecture")
        driver_info = subprocess.check_output([str(arguments.readobj), "--file-headers", "--coff-imports", str(directory / "sirinvpn-app-routing.sys")], text=True)
        if "IMAGE_SUBSYSTEM_NATIVE" not in driver_info or not re.search(r"AddressOfEntryPoint: 0x[1-9A-Fa-f][0-9A-Fa-f]*", driver_info):
            raise ValueError("The routing payload is not an executable native driver")
        if set(re.findall(r"^  Name: (.+)$", driver_info, re.MULTILINE)) - {"ntoskrnl.exe", "fwpkclnt.sys"}:
            raise ValueError("The routing driver imports an unexpected kernel component")
        pins = json.loads((root / "packaging/windows/wireguard-nt.json").read_text())
        vendor_arch = "arm64" if machine == 0xaa64 else "amd64"
        if digest(directory / "wireguard.dll") != pins["dll_sha256"][vendor_arch]:
            raise ValueError("The WireGuardNT payload differs from the vendor pin")
        for name, elf_machine in [("sirinvpn-server", 62), ("sirinvpn-server-aarch64", 183)]:
            with (directory / "resources/vps" / name).open("rb") as source:
                header = source.read(20)
            if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != elf_machine:
                raise ValueError("A VPS payload has an invalid ELF architecture")
        bundled = {path.name.lower() for path in directory.iterdir() if path.is_file()}
        for path in directory.iterdir():
            if path.suffix.lower() not in {".exe", ".dll"} or path.name == "uninstall.exe":
                continue
            imports = subprocess.check_output([str(arguments.readobj), "--coff-imports", str(path)], text=True)
            for library in re.findall(r"^  Name: (.+)$", imports, re.MULTILINE):
                name = library.lower()
                if name not in SYSTEM_DLLS and name not in bundled and not name.startswith(("api-ms-", "ext-ms-")):
                    raise ValueError(f"{path.name} needs an unbundled runtime: {library}")
    print("Windows payload, architectures, vendor pin and runtime dependencies passed.")
    print(f"Installer SHA-256: {digest(package)}")


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--target", default="x86_64-pc-windows-gnullvm")
    parser.add_argument("--profile", choices=["debug", "release"], default="debug")
    parser.add_argument("--readobj", type=Path, default=root / ".cache/tools/llvm-mingw-20260826-ucrt-ubuntu-22.04-x86_64/bin/llvm-readobj")
    inspect(parser.parse_args(), root)


if __name__ == "__main__":
    main()
