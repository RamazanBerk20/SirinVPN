#!/usr/bin/env python3
"""Inspect Debian and AppImage artifacts without installing or executing them."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PAYLOADS = {
    "usr/bin/sirinvpn-desktop": ROOT / "target/release/sirinvpn-desktop",
    "usr/bin/sirinvpn": ROOT / "apps/desktop/src-tauri/binaries/sirinvpn",
    **{
        f"usr/lib/sirinvpn/{name}": ROOT / "apps/desktop/src-tauri/binaries" / name
        for name in ["sirinvpn-helper", "sirinvpn-server", "sirinvpn-release", "sirinvpn-release-fetch"]
    },
}


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def elf_machine(data: bytes) -> int:
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected a little-endian ELF64 executable")
    return int.from_bytes(data[18:20], "little")


def archive_part(package: Path, prefix: str) -> tarfile.TarFile:
    members = subprocess.check_output(["ar", "t", str(package)], text=True).splitlines()
    matches = [name for name in members if name.startswith(prefix + ".tar")]
    if len(matches) != 1:
        raise ValueError(f"Expected one {prefix} archive in the Debian package")
    data = subprocess.check_output(["ar", "p", str(package), matches[0]])
    return tarfile.open(fileobj=io.BytesIO(data), mode="r:*")


def regular_member(archive: tarfile.TarFile, name: str) -> tuple[tarfile.TarInfo, bytes]:
    candidates = [item for item in archive.getmembers() if item.name.removeprefix("./") == name]
    if len(candidates) != 1 or not candidates[0].isreg():
        raise ValueError(f"Expected one regular Debian member: {name}")
    member = candidates[0]
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError(f"Unreadable Debian member: {name}")
    return member, stream.read()


def inspect(debian: Path, appimage: Path) -> dict:
    version = json.loads((ROOT / "apps/desktop/src-tauri/tauri.conf.json").read_text())["version"]
    with archive_part(debian, "control") as control_archive:
        _, encoded = regular_member(control_archive, "control")
        control = encoded.decode("utf-8")
        for name in ["postinst", "prerm", "postrm"]:
            member, script = regular_member(control_archive, name)
            if (member.uid != 0 or member.gid != 0 or member.mode & 0o022
                    or not member.mode & 0o100
                    or script != (ROOT / "packaging/debian" / f"{name}.sh").read_bytes()):
                raise ValueError(f"Debian maintainer script differs or is unsafe: {name}")
    for field, value in [("Package", "sirin-vpn"), ("Version", version), ("Architecture", "amd64")]:
        if not re.search(rf"^{field}: {re.escape(value)}$", control, re.MULTILINE):
            raise ValueError(f"Unexpected Debian {field}")
    dependencies = re.search(r"^Depends: (.+)$", control, re.MULTILINE)
    if dependencies is None:
        raise ValueError("Debian runtime dependencies are missing")
    for dependency in ["iproute2", "iputils-ping", "libayatana-appindicator3-1", "nftables",
                       "pkexec", "polkitd", "systemd-resolved", "wireguard-tools"]:
        if not re.search(rf"(?:^|, )\b{re.escape(dependency)}\b", dependencies[1]):
            raise ValueError(f"Missing Debian dependency: {dependency}")

    payload_hashes = {}
    with archive_part(debian, "data") as data_archive:
        for name, source in PAYLOADS.items():
            member, packaged = regular_member(data_archive, name)
            if member.uid != 0 or member.gid != 0 or member.mode & 0o022 or not member.mode & 0o100:
                raise ValueError(f"Unsafe Debian executable ownership/mode: {name}")
            expected = source.read_bytes()
            if name == "usr/bin/sirinvpn-desktop":
                # Tauri changes only this marker in the bundled GUI and restores
                # the original build file. Other byte changes remain failures.
                marker = b"__TAURI_BUNDLE_TYPE_VAR_UNK"
                if expected.count(marker) != 1:
                    raise ValueError("Expected one Tauri bundle-type marker")
                expected = expected.replace(marker, b"__TAURI_BUNDLE_TYPE_VAR_DEB", 1)
            if elf_machine(packaged) != 62 or packaged != expected:
                raise ValueError(f"Debian executable differs from the current x64 build: {name}")
            payload_hashes[name] = hashlib.sha256(packaged).hexdigest()
        policy_paths = {
            "usr/lib/NetworkManager/conf.d/90-sirinvpn-probe.conf":
                ROOT / "packaging/networkmanager/90-sirinvpn-probe.conf",
            "usr/share/polkit-1/actions/org.sirinvpn.network.policy":
                ROOT / "packaging/polkit/org.sirinvpn.network.policy",
            **{
                f"usr/lib/systemd/system/{name}": ROOT / "packaging/systemd" / name
                for name in ["sirinvpn-killswitch.service", "sirinvpn-reconnect.service", "sirinvpn-transport.service", "sirinvpn-transport@.service"]
            },
        }
        for name, source in policy_paths.items():
            member, packaged = regular_member(data_archive, name)
            if member.uid != 0 or member.gid != 0 or member.mode & 0o022 or packaged != source.read_bytes():
                raise ValueError(f"Debian integration file differs or is unsafe: {name}")

    with tempfile.TemporaryDirectory(prefix="sirinvpn-package-inspection.") as directory:
        extracted = Path(directory)
        subprocess.run(["7z", "x", "-y", "-mmt=2", f"-o{directory}", str(appimage)],
                       check=True, stdout=subprocess.DEVNULL)
        for name in PAYLOADS:
            packaged = extracted / name
            if not packaged.is_file() or not packaged.resolve().is_relative_to(extracted):
                raise ValueError(f"Missing or unsafe AppImage executable: {name}")
            with packaged.open("rb") as source:
                if elf_machine(source.read(20)) != 62:
                    raise ValueError(f"Invalid AppImage executable architecture: {name}")
        for component in ["sirinvpn-server", "sirinvpn-helper"]:
            name = f"usr/lib/sirinvpn/{component}"
            if sha256(extracted / name) != payload_hashes[name]:
                raise ValueError(f"AppImage must retain the exact system-installable {component} bytes")
        if list((extracted / "usr/lib").glob("libwayland-*.so*")):
            raise ValueError("AppImage contains incompatible bundled Wayland libraries")
        # dlopen-loaded tray support is invisible to the main executable's ELF
        # dependencies. Missing it mixes the bundled GLib with newer host GTK.
        for library in ["libayatana-appindicator3.so.1", "libayatana-indicator3.so.7",
                        "libayatana-ido3-0.4.so.0", "libdbusmenu-gtk3.so.4", "libdbusmenu-glib.so.4"]:
            path = extracted / "usr/lib" / library
            if not path.is_file() or not path.resolve().is_relative_to(extracted):
                raise ValueError(f"Missing or unsafe AppImage tray library: {library}")

    return {
        "debian": {"path": str(debian), "sha256": sha256(debian), "version": version,
                   "architecture": "amd64", "root_owned_executables": len(payload_hashes),
                   "current_payload_sha256": payload_hashes, "integration_files": "passed",
                   "maintainer_scripts": "postinst, prerm and postrm verified",
                   "gui_bundle_marker": "only the expected UNK to DEB replacement"},
        "appimage": {"path": str(appimage), "sha256": sha256(appimage),
                     "executables": "present; x64 ELF", "server_matches_debian": True,
                     "helper_matches_debian": True,
                     "bundled_tray_libraries": True,
                     "bundled_wayland_libraries": False},
        "inspection": "static extraction only; no installation or executable launch",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("debian", type=Path)
    parser.add_argument("appimage", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    result = inspect(arguments.debian.resolve(), arguments.appimage.resolve())
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, indent=2) + "\n")
    print("Linux payloads, executable ownership, integrations and AppImage VPS bytes passed.")


if __name__ == "__main__":
    main()
