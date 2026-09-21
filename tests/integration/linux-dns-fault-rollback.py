#!/usr/bin/env python3
"""Root-only rollback owner for the Linux DNS fault-injection gate."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess


ROOT_PATTERN = re.compile(
    r"^sirinvpn-linux-dns-fault-[0-9]+-(?:upstream|resolver)$"
)
TABLE_PATTERN = re.compile(r"^sirinvpn_dns_fault_[0-9]+_(?:upstream|resolver)$")
METADATA_NAME = "state.json"
NFT = "/usr/sbin/nft"
SYSTEMCTL = "/usr/bin/systemctl"
SERVICES = ("unbound.service", "sirinvpn-server.service")


def checked_root(path: str) -> Path:
    root = Path(path)
    if root.parent != Path("/run") or ROOT_PATTERN.fullmatch(root.name) is None:
        raise RuntimeError("refusing an unscoped DNS-fault path")
    if root.exists():
        metadata = root.stat(follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
            raise RuntimeError("the DNS-fault path is not a root-owned directory")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise RuntimeError("the DNS-fault directory mode is unsafe")
    return root


def checked_table(name: str) -> str:
    if TABLE_PATTERN.fullmatch(name) is None:
        raise RuntimeError("refusing an unscoped DNS-fault nftables cleanup")
    return name


def service_active(name: str) -> bool:
    return (
        subprocess.run(
            [SYSTEMCTL, "is-active", "--quiet", name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def table_exists(name: str) -> bool:
    return (
        subprocess.run(
            [NFT, "list", "table", "inet", name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def write_atomic(path: Path, document: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.dns-fault-{os.getpid()}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_metadata(root: Path) -> dict[str, bool]:
    path = root / METADATA_NAME
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        raise RuntimeError("the DNS-fault metadata is not a root-owned regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RuntimeError("the DNS-fault metadata mode is unsafe")
    document = json.loads(path.read_text(encoding="utf-8"))
    if set(document) != set(SERVICES):
        raise RuntimeError("the DNS-fault metadata shape is invalid")
    if not all(isinstance(document[name], bool) for name in SERVICES):
        raise RuntimeError("the DNS-fault metadata fields are invalid")
    return document


def prepare(root_name: str, table_name: str) -> None:
    root = checked_root(root_name)
    table = checked_table(table_name)
    if not root.is_dir():
        raise RuntimeError("the DNS-fault directory is unavailable")
    if (root / METADATA_NAME).exists():
        raise RuntimeError("the DNS-fault metadata already exists")
    if table_exists(table):
        raise RuntimeError("the scoped DNS-fault table already exists")
    states = {service: service_active(service) for service in SERVICES}
    if not all(states.values()):
        raise RuntimeError("the DNS services are not active at preflight")
    write_atomic(root / METADATA_NAME, states)


def set_service_state(name: str, active: bool) -> None:
    action = "start" if active else "stop"
    subprocess.run([SYSTEMCTL, action, name], check=True)
    if service_active(name) != active:
        raise RuntimeError(f"{name} did not return to its original state")


def rollback(root_name: str, table_name: str) -> None:
    root = checked_root(root_name)
    table = checked_table(table_name)
    document = load_metadata(root)

    subprocess.run(
        [NFT, "delete", "table", "inet", table],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if table_exists(table):
        raise RuntimeError("the scoped DNS-fault table remains installed")

    set_service_state("unbound.service", document["unbound.service"])
    set_service_state("sirinvpn-server.service", document["sirinvpn-server.service"])
    shutil.rmtree(root)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("prepare", "rollback"):
        command = commands.add_parser(name)
        command.add_argument("root")
        command.add_argument("nft_table")
    return result


def main() -> None:
    arguments = parser().parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("the DNS-fault helper must run as root")
    if arguments.command == "prepare":
        prepare(arguments.root, arguments.nft_table)
    elif arguments.command == "rollback":
        rollback(arguments.root, arguments.nft_table)


if __name__ == "__main__":
    main()
