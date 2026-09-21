#!/usr/bin/env python3
"""Root-only cleanup owner for the Linux outbound-network audit gate."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess


ROOT_PATTERN = re.compile(r"^sirinvpn-linux-outbound-audit-[0-9]+$")
TABLE_PATTERN = re.compile(r"^sirinvpn_outbound_audit_[0-9]+$")
METADATA_NAME = "state.json"
NFT = "/usr/sbin/nft"
SYSTEMCTL = "/usr/bin/systemctl"
SERVICES = ("unbound.service", "sirinvpn-server.service")


def checked_root(path: str) -> Path:
    root = Path(path)
    if root.parent != Path("/run") or ROOT_PATTERN.fullmatch(root.name) is None:
        raise RuntimeError("refusing an unscoped outbound-audit path")
    if root.exists():
        metadata = root.stat(follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
            raise RuntimeError("the outbound-audit path is not a root-owned directory")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise RuntimeError("the outbound-audit directory mode is unsafe")
    return root


def checked_table(name: str) -> str:
    if TABLE_PATTERN.fullmatch(name) is None:
        raise RuntimeError("refusing an unscoped outbound-audit nftables cleanup")
    return name


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
    temporary = path.with_name(f".{path.name}.outbound-audit-{os.getpid()}")
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


def load_metadata(root: Path) -> dict[str, object]:
    path = root / METADATA_NAME
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        raise RuntimeError("the outbound-audit metadata is not a root-owned regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RuntimeError("the outbound-audit metadata mode is unsafe")
    document = json.loads(path.read_text(encoding="utf-8"))
    if set(document) != {"nft_table", *SERVICES}:
        raise RuntimeError("the outbound-audit metadata shape is invalid")
    if not isinstance(document["nft_table"], str) or not all(
        isinstance(document[service], bool) for service in SERVICES
    ):
        raise RuntimeError("the outbound-audit metadata fields are invalid")
    checked_table(document["nft_table"])
    return document


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


def prepare(root_name: str, table_name: str) -> None:
    root = checked_root(root_name)
    table = checked_table(table_name)
    if not root.is_dir():
        raise RuntimeError("the outbound-audit directory is unavailable")
    if (root / METADATA_NAME).exists():
        raise RuntimeError("the outbound-audit metadata already exists")
    if table_exists(table):
        raise RuntimeError("the scoped outbound-audit table already exists")
    states = {service: service_active(service) for service in SERVICES}
    if not all(states.values()):
        raise RuntimeError("the audited VPS services are not active at preflight")
    write_atomic(root / METADATA_NAME, {"nft_table": table, **states})


def set_service_state(name: str, active: bool) -> None:
    action = "start" if active else "stop"
    subprocess.run([SYSTEMCTL, action, name], check=True)
    if service_active(name) != active:
        raise RuntimeError(f"{name} did not return to its original state")


def rollback(root_name: str, table_name: str) -> None:
    root = checked_root(root_name)
    table = checked_table(table_name)
    document = load_metadata(root)
    if document["nft_table"] != table:
        raise RuntimeError("the outbound-audit table does not match its metadata")

    subprocess.run(
        [NFT, "delete", "table", "inet", table],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if table_exists(table):
        raise RuntimeError("the scoped outbound-audit table remains installed")

    set_service_state("unbound.service", bool(document["unbound.service"]))
    set_service_state(
        "sirinvpn-server.service", bool(document["sirinvpn-server.service"])
    )
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
        raise RuntimeError("the outbound-audit helper must run as root")
    if arguments.command == "prepare":
        prepare(arguments.root, arguments.nft_table)
    elif arguments.command == "rollback":
        rollback(arguments.root, arguments.nft_table)


if __name__ == "__main__":
    main()
