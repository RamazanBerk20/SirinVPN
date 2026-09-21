#!/usr/bin/env python3
"""Root-only, short-lived netem owner for the Linux impairment live gate."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess


INTERFACE = "sirinvpn0"
QDISC_HANDLE = "7a1:"
ROOT_PREFIX = "sirinvpn-linux-impairment-"
TABLE_PREFIX = "sirinvpn_impairment_"
METADATA_NAME = "netem.json"
TC = "/usr/sbin/tc"
NFT = "/usr/sbin/nft"
MODPROBE = "/usr/sbin/modprobe"


def checked_root(path: str) -> Path:
    root = Path(path)
    if root.parent != Path("/run") or not root.name.startswith(ROOT_PREFIX):
        raise RuntimeError("refusing an unscoped impairment-test path")
    if root.exists():
        metadata = root.stat(follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
            raise RuntimeError("the impairment-test path is not a root-owned directory")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise RuntimeError("the impairment-test directory mode is unsafe")
    return root


def qdisc_output(statistics: bool = False) -> str:
    command = [TC]
    if statistics:
        command.append("-s")
    command.extend(["qdisc", "show", "dev", INTERFACE])
    return subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def write_atomic(path: Path, document: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.impairment-{os.getpid()}")
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
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_metadata(root: Path) -> dict[str, object]:
    path = root / METADATA_NAME
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        raise RuntimeError("the impairment metadata is not a root-owned regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RuntimeError("the impairment metadata mode is unsafe")
    document = json.loads(path.read_text(encoding="utf-8"))
    if set(document) != {"baseline", "module_initially_loaded"}:
        raise RuntimeError("the impairment metadata shape is invalid")
    baseline = document["baseline"]
    module_loaded = document["module_initially_loaded"]
    if not isinstance(baseline, str) or not isinstance(module_loaded, bool):
        raise RuntimeError("the impairment metadata fields are invalid")
    if not baseline.startswith("qdisc noqueue 0: root") or "\n" in baseline:
        raise RuntimeError("the baseline qdisc is outside the supported boundary")
    return document


def prepare(root_name: str) -> None:
    root = checked_root(root_name)
    if not root.is_dir():
        raise RuntimeError("the impairment-test directory is unavailable")
    path = root / METADATA_NAME
    if path.exists():
        raise RuntimeError("the impairment metadata already exists")
    baseline = qdisc_output()
    if not baseline.startswith("qdisc noqueue 0: root") or "\n" in baseline:
        raise RuntimeError("sirinvpn0 does not have the expected default qdisc")
    all_qdiscs = subprocess.run(
        [TC, "qdisc", "show"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout
    if re.search(r"^qdisc netem ", all_qdiscs, re.MULTILINE):
        raise RuntimeError("another netem qdisc is already active")
    write_atomic(
        path,
        {
            "baseline": baseline,
            "module_initially_loaded": Path("/sys/module/sch_netem").is_dir(),
        },
    )


def apply(root_name: str) -> None:
    root = checked_root(root_name)
    document = load_metadata(root)
    if qdisc_output() != document["baseline"]:
        raise RuntimeError("the WireGuard qdisc changed after impairment preflight")
    subprocess.run([MODPROBE, "sch_netem"], check=True)
    subprocess.run(
        [
            TC,
            "qdisc",
            "add",
            "dev",
            INTERFACE,
            "root",
            "handle",
            QDISC_HANDLE,
            "netem",
            "delay",
            "120ms",
            "30ms",
            "distribution",
            "normal",
            "loss",
            "random",
            "10%",
        ],
        check=True,
    )
    if not qdisc_output().startswith(f"qdisc netem {QDISC_HANDLE} root"):
        raise RuntimeError("the owned netem qdisc did not become active")


def stats(root_name: str) -> None:
    root = checked_root(root_name)
    load_metadata(root)
    output = qdisc_output(statistics=True)
    if not output.startswith(f"qdisc netem {QDISC_HANDLE} root"):
        raise RuntimeError("the owned netem qdisc is unavailable")
    counters = re.search(
        r"Sent\s+\d+\s+bytes\s+(\d+)\s+pkt\s+\(dropped\s+(\d+),",
        output,
    )
    if counters is None:
        raise RuntimeError("the netem counters could not be parsed")
    print(
        json.dumps(
            {
                "packets": int(counters.group(1)),
                "dropped": int(counters.group(2)),
            },
            separators=(",", ":"),
        )
    )


def quiet_run(*arguments: str) -> None:
    subprocess.run(
        arguments,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def rollback(root_name: str, nft_table: str) -> None:
    root = checked_root(root_name)
    if not nft_table.startswith(TABLE_PREFIX):
        raise RuntimeError("refusing an unscoped impairment-test nftables cleanup")

    error: Exception | None = None
    try:
        if (root / METADATA_NAME).exists():
            document = load_metadata(root)
            current = qdisc_output()
            if current.startswith(f"qdisc netem {QDISC_HANDLE} root"):
                subprocess.run(
                    [TC, "qdisc", "del", "dev", INTERFACE, "root"],
                    check=True,
                )
                current = qdisc_output()
            if current != document["baseline"]:
                raise RuntimeError("the WireGuard qdisc did not return to baseline")
            if not document["module_initially_loaded"]:
                quiet_run(MODPROBE, "-r", "sch_netem")
                if Path("/sys/module/sch_netem").is_dir():
                    raise RuntimeError("the temporary sch_netem module remains loaded")
    except Exception as caught:  # Preserve ownership evidence on uncertain cleanup.
        error = caught
    finally:
        quiet_run(NFT, "delete", "table", "inet", nft_table)

    if error is not None:
        raise error
    if root.exists():
        shutil.rmtree(root)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("prepare", "apply", "stats"):
        command = commands.add_parser(name)
        command.add_argument("root")
    cleanup = commands.add_parser("rollback")
    cleanup.add_argument("root")
    cleanup.add_argument("nft_table")
    return result


def main() -> None:
    arguments = parser().parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("the impairment helper must run as root")
    if arguments.command == "prepare":
        prepare(arguments.root)
    elif arguments.command == "apply":
        apply(arguments.root)
    elif arguments.command == "stats":
        stats(arguments.root)
    elif arguments.command == "rollback":
        rollback(arguments.root, arguments.nft_table)


if __name__ == "__main__":
    main()
