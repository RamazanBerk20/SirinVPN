#!/usr/bin/env python3
"""Root-only, short-lived fault injector for transport fallback live gates."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess


SERVER_SERVICE = "sirinvpn-server.service"
TLS_HANDSHAKE_RECORD = b"\x16"
COPY_BUFFER_SIZE = 64 * 1024


def bounded_port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def checked_file(path: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError("test paths must be absolute")
    return candidate


def write_atomic(path: Path, content: bytes, source: os.stat_result) -> None:
    temporary = path.with_name(f".{path.name}.fallback-test-{os.getpid()}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        stat.S_IMODE(source.st_mode),
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chown(temporary, source.st_uid, source.st_gid, follow_symlinks=False)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def rewrite_config(config_name: str, backup_name: str, internal_port: int) -> None:
    config = checked_file(config_name)
    backup = checked_file(backup_name)
    if backup.exists():
        raise RuntimeError("the fallback-test configuration backup already exists")
    source = config.stat(follow_symlinks=False)
    if not stat.S_ISREG(source.st_mode):
        raise RuntimeError("the SirinVPN server configuration is not a regular file")
    original = config.read_bytes()
    document = json.loads(original)
    tcp = document.get("tcp_fallback")
    tls = document.get("tls_like")
    if not isinstance(tcp, dict) or not isinstance(tls, dict):
        raise RuntimeError("the managed VPS does not advertise both TCP transports")
    public_port = tcp.get("port")
    if public_port != tls.get("port") or public_port == internal_port:
        raise RuntimeError("the shared public TCP transport port is inconsistent")

    descriptor = os.open(
        backup,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(original)
        output.flush()
        os.fsync(output.fileno())

    tcp["port"] = internal_port
    tls["port"] = internal_port
    replacement = json.dumps(document, separators=(",", ":")).encode("utf-8") + b"\n"
    write_atomic(config, replacement, source)


def restore_config(config_name: str, backup_name: str) -> None:
    config = checked_file(config_name)
    backup = checked_file(backup_name)
    if not backup.exists():
        return
    source = config.stat(follow_symlinks=False)
    original = backup.read_bytes()
    json.loads(original)
    write_atomic(config, original, source)
    backup.unlink()


class ProxyCounters:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.tls_rejected = 0
        self.raw_forwarded = 0
        self.write()

    def write(self) -> None:
        content = (
            f"tls_rejected={self.tls_rejected}\n"
            f"raw_forwarded={self.raw_forwarded}\n"
        ).encode("ascii")
        descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)


async def copy_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(COPY_BUFFER_SIZE):
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.write_eof()
        except (AttributeError, ConnectionError, RuntimeError):
            pass


async def handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    internal_port: int,
    counters: ProxyCounters,
) -> None:
    upstream_writer: asyncio.StreamWriter | None = None
    try:
        first = await asyncio.wait_for(reader.readexactly(1), timeout=4)
        if first == TLS_HANDSHAKE_RECORD:
            counters.tls_rejected += 1
            counters.write()
            return
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", internal_port),
            timeout=4,
        )
        upstream_writer.write(first)
        await upstream_writer.drain()
        counters.raw_forwarded += 1
        counters.write()
        await asyncio.gather(
            copy_stream(reader, upstream_writer),
            copy_stream(upstream_reader, writer),
        )
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        if upstream_writer is not None:
            upstream_writer.close()
        writer.close()
        if upstream_writer is not None:
            await upstream_writer.wait_closed()
        await writer.wait_closed()


async def serve(public_port: int, internal_port: int, counter_name: str) -> None:
    counter = checked_file(counter_name)
    counters = ProxyCounters(counter)
    server = await asyncio.start_server(
        lambda reader, writer: handle_connection(reader, writer, internal_port, counters),
        host="0.0.0.0",
        port=public_port,
        reuse_address=True,
    )
    async with server:
        await server.serve_forever()


def quiet_run(*arguments: str) -> None:
    subprocess.run(arguments, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def rollback(
    config_name: str,
    backup_name: str,
    nft_table: str,
    proxy_unit: str,
    test_root_name: str,
) -> None:
    test_root = checked_file(test_root_name)
    if test_root.parent != Path("/run") or not test_root.name.startswith(
        "sirinvpn-linux-fallback-"
    ):
        raise RuntimeError("refusing an unscoped fallback-test cleanup")
    if not nft_table.startswith("sirinvpn_linux_"):
        raise RuntimeError("refusing an unscoped nftables cleanup")
    if not proxy_unit.startswith(
        "sirinvpn-linux-fallback-"
    ):
        raise RuntimeError("refusing an unscoped transient-unit cleanup")

    restart_error: subprocess.CalledProcessError | None = None
    quiet_run("systemctl", "stop", proxy_unit)
    try:
        if Path(backup_name).exists():
            quiet_run("systemctl", "stop", SERVER_SERVICE)
            restore_config(config_name, backup_name)
            try:
                subprocess.run(
                    ["systemctl", "start", SERVER_SERVICE],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
            except subprocess.CalledProcessError as error:
                restart_error = error
    finally:
        quiet_run("nft", "delete", "table", "inet", nft_table)
        quiet_run("systemctl", "reset-failed", proxy_unit)
        if test_root.exists():
            shutil.rmtree(test_root)
    if restart_error is not None:
        raise restart_error


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subcommands = result.add_subparsers(dest="command", required=True)

    rewrite = subcommands.add_parser("rewrite-config")
    rewrite.add_argument("config")
    rewrite.add_argument("backup")
    rewrite.add_argument("internal_port", type=bounded_port)

    proxy = subcommands.add_parser("serve")
    proxy.add_argument("public_port", type=bounded_port)
    proxy.add_argument("internal_port", type=bounded_port)
    proxy.add_argument("counter")

    cleanup = subcommands.add_parser("rollback")
    cleanup.add_argument("config")
    cleanup.add_argument("backup")
    cleanup.add_argument("nft_table")
    cleanup.add_argument("proxy_unit")
    cleanup.add_argument("test_root")

    return result


def main() -> None:
    arguments = parser().parse_args()
    if arguments.command == "rewrite-config":
        rewrite_config(arguments.config, arguments.backup, arguments.internal_port)
    elif arguments.command == "serve":
        asyncio.run(serve(arguments.public_port, arguments.internal_port, arguments.counter))
    elif arguments.command == "rollback":
        rollback(
            arguments.config,
            arguments.backup,
            arguments.nft_table,
            arguments.proxy_unit,
            arguments.test_root,
        )
if __name__ == "__main__":
    main()
