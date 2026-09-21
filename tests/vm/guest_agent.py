"""Bounded QEMU guest-agent execution over a private host Unix socket.

The virtio channel remains available when the guest's kill switch blocks SSH.
Protocol: https://www.qemu.org/docs/master/interop/qemu-ga-ref.html
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import secrets
import socket
import subprocess
import time


class GuestAgent:
    def __init__(self, path: Path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(10)
        self.buffer = b""
        try:
            self.socket.connect(str(path))
            identity = secrets.randbits(63)
            self.socket.sendall(b"\xff" + self._encode(
                "guest-sync-delimited", {"id": identity}
            ))
            for _ in range(20):
                if self._receive().get("return") == identity:
                    break
            else:
                raise RuntimeError("The guest-agent stream did not synchronize")
        except BaseException:
            self.socket.close()
            raise

    @staticmethod
    def _encode(command: str, arguments: dict) -> bytes:
        return (json.dumps({"execute": command, "arguments": arguments}) + "\n").encode()

    def _receive(self) -> dict:
        while True:
            if b"\xff" in self.buffer:
                self.buffer = self.buffer.rsplit(b"\xff", 1)[1]
            if b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                try:
                    result = json.loads(line)
                except (ValueError, UnicodeError):
                    continue
                if isinstance(result, dict):
                    return result
            else:
                chunk = self.socket.recv(65536)
                if not chunk:
                    raise RuntimeError("The guest-agent channel closed")
                self.buffer += chunk
                if len(self.buffer) > 4 * 1024**2:
                    raise RuntimeError("Guest-agent output exceeded its bound")

    def request(self, command: str, arguments: dict | None = None) -> dict:
        self.socket.sendall(self._encode(command, arguments or {}))
        response = self._receive()
        if "error" in response:
            raise RuntimeError(f"Guest agent rejected {command}: "
                               + str(response["error"].get("desc", "unknown error"))[:300])
        if "return" not in response:
            raise RuntimeError("The guest-agent response has no result")
        return response["return"]

    def run(self, arguments: list[str], *, data: bytes | None = None,
            timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess:
        if not arguments or not 1 <= timeout <= 900:
            raise ValueError("A guest command and a bounded timeout are required")
        command = ["/usr/bin/timeout", "--signal=TERM", "--kill-after=5", str(timeout), *arguments]
        request = {"path": command[0], "arg": command[1:], "capture-output": True}
        if data is not None:
            if len(data) > 2 * 1024**2:
                raise ValueError("Guest input exceeds its bound; use a fixture file")
            request["input-data"] = base64.b64encode(data).decode("ascii")
        pid = self.request("guest-exec", request)["pid"]
        deadline = time.monotonic() + timeout + 10
        while time.monotonic() < deadline:
            status = self.request("guest-exec-status", {"pid": pid})
            if status["exited"]:
                if status.get("out-truncated") or status.get("err-truncated"):
                    raise RuntimeError("The guest truncated command output")
                result = subprocess.CompletedProcess(
                    arguments, status.get("exitcode", -status.get("signal", 1)),
                    base64.b64decode(status.get("out-data", ""), validate=True),
                    base64.b64decode(status.get("err-data", ""), validate=True),
                )
                if check:
                    result.check_returncode()
                return result
            time.sleep(0.2)
        raise subprocess.TimeoutExpired(arguments, timeout)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.socket.close()
