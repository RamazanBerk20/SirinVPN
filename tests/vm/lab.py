"""Disposable QEMU guests controlled as an ordinary host user.

Privileged commands run over pinned SSH inside the guest. The caller must put
the whole lab in a CPU/memory-limited user cgroup before creating a VM.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

from guest_agent import GuestAgent


ROOT = Path(__file__).resolve().parents[2]
MEMORY_LIMIT = 4 * 1024**3


def require_host_limits() -> None:
    if os.geteuid() == 0:
        raise RuntimeError("Launch the VM lab as an ordinary host user")
    group = next(
        (line.partition("::")[2] for line in Path("/proc/self/cgroup").read_text().splitlines()
         if line.startswith("0::")), None
    )
    if group is None:
        raise RuntimeError("The VM lab requires a cgroup v2 user scope")
    directory = Path("/sys/fs/cgroup") / group.lstrip("/")
    memory = (directory / "memory.max").read_text().strip()
    swap = (directory / "memory.swap.max").read_text().strip()
    quota, period = (directory / "cpu.max").read_text().split()
    if (memory == "max" or int(memory) > MEMORY_LIMIT or swap != "0"
            or quota == "max" or int(quota) * 100 > int(period) * 150):
        raise RuntimeError("Use the lab launcher: RAM <= 4 GiB, no swap, CPU <= 150%")


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class VirtualMachine:
    def __init__(self, base: Path, directory: Path, name: str, *, memory: int = 2048,
                 socket_directory: Path, extra_network: list[str] | None = None,
                 canary: tuple[str, str] | None = None, ipv6: bool = True,
                 forwarded_ports: list[tuple[str, int, int]] | None = None):
        require_host_limits()
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", name) or not 512 <= memory <= 3072:
            raise ValueError("Invalid guest name or memory size")
        for tool in ["qemu-system-x86_64", "qemu-img", "xorriso", "ssh", "scp", "ssh-keygen"]:
            if shutil.which(tool) is None:
                raise RuntimeError(f"Missing VM tool: {tool}")
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise RuntimeError("KVM access is required; do not start a slow emulated fallback")
        self.base = base.resolve(strict=True)
        if not self.base.is_file():
            raise ValueError("The base image must be a regular file")
        self.directory = directory / name
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.name = name
        self.memory = memory
        self.extra_network = list(extra_network or [])
        if canary is not None and (canary[0] not in ["direct", "vps"]
                                   or str(uuid.UUID(canary[1])) != canary[1]):
            raise ValueError("Invalid guest test endpoint")
        self.canary = canary
        self.ipv6 = ipv6
        self.forwarded_ports = list(forwarded_ports or [])
        if any(protocol not in ("tcp", "udp") or not 1024 <= host <= 65535 or not 1 <= guest <= 65535
               for protocol, host, guest in self.forwarded_ports):
            raise ValueError("Invalid isolated loopback forwarding")
        self.agent_ready = False
        self.port = free_port()
        self.run_id = str(uuid.uuid4())
        self.key = self.directory / "ssh-key"
        self.known_hosts = self.directory / "known-hosts"
        self.agent_path = socket_directory / f"{name}.sock"
        self.process: subprocess.Popen | None = None
        self.stderr = None
        self._prepare()

    def _prepare(self) -> None:
        host_key = self.directory / "guest-host-key"
        for key in [self.key, host_key]:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                           check=True)
        public_host_key = host_key.with_suffix(".pub").read_text().split()
        self.known_hosts.write_text(
            f"{self.name} {' '.join(public_host_key[:2])}\n"
        )
        configuration = {
            "users": [{"name": "sirin", "groups": ["sudo"], "shell": "/bin/bash",
                       "lock_passwd": True, "sudo": "ALL=(ALL) NOPASSWD:ALL",
                       "ssh_authorized_keys": [self.key.with_suffix(".pub").read_text().strip()]}],
            "ssh_pwauth": False, "disable_root": True, "ssh_deletekeys": True,
            "manage_etc_hosts": True,
            "ssh_keys": {"ed25519_private": host_key.read_text(),
                         "ed25519_public": host_key.with_suffix(".pub").read_text()},
            "package_update": False, "package_upgrade": False,
            "write_files": [{"path": "/etc/sirinvpn-acceptance-fixture", "permissions": "0444",
                             "content": self.run_id + "\n"}],
            "runcmd": [["systemctl", "disable", "--now", "apt-daily.timer",
                        "apt-daily-upgrade.timer"]],
        }
        user_data = self.directory / "user-data"
        user_data.write_text("#cloud-config\n" + json.dumps(configuration) + "\n")
        user_data.chmod(0o600)
        (self.directory / "meta-data").write_text(
            json.dumps({"instance-id": self.run_id, "local-hostname": self.name}) + "\n"
        )
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b",
                        str(self.base), str(self.directory / "disk.qcow2")], check=True)
        subprocess.run(["qemu-img", "resize", "-q", str(self.directory / "disk.qcow2"), "16G"],
                       check=True)
        subprocess.run(["xorriso", "-as", "mkisofs", "-output", str(self.directory / "seed.img"),
                        "-volid", "cidata", "-joliet", "-rock", "-graft-points",
                        f"user-data={user_data}", f"meta-data={self.directory / 'meta-data'}"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start(self, *, network: bool = True, via_agent: bool = False) -> None:
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError("VM is already running")
        self.stderr = (self.directory / "qemu.log").open("ab")
        self.agent_path.unlink(missing_ok=True)
        self.agent_ready = False
        networking = (f"user,id=management,restrict={'off' if network else 'on'},"
                      f"ipv4=on,ipv6={'on' if self.ipv6 else 'off'},"
                      f"hostfwd=tcp:127.0.0.1:{self.port}-:22")
        for protocol, host, guest in self.forwarded_ports:
            networking += f",hostfwd={protocol}:127.0.0.1:{host}-:{guest}"
        if self.canary:
            # Unlike a lifetime chardev, cmd starts a fresh stream per guest TCP
            # connection. The responder uses only stdin/stdout inside this cgroup.
            command = shlex.join(["/usr/bin/python3", str(ROOT / "tests/vm/canary_http.py"),
                                  *self.canary])
            networking += f",guestfwd=tcp:10.0.2.100:18080-cmd:{command}"
        self.process = subprocess.Popen([
            "qemu-system-x86_64", "-machine", "accel=kvm", "-cpu", "host",
            "-m", str(self.memory), "-smp", "1", "-display", "none", "-no-reboot",
            "-drive", f"file={self.directory / 'disk.qcow2'},if=virtio,format=qcow2",
            "-drive", f"file={self.directory / 'seed.img'},if=virtio,format=raw,readonly=on",
            "-netdev", networking,
            "-device", "virtio-net-pci,netdev=management",
            "-chardev", f"socket,path={self.agent_path},id=agent,server=on,wait=off",
            "-device", "virtio-serial-pci",
            "-device", "virtserialport,chardev=agent,name=org.qemu.guest_agent.0",
            "-serial", f"file:{self.directory / 'serial.log'}", *self.extra_network,
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self.stderr)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"{self.name} exited during startup; inspect its private QEMU log")
            if via_agent:
                try:
                    result = self.run(["cat", "/etc/sirinvpn-acceptance-fixture"], timeout=3)
                    if result.stdout.decode().strip() == self.run_id:
                        return
                except (OSError, RuntimeError, subprocess.SubprocessError):
                    pass
                time.sleep(1)
                continue
            result = self.ssh(["cat", "/etc/sirinvpn-acceptance-fixture"], check=False, timeout=5)
            if result.returncode == 0 and result.stdout.decode().strip() == self.run_id:
                self.ssh(["sudo", "-n", "cloud-init", "status", "--wait"], timeout=180)
                if self.ssh(["sudo", "-n", "id", "-u"]).stdout.strip() != b"0":
                    raise RuntimeError("The disposable guest cannot run privileged tests")
                return
            time.sleep(1)
        raise RuntimeError(f"{self.name} did not become ready within 180 seconds")

    def _options(self) -> list[str]:
        return ["-i", str(self.key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "ConnectTimeout=3", "-o", "ConnectionAttempts=1", "-o", "LogLevel=ERROR",
                "-o", "StrictHostKeyChecking=yes", "-o", f"HostKeyAlias={self.name}",
                "-o", f"UserKnownHostsFile={self.known_hosts}",
                "-o", "GlobalKnownHostsFile=/dev/null"]

    def ssh(self, arguments: list[str], *, data: bytes | None = None, check: bool = True,
            timeout: int = 60, stdout=None, stderr=None) -> subprocess.CompletedProcess:
        return subprocess.run(["ssh", *self._options(), "-p", str(self.port), "sirin@127.0.0.1",
                               shlex.join(arguments)], input=data, check=check, timeout=timeout,
                              stdout=subprocess.PIPE if stdout is None else stdout,
                              stderr=subprocess.PIPE if stderr is None else stderr)

    def put(self, source: Path, destination: str, *, timeout: int = 300) -> None:
        if not destination.startswith("/") or any(char in destination for char in "\r\n"):
            raise ValueError("Guest destinations must be absolute paths")
        subprocess.run(["scp", *self._options(), "-P", str(self.port), str(source),
                        "sirin@127.0.0.1:" + destination], check=True, timeout=timeout,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def run(self, arguments: list[str], *, data: bytes | None = None,
            check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
        with GuestAgent(self.agent_path) as agent:
            result = agent.run(arguments, data=data, check=check, timeout=timeout)
            self.agent_ready = True
            return result

    def stop(self, *, crash: bool = False) -> None:
        if self.process is None:
            return
        if self.process.poll() is None and not crash:
            try:
                if self.agent_ready:
                    self.run(["systemctl", "poweroff"], timeout=8, check=False)
                else:
                    self.ssh(["sudo", "-n", "systemctl", "poweroff"], timeout=8, check=False)
                self.process.wait(timeout=20)
            except (subprocess.SubprocessError, OSError, RuntimeError):
                pass
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        if self.stderr is not None:
            self.stderr.close()


class Lab:
    def __init__(self, directory: Path):
        require_host_limits()
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix="runtime-", dir=directory))
        # Unix socket paths have a small fixed bound; checkout paths can be long.
        self.socket_directory = Path(tempfile.mkdtemp(prefix="sirinvpn-vm-agent."))
        self.guests: list[VirtualMachine] = []

    def guest(self, base: Path, name: str, **arguments) -> VirtualMachine:
        guest = VirtualMachine(base, self.directory, name,
                               socket_directory=self.socket_directory, **arguments)
        self.guests.append(guest)
        return guest

    def close(self) -> None:
        for guest in reversed(self.guests):
            guest.stop()
        shutil.rmtree(self.directory)
        shutil.rmtree(self.socket_directory)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
