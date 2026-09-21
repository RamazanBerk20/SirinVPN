#!/usr/bin/env python3
"""Run the deferred Linux kernel tests in fresh containers inside a QEMU VM."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import subprocess
import tarfile
import time

from lab import Lab, ROOT, digest


EXPECTED = {"sirinvpn_linux_helper", "sirinvpn_installer", "sirinvpn_server"}
IMAGE = "sirinvpn-kernel-runtime:acceptance"


def inputs(artifacts: Path, destination: Path) -> dict:
    binaries = {}
    for line in artifacts.read_text().splitlines():
        row = json.loads(line)
        if row.get("executable") and row.get("profile", {}).get("test"):
            name = row["target"]["name"]
            if name in binaries or name not in EXPECTED:
                raise ValueError("Unexpected or duplicate kernel test executable")
            path = ROOT / Path(row["executable"]).relative_to("/workspace")
            if path.is_symlink() or not path.is_file():
                raise ValueError("A test executable is missing or is a symlink")
            binaries[name] = path
    if set(binaries) != EXPECTED:
        raise ValueError("The current installer, helper and server tests are required")
    helper = ROOT / "apps/desktop/src-tauri/binaries/sirinvpn-helper"
    paths = {f"binaries/{name}": path for name, path in binaries.items()}
    paths["binaries/sirinvpn-helper"] = helper
    for path in sorted((ROOT / "tests/network").glob("*.py")):
        paths[path.relative_to(ROOT).as_posix()] = path
    manifest = {"sha256": {name: digest(path) for name, path in paths.items()},
                "test_binaries": sorted(binaries)}
    with tarfile.open(destination, "w") as archive:
        for name in ["crates", "crates/linux-helper", "crates/installer", "crates/server"]:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            archive.addfile(member)
        for name, path in paths.items():
            if path.is_symlink():
                raise ValueError("Only ordinary source and executable files enter the VM")
            member = archive.gettarinfo(str(path), arcname=name)
            member.uid = member.gid = 0
            member.uname = member.gname = "root"
            member.mode = 0o755 if name.startswith("binaries/") else 0o644
            with path.open("rb") as content:
                archive.addfile(member, content)
        content = (json.dumps(manifest, indent=2) + "\n").encode()
        member = tarfile.TarInfo("input-manifest.json")
        member.size = len(content)
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(content))
    return manifest


def run(arguments) -> int:
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    logs = output / "logs"
    logs.mkdir(exist_ok=True)
    bundle = output / "kernel-input.tar"
    manifest = inputs(arguments.artifacts, bundle)
    report = {
        "scope": "Debian 13 guest kernel; each check in a fresh network-none guest container",
        "host_privileged_networking": False, "host_root": False,
        "limits": {"host_memory_bytes": 4 * 1024**3, "host_cpu_percent": 150,
                   "guest_memory_mib": 2048, "swap_bytes": 0, "test_threads": 1},
        "base_image_sha256": digest(arguments.base),
        "runtime_image_archive_sha256": digest(arguments.image),
        "inputs": manifest, "tests": [],
    }
    report_path = output / "kernel-results.json"
    try:
        with Lab(output) as lab:
            guest = lab.guest(arguments.base, "sirin-kernel", memory=2048)
            print("Starting the disposable Debian kernel VM", flush=True)
            guest.start()
            report["kernel"] = guest.ssh(["uname", "-r"]).stdout.decode().strip()
            print("Preparing guest-only Docker and kernel modules", flush=True)
            with (logs / "guest-setup.log").open("wb") as log:
                guest.ssh(["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "sh", "-ec",
                           "apt-get -o Acquire::Retries=2 update\n"
                           "apt-get install -y --no-install-recommends docker.io docker-cli kmod\n"
                           "systemctl start docker\nmodprobe wireguard\nmodprobe nft_chain_nat\n"
                           "modprobe nf_tables\nmodprobe dummy\nmodprobe veth\n"],
                          timeout=600, stdout=log, stderr=log)
            guest.put(arguments.image, "/home/sirin/kernel-runtime.tar")
            guest.put(bundle, "/home/sirin/kernel-input.tar")
            with (logs / "guest-image.log").open("wb") as log:
                guest.ssh(["sudo", "-n", "sh", "-ec",
                           "docker load -i /home/sirin/kernel-runtime.tar\n"
                           "mkdir -p /opt/sirinvpn-kernel-input\n"
                           "tar -xf /home/sirin/kernel-input.tar -C /opt/sirinvpn-kernel-input\n"
                           "rm /home/sirin/kernel-runtime.tar /home/sirin/kernel-input.tar\n"],
                          timeout=300, stdout=log, stderr=log)
            report["runtime_image_id"] = guest.ssh(
                ["sudo", "-n", "docker", "image", "inspect", "--format", "{{.Id}}", IMAGE]
            ).stdout.decode().strip()
            print("Restarting the guest with external networking disabled", flush=True)
            guest.stop()
            guest.start(network=False)
            # Docker containers cannot load host modules. Load them in this VM,
            # whose kernel is separate from the development workstation.
            guest.ssh(["sudo", "-n", "sh", "-ec",
                       "modprobe wireguard\nmodprobe nft_chain_nat\nmodprobe nf_tables\n"
                       "modprobe dummy\nmodprobe veth\nsystemctl start docker\n"])
            run_prefix = ["sudo", "-n", "docker", "run", "--rm", "--network", "none",
                          "--memory=1g", "--memory-swap=1g", "--cpus=1", "--pids-limit=128",
                          "--volume", "/opt/sirinvpn-kernel-input:/workspace:ro",
                          "--workdir", "/workspace", "--env", "SIRINVPN_POLICY_ISOLATED=1",
                          "--env", "RUST_TEST_THREADS=1"]
            tests = []
            for binary in manifest["test_binaries"]:
                listed = guest.ssh([*run_prefix, IMAGE, f"/workspace/binaries/{binary}",
                                    "--list", "--ignored"], timeout=90).stdout.decode()
                tests.extend((binary, line.removesuffix(": test")) for line in listed.splitlines()
                             if line.endswith(": test"))
            if len(tests) != 15:
                raise RuntimeError(f"Expected the 15 deferred checks, discovered {len(tests)}")
            selected = [(binary, name) for binary, name in tests
                        if not arguments.filter or arguments.filter in name]
            if not selected:
                raise ValueError("The filter selected no deferred tests")
            report["discovered"] = len(tests)
            report["selected"] = len(selected)
            cases = [(binary, name, forwarding)
                     for binary, name in selected
                     for forwarding in ([0, 1] if "kernel_application_packet_" in name
                                        else [1] if binary == "sirinvpn_server" else [0])]
            report["cases"] = len(cases)
            for index, (binary, name, forwarding) in enumerate(cases, 1):
                print(f"[{index}/{len(cases)}] {name} (IPv6 forwarding={forwarding})", flush=True)
                options = []
                if name.endswith("isolated_root_staging_runs_when_run_is_noexec"):
                    options += ["--tmpfs", "/run:rw,noexec,nosuid,nodev,size=16m"]
                if "kernel_" in name:
                    options += ["--cap-add=NET_ADMIN", "--cap-add=SYS_ADMIN", "--cap-add=SYS_PTRACE",
                               "--security-opt=apparmor=unconfined", "--security-opt=seccomp=unconfined"]
                options += ["--sysctl", "net.ipv4.ip_forward=1", "--sysctl",
                            f"net.ipv6.conf.all.forwarding={forwarding}"]
                setup = ("install -D -m 0755 /workspace/binaries/sirinvpn-helper "
                         "/usr/lib/sirinvpn/sirinvpn-helper\nexec \"$@\"")
                started = time.monotonic()
                result = guest.ssh([*run_prefix, *options, IMAGE, "sh", "-ec", setup, "sh",
                                    f"/workspace/binaries/{binary}", "--ignored", "--exact", name,
                                    "--test-threads=1", "--nocapture"], timeout=300, check=False)
                (logs / f"kernel-{index:02d}.log").write_bytes(result.stdout + result.stderr)
                passed = (result.returncode == 0 and b"1 passed; 0 failed" in result.stdout)
                report["tests"].append({"binary": binary, "name": name,
                                        "initial_ipv6_forwarding": forwarding,
                                        "passed": passed, "exit_code": result.returncode,
                                        "seconds": round(time.monotonic() - started, 2)})
                report_path.write_text(json.dumps(report, indent=2) + "\n")
                print("PASS" if passed else f"FAIL (kernel-{index:02d}.log)", flush=True)
            report["passed"] = sum(test["passed"] for test in report["tests"])
            report["failed"] = len(report["tests"]) - report["passed"]
            print(f"Deferred checks: {report['passed']} passed, {report['failed']} failed", flush=True)
        report["guest_cleanup"] = "complete"
        return 0 if report["failed"] == 0 else 1
    finally:
        report_path.write_text(json.dumps(report, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--filter", help="Run only deferred tests containing this literal text")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
