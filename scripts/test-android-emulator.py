#!/usr/bin/env python3
"""Run native tests in a fresh, owned AVD; never attach to an existing device.

Run under the documented 4 GiB systemd resource scope. Requires installed SDK
tools and google_apis/x86_64 image for --api, plus current debug/test APKs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    sys.path.insert(0, str(ROOT / "tests/vm"))
    from lab import require_host_limits
    require_host_limits()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--api", choices=[29, 36], type=int, default=36)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700)  # Refuse preexisting fixture state.
    sdk = Path(os.environ.get("ANDROID_HOME", str(Path.home() / "Android/Sdk")))
    report = {"fixture": "fresh disposable AVD; no personal device", "result": "failed",
              "api": args.api, "artifacts": []}
    group = next(line.split("::")[1] for line in Path("/proc/self/cgroup").read_text().splitlines()
                 if line.startswith("0::"))
    scope = Path("/sys/fs/cgroup") / group.lstrip("/")
    report["resource_limits"] = {name: (scope / name).read_text().strip()
        for name in ["memory.high", "memory.max", "memory.swap.max", "cpu.max", "pids.max"]}
    for path in [args.apk, args.tests]:
        with path.open("rb") as source:
            report["artifacts"].append({"filename": path.name, "size": path.stat().st_size,
                "sha256": hashlib.file_digest(source, "sha256").hexdigest(), "signing_category": "development"})
    env = dict(os.environ, ANDROID_AVD_HOME=str(output / "avd-home"),
               ANDROID_EMULATOR_HOME=str(output / "emulator-home"), ANDROID_USER_HOME=str(output / "android-user"))
    for directory in [env["ANDROID_AVD_HOME"], env["ANDROID_EMULATOR_HOME"], env["ANDROID_USER_HOME"]]:
        Path(directory).mkdir()
    # Keep this harness's ADB server independent of the user's device connections.
    with socket.socket() as port:
        port.bind(("127.0.0.1", 0))
        adb_port = port.getsockname()[1]
    env["ANDROID_ADB_SERVER_PORT"] = str(adb_port)
    emulator_port = None
    for number in range(5580, 5680, 2):
        try:
            with socket.socket() as first, socket.socket() as second:
                first.bind(("127.0.0.1", number)); second.bind(("127.0.0.1", number+1))
            emulator_port = number
            break
        except OSError:
            continue
    assert emulator_port, "No free emulator port"
    serial = f"emulator-{emulator_port}"
    adb = [str(sdk / "platform-tools/adb"), "-P", str(adb_port), "-s", serial]
    child = None
    def run(command, **kwargs):
        timeout = kwargs.pop("timeout", 120)
        return subprocess.run(command, env=env, check=True, timeout=timeout, capture_output=True, **kwargs)
    try:
        run([str(sdk / "cmdline-tools/latest/bin/avdmanager"), "create", "avd", "--name", "sirin-remediation",
             "--path", str(output / "avd"), "--package", f"system-images;android-{args.api};google_apis;x86_64"], input=b"no\n")
        run([*adb[:-2], "start-server"])
        with (output / "emulator.log").open("wb") as log:
            child = subprocess.Popen([str(sdk / "emulator/emulator"), "-avd", "sirin-remediation",
                "-port", str(emulator_port), "-no-window", "-no-audio", "-no-snapshot", "-no-boot-anim",
                "-no-metrics", "-skin", "320x640", "-dpi-device", "160", "-feature", "-Vulkan",
                "-memory", "2560" if args.api == 36 else "1024", "-cores", "1", "-gpu", "swiftshader"],
                env=env, stdout=log, stderr=log)
        deadline = time.monotonic() + 360
        while time.monotonic() < deadline:
            if child.poll() is not None:
                report["emulator_exit_code"] = child.returncode
                raise RuntimeError("Disposable emulator failed to start; inspect emulator.log")
            try:
                result = subprocess.run([*adb, "shell", "getprop", "sys.boot_completed"], env=env, capture_output=True, timeout=10)
            except subprocess.TimeoutExpired:
                continue
            if result.stdout.strip() == b"1":
                break
            time.sleep(2)
        else:
            raise TimeoutError("Emulator boot deadline exceeded")
        assert run([*adb, "shell", "getprop", "ro.hardware"]).stdout.strip() in [b"ranchu", b"goldfish"]
        report["build"] = run([*adb, "shell", "getprop", "ro.build.fingerprint"]).stdout.decode().strip()
        for apk in [args.apk, args.tests]:
            run([*adb, "install", "--no-streaming", "--no-incremental", "-t", str(apk.resolve())], timeout=300)
        if args.api >= 33:
            run([*adb, "shell", "pm", "grant", "org.sirinvpn.client", "android.permission.POST_NOTIFICATIONS"])
        # This fresh AVD alone receives fixture consent/permissions. These native
        # service checks do not qualify the OS consent-dialog interaction.
        run([*adb, "shell", "appops", "set", "org.sirinvpn.client", "ACTIVATE_VPN", "allow"])
        for permission in ["ACCESS_COARSE_LOCATION", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION"]:
            run([*adb, "shell", "pm", "grant", "org.sirinvpn.client", "android.permission." + permission])
        run([*adb, "shell", "settings", "put", "secure", "location_mode", "3"])
        cases = ["VaultAcceptanceTest", "NotificationTrafficTest", "QrScannerTest",
                 "OptionHandlingTest#packageReplacementUsesOrdinaryRecovery",
                 "OptionHandlingTest#optionsControlTheRunningService"]
        if args.api >= 30:
            cases.append("OptionHandlingTest#savedWifiIdentitySurvivesRoaming")
        result = run([*adb, "shell", "am", "instrument", "-w", "-r", "-e", "class",
            ",".join("org.sirinvpn.client." + case for case in cases),
            "org.sirinvpn.client.test/androidx.test.runner.AndroidJUnitRunner"], timeout=300)
        (output / "instrumentation.log").write_bytes(result.stdout + result.stderr)
        match = re.search(rb"OK \((\d+) tests?\)", result.stdout)
        assert match and b"FAILURES" not in result.stdout, "Instrumentation assertions failed"
        report.update(result="passed", tests=int(match[1]), cases=cases)
        return 0
    except Exception as error:
        report["failure"] = type(error).__name__
        raise
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=10)
            assert child.poll() is not None
        subprocess.run([*adb[:-2], "kill-server"], env=env, capture_output=True, timeout=15)
        for directory in [output / "avd", output / "avd-home", output / "emulator-home", output / "android-user"]:
            if directory.exists():
                shutil.rmtree(directory)
        report["cleanup"] = "owned emulator stopped; AVD and credentials removed"
        report["memory_events"] = dict(line.split() for line in (scope / "memory.events").read_text().splitlines())
        report["peak_memory_bytes"] = int((scope / "memory.peak").read_text())
        (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
