#!/usr/bin/env python3
"""Run native tests in a fresh, owned AVD; never attach to an existing device.

Run under the documented 8 GiB systemd resource scope. Requires installed SDK
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
    parser.add_argument("--upgrade-from", type=Path, help="Older same-signer development APK for interrupted in-place upgrade checks")
    parser.add_argument("--api", choices=[31, 36], type=int, default=36)
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
    for path in [args.apk, args.tests, *([args.upgrade_from] if args.upgrade_from else [])]:
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
    def reboot():
        run([*adb, "reboot"])
        run([*adb, "wait-for-device"], timeout=180)
        deadline = time.monotonic() + 360
        while time.monotonic() < deadline:
            if run([*adb, "shell", "getprop", "sys.boot_completed"]).stdout.strip() == b"1": return
            time.sleep(2)
        raise TimeoutError("Emulator reboot timed out")
    def wifi_lifecycle():
        """Wi-Fi auto-connect without opening the app: after a kill, a reboot and an update; never after force-stop."""
        package = "org.sirinvpn.client"
        def step(method):
            # Finishing ordinary instrumentation force-stops the app; attach to a running one instead.
            run([*adb, "shell", "am", "start", "-W", "-n", package + "/.MainActivity"], timeout=60)
            result = run([*adb, "shell", "am", "instrument", "-w", "-r", "--no-restart", "-e", "class",
                "org.sirinvpn.client.WifiAutoConnectTest#" + method, package + ".test/androidx.test.runner.AndroidJUnitRunner"], timeout=300)
            (output / ("wifi-" + method + ".log")).write_bytes(result.stdout + result.stderr)
            assert b"OK (1 test)" in result.stdout and b"FAILURES" not in result.stdout, "Wi-Fi step failed: " + method
            run([*adb, "shell", "input", "keyevent", "KEYCODE_HOME"])
        def wifi(on):
            run([*adb, "shell", "svc", "wifi", "enable" if on else "disable"])
            if not on: return
            run([*adb, "shell", "cmd", "wifi", "connect-network", "AndroidWifi", "open"], timeout=60)
            # A "nothing started" check means something only once the Wi-Fi is really back.
            deadline = time.monotonic() + 90
            while b"Wifi is connected to" not in run([*adb, "shell", "cmd", "wifi", "status"], timeout=30).stdout:
                if time.monotonic() > deadline: raise TimeoutError("AndroidWifi did not reconnect")
                time.sleep(2)
        def services(expected, after):
            """expected: the one service running in the foreground, or None."""
            names = [".SirinVpnService", ".WifiWatchService"]
            deadline = time.monotonic() + 90
            while True:
                dump = run([*adb, "shell", "dumpsys", "activity", "services", package], timeout=30).stdout
                running = [name for name in names if name.encode() in dump]
                if running == ([expected] if expected else []) or time.monotonic() > deadline: break
                time.sleep(1)
            time.sleep(5)  # A start that is undone at once must not count.
            dump = run([*adb, "shell", "dumpsys", "activity", "services", package], timeout=30).stdout
            (output / ("wifi-services-" + after.replace(" ", "-") + ".log")).write_bytes(dump)
            running = [name for name in names if name.encode() in dump]
            assert running == ([expected] if expected else []) and (not expected or b"isForeground=true" in dump), \
                f"After {after}: expected {expected or 'nothing'}, found {running or 'nothing'}"
            return after
        def killed():
            # A low-memory style kill, not a force stop: Android keeps the app's network callback.
            run([*adb, "shell", "am", "kill", package])
            time.sleep(2)
            alive = subprocess.run([*adb, "shell", "pidof", package + ":vpn"], env=env, capture_output=True, timeout=30)
            assert not alive.stdout.strip(), ":vpn survived am kill"
        def booted():
            reboot()
            deadline = time.monotonic() + 180
            while b"act=android.intent.action.BOOT_COMPLETED" not in run([*adb, "shell", "dumpsys", "activity", "broadcasts", "history"], timeout=60).stdout:
                if time.monotonic() > deadline: raise TimeoutError("BOOT_COMPLETED was not sent")
                time.sleep(2)
        checks = []
        step("seedPausedOnUntrustedWifi")
        checks.append(services(".WifiWatchService", "pause on untrusted wifi"))
        wifi(False); checks.append(services(None, "wifi off"))
        killed(); wifi(True)
        checks.append(services(".SirinVpnService", "app killed then untrusted wifi joined"))
        step("verifyAutoConnectedThenTrust")
        checks.append(services(".WifiWatchService", "trusted wifi"))
        booted(); checks.append(services(".WifiWatchService", "reboot on trusted wifi"))
        wifi(False); checks.append(services(None, "wifi off after reboot"))
        killed(); wifi(True); checks.append(services(".WifiWatchService", "app killed then trusted wifi joined"))
        run([*adb, "install", "--no-streaming", "--no-incremental", "-r", "-t", str(args.apk.resolve())], timeout=300)
        checks.append(services(".WifiWatchService", "update on trusted wifi"))
        run([*adb, "shell", "am", "force-stop", package]); checks.append(services(None, "force stop"))
        wifi(False); wifi(True); checks.append(services(None, "force stop then wifi rejoined"))
        step("cleanupWifiAutoConnect")
        return {"checks": checks, "network": "emulator AndroidWifi (open); unreachable loopback server"}
    try:
        run([str(sdk / "cmdline-tools/latest/bin/avdmanager"), "create", "avd", "--name", "sirin-remediation",
             "--path", str(output / "avd"), "--package", f"system-images;android-{args.api};google_apis;x86_64"], input=b"no\n")
        run([*adb[:-2], "start-server"])
        with (output / "emulator.log").open("wb") as log:
            child = subprocess.Popen([str(sdk / "emulator/emulator"), "-avd", "sirin-remediation",
                "-port", str(emulator_port), "-no-window", "-no-audio", "-no-snapshot", "-no-boot-anim",
                "-no-metrics", "-skin", "320x640", "-dpi-device", "160", "-feature", "-Vulkan",
                "-memory", "2560" if args.api == 36 else "2048", "-cores", "1", "-gpu", "swiftshader"],
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
        if args.upgrade_from:
            for apk in [args.upgrade_from, args.tests]:
                run([*adb, "install", "--no-streaming", "--no-incremental", "-t", str(apk.resolve())], timeout=300)
            upgrade_invocation = 0
            def upgrade_check(method, expectation):
                nonlocal upgrade_invocation
                upgrade_invocation += 1
                result = run([*adb, "shell", "am", "instrument", "-w", "-r", "-e", "class",
                    "org.sirinvpn.client.UpgradeAcceptanceTest#"+method, "-e", "expectation", expectation,
                    "org.sirinvpn.client.test/androidx.test.runner.AndroidJUnitRunner"], timeout=120)
                (output / (f"upgrade-{upgrade_invocation}-"+method+"-"+expectation+".log")).write_bytes(result.stdout+result.stderr)
                assert b"OK (1 test)" in result.stdout and b"FAILURES" not in result.stdout, "Upgrade assertion failed"
            upgrade_check("seed", "old")
            upgrade_check("verifyPreserved", "old")
            run([*adb,"push",str(args.apk.resolve()),"/data/local/tmp/sirin-upgrade.apk"],timeout=180)
            created=run([*adb,"shell","pm","install-create","-r","-t","-S",str(args.apk.stat().st_size)]).stdout
            match=re.search(rb"Success: created install session \[(\d+)\]",created)
            assert match, "Could not create isolated upgrade session"
            session=match[1].decode()
            written=run([*adb,"shell","pm","install-write",session,"base","/data/local/tmp/sirin-upgrade.apk"]).stdout
            assert b"Success" in written
            # Interrupt an actual staged but uncommitted PackageInstaller update.
            reboot()
            if args.api == 36:
                barrier = run([*adb, "shell", "am", "wait-for-broadcast-barrier"], timeout=180)
                (output / "post-reboot-broadcast-barrier.log").write_bytes(barrier.stdout+barrier.stderr)
            upgrade_check("verifyPreserved", "old")
            assert b"Success" in run([*adb,"shell","pm","install-abandon",session]).stdout
            run([*adb,"install","--no-streaming","--no-incremental","-r","-t",str(args.apk.resolve())],timeout=300)
            upgrade_check("verifyPreserved", "candidate")
            upgrade_check("cleanup", "candidate")
            report["upgrade"]={"prior_install":args.upgrade_from.name, "interruption":"reboot before PackageInstaller commit",
                "old_state_after_interruption":True,"retry_installs_candidate":True,"profile_bytes_preserved":True,
                "native_profile_read":True,"ciphertext_and_keystore_read_preserved":True,"deleted_reference_stays_deleted":True,
                "paused_connection_intent_preserved":True,"scope":"synthetic profile/storage; no live VPS connection"}
        else:
            for apk in [args.apk, args.tests]:
                run([*adb, "install", "--no-streaming", "--no-incremental", "-t", str(apk.resolve())], timeout=300)
        if args.api >= 33:
            run([*adb, "shell", "pm", "grant", "org.sirinvpn.client", "android.permission.POST_NOTIFICATIONS"])
        # This fresh AVD alone receives fixture consent/permissions. These native
        # service checks do not qualify the OS consent-dialog interaction.
        run([*adb, "shell", "appops", "set", "org.sirinvpn.client", "ACTIVATE_VPN", "allow"])
        if args.api == 36:
            # Boot completion alone does not mean broadcasts have drained or the
            # synthetic Wi-Fi is the active underlay after an interrupted update.
            run([*adb, "shell", "am", "wait-for-broadcast-barrier"], timeout=180)
        # API 36 must have the synthetic AndroidWifi; an API 31 image without it only skips the Wi-Fi cases.
        wifi = False
        run([*adb, "shell", "svc", "wifi", "enable"])
        selected = subprocess.run([*adb, "shell", "cmd", "wifi", "connect-network", "AndroidWifi", "open"], env=env, capture_output=True, timeout=60)
        (output / "wifi-connect.log").write_bytes(selected.stdout+selected.stderr)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            status = run([*adb, "shell", "cmd", "wifi", "status"], timeout=30)
            (output / "wifi-before-native.log").write_bytes(status.stdout+status.stderr)
            if b"Wifi is connected to" in status.stdout and b"AndroidWifi" in status.stdout:
                wifi = True
                break
            time.sleep(2)
        if not wifi and args.api == 36:
            raise TimeoutError("Synthetic AndroidWifi fixture did not connect")
        report["wifi_fixture"] = wifi
        if wifi:
            state = run([*adb, "shell", "dumpsys", "connectivity"], timeout=30)
            (output / "network-before-native.log").write_bytes(state.stdout+state.stderr)
            # Wi-Fi auto-connect reads the network name, which Android shows only with precise
            # location, from the background only with "all the time", and only with Location on.
            for permission in ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION"]:
                run([*adb, "shell", "pm", "grant", "org.sirinvpn.client", "android.permission." + permission])
            run([*adb, "shell", "cmd", "location", "set-location-enabled", "true"])
        cases = ["VaultAcceptanceTest", "NotificationTrafficTest", "QrScannerTest", "NetworkRecoveryTest",
                 "OptionHandlingTest#packageReplacementUsesOrdinaryRecovery",
                 "OptionHandlingTest#optionsControlTheRunningService", "ExternalControlsTest",
                 *(["WifiAutoConnectTest#ruleFollowsTheNetworkLikeDesktop"] if wifi else [])]
        result = run([*adb, "shell", "am", "instrument", "-w", "-r", "-e", "class",
            ",".join("org.sirinvpn.client." + case for case in cases),
            "org.sirinvpn.client.test/androidx.test.runner.AndroidJUnitRunner"], timeout=300)
        (output / "instrumentation.log").write_bytes(result.stdout + result.stderr)
        match = re.search(rb"OK \((\d+) tests?\)", result.stdout)
        assert match and b"FAILURES" not in result.stdout, "Instrumentation assertions failed"
        if wifi:
            report["wifi_auto_connect"] = wifi_lifecycle()
        report.update(result="passed", tests=int(match[1]), cases=cases)
        return 0
    except Exception as error:
        report["failure"] = type(error).__name__
        if isinstance(error, subprocess.CalledProcessError):
            # The traceback names the device command; its captured output says why it failed.
            sys.stderr.buffer.write(error.stdout + error.stderr)
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
