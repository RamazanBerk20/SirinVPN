"""Provision only vps_lab.py's disposable guest, through the real Android service."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("fixture", type=Path)
args = parser.parse_args()
serial = os.environ.get("ANDROID_SERIAL", "emulator-5560")
assert re.fullmatch(r"emulator-\d+", serial)
fixture = json.loads(args.fixture.read_text())
assert fixture["host"] == "10.0.2.2" and fixture["name"] == "Android isolated VPS"
key = Path(fixture["private_key_source"])
ssh = ["ssh", "-i", str(key), "-p", str(fixture["ssh_port"]), "-o", "HostKeyAlias=android-vps",
       "-o", "UserKnownHostsFile=" + str(key.parent / "known-hosts"), "-o", "GlobalKnownHostsFile=/dev/null",
       "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "sirin@127.0.0.1"]
assert subprocess.check_output(ssh + ["cat /etc/sirinvpn-acceptance-fixture"], text=True).strip() == fixture["fixture"]
fixture["private_key_pem"] = key.read_text()
adb = [str(Path(os.environ.get("ANDROID_HOME", Path.home() / "Android/Sdk")) / "platform-tools/adb"), "-s", serial]
# Test-only file is private to the app and deleted by the native test immediately after reading.
subprocess.run(adb + ["shell", "run-as org.sirinvpn.client sh -c 'umask 077; cat > no_backup/acceptance-vps-input'"],
               input=json.dumps(fixture), text=True, check=True)
result = subprocess.run(adb + ["shell", "am", "instrument", "-w", "-e", "class",
    "org.sirinvpn.client.ServiceAcceptanceTest", "-e", "action", "provision",
    "org.sirinvpn.client.test/androidx.test.runner.AndroidJUnitRunner"], text=True, capture_output=True)
print(result.stdout)
assert result.returncode == 0 and "OK (1 test)" in result.stdout, "Native provisioning failed"
