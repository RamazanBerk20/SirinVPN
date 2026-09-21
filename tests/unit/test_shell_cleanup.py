"""Exercise the actual cleanup assertion with fake OS commands, without a VPN."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CleanupAssertions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "tests/integration/linux-fallback-vps.sh").read_text()
        match = re.search(r"^assert_local_clean\(\) \{\n.*?^\}", source, re.M | re.S)
        if not match:
            raise AssertionError("The integration cleanup assertion was not found")
        cls.assertion = match[0]

    def run_assertion(self, failure, conditional):
        stubs = """
failure=$1
HELPER_STATUS=$2
helper_status() { [ "$failure" != helper ]; }
jq() { [ "$failure" != status ]; }
ip() { [ "$failure" = sirinvpn0 ]; }
systemctl() { [ "$failure" = "$3" ]; }
local_root() { [ "$failure" = "$5" ]; }
"""
        # A conditional caller disables errexit within a shell function. Both
        # call forms must still reject a failed proof or any leftover resource.
        call = "if assert_local_clean; then exit 0; else exit 1; fi" if conditional else "assert_local_clean"
        with tempfile.TemporaryDirectory(prefix="sirinvpn-shell-test-") as directory:
            return subprocess.run(
                ["/bin/sh", "-eu", "-c", stubs + self.assertion + "\n" + call,
                 "cleanup-test", failure, str(Path(directory) / "status")],
                capture_output=True, timeout=5,
            ).returncode

    def test_clean_system_is_accepted(self):
        for conditional in [False, True]:
            with self.subTest(conditional=conditional):
                self.assertEqual(self.run_assertion("none", conditional), 0)

    def test_each_failed_proof_and_leftover_resource_is_rejected(self):
        for failure in ["helper", "status", "sirinvpn0", "sirinvpn-killswitch.service",
                        "sirinvpn-reconnect.service", "sirinvpn-transport.service",
                        "sirinvpn_guard", "sirinvpn_client", "sirinvpn_client6"]:
            for conditional in [False, True]:
                with self.subTest(failure=failure, conditional=conditional):
                    self.assertNotEqual(self.run_assertion(failure, conditional), 0)


if __name__ == "__main__":
    unittest.main()
