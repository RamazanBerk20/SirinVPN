"""A failed or missing command must never become a passing evidence bundle."""
import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Evidence(unittest.TestCase):
    def test_changed_or_missing_test_input_cannot_qualify(self):
        for initial in (None, b'original artifact'):
            with self.subTest(initial=initial), tempfile.TemporaryDirectory() as directory:
                artifact = Path(directory) / 'synthetic.bin'
                if initial is not None:
                    artifact.write_bytes(initial)
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/record-evidence.py'),
                    '--suite', 'immutable', '--output', directory, '--tested-artifact', str(artifact),
                    '--', sys.executable, '-c',
                    'import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b"replacement")',
                    str(artifact)], capture_output=True, timeout=45)
                self.assertNotEqual(result.returncode, 0)
                report = json.loads((Path(directory) / 'immutable.json').read_text())
                self.assertEqual(report['result'], 'failed')
                self.assertEqual(report['reason'], 'ArtifactMissingOrUnsafe' if initial is None else 'TestedArtifactChanged')
                if initial is None:
                    self.assertFalse(artifact.exists(), 'Command ran without its declared test input')

    def test_artifact_is_bound_after_the_build(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "synthetic.bin"
            subprocess.run([sys.executable, str(ROOT / "scripts/record-evidence.py"),
                "--suite", "build", "--output", directory, "--artifact", str(artifact),
                "--signing-category", "unsigned-engineering", "--fixture", "disposable-test", "--", sys.executable,
                "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'synthetic artifact')",
                str(artifact)], check=True, capture_output=True, timeout=45)
            report = json.loads((Path(directory) / "build.json").read_text())
            self.assertEqual(report["result"], "passed")
            self.assertEqual(report["fixture"], "disposable-test")
            self.assertEqual(report["artifacts"][0]["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())

    def test_failures_missing_tools_and_timeouts_survive_reporting(self):
        cases = [(0, [sys.executable, "-c", "print('synthetic check')"]),
                 (7, [sys.executable, "-c", "raise SystemExit(7)"]),
                 (1, ["sirinvpn-nonexistent-test-tool"]),
                 (1, [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * (17*1024*1024))"]),
                 (1, [sys.executable, "-c", "import time; time.sleep(10)"])]
        for expected, command in cases:
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run([sys.executable, str(ROOT / "scripts/record-evidence.py"),
                                         "--suite", "fixture", "--output", directory,
                                         "--timeout", "1", "--", *command], capture_output=True, timeout=45)
                self.assertEqual(result.returncode, expected, result.stderr.decode())
                report = json.loads((Path(directory) / "fixture.json").read_text())
                self.assertEqual(report["result"], "passed" if expected == 0 else "failed")
                self.assertEqual(len(report["source"]["source_sha256"]), 64)
                self.assertIn("toolchains", report)
                self.assertLessEqual((Path(directory) / "fixture.log").stat().st_size, 16*1024*1024)
                repeated = subprocess.run([sys.executable, str(ROOT / "scripts/record-evidence.py"),
                    "--suite", "fixture", "--output", directory, "--", *command], capture_output=True, timeout=5)
                self.assertNotEqual(repeated.returncode, 0)
                self.assertEqual(json.loads((Path(directory) / "fixture.json").read_text()), report)


if __name__ == "__main__":
    unittest.main()
