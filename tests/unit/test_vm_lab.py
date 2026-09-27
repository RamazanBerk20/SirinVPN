"""Failure paths use temporary directories and fake guests; never launch QEMU."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vm"))
from lab import Lab


class Cleanup(unittest.TestCase):
    def test_setup_interruption_and_cleanup_errors_are_not_success(self):
        with tempfile.TemporaryDirectory() as directory, patch("lab.require_host_limits"):
            root = Path(directory)
            for error in [ValueError("setup failed"), KeyboardInterrupt()]:
                lab = Lab(root)
                with self.assertRaises(type(error)):
                    with lab:
                        if isinstance(error, ValueError):
                            lab.guest(root / "absent.qcow2", "invalid guest name")
                        raise error
                self.assertFalse(lab.directory.exists())
                self.assertFalse(lab.socket_directory.exists())

            lab = Lab(root)
            stopped = []

            def failed_stop():
                stopped.append("failed")
                raise RuntimeError("synthetic guest shutdown failure")

            lab.guests = [SimpleNamespace(stop=lambda: stopped.append("healthy")),
                          SimpleNamespace(stop=failed_stop)]
            try:
                with self.assertRaisesRegex(ExceptionGroup, "shutdown incomplete"):
                    lab.close()
                self.assertEqual(stopped, ["failed", "healthy"])
                self.assertTrue(lab.directory.exists())
                self.assertTrue(lab.socket_directory.exists())
            finally:
                lab.guests = []  # No actual process was started in this test.
                lab.close()

            lab = Lab(root)
            lab.directory.rmdir()  # Simulate an unexpected cleanup error.
            with self.assertRaisesRegex(ExceptionGroup, "file cleanup incomplete"):
                lab.close()
            self.assertFalse(lab.socket_directory.exists())


if __name__ == "__main__":
    unittest.main()
