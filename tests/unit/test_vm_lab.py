"""Failure paths use temporary directories and fake guests; never launch QEMU."""
from pathlib import Path
from contextlib import contextmanager
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vm"))
from lab import Lab
from linux_acceptance import Acceptance


class Cleanup(unittest.TestCase):
    def test_fallback_measures_new_packets_and_observes_disconnect(self):
        @contextmanager
        def capture(test, observation):
            test.clean_disconnect.assert_not_called()
            yield
            test.clean_disconnect.assert_called_once()

        for before, after, passes in [(0, 0, True), (1, 1, True), (0, 1, False),
                                      (1, 2, False), (1, 0, False)]:
            with self.subTest(before=before, after=after):
                test = Mock(spec=Acceptance)
                test.report, test.server_id = {}, 'synthetic'
                test.server = Mock()
                test.server.run.return_value.stdout = b'{"nftables":[{"rule":{"expr":[{"counter":{"packets":1}}]}}]}'
                test.counter.side_effect = [{"dns": before, "ipv6": 0}, {"dns": after, "ipv6": 0}]
                test.wait_connected.return_value = {"transport": "tls_like", "auto_reconnect_enabled": True,
                                                    "connect_on_startup": True}
                test.request.return_value = 'vps'
                with patch('dns_attribution.capture', capture), patch('dns_attribution.mark'):
                    if passes:
                        Acceptance.automatic_fallback(test)
                    else:
                        with self.assertRaises(AssertionError):
                            Acceptance.automatic_fallback(test)
                test.block_server.assert_called_with(None)

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
