"""Notice collection must reject unbound or path-escaping source archives."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("materials", Path(__file__).resolve().parents[2] / "scripts/create-release-materials.py")
MATERIALS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIALS)


class PublisherNotices(unittest.TestCase):
    def test_archive_binding_and_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.crate"
            with tarfile.open(path, "w:gz") as archive:
                item = tarfile.TarInfo("fixture-1/LICENSE")
                item.size = 7
                archive.addfile(item, io.BytesIO(b"fixture"))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(list(MATERIALS.crate_notices(path, digest)), [("fixture-1/LICENSE", b"fixture")])
            with self.assertRaises(AssertionError):
                list(MATERIALS.crate_notices(path, "0" * 64))
            for name in ["../LICENSE", "/LICENSE", "a\\LICENSE", "C:/LICENSE", "bad\0/LICENSE"]:
                with self.assertRaises(AssertionError):
                    MATERIALS.safe_name(name)
