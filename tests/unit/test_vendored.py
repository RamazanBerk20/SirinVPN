"""Advisory mitigation requires both the reviewed code and Cargo's selection."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("vendored", ROOT / "scripts/check-vendored.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class VendoredBackport(unittest.TestCase):
    def test_modified_source_and_registry_fallback_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "vendor", root / "vendor")
            for name in ["Cargo.toml", "Cargo.lock"]:
                shutil.copyfile(ROOT / name, root / name)
            previous = CHECK.ROOT
            CHECK.ROOT = root
            try:
                CHECK.verify()
                source = root / "vendor/glib/src/variant_iter.rs"
                original = source.read_bytes()
                source.write_bytes(original + b"\n// changed\n")
                with self.assertRaises(AssertionError):
                    CHECK.verify()
                source.write_bytes(original)
                link = source.parent / "unreviewed-directory"
                link.symlink_to(root, target_is_directory=True)
                with self.assertRaises(AssertionError):
                    CHECK.verify()
                link.unlink()
                lock = root / "Cargo.lock"
                lock.write_text(lock.read_text().replace(
                    'name = "glib"\nversion = "0.18.5"',
                    'name = "glib"\nversion = "0.18.5"\nsource = "registry+https://github.com/rust-lang/crates.io-index"'))
                with self.assertRaises(AssertionError):
                    CHECK.verify()
            finally:
                CHECK.ROOT = previous
