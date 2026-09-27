"""Notice collection must reject unbound or path-escaping source archives."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("materials", Path(__file__).resolve().parents[2] / "scripts/create-release-materials.py")
MATERIALS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIALS)
SYSTEM_SPEC = importlib.util.spec_from_file_location("system_notices", Path(__file__).resolve().parents[2] / "scripts/collect-appimage-notices.py")
SYSTEM = importlib.util.module_from_spec(SYSTEM_SPEC)
SYSTEM_SPEC.loader.exec_module(SYSTEM)


class PublisherNotices(unittest.TestCase):
    def test_checked_in_publisher_bytes_match_provenance(self):
        manifest = json.loads((MATERIALS.ROOT / 'release/publisher-notice-sources.json').read_text())
        documents = [file for row in manifest['components'].values() for file in row['files']]
        documents += manifest['appimage_notice_review']['notices']
        for document in documents:
            path = (MATERIALS.ROOT / document['path']).resolve(strict=True)
            self.assertTrue(path.is_relative_to(MATERIALS.ROOT / 'packaging/third-party'))
            self.assertEqual(MATERIALS.digest(path), document['sha256'], document['path'])

    @unittest.skipUnless(shutil.which('dpkg-query') and shutil.which('readelf'), 'Debian tools required')
    def test_unowned_bundled_elf_cannot_disappear_from_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sirin-acceptance-unowned-elf'
            shutil.copyfile('/bin/true', path)
            with self.assertRaisesRegex(AssertionError, 'Unidentified'):
                SYSTEM.package_source(path)

    def test_supplemental_notice_is_bound_to_crate_and_notice_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'packaging/third-party/LICENSE'
            source.parent.mkdir(parents=True)
            source.write_bytes(b'synthetic publisher notice')
            rows = {'pkg:cargo/fixture@1': {'crate_sha256': 'crate-digest', 'files': [{
                'path': 'packaging/third-party/LICENSE',
                'url': 'https://example.invalid/pinned-commit/LICENSE',
                'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}]}}
            with patch.object(MATERIALS, 'ROOT', root):
                files, _ = MATERIALS.supplemental_notices('pkg:cargo/fixture@1', 'crate-digest', rows)
                self.assertTrue(MATERIALS.notice(files[0][0]))
                with self.assertRaises(AssertionError):
                    MATERIALS.supplemental_notices('pkg:cargo/fixture@1', 'changed-crate', rows)
                source.write_bytes(b'changed notice')
                with self.assertRaises(AssertionError):
                    MATERIALS.supplemental_notices('pkg:cargo/fixture@1', 'crate-digest', rows)

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
