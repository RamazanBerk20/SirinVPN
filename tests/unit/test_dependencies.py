"""Reviewed notices must never hide new findings or an incomplete scan."""
import copy
import datetime
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dependencies", ROOT / "scripts/check-dependencies.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
TODAY = datetime.date(2026, 9, 27)


def fixture():
    packages = []
    for advisory, (ecosystem, name, version, _) in CHECK.REVIEWS.items():
        packages.append({"package": {"ecosystem": ecosystem, "name": name, "version": version},
                         "licenses": ["MIT"], "vulnerabilities": [{"id": advisory, "affected": [
                             {"package": {"name": name}, "database_specific": {"informational": "unmaintained"}}]}]})
    return {"results": [{"source": {"path": str(ROOT / "Cargo.lock"), "type": "lockfile"},
                         "packages": packages}],
            "experimental_config": {"licenses": {"allowlist": CHECK.LICENSES.split(",")}}}


class DependencyPolicy(unittest.TestCase):
    def test_only_reviewed_findings_pass_without_rewriting_raw_evidence(self):
        report = fixture()
        original = copy.deepcopy(report)
        reviewed, blocked = CHECK.review_results(report, 1, ["Cargo.lock"], TODAY)
        self.assertEqual((len(reviewed), blocked), (9, []))
        self.assertEqual(report, original)
        for change in ("id", "version", "ecosystem", "license", "classification", "severity", "expiry"):
            with self.subTest(change=change):
                report = fixture()
                item = report["results"][0]["packages"][2]
                day = TODAY
                if change == "id":
                    item["vulnerabilities"].append({"id": "NEW-ADVISORY", "aliases": ["RUSTSEC-2024-0370"]})
                elif change in ("version", "ecosystem"):
                    item["package"][change] = "unreviewed"
                elif change == "license":
                    item["license_violations"] = ["UNKNOWN"]
                elif change == "classification":
                    item["vulnerabilities"][0]["affected"][0]["database_specific"]["informational"] = "unsound"
                elif change == "severity":
                    item["vulnerabilities"][0]["severity"] = [{"type": "CVSS_V3", "score": "new"}]
                else:
                    day = CHECK.REVIEW_UNTIL
                self.assertTrue(CHECK.review_results(report, 1, ["Cargo.lock"], day)[1])

    def test_failed_empty_partial_and_inconsistent_scans_cannot_pass(self):
        for code in (-9, 0, 2, 127, 128):
            with self.subTest(code=code), self.assertRaises(AssertionError):
                CHECK.review_results(fixture(), code, ["Cargo.lock"], TODAY)
        for change in ("empty", "missing-lock", "licenses", "generic", "unexplained-exit"):
            report = fixture()
            if change == "empty":
                report["results"] = []
            elif change == "missing-lock":
                report["results"][0]["source"]["path"] = "/unscanned.lock"
            elif change == "licenses":
                report["experimental_config"]["licenses"]["allowlist"] = []
            elif change == "generic":
                report["experimental_generic_findings"] = [{"id": "unreviewed"}]
            else:
                for item in report["results"][0]["packages"]:
                    item["vulnerabilities"] = []
            with self.subTest(change=change), self.assertRaises(AssertionError):
                CHECK.review_results(report, 1, ["Cargo.lock"], TODAY)
        self.assertEqual(CHECK.review_results(report, 0, ["Cargo.lock"], TODAY), ([], []))

    def test_openpgp_absence_requires_both_android_import_graphs(self):
        version = next(line.split()[1] for line in
                       (ROOT / "apps/desktop/android/wireguard/go.mod").read_text().splitlines()
                       if line.startswith("go "))
        clean = "org.sirinvpn/wireguard\ngolang.zx2c4.com/wireguard/device\n"
        with patch.object(CHECK.subprocess, "check_output", side_effect=["go" + version, clean, clean]) as run:
            CHECK.verify_go_imports()
            self.assertEqual([call.kwargs["env"]["GOARCH"] for call in run.call_args_list[1:]], ["arm64", "amd64"])
        for imports in ("", clean + "golang.org/x/crypto/openpgp\n", clean + "golang.org/x/crypto/openpgp/packet\n"):
            with patch.object(CHECK.subprocess, "check_output", side_effect=["go" + version, clean, imports]):
                with self.assertRaises(AssertionError):
                    CHECK.verify_go_imports()
        with patch.object(CHECK.subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, "go")):
            with self.assertRaises(subprocess.CalledProcessError):
                CHECK.verify_go_imports()
