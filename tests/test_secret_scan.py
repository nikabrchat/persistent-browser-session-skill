from __future__ import annotations

import pathlib
import re
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import secret_scan  # noqa: E402

# A benign, obviously-non-secret marker used to exercise scanner
# mechanics (matching, line numbers, tree walking) without ever
# constructing a provider-key-shaped or otherwise secret-shaped value.
CANARY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("synthetic_canary", re.compile(r"SYNTHETIC_CANARY_MARKER")),
]

# Category names the production registry must keep detecting. Listing
# the *names* lets this suite assert on scanner coverage without ever
# generating a value shaped to match any of them.
REQUIRED_DETECTOR_CATEGORIES = frozenset(
    {
        "private_key_block",
        "bearer_token",
        "basic_auth_url",
        "aws_access_key_id",
        "generic_api_key_assignment",
        "password_assignment",
        "jwt_like",
        "yandex_oauth_token",
    }
)


class TestScanMechanicsWithCanaryPatterns(unittest.TestCase):
    """Exercise scan_text/scan_path/scan_tree mechanics safely.

    The real SECRET_PATTERNS registry is temporarily replaced (via
    unittest.mock) with a benign canary regex for the duration of each
    test, so these tests prove the scanner *plumbing* works -- pattern
    matching, line-number accounting, tree walking, report shape --
    without ever needing a secret-shaped or provider-key-shaped value.
    """

    def test_scan_text_finds_canary_marker(self):
        sample = "line one\nSYNTHETIC_CANARY_MARKER appears here\nline three\n"
        with mock.patch.object(secret_scan, "SECRET_PATTERNS", CANARY_PATTERNS):
            hits = secret_scan.scan_text(sample)
        self.assertEqual([(h.category, h.line) for h in hits], [("synthetic_canary", 2)])

    def test_scan_text_without_canary_has_no_hits(self):
        sample = "This is an ordinary message with no markers in it.\n"
        with mock.patch.object(secret_scan, "SECRET_PATTERNS", CANARY_PATTERNS):
            hits = secret_scan.scan_text(sample)
        self.assertEqual(hits, [])

    def test_scan_path_finds_canary_marker(self):
        with mock.patch.object(secret_scan, "SECRET_PATTERNS", CANARY_PATTERNS):
            with mock.patch(
                "pathlib.Path.read_text",
                return_value="SYNTHETIC_CANARY_MARKER\n",
            ):
                hits = secret_scan.scan_path("ignored-path.txt")
        categories = {h.category for h in hits}
        self.assertIn("synthetic_canary", categories)

    def test_scan_tree_reports_canary_hit_by_relative_path(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = pathlib.Path(tmp)
            (tmp_dir / "canary.txt").write_text("SYNTHETIC_CANARY_MARKER\n", encoding="utf-8")
            (tmp_dir / "clean.txt").write_text("nothing to see here\n", encoding="utf-8")
            with mock.patch.object(secret_scan, "SECRET_PATTERNS", CANARY_PATTERNS):
                report = secret_scan.scan_tree(tmp_dir)
        self.assertEqual(set(report.keys()), {"canary.txt"})
        self.assertEqual(report["canary.txt"], [{"category": "synthetic_canary", "line": 1}])

    def test_scan_tree_clean_tree_has_no_hits(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = pathlib.Path(tmp)
            (tmp_dir / "clean.txt").write_text("nothing to see here\n", encoding="utf-8")
            with mock.patch.object(secret_scan, "SECRET_PATTERNS", CANARY_PATTERNS):
                report = secret_scan.scan_tree(tmp_dir)
        self.assertEqual(report, {})


class TestProductionRegistryCoversRequiredDetectors(unittest.TestCase):
    """Assert the real scanner still declares every required detector,
    by name only -- never by feeding it a matching value.
    """

    def test_all_required_categories_are_registered(self):
        registered = {category for category, _pattern in secret_scan.SECRET_PATTERNS}
        self.assertTrue(REQUIRED_DETECTOR_CATEGORIES.issubset(registered))

    def test_no_pattern_is_trivially_empty(self):
        for category, pattern in secret_scan.SECRET_PATTERNS:
            self.assertTrue(pattern.pattern, f"{category} has an empty pattern")


class TestScanTreeAgainstRepo(unittest.TestCase):
    """The shipped repository itself must come back clean against the
    real, unmodified production patterns -- no exemptions.
    """

    def test_repo_tree_has_no_secret_shaped_content(self):
        report = secret_scan.scan_tree(ROOT)
        self.assertEqual(report, {}, f"secret-shaped content found: {report}")


if __name__ == "__main__":
    unittest.main()
