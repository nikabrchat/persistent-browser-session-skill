from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GITIGNORE = ROOT / ".gitignore"


class TestGitignoreCoversRequiredPatterns(unittest.TestCase):
    def setUp(self):
        self.text = GITIGNORE.read_text(encoding="utf-8")

    def test_gitignore_exists(self):
        self.assertTrue(GITIGNORE.is_file())

    def test_covers_profiles(self):
        self.assertIn("profiles/", self.text)

    def test_covers_cookies(self):
        self.assertIn("cookies", self.text)

    def test_covers_storage_state(self):
        self.assertIn("storageState", self.text)

    def test_covers_screenshots(self):
        self.assertIn("screenshots/", self.text)

    def test_covers_logs(self):
        self.assertIn("logs/", self.text)

    def test_covers_downloads(self):
        self.assertIn("downloads/", self.text)

    def test_covers_state(self):
        self.assertIn("state/", self.text)

    def test_covers_credential_files(self):
        for pattern in ("*.pem", "*.key", "credentials.json", "secrets.json"):
            with self.subTest(pattern):
                self.assertIn(pattern, self.text)

    def test_does_not_use_overbroad_secret_wildcard(self):
        # A bare "*secret*" wildcard would also match this repo's own
        # legitimate scripts/secret_scan.py and tests/test_secret_scan.py.
        self.assertNotIn("*secret*", self.text)
        self.assertNotIn("*password*", self.text)


class TestGitignoreActuallyExcludesLegitimateSourceFiles(unittest.TestCase):
    """Regression guard: credential-file patterns must not accidentally
    shadow real, tracked source files in this repository.
    """

    def test_secret_scan_py_not_matched_by_any_gitignore_line(self):
        import fnmatch

        patterns = [
            line.strip()
            for line in GITIGNORE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        target = "secret_scan.py"
        for pattern in patterns:
            cleaned = pattern.strip("/")
            with self.subTest(pattern):
                self.assertFalse(
                    fnmatch.fnmatch(target, cleaned),
                    f"gitignore pattern {pattern!r} would shadow {target}",
                )


if __name__ == "__main__":
    unittest.main()
