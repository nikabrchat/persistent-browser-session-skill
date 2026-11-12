from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import profile_guard  # noqa: E402


class TestCheckProfileDir(unittest.TestCase):
    def test_missing_dir_fails(self):
        result = profile_guard.check_profile_dir("/nonexistent/path/for/this/test")
        self.assertFalse(result.ok)

    def test_correct_permissions_and_location_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile_dir = pathlib.Path(tmp) / "profile"
            profile_dir.mkdir(mode=0o700)
            result = profile_guard.check_profile_dir(profile_dir)
            self.assertTrue(result.ok, result.errors)

    def test_overly_permissive_mode_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile_dir = pathlib.Path(tmp) / "profile"
            profile_dir.mkdir(mode=0o755)
            result = profile_guard.check_profile_dir(profile_dir)
            self.assertFalse(result.ok)

    def test_inside_git_tree_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / ".git").mkdir()
            profile_dir = root / "nested" / "profile"
            profile_dir.mkdir(parents=True, mode=0o700)
            result = profile_guard.check_profile_dir(profile_dir)
            self.assertFalse(result.ok)
            self.assertTrue(any("Git" in e for e in result.errors))

    def test_file_instead_of_dir_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = pathlib.Path(tmp) / "profile_file"
            profile_path.write_text("not a directory")
            result = profile_guard.check_profile_dir(profile_path)
            self.assertFalse(result.ok)


class TestCheckNotRoot(unittest.TestCase):
    def test_root_uid_fails(self):
        result = profile_guard.check_not_root(uid=0)
        self.assertFalse(result.ok)

    def test_nonzero_uid_passes(self):
        result = profile_guard.check_not_root(uid=1000)
        self.assertTrue(result.ok)


if __name__ == "__main__":
    unittest.main()
