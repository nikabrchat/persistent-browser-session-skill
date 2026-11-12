from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import dry_run  # noqa: E402


class TestDryRun(unittest.TestCase):
    def test_fixture_file_exists(self):
        self.assertTrue(dry_run.FIXTURE_PATH.is_file())

    def test_run_reports_no_failures_against_shipped_fixture(self):
        fixture = dry_run.load_fixture()
        failures = dry_run.run(fixture)
        self.assertEqual(failures, [])

    def test_main_exits_zero(self):
        self.assertEqual(dry_run.main(), 0)

    def test_injection_laden_message_is_still_denied_without_approval(self):
        fixture = dry_run.load_fixture()
        forward_requests = [
            r for r in fixture["requested_actions"] if r["action"] == "forward_message"
        ]
        self.assertTrue(forward_requests)
        for request in forward_requests:
            self.assertFalse(request["expect_allowed"])
            self.assertIsNone(request["approval"])


if __name__ == "__main__":
    unittest.main()
