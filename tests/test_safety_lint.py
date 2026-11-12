"""Static safety-lint eval: every *other* script shipped in scripts/
must be free of network access, subprocess/exec-style execution,
credential prompts, destructive filesystem calls, and -- specific to
this skill -- anti-detect/fingerprint-spoofing/stealth-automation/
CAPTCHA-solving/proxy-rotation/synthetic-human-input patterns.

scripts/safety_lint.py itself is excluded from the self-scan: its own
source necessarily *names* the patterns it bans (e.g. the literal
string "undetected_chromedriver" appears inside its own pattern
table), which would otherwise trip its own scanner. Every other
script must still come back clean, which is what actually matters:
the lint's *behavior* (does it correctly flag a synthetic sample?) is
covered separately below, and does not depend on scanning its own
definition file.

This is a *textual* scan -- it never imports or executes the files it
checks (other than scripts/safety_lint.py itself, which this test does
import, since it is the module under test).
"""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import safety_lint  # noqa: E402

SCRIPTS_DIR = ROOT / "scripts"
SELF_EXEMPT = {"safety_lint.py"}


class TestScriptsAreSideEffectAndAntiDetectSafe(unittest.TestCase):
    def test_scripts_directory_exists(self):
        self.assertTrue(SCRIPTS_DIR.is_dir())

    def test_every_non_exempt_script_has_zero_banned_patterns(self):
        py_files = sorted(
            p for p in SCRIPTS_DIR.glob("*.py") if p.name not in SELF_EXEMPT
        )
        self.assertGreaterEqual(len(py_files), 4, "expected several shipped scripts")
        for py_file in py_files:
            with self.subTest(py_file.name):
                hits = safety_lint.scan_file(py_file)
                self.assertEqual(
                    hits, [], f"{py_file.name} contains banned pattern(s): {hits}"
                )

    def test_scan_source_detects_eval_in_synthetic_sample(self):
        sample = "user_input = '1+1'\nresult = eval(user_input)\n"
        hits = safety_lint.scan_source(sample)
        categories = {h["category"] for h in hits}
        self.assertIn("eval_call", categories)

    def test_scan_source_detects_network_import_in_synthetic_sample(self):
        sample = "import urllib.request\nurllib.request.urlopen('http://example.com')\n"
        hits = safety_lint.scan_source(sample)
        categories = {h["category"] for h in hits}
        self.assertIn("network_client", categories)

    def test_scan_source_detects_credential_prompt_in_synthetic_sample(self):
        sample = "import getpass\npw = getpass.getpass()\n"
        hits = safety_lint.scan_source(sample)
        categories = {h["category"] for h in hits}
        self.assertIn("credential_prompt", categories)

    def test_scan_source_detects_stealth_plugin_in_synthetic_sample(self):
        sample = "from undetected_chromedriver import Chrome\n"
        hits = safety_lint.scan_source(sample)
        categories = {h["category"] for h in hits}
        self.assertIn("stealth_automation_plugin", categories)

    def test_scan_source_detects_captcha_solver_in_synthetic_sample(self):
        sample = "client = TwoCaptchaClient(api_key='x')  # 2captcha\n"
        hits = safety_lint.scan_source(sample)
        categories = {h["category"] for h in hits}
        self.assertIn("captcha_solver", categories)

    def test_scan_source_detects_proxy_rotation_in_synthetic_sample(self):
        sample = "proxy = get_next_residential_proxy()\n"
        hits = safety_lint.scan_source(sample)
        categories = {h["category"] for h in hits}
        self.assertIn("proxy_rotation", categories)

    def test_scan_source_detects_fingerprint_spoofing_flag_in_synthetic_sample(self):
        sample = "args.append('--disable-blink-features=AutomationControlled')\n"
        hits = safety_lint.scan_source(sample)
        categories = {h["category"] for h in hits}
        self.assertIn("fingerprint_spoofing_flag", categories)

    def test_scan_source_detects_synthetic_human_input_in_synthetic_sample(self):
        sample = "humanize_mouse_path(start, end)\n"
        hits = safety_lint.scan_source(sample)
        categories = {h["category"] for h in hits}
        self.assertIn("synthetic_human_input", categories)

    def test_scan_source_detects_no_sandbox_flag_in_synthetic_sample(self):
        sample = "args.append('--no-sandbox')\n"
        hits = safety_lint.scan_source(sample)
        categories = {h["category"] for h in hits}
        self.assertIn("no_sandbox_flag", categories)

    def test_scan_source_clean_for_ordinary_code(self):
        sample = "def add(a, b):\n    return a + b\n"
        self.assertEqual(safety_lint.scan_source(sample), [])


if __name__ == "__main__":
    unittest.main()
