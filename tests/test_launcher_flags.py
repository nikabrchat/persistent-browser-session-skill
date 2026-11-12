"""Static checks over scripts/launch_browser.sh's text -- never executes
the script. Confirms the required invariants from SKILL.md are present
in the launcher's logic, and that no anti-detect/sandbox-disabling flag
is ever actually passed to the browser (as opposed to being named only
in a comment or the --help text explaining it is forbidden).
"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "scripts" / "launch_browser.sh"


class TestLauncherInvariants(unittest.TestCase):
    def setUp(self):
        self.text = LAUNCHER.read_text(encoding="utf-8")
        self.lines = self.text.splitlines()

    def test_launcher_exists_with_shebang(self):
        # The execute bit itself is tracked by Git (mode 100755 in the
        # index, restored by a normal checkout) rather than asserted
        # here against the filesystem, since sandboxed CI/build
        # environments can restrict chmod. A shebang line is the
        # portable signal that this file is meant to be run directly.
        self.assertTrue(LAUNCHER.is_file())
        self.assertTrue(self.lines[0].startswith("#!"))

    def test_refuses_to_run_as_root(self):
        self.assertIn('id -u', self.text)
        self.assertIn("refusing to run as root", self.text)

    def test_uses_flock_for_single_worker_lock(self):
        self.assertIn("flock -n 9", self.text)

    def test_checks_profile_not_in_git_tree(self):
        self.assertIn("check_not_in_git_tree", self.text)
        self.assertIn(".git", self.text)

    def test_checks_profile_permissions(self):
        self.assertIn("check_profile_permissions", self.text)

    def test_cdp_binds_loopback_only_when_enabled(self):
        self.assertIn("--remote-debugging-address=127.0.0.1", self.text)
        self.assertNotIn("--remote-debugging-address=0.0.0.0", self.text)

    def test_domain_allowlist_consulted_before_navigation(self):
        self.assertIn("domain_policy.py", self.text)

    def test_no_sandbox_flag_never_actually_passed(self):
        offending_lines = []
        for line in self.lines:
            if "--no-sandbox" in line or "--disable-setuid-sandbox" in line:
                stripped = line.strip()
                is_comment_or_doc = stripped.startswith("#") or "never" in stripped.lower() or "Never" in line
                if not is_comment_or_doc:
                    offending_lines.append(line)
        self.assertEqual(offending_lines, [], f"sandbox-disabling flag actually used: {offending_lines}")

    def test_no_anti_detect_flags_present_anywhere(self):
        banned_substrings = [
            "disable-blink-features=AutomationControlled",
            "undetected_chromedriver",
            "puppeteer-extra-plugin-stealth",
            "2captcha",
            "anticaptcha",
            "--proxy-server",
            "residential-proxy",
        ]
        for substring in banned_substrings:
            with self.subTest(substring):
                self.assertNotIn(substring, self.text)

    def test_no_user_agent_override(self):
        self.assertNotIn("--user-agent", self.text)

    def test_stable_lang_tz_display_flags_present(self):
        self.assertIn("--lang=", self.text)
        self.assertIn('TZ="$TZ_NAME"', self.text)
        self.assertIn("DISPLAY=", self.text)

    def test_bash_syntax_is_valid(self):
        import subprocess

        result = subprocess.run(
            ["bash", "-n", str(LAUNCHER)], capture_output=True, text=True, timeout=10
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
