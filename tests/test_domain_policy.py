from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import domain_policy  # noqa: E402


class TestAllowedHosts(unittest.TestCase):
    def test_mail_yandex_ru_allowed(self):
        self.assertTrue(domain_policy.check("https://mail.yandex.ru/").ok)

    def test_mail_yandex_com_allowed(self):
        self.assertTrue(domain_policy.check("https://mail.yandex.com/inbox").ok)

    def test_passport_yandex_ru_allowed(self):
        self.assertTrue(domain_policy.check("https://passport.yandex.ru/auth").ok)

    def test_subdomain_of_allowed_domain_allowed(self):
        self.assertTrue(domain_policy.check("https://m.mail.yandex.ru/").ok)


class TestRejectedHosts(unittest.TestCase):
    def test_unrelated_domain_rejected(self):
        result = domain_policy.check("https://example.test/")
        self.assertFalse(result.ok)

    def test_lookalike_domain_rejected(self):
        result = domain_policy.check("https://mail-yandex.ru.attacker.test/")
        self.assertFalse(result.ok)

    def test_suffix_trick_rejected(self):
        # "yandex.ru.attacker.test" must not satisfy endswith(".yandex.ru").
        result = domain_policy.check("https://yandex.ru.attacker.test/")
        self.assertFalse(result.ok)

    def test_non_https_scheme_rejected(self):
        result = domain_policy.check("http://mail.yandex.ru/")
        self.assertFalse(result.ok)

    def test_file_scheme_rejected(self):
        result = domain_policy.check("file:///etc/passwd")
        self.assertFalse(result.ok)

    def test_javascript_scheme_rejected(self):
        result = domain_policy.check("javascript:alert(1)")
        self.assertFalse(result.ok)

    def test_userinfo_trick_rejected(self):
        result = domain_policy.check("https://mail.yandex.ru@attacker.test/")
        self.assertFalse(result.ok)

    def test_empty_url_rejected(self):
        self.assertFalse(domain_policy.check("").ok)

    def test_whitespace_in_url_rejected(self):
        result = domain_policy.check("https://mail.yandex.ru/ \t/path")
        self.assertFalse(result.ok)


class TestCli(unittest.TestCase):
    def test_main_allow_exit_code(self):
        self.assertEqual(domain_policy._main(["prog", "check", "https://mail.yandex.ru/"]), 0)

    def test_main_block_exit_code(self):
        self.assertEqual(domain_policy._main(["prog", "check", "https://example.test/"]), 1)

    def test_main_usage_exit_code(self):
        self.assertEqual(domain_policy._main(["prog"]), 2)


if __name__ == "__main__":
    unittest.main()
