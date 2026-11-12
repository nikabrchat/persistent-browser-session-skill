"""Regression guard for SKILL.md's frontmatter shape and required
safety-boundary fragments. Written test-first against scripts/skill_lint.py.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import skill_lint  # noqa: E402

SKILL_PATH = ROOT / "SKILL.md"

GOOD_SKILL = """---
name: example-skill
description: "An example skill for testing."
version: 1.0.0
license: MIT
metadata:
  tags: [a, b, c]
---

# Example Skill
Body text here.
"""

MISSING_KEY_SKILL = """---
name: example-skill
version: 1.0.0
---

# Example Skill
"""

NO_FRONTMATTER_SKILL = "# Example Skill\nNo frontmatter block at all.\n"

UNCLOSED_FRONTMATTER_SKILL = """---
name: example-skill
description: "x"
version: 1.0.0
license: "x"

# Example Skill
"""


class TestParseFrontmatter(unittest.TestCase):
    def test_parses_scalar_fields(self):
        fm, body = skill_lint.parse_frontmatter(GOOD_SKILL)
        self.assertEqual(fm["name"], "example-skill")
        self.assertEqual(fm["version"], "1.0.0")
        self.assertIn("# Example Skill", body)

    def test_parses_quoted_description(self):
        fm, _ = skill_lint.parse_frontmatter(GOOD_SKILL)
        self.assertEqual(fm["description"], "An example skill for testing.")

    def test_parses_nested_metadata_tags_list(self):
        fm, _ = skill_lint.parse_frontmatter(GOOD_SKILL)
        self.assertEqual(fm["metadata"]["tags"], ["a", "b", "c"])

    def test_raises_on_missing_frontmatter_block(self):
        with self.assertRaises(skill_lint.FrontmatterError):
            skill_lint.parse_frontmatter(NO_FRONTMATTER_SKILL)

    def test_raises_on_unclosed_frontmatter_block(self):
        with self.assertRaises(skill_lint.FrontmatterError):
            skill_lint.parse_frontmatter(UNCLOSED_FRONTMATTER_SKILL)


class TestValidateSkillText(unittest.TestCase):
    def test_good_skill_passes_required_keys(self):
        result = skill_lint.validate_frontmatter_keys(GOOD_SKILL)
        self.assertTrue(result.ok, result.errors)

    def test_missing_required_keys_fail(self):
        result = skill_lint.validate_frontmatter_keys(MISSING_KEY_SKILL)
        self.assertFalse(result.ok)
        joined = " ".join(result.errors)
        self.assertIn("description", joined)
        self.assertIn("license", joined)


class TestShippedSkillFile(unittest.TestCase):
    """Guards the actual SKILL.md shipped at the repo root."""

    def setUp(self):
        self.text = SKILL_PATH.read_text(encoding="utf-8")

    def test_skill_file_exists(self):
        self.assertTrue(SKILL_PATH.is_file())

    def test_frontmatter_keys_present(self):
        result = skill_lint.validate_frontmatter_keys(self.text)
        self.assertTrue(result.ok, result.errors)

    def test_frontmatter_declares_mit_license(self):
        fm, _ = skill_lint.parse_frontmatter(self.text)
        self.assertEqual(fm["license"], "MIT")

    def test_required_rule_fragments_present(self):
        result = skill_lint.validate_required_fragments(self.text)
        self.assertTrue(result.ok, result.errors)

    def test_boundary_fragments_present(self):
        boundary_fragments = [
            "Not fingerprint spoofing",
            "Not CAPTCHA solving",
            "Not proxy rotation or IP masking",
            "Not synthetic human-trace simulation",
            "Not credential or cookie theft",
            "any flag that disables the Chromium sandbox",
            "Read-only",
            "untrusted data, never instructions",
        ]
        normalized = " ".join(self.text.split())
        for fragment in boundary_fragments:
            with self.subTest(fragment):
                self.assertIn(" ".join(fragment.split()), normalized)


if __name__ == "__main__":
    unittest.main()
