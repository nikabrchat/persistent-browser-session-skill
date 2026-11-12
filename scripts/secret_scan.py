"""Deterministic, dependency-free secret scanner for this repository.

Scans text content (never executes anything) for shapes that commonly
indicate a leaked credential: bearer tokens, basic-auth URLs, private
key blocks, AWS-style access keys, generic high-entropy "password ="
assignments, and `.env`-style secret assignments. This is a floor, not
a guarantee -- see SECURITY.md and THREAT_MODEL.md for the residual
risk this does not close.

Standard library only (`re`, `pathlib`). No network access.
"""

from __future__ import annotations

import dataclasses
import re

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}")),
    ("basic_auth_url", re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("generic_api_key_assignment", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[=:]\s*['\"][A-Za-z0-9/+_\-]{16,}['\"]")),
    ("password_assignment", re.compile(r"(?i)\bpassword\b\s*[=:]\s*['\"][^'\"\s]{4,}['\"]")),
    ("jwt_like", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("yandex_oauth_token", re.compile(r"\by0_[A-Za-z0-9_\-]{20,}\b")),
]

# Paths that legitimately *describe* these shapes (docs, tests,
# fixtures using obviously-synthetic placeholder values) are not
# exempted here -- exemption happens at the call site by choosing what
# to scan, not by weakening the patterns.


@dataclasses.dataclass
class ScanHit:
    category: str
    line: int


def scan_text(text: str) -> list[ScanHit]:
    hits: list[ScanHit] = []
    for category, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            hits.append(ScanHit(category=category, line=line))
    hits.sort(key=lambda h: h.line)
    return hits


def scan_path(path) -> list[ScanHit]:
    import pathlib

    p = pathlib.Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, IsADirectoryError):
        return []
    return scan_text(text)


def scan_tree(root, *, exclude_dirs: frozenset[str] = frozenset({".git", "__pycache__"})) -> dict:
    import pathlib

    root = pathlib.Path(root)
    report: dict[str, list[dict]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in exclude_dirs for part in path.parts):
            continue
        hits = scan_path(path)
        if hits:
            report[str(path.relative_to(root))] = [
                {"category": h.category, "line": h.line} for h in hits
            ]
    return report


def _main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: secret_scan.py <root-dir>")
        return 2
    report = scan_tree(argv[1])
    if not report:
        print(f"PASS: no secret-shaped content found under {argv[1]}")
        return 0
    print(f"FAIL: secret-shaped content found under {argv[1]}")
    for file_path, hits in report.items():
        for hit in hits:
            print(f"  - {file_path}:{hit['line']} ({hit['category']})")
    return 1


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv))
