"""Offline allowlist check for navigation targets used by this skill.

Unlike a blocklist-style SSRF filter, this is a strict *allowlist*:
the only hosts an agent driving the persistent profile may navigate to
are the small, fixed set of public Yandex Mail / Yandex Passport
domains this skill exists to work with. Everything else is rejected,
including look-alike and subdomain tricks.

Standard library only. No network access -- this is a static string
check over a URL/hostname.
"""

from __future__ import annotations

import dataclasses
from urllib.parse import urlsplit

# Public, well-known Yandex domains this skill is scoped to. These are
# Yandex's own published domains (not private/internal infrastructure)
# and are the minimum set needed for mail access and its login flow.
ALLOWED_DOMAINS: tuple[str, ...] = (
    "mail.yandex.ru",
    "mail.yandex.com",
    "yandex.ru",
    "passport.yandex.ru",
    "passport.yandex.com",
    "ya.ru",
)

ALLOWED_SCHEMES: tuple[str, ...] = ("https",)


@dataclasses.dataclass
class PolicyResult:
    ok: bool
    reason: str = ""


def _host_matches_allowlist(host: str) -> bool:
    host = host.lower().rstrip(".")
    for allowed in ALLOWED_DOMAINS:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def check(url: str) -> PolicyResult:
    """Return PolicyResult(ok=True) only for an https:// URL whose host
    is, or is a subdomain of, an entry in ALLOWED_DOMAINS.
    """
    if not url or not isinstance(url, str):
        return PolicyResult(ok=False, reason="empty or non-string URL")

    # Reject control characters, embedded whitespace, and userinfo
    # tricks (user:pass@host) up front, before even parsing.
    if any(c.isspace() for c in url):
        return PolicyResult(ok=False, reason="URL contains whitespace")

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        return PolicyResult(ok=False, reason=f"unparseable URL: {exc}")

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return PolicyResult(ok=False, reason=f"scheme {parts.scheme!r} is not allowed")

    if parts.username or parts.password:
        return PolicyResult(ok=False, reason="userinfo in URL is not allowed")

    host = parts.hostname
    if not host:
        return PolicyResult(ok=False, reason="URL has no host")

    if not _host_matches_allowlist(host):
        return PolicyResult(ok=False, reason=f"host {host!r} is not on the Yandex Mail allowlist")

    return PolicyResult(ok=True)


def _main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "check":
        print("usage: domain_policy.py check <url>")
        return 2
    result = check(argv[2])
    if result.ok:
        print(f"ALLOW: {argv[2]}")
        return 0
    print(f"BLOCK: {argv[2]} ({result.reason})")
    return 1


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv))
