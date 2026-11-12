"""Static source-safety lint for this repository's own scripts.

Purely textual/regex scanning -- no import, no `eval`, no `exec`, no
execution of the scanned file whatsoever. Standard library only.

Two families of banned pattern:

1. General capability bans shared with other skills in this workspace
   (network access, subprocess/exec-style execution, credential
   prompts, destructive filesystem calls, hardcoded sensitive paths).
2. Anti-detect / fingerprint-spoofing / stealth-automation bans that
   are specific to this skill's non-negotiable boundary (see
   SKILL.md "What this is not"): no stealth browser-automation
   plugins, no TLS-fingerprint libraries, no CAPTCHA-solving SDKs, no
   proxy-rotation libraries, no synthetic human-input simulation.
"""

from __future__ import annotations

import re

BANNED_SOURCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # -- general capability bans --
    ("os_system", re.compile(r"\bos\.system\(")),
    ("os_popen", re.compile(r"\bos\.popen\(")),
    ("eval_call", re.compile(r"(?<![\w.])eval\(")),
    ("exec_call", re.compile(r"(?<![\w.])exec\(")),
    ("compile_call", re.compile(r"(?<![\w.])compile\(")),
    ("dynamic_import", re.compile(r"__import__\(")),
    ("socket_module", re.compile(r"\bimport\s+socket\b|\bsocket\s*\.\s*socket\(")),
    (
        "network_client",
        re.compile(
            r"\bimport\s+(?:urllib\.request|http\.client|requests|httpx|aiohttp)\b"
        ),
    ),
    ("webbrowser_module", re.compile(r"\bimport\s+webbrowser\b")),
    ("cookie_jar", re.compile(r"\bimport\s+http\.cookiejar\b|CookieJar\(")),
    ("credential_prompt", re.compile(r"\bimport\s+getpass\b")),
    ("destructive_fs", re.compile(r"shutil\.rmtree\(|os\.remove\(|os\.unlink\(")),
    (
        "hardcoded_sensitive_path",
        re.compile(r"""['"](/root|/home/[^'"]*|/etc|/var/[^'"]*)[^'"]*['"]"""),
    ),
    # -- anti-detect / fingerprint-spoofing / stealth bans --
    (
        "stealth_automation_plugin",
        re.compile(
            r"undetected_chromedriver|puppeteer-extra-plugin-stealth|selenium-stealth|playwright-stealth",
            re.IGNORECASE,
        ),
    ),
    (
        "tls_fingerprint_library",
        re.compile(r"\bimport\s+(?:curl_cffi|tls_client)\b", re.IGNORECASE),
    ),
    (
        "captcha_solver",
        re.compile(
            r"2captcha|anticaptcha|capsolver|deathbycaptcha|captcha[_-]?solv",
            re.IGNORECASE,
        ),
    ),
    (
        "proxy_rotation",
        re.compile(r"proxy[_-]?rotat|residential[_-]?proxy|proxy[_-]?pool", re.IGNORECASE),
    ),
    (
        "fingerprint_spoofing_flag",
        re.compile(
            r"disable-blink-features=AutomationControlled|navigator\.webdriver\s*=|spoof[_-]?(canvas|webgl|fingerprint)",
            re.IGNORECASE,
        ),
    ),
    (
        "synthetic_human_input",
        re.compile(
            r"human[_-]?(mouse|typing|cadence)|humanize[_-]?(mouse|typing)|pyautogui\.(move|click)",
            re.IGNORECASE,
        ),
    ),
    (
        "no_sandbox_flag",
        re.compile(r"--no-sandbox|--disable-setuid-sandbox"),
    ),
]


def scan_source(text: str) -> list[dict]:
    """Return [{"category", "line"}] for every banned-pattern hit in `text`."""
    hits: list[dict] = []
    for category, pattern in BANNED_SOURCE_PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            hits.append({"category": category, "line": line})
    hits.sort(key=lambda h: h["line"])
    return hits


def scan_file(path) -> list[dict]:
    import pathlib

    text = pathlib.Path(path).read_text(encoding="utf-8")
    return scan_source(text)
