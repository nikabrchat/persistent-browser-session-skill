# Security Policy

## Scope

This repository is a skill definition (`SKILL.md`), reference
documents, a small dependency-free shell launcher
(`scripts/launch_browser.sh`), a small dependency-free Python policy
toolkit (`scripts/*.py`), tests (`tests/`), and a synthetic dry-run
fixture (`fixtures/`). It is not a running network service and ships
no credentials, cookies, or real mail data. "Security" here means:

- the boundary in `SKILL.md` ("What this is not") is correct,
  complete, and enforced in code, not just prose;
- `scripts/domain_policy.py` correctly allows only the Yandex Mail
  domains in `references/yandex_mail_allowlist.md` and rejects
  everything else, including userinfo and non-`https` tricks;
- `scripts/action_policy.py` never allows a mutating action (send/
  delete/move/forward/settings) without an approval record that
  matches the exact action and target;
- `scripts/launch_browser.sh` never disables the Chromium sandbox,
  never runs as root, never binds CDP to a non-loopback address, and
  refuses to use a profile directory that is inside Git or not mode
  `0700`;
- none of the shipped scripts perform network access, subprocess/
  `exec`/`eval`, or read a password/credential — enforced by
  `scripts/safety_lint.py` and `tests/test_safety_lint.py`;
- no anti-detect, fingerprint-spoofing, CAPTCHA-solving, proxy-
  rotation, or synthetic-human-input capability exists anywhere in
  this repository — enforced by the same lint plus a manual `git
  grep` sweep before every release.

## Handling of this repository itself

- This repository never contains a real browser profile, cookies,
  `storageState`, screenshots, browser history, downloaded
  attachments, or real mail content. See `.gitignore`.
- Before publishing or sharing a checkout, run:
  `python3 scripts/secret_scan.py .` and confirm `PASS`, and run the
  manual sweep in `tests/test_secret_scan.py` and
  `tests/test_safety_lint.py`.

## Reporting a vulnerability or a safety gap

If you find any of the following while reviewing this repository,
please open an issue (or, for a sensitive finding, contact the
maintainer privately first):

- a way the documented boundary in `SKILL.md` could be bypassed while
  an agent follows the workflow as written;
- a gap in `scripts/domain_policy.py` that lets a non-allowlisted host
  pass as safe, or an encoding/smuggling trick that evades the check;
- a way `scripts/action_policy.py.authorize()` could be made to permit
  a mutating action without a matching, human-sourced approval record;
- a gap in `scripts/launch_browser.sh` that would let it run as root,
  disable the sandbox, bind CDP to a non-loopback address, or use a
  profile directory that is not mode `0700` or is inside Git;
- any code path, anywhere in this repository, that reads a password,
  solves a CAPTCHA, spoofs a fingerprint, rotates a proxy, or
  simulates human input — any of these existing at all is itself the
  bug, regardless of whether it is also exploitable.

Please reproduce the gap as a failing test under `tests/` alongside
the report if you can — this repository was built test-first and new
gaps are expected to arrive the same way.

## What is *not* in scope

- Vulnerabilities in Chromium, the OS, or the agent runtime that
  executes this skill.
- Vulnerabilities in Yandex's own services.
- Confidentiality of a live profile directory against an attacker who
  already has root (or equivalent) access to the host running it —
  see `THREAT_MODEL.md`'s residual-risk section.
- Host-specific deployment configuration (service manager units,
  reverse proxies, mandatory-access-control policy) — intentionally
  not included in this repository; see `references/profile_storage.md`.

## Response

There is no formal SLA; this is a community open-source project. Any
confirmed gap gets a regression test added under `tests/` so it
cannot silently reappear.
