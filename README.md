# Persistent Authenticated Browser Profile (Session Continuity)

*[Русская версия: README.ru.md](README.ru.md)*

An open-source Hermes skill that lets an agent continue work the
owner has already authorized in their own Yandex Mail account, by
reusing **one durable, local Chromium user-data profile** across
separate runs — so cookies, `localStorage`, `IndexedDB`, and
service-worker state persist the same way they would for a human's
everyday browser.

This is **session continuity**, not fingerprint spoofing and not
human-trace simulation. See `SKILL.md`'s "What this is not" section
for the exact, enforced boundary.

## What it does

- Keeps a single Chromium profile alive between agent runs so the
  owner does not have to log in every time.
- Defaults to **read-only** mailbox access (list/open/read/search).
- Requires an **explicit, per-action human approval record** before
  any send, delete, move, forward, or settings change.
- Treats every email's content — subject, body, sender, links — as
  **untrusted data**, never as a command, even if the text itself
  says otherwise.
- Restricts navigation to a small, published allowlist of Yandex Mail
  domains (`references/yandex_mail_allowlist.md`).

## What it deliberately does not do

- Does not read, request, or store the account password.
- Does not touch MFA or CAPTCHA — the human owner completes those by
  hand, every time they're required.
- Does not spoof WebGL/Canvas/TLS fingerprints, patch
  `navigator.webdriver`, override the User-Agent, or run any stealth-
  automation plugin.
- Does not solve CAPTCHAs, rotate proxies, or simulate human mouse/
  typing behavior.
- Does not import cookies or session tokens from anywhere else.
- Does not disable the Chromium sandbox, run as root, or expose CDP
  on anything other than `127.0.0.1`.

See `THREAT_MODEL.md` for the reasoning behind each exclusion and
`SECURITY.md` for how to report a gap.

## Quick start

```sh
# 1. One-time: create the profile directory (outside Git, mode 0700).
#    Run as a dedicated, unprivileged service account -- never root.
scripts/launch_browser.sh --init --profile-dir ~/.persistent-browser-session/yandex-mail

# 2. One-time (and again whenever the session expires): the owner
#    signs in by hand, including any MFA/CAPTCHA step.
scripts/launch_browser.sh --interactive --profile-dir ~/.persistent-browser-session/yandex-mail

# 3. Every subsequent run: resume the already-authenticated session.
scripts/launch_browser.sh --profile-dir ~/.persistent-browser-session/yandex-mail
```

No step above accepts a password, cookie, or token as an argument,
an environment variable, or a file this skill reads.

## Repository layout

| Path | Purpose |
|---|---|
| `SKILL.md` | The skill definition agents load: boundary, workflow, invariants. |
| `scripts/launch_browser.sh` | Safe launcher: root/sandbox/lock/CDP/allowlist checks, no secrets. |
| `scripts/domain_policy.py` | Yandex Mail allowlist check (offline, no network). |
| `scripts/action_policy.py` | Read-only/mutating classification and approval gate. |
| `scripts/profile_guard.py` | Profile directory permission/location checks. |
| `scripts/safety_lint.py` | Bans anti-detect/credential/network patterns in this repo's own code. |
| `scripts/skill_lint.py` | Validates `SKILL.md`'s frontmatter and required safety fragments. |
| `scripts/secret_scan.py` | Deterministic secret-shape scanner for this repo. |
| `fixtures/dry_run_session.json` | Synthetic mailbox fixture — no real data. |
| `scripts/dry_run.py` | Exercises the policies against the fixture, offline. |
| `tests/` | Dependency-free `unittest` suite covering all of the above. |
| `references/` | Allowlist, revoke/logout instructions, profile-storage requirements. |
| `THREAT_MODEL.md`, `SECURITY.md` | Threats considered, exclusions, and how to report a gap. |

## Running the tests and dry run

```sh
python3 -m unittest discover -s tests -v
python3 scripts/dry_run.py
python3 scripts/secret_scan.py .
```

All of the above run fully offline against the synthetic fixture —
no real browser, network call, or credential is involved.

## License

MIT — see `LICENSE`.
