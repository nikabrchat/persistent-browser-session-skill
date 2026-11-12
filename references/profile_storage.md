# Profile storage, isolation, and stability requirements

This reference documents the operational invariants
`scripts/launch_browser.sh` enforces, and why each one exists. None of
it is deployment-specific — there are no real paths, hostnames, or
host-specific service configuration here, only the general
requirements an operator must satisfy on their own host.

## Location

- The profile directory lives **outside any Git working tree** —
  typically under the dedicated service account's home directory
  (e.g. `~/.persistent-browser-session/<label>/`), never inside this
  skill's own repository checkout.
- `scripts/launch_browser.sh` refuses to run if the resolved profile
  path, or any of its parent directories, contains a `.git` directory.

## Permissions

- The profile directory must be exactly mode `0700` (owner
  read/write/execute only) before the launcher will use it.
  `scripts/launch_browser.sh --init` creates it with that mode;
  `scripts/profile_guard.py` can verify an existing directory.
- The directory must be owned by a **dedicated, unprivileged OS
  user** created specifically to run this skill — not the owner's own
  interactive login account, and never `root`. This limits the blast
  radius if the agent process itself is ever compromised: it can read
  the mail session, nothing else on the host.

## Single-worker lock

- `scripts/launch_browser.sh` takes an exclusive `flock` on
  `<profile>/.lock` before launching Chromium, and holds it for the
  lifetime of the browser process. A second invocation against the
  same profile directory fails immediately instead of starting a
  concurrent Chromium instance against the same `IndexedDB`/cookie
  store, which both Chromium and the mail web app assume will not
  happen.

## Sandbox

- The Chromium sandbox is always enabled. The launcher never passes
  `--no-sandbox` or `--disable-setuid-sandbox`, and explicitly omits
  any flag that would weaken process isolation between the renderer
  and the host.

## Optional CDP, loopback only

- Chrome DevTools Protocol access is **off by default**. When an
  operator opts in with `--enable-cdp PORT`, the launcher binds
  `--remote-debugging-address=127.0.0.1` — never `0.0.0.0` or any
  routable interface — so CDP is reachable only from processes on the
  same host, never over the network.

## Stability, not fingerprint diversity

- Binary path, `--lang`, `TZ`, and `DISPLAY` are pinned to fixed
  values per deployment and reused on every launch of a given
  profile. The goal is that **the same profile behaves identically
  across runs** — this is the same operational property a human's
  everyday browser already has (it does not change its language or
  timezone between sessions) — not an attempt to make the profile look
  like any particular real device or blend in with other traffic. No
  value here is tuned against what Yandex (or any detection system)
  is believed to check for.
- Changing any of these values for an existing profile is an
  operator decision with operational consequences (Yandex may ask for
  re-verification if the apparent locale/timezone changes
  unexpectedly) — it is not something this skill's own code does
  automatically.

## What operators must still provide themselves

This skill ships the launcher and its checks; it does not ship or
assume any specific host's service-manager unit, reverse proxy,
firewall, or mandatory-access-control (e.g. AppArmor/SELinux) policy.
Operators running this in production should apply their own host
hardening (a systemd service running as the dedicated user with
`ProtectHome`, `NoNewPrivileges`, etc., or equivalent) — this is
general host-security practice, not something specific to this skill,
and intentionally not encoded here so this repository never needs to
describe anyone's real infrastructure.
