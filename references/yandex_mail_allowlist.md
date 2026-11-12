# Yandex Mail navigation allowlist

`scripts/domain_policy.py` enforces this as a strict **allowlist** —
only these public, Yandex-published domains (and their subdomains) may
be navigated to by the agent-driven side of this skill. Everything
else is rejected, including redirect targets, embedded links inside
mail content, and look-alike domains.

| Domain | Purpose |
|---|---|
| `mail.yandex.ru` | Primary Yandex Mail web interface (Russian locale) |
| `mail.yandex.com` | Yandex Mail web interface, international locale |
| `yandex.ru` | Yandex's main domain; some mail-related redirects pass through it |
| `passport.yandex.ru` | Yandex Passport — the login/MFA/account-security flow |
| `passport.yandex.com` | Yandex Passport, international locale |
| `ya.ru` | Yandex's short domain, used in some login redirects |

These are Yandex's own public, documented domains — not private or
internal infrastructure, and not specific to any individual owner's
deployment. No other host is in scope for this skill, regardless of
what a page or a message links to.

## Why an allowlist instead of a blocklist

A blocklist (reject known-bad hosts) is the wrong shape for a skill
that only ever needs to talk to one service: it would require
enumerating every host it must *not* visit, which is unbounded. An
allowlist (accept only the known-good, small, fixed set above) is
strictly smaller and fails closed — a host this list does not name is
rejected by default, with no exception path.

## What this does not cover

- It does not vouch for the safety of *content* served from an
  allowlisted host — email bodies, attachments, and embedded links are
  still untrusted data per `SKILL.md`.
- It does not replace server-side SSRF protections if this skill is
  ever composed with a tool that fetches arbitrary resources on the
  agent's behalf; `domain_policy.check()` only governs navigation
  performed by this skill's own launcher and action policy.
- It intentionally does not grow to include analytics, CDN, or
  third-party tracker domains that Yandex Mail's page may load in a
  browser; those load as a side effect of rendering the page, not as a
  navigation this skill initiates, and are outside this policy's
  concern.

## Changing the allowlist

Any change to `ALLOWED_DOMAINS` in `scripts/domain_policy.py` is a
security-relevant change to this skill's scope and should be reviewed
as carefully as a change to the action-approval gate — see
`tests/test_domain_policy.py` for the regression tests that must keep
passing.
