# Revoking the session and logging out

The owner — not the agent — controls when the persistent session ends.
This skill never logs the owner out, revokes tokens, or deletes the
profile on its own initiative. If any of the following is wanted,
the owner (or an operator acting on the owner's explicit instruction)
performs it directly:

## 1. End the session from inside Yandex (recommended)

1. Sign in to <https://passport.yandex.ru> in any browser.
2. Open **Account → Security → Devices and account activity**
   ("Устройства и история активности" / "Активные сессии").
3. Find the session matching the agent's browser profile (it will
   show the approximate time of last activity and, if available, the
   user agent / platform string).
4. Choose **End session** / **Log out of this device**
   ("Завершить сеанс" / "Выйти на этом устройстве").

This immediately invalidates the server-side session, independent of
what is stored in the local Chromium profile — so it is the correct
first step if the owner suspects the profile or its host has been
compromised.

## 2. Log out from within the browser profile itself

1. Launch the profile interactively:
   `scripts/launch_browser.sh --interactive --profile-dir DIR`.
2. In Yandex Mail, use the account menu's **Log out** /
   **Выйти** action as the owner normally would.
3. Close the browser. The next launch will present the login page
   again rather than resuming a session.

## 3. Remove the local profile entirely

If the owner wants to make sure no local session state remains on
this host at all:

```sh
# Only the owner or an operator explicitly instructed by the owner
# should run this. It is irreversible for this profile.
rm -rf -- "$PROFILE_DIR"
```

After this, a fresh `scripts/launch_browser.sh --init` and a new
manual login (with MFA/CAPTCHA as Yandex requires) are needed before
the skill can resume any mail work.

## 4. Revoke third-party app access (if ever granted)

This skill does not use OAuth app tokens — it only relies on the
browser session created by the owner's own interactive login. If the
owner separately granted any third-party application access to the
mailbox (unrelated to this skill), that is managed at
**Account → Security → Apps with account access**
("Приложения с доступом к аккаунту") and is revoked from there, not by
this skill.

## When to do this

- Before decommissioning the host or dedicated service account that
  runs the profile.
- If the owner no longer wants the agent to have access, for any
  reason, without needing to explain why.
- If `scripts/action_policy.py`'s injection-marker scan, or any other
  signal, suggests the mailbox may be receiving content specifically
  crafted to manipulate the agent — ending the session is a reasonable
  precaution while the owner reviews what happened.
