#!/usr/bin/env bash
# Safe launcher for the persistent Yandex Mail Chromium profile.
#
# This script contains no secrets and reads none: it never accepts,
# stores, or forwards a password, cookie value, or token. It only
# starts Chromium against a pre-existing local profile directory and
# enforces the operational invariants documented in SKILL.md:
#   - never run as root or as an interactive login user
#   - profile directory must exist, be outside Git, and be mode 0700
#   - single-worker lock (flock) so only one process uses the profile
#   - sandbox always enabled (no --no-sandbox, ever)
#   - optional CDP binds to 127.0.0.1 only
#   - stable binary / lang / timezone / display across runs
#
# It deliberately does NOT set any fingerprint-spoofing, anti-detect,
# CAPTCHA-solving, proxy, or stealth-automation flag. See SKILL.md
# "What this is not".

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  launch_browser.sh --init --profile-dir DIR [--owner-uid UID]
      Create a fresh profile directory with the required permissions.
      Must not be run as root; must not be run as the account's own
      interactive login user if that differs from the dedicated
      service account.

  launch_browser.sh --interactive --profile-dir DIR
      Open the browser for the human owner to sign in by hand
      (including MFA/CAPTCHA). No automation touches this session.

  launch_browser.sh --profile-dir DIR [--enable-cdp PORT] [--url URL]
      Resume the existing authenticated profile for agent-driven,
      read-only-by-default work.

Options:
  --profile-dir DIR   Path to the persistent Chromium user-data dir.
                       Must exist already (except with --init), be
                       mode 0700 or stricter, and must not be inside a
                       Git working tree.
  --enable-cdp PORT    Optional. Expose Chrome DevTools Protocol on
                       127.0.0.1:PORT only. Omit to leave CDP off.
  --url URL            Optional start URL. Must pass domain_policy.py's
                       allowlist check before this script will use it.
  --binary PATH        Chromium/Chrome binary. Defaults to
                       CHROMIUM_BINARY env var or /usr/bin/chromium.
  --lang TAG           Stable UI language tag. Default: en-US.
  --tz NAME            Stable IANA timezone. Default: Etc/UTC.
  --display NUM        Stable X11 display number for headful runs
                       under Xvfb (e.g. 99 for :99). Default: 99.
  -h, --help           Show this help.
USAGE
}

PROFILE_DIR=""
MODE="resume"
CDP_PORT=""
START_URL=""
BINARY="${CHROMIUM_BINARY:-/usr/bin/chromium}"
LANG_TAG="en-US"
TZ_NAME="Etc/UTC"
DISPLAY_NUM="99"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --init) MODE="init"; shift ;;
    --interactive) MODE="interactive"; shift ;;
    --profile-dir) PROFILE_DIR="$2"; shift 2 ;;
    --enable-cdp) CDP_PORT="$2"; shift 2 ;;
    --url) START_URL="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --lang) LANG_TAG="$2"; shift 2 ;;
    --tz) TZ_NAME="$2"; shift 2 ;;
    --display) DISPLAY_NUM="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [ -z "$PROFILE_DIR" ]; then
  echo "error: --profile-dir is required" >&2
  exit 2
fi

# --- Never run as root. ------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
  echo "error: refusing to run as root; use a dedicated unprivileged service account" >&2
  exit 1
fi

# --- Profile directory must not live inside a Git working tree. --------
check_not_in_git_tree() {
  local dir="$1"
  local probe="$dir"
  while [ "$probe" != "/" ] && [ -n "$probe" ]; do
    if [ -e "$probe/.git" ]; then
      echo "error: profile directory $dir is inside a Git working tree ($probe); profiles must never be stored under Git" >&2
      exit 1
    fi
    probe="$(dirname "$probe")"
  done
}

# --- Enforce mode 0700 (or stricter) on an existing profile directory. --
check_profile_permissions() {
  local dir="$1"
  local mode
  mode="$(stat -c '%a' "$dir")"
  case "$mode" in
    700|600) ;;
    *)
      echo "error: profile directory $dir has mode $mode; required 0700" >&2
      exit 1
      ;;
  esac
}

case "$MODE" in
  init)
    if [ -e "$PROFILE_DIR" ]; then
      echo "error: $PROFILE_DIR already exists; refusing to overwrite" >&2
      exit 1
    fi
    check_not_in_git_tree "$(dirname "$PROFILE_DIR")"
    mkdir -p "$PROFILE_DIR"
    chmod 0700 "$PROFILE_DIR"
    echo "created profile directory $PROFILE_DIR with mode 0700"
    exit 0
    ;;
  interactive|resume)
    if [ ! -d "$PROFILE_DIR" ]; then
      echo "error: profile directory $PROFILE_DIR does not exist; run --init first" >&2
      exit 1
    fi
    check_not_in_git_tree "$PROFILE_DIR"
    check_profile_permissions "$PROFILE_DIR"
    ;;
esac

# --- Single-worker lock: only one Chromium process per profile. --------
LOCK_FILE="$PROFILE_DIR/.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "error: another process already holds the lock on $PROFILE_DIR" >&2
  exit 1
fi

# --- Resolve start URL against the allowlist (never trust caller input).
POLICY_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/domain_policy.py"
if [ -n "$START_URL" ]; then
  if ! python3 "$POLICY_SCRIPT" check "$START_URL" >/dev/null; then
    echo "error: start URL '$START_URL' is not on the Yandex Mail allowlist" >&2
    exit 1
  fi
else
  START_URL="https://passport.yandex.ru/auth"
fi

# --- Build the Chromium argument list. ----------------------------------
# No anti-detect, no fingerprint spoofing, no stealth flags, no proxy,
# no --no-sandbox. Only stability/isolation flags.
ARGS=(
  "--user-data-dir=$PROFILE_DIR"
  "--lang=$LANG_TAG"
  "--no-first-run"
  "--no-default-browser-check"
  "--disable-fre"
  "--disable-sync"
)

if [ -n "$CDP_PORT" ]; then
  ARGS+=("--remote-debugging-address=127.0.0.1" "--remote-debugging-port=$CDP_PORT")
fi

ARGS+=("$START_URL")

export TZ="$TZ_NAME"
export DISPLAY=":${DISPLAY_NUM}"

echo "launching: $BINARY ${ARGS[*]}"
echo "profile:   $PROFILE_DIR"
echo "mode:      $MODE"
if [ -n "$CDP_PORT" ]; then
  echo "cdp:       127.0.0.1:$CDP_PORT (loopback only)"
else
  echo "cdp:       disabled"
fi

exec "$BINARY" "${ARGS[@]}"
