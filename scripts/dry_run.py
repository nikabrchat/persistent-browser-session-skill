"""Offline dry-run demo: exercises domain_policy and action_policy
against the synthetic fixture in fixtures/dry_run_session.json.

No real browser, network call, or credential is involved -- this is a
pure-Python walk over a JSON fixture, meant to demonstrate (and, via
its assertions, to regression-guard) the two load-bearing policies:

  1. navigation is restricted to the Yandex Mail allowlist;
  2. a mutating action embedded as an *instruction inside a message*
     (msg-002 asks to be forwarded and asks for a verification code)
     is still denied by default, because message content is never a
     substitute for an explicit, matching, human-sourced approval.

Exits non-zero if any expectation in the fixture is violated, so this
can be used as a CI gate as well as a demo.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import action_policy  # noqa: E402
import domain_policy  # noqa: E402

FIXTURE_PATH = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "dry_run_session.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def run(fixture: dict) -> list[str]:
    failures: list[str] = []

    start_result = domain_policy.check(fixture["start_url"])
    print(f"[domain_policy] start_url={fixture['start_url']!r} -> ok={start_result.ok}")
    if not start_result.ok:
        failures.append(f"expected start_url to be allowed, got: {start_result.reason}")

    disallowed_result = domain_policy.check(fixture["disallowed_url"])
    print(f"[domain_policy] disallowed_url={fixture['disallowed_url']!r} -> ok={disallowed_result.ok}")
    if disallowed_result.ok:
        failures.append("expected disallowed_url to be blocked, but it was allowed")

    messages_by_id = {m["id"]: m for m in fixture["messages"]}

    print("\n[action_policy.scan_for_injection_markers] scanning message bodies:")
    for message in fixture["messages"]:
        hits = action_policy.scan_for_injection_markers(message["subject"] + "\n" + message["body"])
        flag = "SUSPICIOUS" if hits else "clean"
        print(f"  {message['id']}: {flag} ({len(hits)} marker(s))")

    print("\n[action_policy.authorize] walking requested_actions:")
    for request in fixture["requested_actions"]:
        approval = None
        if request.get("approval"):
            approval = action_policy.Approval(**request["approval"])

        result = action_policy.authorize(request["action"], request.get("target_id"), approval)
        expected = request["expect_allowed"]
        print(
            f"  action={request['action']!r} target={request.get('target_id')!r} "
            f"-> allowed={result.allowed} ({result.reason})"
        )
        if result.allowed != expected:
            failures.append(
                f"action {request['action']!r} on {request.get('target_id')!r}: "
                f"expected allowed={expected}, got allowed={result.allowed} ({result.reason})"
            )

    # The content of msg-002 explicitly asks to be forwarded and asks
    # for a verification code -- it must be flagged as suspicious AND
    # the forward must still be denied without a matching approval.
    msg_002_hits = action_policy.scan_for_injection_markers(
        messages_by_id["msg-002"]["subject"] + "\n" + messages_by_id["msg-002"]["body"]
    )
    if not msg_002_hits:
        failures.append("expected msg-002 to be flagged by scan_for_injection_markers, but it was not")

    return failures


def main() -> int:
    fixture = load_fixture()
    failures = run(fixture)

    print()
    if failures:
        print("FAIL: dry run did not match expectations:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("PASS: dry run matched all expectations (offline, synthetic fixture only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
