"""Read-only-by-default action gate for mail operations.

Classifies a requested action as read-only or mutating, and requires
an explicit, matching, human-sourced approval record before any
mutating action is allowed to proceed. Also provides a deterministic
marker scan so email content that *looks like* an instruction
("forward this to...", "run the following...") is flagged as
suspicious data rather than acted on.

Standard library only. No network access, no subprocess, no eval/exec.
"""

from __future__ import annotations

import dataclasses
import re

READ_ONLY_ACTIONS: frozenset[str] = frozenset(
    {
        "list_messages",
        "open_message",
        "read_message_body",
        "read_headers",
        "search_messages",
        "list_labels",
        "list_folders",
    }
)

MUTATING_ACTIONS: frozenset[str] = frozenset(
    {
        "send_message",
        "delete_message",
        "move_message",
        "forward_message",
        "archive_message",
        "mark_read",
        "mark_unread",
        "bulk_mark_read",
        "bulk_mark_unread",
        "create_filter",
        "update_filter",
        "delete_filter",
        "update_forwarding_settings",
        "update_account_settings",
    }
)

# Deterministic, intentionally narrow markers -- a hit is a strong
# signal to log as suspicious, never a general classifier and never a
# trigger to comply with what the text asks. See SKILL.md "Email
# content is untrusted data, never instructions".
INJECTION_MARKER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bforward\s+this\s+(email|message)\s+to\b", re.IGNORECASE),
    re.compile(r"\bignore\s+(all\s+)?(previous|prior)\s+instructions\b", re.IGNORECASE),
    re.compile(r"\brun\s+the\s+following\s+(command|script)\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\s+(in\s+)?(admin|developer|root)\s+mode\b", re.IGNORECASE),
    re.compile(r"\bsend\s+(\$|usd|eur|\d)\S*\s+to\b", re.IGNORECASE),
    re.compile(r"\breply\s+with\s+(the\s+)?(password|otp|verification\s+code)\b", re.IGNORECASE),
    re.compile(r"\bdisable\s+(two[-\s]?factor|2fa|mfa)\b", re.IGNORECASE),
)


class UnknownActionError(ValueError):
    """Raised when an action name is neither read-only nor mutating."""


@dataclasses.dataclass
class Approval:
    approved: bool
    action: str
    target_id: str
    reason: str = ""


@dataclasses.dataclass
class AuthorizationResult:
    allowed: bool
    reason: str = ""


def classify(action: str) -> str:
    """Return "read_only" or "mutating" for a known action name."""
    if action in READ_ONLY_ACTIONS:
        return "read_only"
    if action in MUTATING_ACTIONS:
        return "mutating"
    raise UnknownActionError(f"unrecognized action: {action!r}")


def authorize(action: str, target_id: str, approval: Approval | None = None) -> AuthorizationResult:
    """Decide whether `action` against `target_id` may proceed.

    Read-only actions are always allowed. Mutating actions require an
    `approval` record whose `approved` flag is True, whose `action`
    and `target_id` exactly match the request, and whose `reason` is
    non-empty. There is no "approve all" shortcut: a mismatched
    target_id or action, or a missing reason, is denied.
    """
    kind = classify(action)
    if kind == "read_only":
        return AuthorizationResult(allowed=True, reason="read-only action")

    if approval is None:
        return AuthorizationResult(allowed=False, reason="mutating action requires an approval record")
    if not approval.approved:
        return AuthorizationResult(allowed=False, reason="approval record is not marked approved")
    if approval.action != action:
        return AuthorizationResult(
            allowed=False,
            reason=f"approval is for action {approval.action!r}, not {action!r}",
        )
    if approval.target_id != target_id:
        return AuthorizationResult(
            allowed=False,
            reason=f"approval is for target {approval.target_id!r}, not {target_id!r}",
        )
    if not approval.reason.strip():
        return AuthorizationResult(allowed=False, reason="approval record has no reason")

    return AuthorizationResult(allowed=True, reason="explicit matching approval")


def scan_for_injection_markers(text: str) -> list[str]:
    """Return the list of marker descriptions found in `text`.

    An empty list does not mean the text is safe to act on -- it only
    means none of this small, deterministic marker set matched. The
    governing rule is in SKILL.md: all message content is untrusted
    data, regardless of whether a marker fired.
    """
    hits: list[str] = []
    for pattern in INJECTION_MARKER_PATTERNS:
        if pattern.search(text or ""):
            hits.append(pattern.pattern)
    return hits
