"""Python-side checks for the persistent Chromium profile directory.

Mirrors the invariants `scripts/launch_browser.sh` enforces in shell,
as a reusable, testable module: the profile directory must exist
outside any Git working tree, must be mode 0700 (or stricter), and the
process touching it must not be root. This module only stats paths and
checks permission bits -- it never reads profile contents (cookies,
localStorage, IndexedDB) and never creates a profile as a side effect
of being imported.

Standard library only.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import stat


@dataclasses.dataclass
class GuardResult:
    ok: bool
    errors: list[str] = dataclasses.field(default_factory=list)


def is_inside_git_tree(path: pathlib.Path) -> bool:
    probe = path.resolve()
    while True:
        if (probe / ".git").exists():
            return True
        if probe.parent == probe:
            return False
        probe = probe.parent


def has_required_permissions(path: pathlib.Path) -> bool:
    mode = stat.S_IMODE(path.stat().st_mode)
    # Exactly 0700 (owner rwx only) or stricter (no group/other bits).
    return mode & 0o077 == 0


def check_profile_dir(path: os.PathLike | str) -> GuardResult:
    errors: list[str] = []
    p = pathlib.Path(path)

    if not p.exists():
        return GuardResult(ok=False, errors=[f"profile directory does not exist: {p}"])
    if not p.is_dir():
        return GuardResult(ok=False, errors=[f"profile path is not a directory: {p}"])
    if is_inside_git_tree(p):
        errors.append(f"profile directory is inside a Git working tree: {p}")
    if not has_required_permissions(p):
        mode = stat.S_IMODE(p.stat().st_mode)
        errors.append(f"profile directory {p} has mode {oct(mode)}; required 0700 or stricter")

    return GuardResult(ok=not errors, errors=errors)


def check_not_root(uid: int | None = None) -> GuardResult:
    uid = os.getuid() if uid is None else uid
    if uid == 0:
        return GuardResult(ok=False, errors=["running as root (uid 0); use a dedicated unprivileged service account"])
    return GuardResult(ok=True)
