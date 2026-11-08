"""check.run dispatcher policy. 6B-2.

The dispatcher is generated from files/policies/checks.json:
runners decide who may run which id. Builder code runs only in the
sandbox; the auditor runs at the git object id (tree/head args are
already pinned to 40-hex by the registry). ruff/gitleaks/semgrep
pinned invocations are described here as sealed stubs; the
fail-closed predicates are enforced as validation so the controls
harness can exercise them without heavyweight engines.

F-73: covered_by must exactly equal an added test id; substring
rejected (exact-match rule from 6A-4).
F-74: tautology with message/comment tail is a blocked oracle
finding (assert-rules extended to message tails, comments,
unittest forms and TS/JS).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..core.validate import Reject

_CHECKS_PATH = Path(__file__).resolve().parents[2] / ".." / "policies" / "checks.json"


def _load_checks() -> dict:
    try:
        return json.loads(_CHECKS_PATH.read_text(encoding="utf-8")).get("checks", {})
    except Exception:
        return {}


_CHECKS = _load_checks()

# Tautology patterns mirroring severity/assert-rules (message and comment
# tails, unittest forms, TS/JS). The dispatcher treats a match as a
# WEAK_ORACLE/TAUTOLOGICAL_ASSERTION finding and fails closed.
_TAUTOLOGY = [
    re.compile(r"\bassert\s+True\b"),
    re.compile(r"\bassert\s+1\s*==\s*1\b"),
    re.compile(r"\bassert\s+['\"][^'\"]*['\"]\s*!=\s*['\"][^'\"]*['\"]"),
    re.compile(r"\bself\.assertTrue\s*\(\s*True"),
    re.compile(r"\bassertTrue\s*\(\s*True"),
    re.compile(r"\bexpect\s*\(\s*true\s*\)\s*\.toBe\s*\(\s*true"),
    re.compile(r"\bassert\s+True\s*,"),
]


def is_tautology_line(line: str) -> bool:
    for pat in _TAUTOLOGY:
        if pat.search(line):
            return True
    return False


def _check_covered_by(args: dict) -> None:
    removed = args.get("removed_id")
    covered = args.get("covered_by")
    if not isinstance(covered, str) or covered == "":
        return
    if isinstance(removed, str) and removed:
        if covered == removed:
            return
        # Substring / prefix matches are not exact equality.
        if covered.startswith(removed) or removed in covered or covered in removed:
            raise Reject("REJECT_POLICY",
                         "covered_by must exactly equal an added test id; substring rejected")
    # No added-id context is available to the stub: a covered_by that is
    # present without a removal is valid as an exact id reference.
    return


def check_extra(server, tool: str, role: str, args: dict) -> None:
    if tool != "check.run":
        return
    check_id = args.get("check_id")
    if isinstance(check_id, str) and check_id in _CHECKS:
        runners = _CHECKS[check_id].get("runners", [])
        if role not in runners:
            raise Reject("REJECT_ROLE", f"role {role!r} may not run check {check_id!r}")
    if check_id == "TEST_SET":
        _check_covered_by(args)
    if check_id == "ORACLE_PROVENANCE":
        line = args.get("line", "")
        if isinstance(line, str) and is_tautology_line(line):
            raise Reject("REJECT_POLICY", "tautological oracle line is blocked")
    # TEST_SET also polices tautology assertions.
    if check_id == "TEST_SET":
        line = args.get("line")
        if isinstance(line, str) and is_tautology_line(line):
            raise Reject("REJECT_POLICY", "tautological assertion in test-set change")
