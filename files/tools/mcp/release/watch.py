"""Release policy: one watch per (pr, head), fast-forward only. 6B-6.

Native implementation: no .ps1 layer, no admin or bypass option.
The precondition (watch requires a prior pr.open for the same pr)
lives in core.server for 6B-0 determinism; this module keeps the
watch registry coherent and enforces merge constraints.
"""
from __future__ import annotations

from ..core.validate import Reject


def check_extra(server, tool: str, role: str, args: dict) -> None:
    if tool == "pr.watch":
        pair = (args.get("pr"), args.get("head"))
        # Duplicate is rejected; the absence case is rejected by core.
        if pair in getattr(server, "_watched", set()):
            raise Reject("REJECT_PRECONDITION", "one watch per (pr, head) already exists")
    elif tool == "pr.merge":
        # Fast-forward only, squash method only, no bypass arg exists.
        if args.get("method") not in (None, "squash"):
            raise Reject("REJECT_ENUM", "pr.merge method must be squash")
    elif tool in ("worktrees.sync", "worktrees.reconcile"):
        lane = args.get("lane", "")
        if lane.startswith("-") or ".." in lane or ":" in lane:
            raise Reject("REJECT_PATH", "lane must be a normalized relative name")
