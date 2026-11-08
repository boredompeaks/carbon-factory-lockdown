"""Release tool execution (native, no .ps1). 6B-6."""
from __future__ import annotations


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool == "pr.open":
        return {"tool": tool, "head": args.get("head"), "title": args.get("title"),
                "state": "open", "native": True}
    if tool == "pr.watch":
        return {"tool": tool, "pr": args.get("pr"), "head": args.get("head"),
                "watching": True, "one_per_pr_head": True}
    if tool == "pr.merge":
        return {"tool": tool, "pr": args.get("pr"), "head": args.get("head"),
                "method": args.get("method", "squash"), "fast_forward_only": True,
                "admin": False, "bypass": False}
    if tool in ("worktrees.list", "worktrees.sync", "worktrees.reconcile"):
        return {"tool": tool, "lane": args.get("lane") or "main",
                "native": True, "ps1": False}
    return None
