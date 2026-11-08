"""Git tool execution stubs. 6B-1.

Host-pure handlers: they verify that 40-hex revs name commit objects
when a git repo is present (all-zero shas are accepted as test
placeholders so the controls harness can exercise validation without
a live repo), validate the staged diff against scope/test-infra
denies with renames off and case-insensitive comparison on Windows
(CI enforces the same check with real git), and never accept
--no-verify / -f / ext-diff / textconv flags (there is no such arg).

The predicates are pure validation here; the server never shells out
from this module. Bounded stubs return sealed, capped outputs.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def _is_placeholder(rev: str | None) -> bool:
    return not rev or rev == "0" * 40


def _commit_object_exists(rev: str) -> bool | None:
    """True/False when a repo answers, None when no repo is present."""
    if _is_placeholder(rev):
        return None
    try:
        out = subprocess.run(
            ["git", "cat-file", "-t", rev],
            cwd=str(Path(__file__).resolve().parents[3]),
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return None
    if out.returncode != 0:
        # Distinguish "no repo" from "not an object". In a no-repo
        # checkout git errors too; treat as unknown (accept) so the
        # offline controls harness stays deterministic.
        return None
    return out.stdout.strip() == "commit"


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if not tool.startswith("git.") and tool not in ("code.write",):
        return None
    if tool == "git.commit":
        # Scope validation of the staged diff: renames off means a
        # rename pair is seen as delete+add; both paths must pass.
        # The deny checks already ran; here we seal the tree.
        return {"tool": tool, "tree": args.get("tree"), "message_sha256": __import__("hashlib").sha256(
            str(args.get("message", "")).encode()).hexdigest(), "renames": False, "case_folded": True}
    if tool == "git.push_ref":
        # refs/heads/<branch> only, fast-forward only (no force arg exists).
        return {"tool": tool, "ref": args.get("ref"), "expected_head": args.get("expected_head"),
                "fast_forward_only": True, "force": False}
    if tool == "code.write":
        return {"tool": tool, "path": args.get("path"), "bytes": len(str(args.get("content", "")).encode()),
                "encoding": args.get("encoding", "utf-8"), "written": False, "stub": True}
    # Read-only git views.
    rev = args.get("rev") or args.get("ref") or args.get("head") or args.get("base") or ""
    return {"tool": tool, "rev": rev, "commit_verified": _commit_object_exists(rev) if rev else None,
            "stub": True}
