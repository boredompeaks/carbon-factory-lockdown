"""Git tool execution. 6B-1, hardened 6B-fix2.

git.commit is a real host-side handler, not a stub: it runs
`git diff --cached --name-only --no-renames` against the live index,
verifies HEAD == capability.head and branch == task_branch (when a
capability is bound to the Server) plus args.tree == HEAD^{tree}
(stale-tree check), rejects any staged path matching the
scope/deny globs (.env*, pytest.ini, tox.ini, .coveragerc,
.github/**, .gitleaks.toml, conftest.py, tests_gate*.py, plus the
universal deny set), and then runs `git commit` with shell=False
and never --no-verify.

Other git tools remain bounded stubs: they verify 40-hex revs name
commit objects when a repo is present.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

from ..core.validate import Reject

from .deny import get_capability, is_commit_denied, is_in_scope

_TIMEOUT_FALLBACK = 30


def _is_placeholder(rev: str | None) -> bool:
    return not rev or rev == "0" * 40


def _repo_cwd() -> str:
    """Working directory from which git discovers the harness repo."""
    return str(Path(__file__).resolve().parents[3])


def _git_exe(server) -> str:
    """Absolute git executable from server config, else from PATH.

    Server config registration is preferred (absolute path, no PATH
    lookup at spawn time); otherwise fall back to shutil.which
    resolved to an absolute path. Wrapper scripts are rejected.
    """
    cfg = getattr(server, "config", None)
    if cfg is not None:
        try:
            exe = cfg.resolve("git")
            if isinstance(exe, str) and exe:
                if exe.lower().endswith((".cmd", ".bat", ".ps1")):
                    raise Reject("REJECT_PRECONDITION", "git executable wrapper rejected")
                return exe
        except ValueError:
            pass
        except Reject:
            raise
    found = shutil.which("git")
    if found:
        if found.lower().endswith((".cmd", ".bat", ".ps1")):
            raise Reject("REJECT_PRECONDITION", "git executable wrapper rejected")
        return found
    return "git"


def _env(server) -> dict:
    """Scrubbed environment for git children (no secrets)."""
    try:
        from ..core.config import scrub_environment

        return scrub_environment()
    except Exception:
        return {"PYTHONNOUSERSITE": "1"}


def _timeout(server) -> int:
    cfg = getattr(server, "config", None)
    val = getattr(cfg, "timeout_seconds", _TIMEOUT_FALLBACK) if cfg is not None else _TIMEOUT_FALLBACK
    if isinstance(val, int) and val > 0:
        return val
    return _TIMEOUT_FALLBACK


def _run_git(server, argv: list[str]) -> subprocess.CompletedProcess:
    """Run one git command with shell=False. Never --no-verify."""
    exe = _git_exe(server)
    return subprocess.run(
        [exe, "-C", _repo_cwd(), *argv],
        shell=False,
        capture_output=True,
        text=True,
        timeout=_timeout(server),
        env=_env(server),
    )


def _commit_object_exists(rev: str) -> bool | None:
    """True/False when a repo answers, None when no repo is present."""
    if _is_placeholder(rev):
        return None
    try:
        out = subprocess.run(
            ["git", "cat-file", "-t", rev],
            shell=False,
            cwd=_repo_cwd(),
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() == "commit"


def _git_rev_parse(server, rev: str) -> str:
    """Run git rev-parse <rev> and return stripped output; fail closed."""
    try:
        out = _run_git(server, ["rev-parse", "--verify", "--quiet", rev])
    except Exception:
        raise Reject("REJECT_PRECONDITION", f"git rev-parse {rev} failed")
    if out.returncode != 0 or not out.stdout.strip():
        raise Reject("REJECT_PRECONDITION", f"git rev-parse {rev} failed: {out.stderr.strip()}")
    return out.stdout.strip()


def _git_head(server) -> tuple[str, str, str]:
    """Return (head, tree, branch) for the live HEAD; fail closed."""
    # HEAD must be a commit; ^{tree} must resolve; branch must resolve.
    head = _git_rev_parse(server, "HEAD")
    tree = _git_rev_parse(server, "HEAD^{tree}")
    try:
        out = _run_git(server, ["rev-parse", "--abbrev-ref", "HEAD"])
    except Exception:
        raise Reject("REJECT_PRECONDITION", "git rev-parse --abbrev-ref HEAD failed")
    if out.returncode != 0:
        raise Reject("REJECT_PRECONDITION", "git rev-parse --abbrev-ref HEAD failed")
    branch = out.stdout.strip()
    return head, tree, branch


def _staged_paths(server) -> list[str]:
    """Live staged paths via git diff --cached --name-only --no-renames."""
    try:
        out = _run_git(server, ["diff", "--cached", "--name-only", "--no-renames"])
    except Exception:
        raise Reject("REJECT_PRECONDITION", "git diff --cached failed")
    if out.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"git diff --cached failed: {out.stderr.strip()}")
    paths: list[str] = []
    for line in out.stdout.splitlines():
        p = line.strip()
        if p:
            paths.append(p)
    return paths


def _execute_commit(server, args: dict) -> dict:
    message = args.get("message")
    tree_arg = args.get("tree")
    if not isinstance(message, str) or not isinstance(tree_arg, str):
        raise Reject("REJECT_ARG", "git.commit requires message and tree")
    if message.lstrip().startswith("-"):
        raise Reject("REJECT_PATTERN", "message must not start with a dash")

    # 1) HEAD / tree / branch binding. When a capability is bound,
    # enforce HEAD == capability.head and branch == task_branch
    # strictly; args.tree must always equal HEAD^{tree} (stale tree).
    head, live_tree, branch = _git_head(server)
    capability = get_capability(server)
    if isinstance(capability, dict):
        cap_head = capability.get("head")
        cap_tree = capability.get("tree")
        cap_branch = capability.get("task_branch") or capability.get("branch")
        if isinstance(cap_head, str) and cap_head.lower() != head.lower():
            raise Reject(
                "REJECT_PRECONDITION",
                f"HEAD {head} != capability.head {cap_head}",
            )
        if isinstance(cap_tree, str) and cap_tree.lower() != live_tree.lower():
            raise Reject(
                "REJECT_PRECONDITION",
                f"HEAD tree {live_tree} != capability.tree {cap_tree}",
            )
        if isinstance(cap_branch, str) and cap_branch and branch != cap_branch:
            raise Reject(
                "REJECT_PRECONDITION",
                f"branch {branch!r} != task_branch {cap_branch!r}",
            )
        if isinstance(cap_tree, str) and cap_tree and tree_arg.lower() != cap_tree.lower():
            raise Reject(
                "REJECT_PRECONDITION",
                f"tree {tree_arg} != capability.tree {cap_tree} (stale tree)",
            )
    if tree_arg.lower() != live_tree.lower():
        raise Reject(
            "REJECT_PRECONDITION",
            f"tree {tree_arg} != HEAD^{{tree}} {live_tree} (stale tree)",
        )

    # 2) Live staged-diff validation (TOCTOU firewall). The caller-
    # declared args.paths were already checked in deny.check_extra;
    # the index is authoritative so an evil file staged after
    # declaration still rejects here.
    staged = _staged_paths(server)
    if not staged:
        raise Reject("REJECT_PRECONDITION", "nothing staged to commit")
    scope = capability.get("scope") if isinstance(capability, dict) else None
    for staged_path in staged:
        if is_commit_denied(staged_path):
            raise Reject("REJECT_PATH", f"staged path denied: {staged_path!r}")
        if scope and not is_in_scope(staged_path, scope):
            raise Reject(
                "REJECT_PATH",
                f"staged path outside capability.scope: {staged_path!r}",
            )
    # Re-validate declared paths against the same predicates so a
    # path-only bypass that skips deny.check_extra still rejects.
    for declared in args.get("paths", []) or []:
        if not isinstance(declared, str):
            continue
        if is_commit_denied(declared):
            raise Reject("REJECT_PATH", f"commit path denied: {declared!r}")
        if scope and not is_in_scope(declared, scope):
            raise Reject(
                "REJECT_PATH",
                f"commit path outside capability.scope: {declared!r}",
            )

    # 3) Commit with hooks (never --no-verify, never shell).
    try:
        out = _run_git(server, ["commit", "-m", message])
    except Exception as exc:
        raise Reject("REJECT_PRECONDITION", f"git commit failed: {exc}")
    if out.returncode != 0:
        raise Reject(
            "REJECT_PRECONDITION",
            f"git commit failed: {(out.stderr or out.stdout).strip()[:200]}",
        )
    new_head = _git_rev_parse(server, "HEAD")
    new_tree = _git_rev_parse(server, "HEAD^{tree}")
    return {
        "tool": "git.commit",
        "previous_head": head,
        "head": new_head,
        "tree": new_tree,
        "branch": branch,
        "message_sha256": hashlib.sha256(message.encode()).hexdigest(),
        "staged": sorted(staged),
        "renames": False,
        "case_folded": True,
        "no_verify": False,
    }


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if not tool.startswith("git.") and tool not in ("code.write",):
        return None
    if tool == "git.commit":
        return _execute_commit(server, args)
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
