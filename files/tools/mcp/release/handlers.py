"""Release tool execution (real argv handlers, 6B-6/P3b).

Each tool runs its real PowerShell script (or git) argv-only with
shell=False from the harness repo root with a 120s timeout. Successful
results carry executed=True plus evidence{argv, exit_code,
stdout_sha256}. Script refusal (non-zero exit) or unproven output
degrades to Reject REJECT_PRECONDITION, never a fabricated success.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from ..core.validate import Reject

_TIMEOUT_SECONDS = 120
_POWERSHELL = "powershell"
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_MERGE_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$")


def _repo_root() -> str:
    # handlers.py -> release -> mcp -> tools -> files -> repo root.
    return str(Path(__file__).resolve().parents[4])


def _script_path(name: str) -> Path:
    return Path(_repo_root()) / "scripts" / name


def _require_script(name: str) -> str:
    path = _script_path(name)
    if not path.is_file():
        raise Reject("REJECT_PRECONDITION", f"script missing: {path}")
    return str(path)


def _evidence(argv: list[str], returncode: int, stdout: str) -> dict:
    return {
        "argv": list(argv),
        "exit_code": returncode,
        "stdout_sha256": hashlib.sha256((stdout or "").encode("utf-8")).hexdigest(),
    }


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv,
            shell=False,
            cwd=_repo_root(),
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise Reject("REJECT_PRECONDITION", f"executable not found: {argv[0]!r}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise Reject("REJECT_PRECONDITION", f"command timed out after {_TIMEOUT_SECONDS}s: {argv[0]}") from exc
    except OSError as exc:
        raise Reject("REJECT_PRECONDITION", f"command spawn failed: {argv[0]}: {exc}") from exc


def _snippet(text: str | None) -> str:
    return (text or "").strip()[:500]


def _wants_whatif(args: dict) -> bool:
    for key in ("whatif", "WhatIf", "dry_run", "dryRun"):
        if args.get(key) is True:
            return True
    return False


def _promotion_branch() -> str | None:
    path = Path(_repo_root()) / "files" / "policies" / "ci.json"
    try:
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = data.get("promotion_branch")
    return value.strip() if isinstance(value, str) and value.strip() else None


def _resolve_branch_for_head(head: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "for-each-ref", "--format=%(objectname) %(refname:short)", "refs/heads/"],
            shell=False,
            cwd=_repo_root(),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == head.strip().lower():
            return parts[1].strip()
    return None


def _execute_open(server, args: dict) -> dict:
    head = args.get("head")
    title = args.get("title")
    if not isinstance(head, str) or not isinstance(title, str):
        raise Reject("REJECT_ARG", "pr.open requires head and title")
    script = _require_script("open_pr.ps1")
    repo = _repo_root()
    whatif = _wants_whatif(args)
    branch = _resolve_branch_for_head(head) or head
    base = args.get("base") if isinstance(args.get("base"), str) and args.get("base").strip() else _promotion_branch()
    argv: list[str] = [_POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Repo", repo]
    if base:
        argv += ["-Base", base]
    argv += ["-Head", branch, "-Title", title]
    if whatif:
        argv += ["-WhatIf"]
    proc = _run(argv)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    evidence = _evidence(argv, proc.returncode, stdout)
    if proc.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"open_pr.ps1 failed exit {proc.returncode}: {_snippet(stderr or stdout)}")
    if whatif:
        return {
            "tool": "pr.open",
            "executed": True,
            "dry_run": True,
            "head_arg": head,
            "head_branch": branch,
            "stdout": stdout,
            "stderr": _snippet(stderr),
            "evidence": evidence,
        }
    match = re.search(r"(created|reuse)\s+PR\s+#(\S+)\s+(\S+)\s+head=(\S*)\s+base=(\S*)", stdout)
    if not match:
        raise Reject("REJECT_PRECONDITION", f"UNPROVEN: open_pr output unparseable: {_snippet(stdout)}")
    mode, pr_token, url, head_oid, base_oid = match.groups()
    if pr_token in ("?", "") or not pr_token.isdigit():
        raise Reject("REJECT_PRECONDITION", f"UNPROVEN: degraded pr number {pr_token!r} in open_pr output")
    if not base_oid:
        raise Reject("REJECT_PRECONDITION", "UNPROVEN: empty base in open_pr output")
    if not head_oid:
        raise Reject("REJECT_PRECONDITION", "UNPROVEN: empty head in open_pr output")
    pr_number = int(pr_token)
    opened = getattr(server, "_opened_prs", None)
    if opened is not None and hasattr(opened, "add"):
        opened.add(pr_number)
    return {
        "tool": "pr.open",
        "executed": True,
        "pr": pr_number,
        "url": url,
        "head": head_oid,
        "base": base_oid,
        "head_arg": head,
        "state": "open",
        "mode": mode,
        "stdout": stdout,
        "stderr": _snippet(stderr),
        "evidence": evidence,
    }


def _execute_watch(server, args: dict) -> dict:
    pr = args.get("pr")
    head = args.get("head")
    if not isinstance(pr, int) or not isinstance(head, str):
        raise Reject("REJECT_ARG", "pr.watch requires pr and head")
    script = _require_script("watch_checks.ps1")
    whatif = _wants_whatif(args)
    watched = getattr(server, "_watched", None)
    if not whatif and watched is not None and (pr, head) in watched:
        raise Reject("REJECT_PRECONDITION", "one watch per (pr, head) already exists")
    argv: list[str] = [_POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Number", str(pr)]
    if whatif:
        argv += ["-WhatIf"]
    proc = _run(argv)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    evidence = _evidence(argv, proc.returncode, stdout)
    if proc.returncode in (0, 1, 8):
        if not whatif and watched is not None and hasattr(watched, "add"):
            watched.add((pr, head))
        return {
            "tool": "pr.watch",
            "executed": True,
            "pr": pr,
            "head": head,
            "watching": True,
            "checks_passed": (proc.returncode == 0 and not whatif),
            "dry_run": whatif,
            "stdout": stdout,
            "stderr": _snippet(stderr),
            "evidence": evidence,
        }
    raise Reject("REJECT_PRECONDITION", f"watch_checks.ps1 failed exit {proc.returncode}: {_snippet(stderr or stdout)}")


def _execute_merge(server, args: dict) -> dict:
    pr = args.get("pr")
    head = args.get("head")
    if not isinstance(pr, int) or not isinstance(head, str):
        raise Reject("REJECT_ARG", "pr.merge requires pr and head")
    if args.get("method") not in (None, "squash"):
        raise Reject("REJECT_ENUM", "pr.merge method must be squash")
    script = _require_script("merge_pr.ps1")
    argv: list[str] = [_POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Number", str(pr), "-MatchHeadCommit", head]
    proc = _run(argv)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    evidence = _evidence(argv, proc.returncode, stdout)
    if proc.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"merge_pr.ps1 failed exit {proc.returncode}: {_snippet(stderr or stdout)}")
    if "(none reported)" in stdout:
        raise Reject("REJECT_PRECONDITION", "UNPROVEN: merged sha not reported by merge_pr.ps1")
    sha_match = re.search(r"merged\s+sha:\s*(\S+)", stdout)
    if not sha_match or not _MERGE_SHA_RE.match(sha_match.group(1).strip()):
        raise Reject("REJECT_PRECONDITION", f"UNPROVEN: merged sha unparseable in merge output: {_snippet(stdout)}")
    merged_sha = sha_match.group(1).strip()
    tree_match = re.search(r"merged\s+tree:\s*(\S+)", stdout)
    merged_tree = tree_match.group(1).strip() if tree_match else None
    return {
        "tool": "pr.merge",
        "executed": True,
        "pr": pr,
        "head": head,
        "merged_sha": merged_sha,
        "merged_tree": merged_tree,
        "method": "squash",
        "fast_forward_only": True,
        "admin": False,
        "bypass": False,
        "stdout": stdout,
        "stderr": _snippet(stderr),
        "evidence": evidence,
    }


def _parse_worktree_list(stdout: str) -> list[dict]:
    worktrees: list[dict] = []
    current: dict | None = None
    for line in (stdout or "").splitlines():
        if line.startswith("worktree "):
            current = {"path": line[len("worktree "):].strip(), "head": "", "branch": None}
            worktrees.append(current)
        elif line.startswith("HEAD "):
            if current is not None:
                current["head"] = line[len("HEAD "):].strip()
        elif line.startswith("branch "):
            if current is not None:
                ref = line[len("branch "):].strip()
                if ref.startswith("refs/heads/"):
                    current["branch"] = ref[len("refs/heads/"):]
                else:
                    current["branch"] = ref
    return worktrees


def _execute_worktrees_list(server, args: dict) -> dict:
    argv: list[str] = ["git", "worktree", "list", "--porcelain"]
    proc = _run(argv)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    evidence = _evidence(argv, proc.returncode, stdout)
    if proc.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"git worktree list failed exit {proc.returncode}: {_snippet(stderr or stdout)}")
    worktrees = _parse_worktree_list(stdout)
    return {
        "tool": "worktrees.list",
        "executed": True,
        "worktrees": worktrees,
        "count": len(worktrees),
        "stdout": stdout,
        "stderr": _snippet(stderr),
        "evidence": evidence,
    }


def _map_sync_set(lane: str) -> str:
    lane = str(lane or "")
    if lane in ("factory", "frontend", "all"):
        return lane
    if lane.startswith("ui/"):
        return "frontend"
    return "factory"


def _execute_worktrees_sync(server, args: dict) -> dict:
    lane = args.get("lane")
    if not isinstance(lane, str):
        raise Reject("REJECT_ARG", "worktrees.sync requires lane")
    script = _require_script("sync_worktrees.ps1")
    whatif = _wants_whatif(args)
    sync_set = _map_sync_set(lane)
    argv: list[str] = [_POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Set", sync_set]
    if whatif:
        argv += ["-WhatIf"]
    proc = _run(argv)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    evidence = _evidence(argv, proc.returncode, stdout)
    if proc.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"sync_worktrees.ps1 failed exit {proc.returncode}: {_snippet(stderr or stdout)}")
    return {
        "tool": "worktrees.sync",
        "executed": True,
        "lane": lane,
        "set": sync_set,
        "dry_run": whatif,
        "stdout": stdout,
        "stderr": _snippet(stderr),
        "evidence": evidence,
    }


def _execute_worktrees_reconcile(server, args: dict) -> dict:
    lane = args.get("lane")
    if not isinstance(lane, str):
        raise Reject("REJECT_ARG", "worktrees.reconcile requires lane")
    script = _require_script("reconcile_lanes.ps1")
    whatif = _wants_whatif(args)
    argv: list[str] = [_POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Repo", _repo_root(), "-Lanes", lane]
    if whatif:
        argv += ["-WhatIf"]
    proc = _run(argv)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    evidence = _evidence(argv, proc.returncode, stdout)
    if proc.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"reconcile_lanes.ps1 failed exit {proc.returncode}: {_snippet(stderr or stdout)}")
    return {
        "tool": "worktrees.reconcile",
        "executed": True,
        "lane": lane,
        "dry_run": whatif,
        "stdout": stdout,
        "stderr": _snippet(stderr),
        "evidence": evidence,
    }


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool == "pr.open":
        return _execute_open(server, args)
    if tool == "pr.watch":
        return _execute_watch(server, args)
    if tool == "pr.merge":
        return _execute_merge(server, args)
    if tool == "worktrees.list":
        return _execute_worktrees_list(server, args)
    if tool == "worktrees.sync":
        return _execute_worktrees_sync(server, args)
    if tool == "worktrees.reconcile":
        return _execute_worktrees_reconcile(server, args)
    return None
