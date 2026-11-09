"""Release tool execution (real argv handlers, 6B-6/P3b).

Each tool runs its real PowerShell script (or git) argv-only with
shell=False from the harness repo root with a 120s timeout. Successful
results carry executed=True plus evidence{argv, exit_code,
stdout_sha256}. Script refusal (non-zero exit) or unproven output
degrades to Reject REJECT_PRECONDITION, never a fabricated success.

Cross-platform (U2): on Windows the PowerShell path is unchanged; on
POSIX (``not IS_WINDOWS``) or when ``CARBON_RELEASE_NATIVE=1`` a native
gh/git path is used with the same evidence shape.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from ..core.platform import IS_WINDOWS, tool_binary
from ..core.validate import Reject

_TIMEOUT_SECONDS = 120
_POWERSHELL = "powershell"
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_MERGE_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$")


def _use_native() -> bool:
    return (not IS_WINDOWS) or os.environ.get("CARBON_RELEASE_NATIVE") == "1"


def _require_native_binary(name: str) -> str:
    if tool_binary(name) is None:
        raise Reject("REJECT_PRECONDITION", f"runtime unavailable: {name}")
    return name


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


def _sha_for_branch(branch: str) -> str | None:
    if not branch or not isinstance(branch, str):
        return None
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--verify", f"refs/heads/{branch}"],
            shell=False,
            cwd=_repo_root(),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    sha = (proc.stdout or "").strip()
    return sha or None


def _tree_for_sha(sha: str) -> str | None:
    if not sha:
        return None
    try:
        proc = subprocess.run(
            ["git", "rev-parse", f"{sha}^{{tree}}"],
            shell=False,
            cwd=_repo_root(),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    tree = (proc.stdout or "").strip()
    return tree or None


def _execute_open_native(server, args: dict) -> dict:
    head = args.get("head")
    title = args.get("title")
    if not isinstance(head, str) or not isinstance(title, str):
        raise Reject("REJECT_ARG", "pr.open requires head and title")
    gh_bin = _require_native_binary("gh")
    base_raw = args.get("base") if isinstance(args.get("base"), str) and args.get("base").strip() else _promotion_branch()
    if not base_raw:
        raise Reject("REJECT_PRECONDITION", "UNPROVEN: no base branch available for gh pr create")
    base = str(base_raw).strip()
    branch = (_resolve_branch_for_head(head) or head).strip()
    if branch == base:
        raise Reject("REJECT_PRECONDITION", f"Base and Head are the same branch '{base}'")
    whatif = _wants_whatif(args)
    if whatif:
        argv: list[str] = [gh_bin, "pr", "create", "--base", base, "--head", branch, "--title", title, "--body", ""]
        stdout = f"create PR: base={base} head={branch} head_sha={head} title={title}"
        evidence = _evidence(argv, 0, stdout)
        return {
            "tool": "pr.open",
            "executed": True,
            "dry_run": True,
            "head_arg": head,
            "head_branch": branch,
            "stdout": stdout,
            "stderr": "",
            "evidence": evidence,
        }
    argv_list: list[str] = [gh_bin, "pr", "list", "--head", branch, "--state", "open", "--json", "number,url,headRefOid,baseRefOid"]
    proc_list = _run(argv_list)
    stdout_list = proc_list.stdout or ""
    stderr_list = proc_list.stderr or ""
    evidence_list = _evidence(argv_list, proc_list.returncode, stdout_list)
    if proc_list.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"gh pr list failed exit {proc_list.returncode}: {_snippet(stderr_list or stdout_list)}")
    try:
        data = json.loads(stdout_list) if stdout_list.strip() else []
    except Exception:
        raise Reject("REJECT_PRECONDITION", f"UNPROVEN: gh pr list output unparseable: {_snippet(stdout_list)}")
    if isinstance(data, list) and len(data) > 0:
        first = data[0]
        if not isinstance(first, dict):
            raise Reject("REJECT_PRECONDITION", f"UNPROVEN: gh pr list output unparseable: {_snippet(stdout_list)}")
        try:
            pr_number = int(first.get("number"))  # type: ignore[arg-type]
            url = str(first.get("url") or "")
            head_oid = str(first.get("headRefOid") or "")
            base_oid = str(first.get("baseRefOid") or "")
        except Exception:
            raise Reject("REJECT_PRECONDITION", f"UNPROVEN: gh pr list output unparseable: {_snippet(stdout_list)}")
        if not url or not head_oid or not base_oid:
            raise Reject("REJECT_PRECONDITION", "UNPROVEN: gh pr list missing url/head/base oid")
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
            "mode": "reuse",
            "stdout": stdout_list,
            "stderr": _snippet(stderr_list),
            "evidence": evidence_list,
        }
    argv_create: list[str] = [gh_bin, "pr", "create", "--base", base, "--head", branch, "--title", title, "--body", ""]
    proc_create = _run(argv_create)
    stdout_create = proc_create.stdout or ""
    stderr_create = proc_create.stderr or ""
    evidence_create = _evidence(argv_create, proc_create.returncode, stdout_create)
    if proc_create.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"gh pr create failed exit {proc_create.returncode}: {_snippet(stderr_create or stdout_create)}")
    url = None
    for line in stdout_create.splitlines():
        line = line.strip()
        if line.startswith("http://") or line.startswith("https://"):
            url = line.split()[0].strip()
    if not url:
        m = re.search(r"https?://\S+", stdout_create)
        if m:
            url = m.group(0).strip()
    if not url:
        raise Reject("REJECT_PRECONDITION", f"UNPROVEN: gh pr create output unparseable: {_snippet(stdout_create)}")
    m_num = re.search(r"/pull/(\d+)(?:[/#]|$)", url)
    if not m_num:
        raise Reject("REJECT_PRECONDITION", f"UNPROVEN: gh pr create URL missing PR number: {url}")
    pr_number = int(m_num.group(1))
    head_oid = _sha_for_branch(branch) or head
    base_oid = _sha_for_branch(base) or base
    if not head_oid or not base_oid:
        raise Reject("REJECT_PRECONDITION", "UNPROVEN: gh pr create missing head/base oid")
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
        "mode": "created",
        "stdout": stdout_create,
        "stderr": _snippet(stderr_create),
        "evidence": evidence_create,
    }


def _execute_watch_native(server, args: dict) -> dict:
    pr = args.get("pr")
    head = args.get("head")
    if not isinstance(pr, int) or not isinstance(head, str):
        raise Reject("REJECT_ARG", "pr.watch requires pr and head")
    gh_bin = _require_native_binary("gh")
    whatif = _wants_whatif(args)
    watched = getattr(server, "_watched", None)
    if not whatif and watched is not None and (pr, head) in watched:
        raise Reject("REJECT_PRECONDITION", "one watch per (pr, head) already exists")
    argv: list[str] = [gh_bin, "pr", "checks", str(pr), "--watch", "--interval", "30"]
    if whatif:
        stdout = f"gh pr checks {pr} --watch --interval 30"
        evidence = _evidence(argv, 0, stdout)
        return {
            "tool": "pr.watch",
            "executed": True,
            "pr": pr,
            "head": head,
            "watching": True,
            "checks_passed": False,
            "dry_run": True,
            "stdout": stdout,
            "stderr": "",
            "evidence": evidence,
        }
    proc = _run(argv)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    evidence = _evidence(argv, proc.returncode, stdout)
    if proc.returncode in (0, 1, 8):
        if watched is not None and hasattr(watched, "add"):
            watched.add((pr, head))
        return {
            "tool": "pr.watch",
            "executed": True,
            "pr": pr,
            "head": head,
            "watching": True,
            "checks_passed": (proc.returncode == 0),
            "dry_run": False,
            "stdout": stdout,
            "stderr": _snippet(stderr),
            "evidence": evidence,
        }
    raise Reject("REJECT_PRECONDITION", f"gh pr checks failed exit {proc.returncode}: {_snippet(stderr or stdout)}")


def _execute_merge_native(server, args: dict) -> dict:
    pr = args.get("pr")
    head = args.get("head")
    if not isinstance(pr, int) or not isinstance(head, str):
        raise Reject("REJECT_ARG", "pr.merge requires pr and head")
    if args.get("method") not in (None, "squash"):
        raise Reject("REJECT_ENUM", "pr.merge method must be squash")
    gh_bin = _require_native_binary("gh")
    merge_argv: list[str] = [gh_bin, "pr", "merge", str(pr), "--squash", "--match-head-commit", head]
    proc_merge = _run(merge_argv)
    stdout_merge = proc_merge.stdout or ""
    stderr_merge = proc_merge.stderr or ""
    if proc_merge.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"gh pr merge failed exit {proc_merge.returncode}: {_snippet(stderr_merge or stdout_merge)}")
    view_argv: list[str] = [gh_bin, "pr", "view", str(pr), "--json", "mergeCommit,mergeStateStatus"]
    proc_view = _run(view_argv)
    stdout_view = proc_view.stdout or ""
    stderr_view = proc_view.stderr or ""
    evidence = _evidence(view_argv, proc_view.returncode, stdout_view)
    if proc_view.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"UNPROVEN: gh pr view failed exit {proc_view.returncode}: {_snippet(stderr_view or stdout_view)}")
    if "(none reported)" in stdout_view or "(none reported)" in stdout_merge:
        raise Reject("REJECT_PRECONDITION", "UNPROVEN: merged sha not reported by gh pr view")
    try:
        data = json.loads(stdout_view) if stdout_view.strip() else {}
    except Exception:
        raise Reject("REJECT_PRECONDITION", f"UNPROVEN: gh pr view output unparseable: {_snippet(stdout_view)}")
    if not isinstance(data, dict):
        raise Reject("REJECT_PRECONDITION", f"UNPROVEN: gh pr view output unparseable: {_snippet(stdout_view)}")
    merge_commit = data.get("mergeCommit")
    oid = None
    if isinstance(merge_commit, dict):
        oid = merge_commit.get("oid")
    if not oid or str(oid).strip() in ("", "null", "(none reported)"):
        raise Reject("REJECT_PRECONDITION", "UNPROVEN: merged sha not reported by gh pr view")
    merged_sha = str(oid).strip()
    if not _MERGE_SHA_RE.match(merged_sha):
        raise Reject("REJECT_PRECONDITION", f"UNPROVEN: merged sha unparseable in gh pr view output: {_snippet(stdout_view)}")
    merged_tree = _tree_for_sha(merged_sha)
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
        "stdout": stdout_view,
        "stderr": _snippet(stderr_view),
        "evidence": evidence,
    }


def _execute_open(server, args: dict) -> dict:
    if _use_native():
        return _execute_open_native(server, args)
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
    if _use_native():
        return _execute_watch_native(server, args)
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
    if _use_native():
        return _execute_merge_native(server, args)
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


def _execute_worktrees_sync_native(server, args: dict) -> dict:
    lane = args.get("lane")
    if not isinstance(lane, str):
        raise Reject("REJECT_ARG", "worktrees.sync requires lane")
    git_bin = _require_native_binary("git")
    whatif = _wants_whatif(args)
    sync_set = _map_sync_set(lane)
    if sync_set == "factory":
        expected = ["spec-comp", "lane/a", "lane/b"]
    elif sync_set == "frontend":
        expected = ["ui/cf-storefront", "ui/t1", "ui/t2", "ui/t3"]
    else:
        expected = ["spec-comp", "lane/a", "lane/b", "ui/cf-storefront", "ui/t1", "ui/t2", "ui/t3"]
    root = _repo_root()
    list_argv: list[str] = [git_bin, "worktree", "list", "--porcelain"]
    proc_list = _run(list_argv)
    if proc_list.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"git worktree list failed exit {proc_list.returncode}: {_snippet(proc_list.stderr or proc_list.stdout)}")
    worktrees = _parse_worktree_list(proc_list.stdout or "")
    branch_to: dict[str, tuple[str, str]] = {}
    for wt in worktrees:
        branch_val = wt.get("branch")
        path_val = wt.get("path")
        head_val = wt.get("head") or ""
        if branch_val and path_val:
            branch_to[branch_val] = (path_val, head_val)
    lanes: list[dict] = []
    active: list[tuple[str, str, str]] = []
    for branch_name in expected:
        entry = branch_to.get(branch_name)
        if entry is None:
            lanes.append({"lane": branch_name, "head": "", "skipped": True, "reason": f"worktree not found for branch {branch_name}"})
            continue
        wt_path, wt_head = entry
        inside_argv = [git_bin, "-C", wt_path, "rev-parse", "--is-inside-work-tree"]
        proc_inside = _run(inside_argv)
        if proc_inside.returncode != 0 or (proc_inside.stdout or "").strip() != "true":
            lanes.append({"lane": branch_name, "head": wt_head, "skipped": True, "reason": f"not a git worktree: {wt_path}"})
            continue
        cur_argv = [git_bin, "-C", wt_path, "branch", "--show-current"]
        proc_cur = _run(cur_argv)
        cur_branch = (proc_cur.stdout or "").strip()
        if proc_cur.returncode != 0 or not cur_branch:
            lanes.append({"lane": branch_name, "head": wt_head, "skipped": True, "reason": f"cannot read current branch in {wt_path}"})
            continue
        if cur_branch != branch_name:
            lanes.append({"lane": branch_name, "head": wt_head, "skipped": True, "reason": f"worktree {wt_path} is on '{cur_branch}'"})
            continue
        status_argv = [git_bin, "-C", wt_path, "status", "--porcelain"]
        proc_status = _run(status_argv)
        if proc_status.returncode != 0:
            lanes.append({"lane": branch_name, "head": wt_head, "skipped": True, "reason": f"status check failed exit {proc_status.returncode}: {_snippet(proc_status.stderr or proc_status.stdout)}"})
            continue
        if (proc_status.stdout or "").strip():
            lanes.append({"lane": branch_name, "head": wt_head, "skipped": True, "reason": f"worktree {wt_path} is dirty: {_snippet(proc_status.stdout)}"})
            continue
        lanes.append({"lane": branch_name, "head": wt_head, "skipped": False, "reason": ""})
        active.append((branch_name, wt_path, wt_head))
    if whatif:
        # Dry: check upstream mirror without fetch/merge (ps1 parity) and report.
        lanes_dry: list[dict] = []
        active_dry: list[tuple[str, str, str]] = []
        for lane_entry in lanes:
            if lane_entry["skipped"]:
                lanes_dry.append(lane_entry)
                continue
            branch_name = lane_entry["lane"]
            wt_path = branch_to[branch_name][0]
            wt_head = lane_entry["head"]
            upstream_ref = f"refs/remotes/origin/{branch_name}"
            verify_argv = [git_bin, "-C", wt_path, "rev-parse", "--verify", upstream_ref]
            proc_verify = _run(verify_argv)
            if proc_verify.returncode != 0 or not (proc_verify.stdout or "").strip():
                lanes_dry.append({"lane": branch_name, "head": wt_head, "skipped": True, "reason": f"{upstream_ref} not found in {wt_path}"})
                continue
            lanes_dry.append({"lane": branch_name, "head": wt_head, "skipped": False, "reason": ""})
            active_dry.append((branch_name, wt_path, wt_head))
        stdout = proc_list.stdout or ""
        for branch_name, wt_path, _head in active_dry:
            upstream = f"origin/{branch_name}"
            stdout += f"\ngit -C \"{wt_path}\" merge --ff-only {upstream}"
        if any(l["skipped"] for l in lanes_dry):
            skipped_names = ", ".join([l["lane"] for l in lanes_dry if l["skipped"]])
            stdout += f"\n# skipped: {skipped_names}"
        evidence = _evidence(list_argv, proc_list.returncode, proc_list.stdout or "")
        return {
            "tool": "worktrees.sync",
            "executed": True,
            "lane": lane,
            "set": sync_set,
            "dry_run": True,
            "lanes": lanes_dry,
            "stdout": stdout,
            "stderr": _snippet(proc_list.stderr),
            "evidence": evidence,
        }
    if not active:
        skipped_names = ", ".join([l["lane"] for l in lanes if l["skipped"]])
        raise Reject("REJECT_PRECONDITION", f"no clean worktree to sync; skipped: {skipped_names}; no push performed")
    fetch_argv: list[str] = [git_bin, "-C", root, "fetch", "--all", "--prune"]
    proc_fetch = _run(fetch_argv)
    if proc_fetch.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"git fetch --all --prune failed exit {proc_fetch.returncode}: {_snippet(proc_fetch.stderr or proc_fetch.stdout)}")
    combined_stdout = proc_fetch.stdout or ""
    combined_stderr = proc_fetch.stderr or ""
    # Upstream check after fetch (ps1 parity) then merge --ff-only per lane.
    for branch_name, wt_path, wt_head in active:
        upstream = f"origin/{branch_name}"
        upstream_ref = f"refs/remotes/{upstream}"
        verify_argv = [git_bin, "-C", wt_path, "rev-parse", "--verify", upstream_ref]
        proc_verify = _run(verify_argv)
        idx = next((i for i, l in enumerate(lanes) if l["lane"] == branch_name), None)
        if proc_verify.returncode != 0 or not (proc_verify.stdout or "").strip():
            if idx is not None:
                lanes[idx] = {"lane": branch_name, "head": wt_head, "skipped": True, "reason": f"{upstream_ref} not found in {wt_path}"}
            continue
        merge_argv = [git_bin, "-C", wt_path, "merge", "--ff-only", upstream]
        proc_merge = _run(merge_argv)
        combined_stdout += proc_merge.stdout or ""
        combined_stderr += proc_merge.stderr or ""
        if idx is None:
            continue
        if proc_merge.returncode == 0:
            head_argv = [git_bin, "-C", wt_path, "rev-parse", "HEAD"]
            proc_head = _run(head_argv)
            new_head = (proc_head.stdout or "").strip() if proc_head.returncode == 0 else wt_head
            lanes[idx] = {"lane": branch_name, "head": new_head, "skipped": False, "reason": ""}
        else:
            lanes[idx] = {"lane": branch_name, "head": wt_head, "skipped": True, "reason": f"merge --ff-only {upstream} failed exit {proc_merge.returncode}: {_snippet(proc_merge.stderr or proc_merge.stdout)}"}
    evidence = _evidence(fetch_argv, proc_fetch.returncode, proc_fetch.stdout or "")
    return {
        "tool": "worktrees.sync",
        "executed": True,
        "lane": lane,
        "set": sync_set,
        "dry_run": False,
        "lanes": lanes,
        "stdout": combined_stdout,
        "stderr": _snippet(combined_stderr),
        "evidence": evidence,
    }


def _execute_worktrees_sync(server, args: dict) -> dict:
    if _use_native():
        return _execute_worktrees_sync_native(server, args)
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


def _execute_worktrees_reconcile_native(server, args: dict) -> dict:
    lane = args.get("lane")
    if not isinstance(lane, str):
        raise Reject("REJECT_ARG", "worktrees.reconcile requires lane")
    git_bin = _require_native_binary("git")
    whatif = _wants_whatif(args)
    lanes_list = [p.strip() for p in lane.split(",") if p.strip()]
    if not lanes_list:
        raise Reject("REJECT_PRECONDITION", "no lanes given")
    seen: set[str] = set()
    for lane_name in lanes_list:
        if not re.match(r"^lane/[A-Za-z0-9][A-Za-z0-9._-]*$", lane_name):
            raise Reject("REJECT_PRECONDITION", f"lane '{lane_name}' is not a lane/<name> ref")
        if ".." in lane_name or "+" in lane_name or lane_name.startswith("-") or any(c.isspace() for c in lane_name):
            raise Reject("REJECT_PRECONDITION", f"lane '{lane_name}' invalid")
        if lane_name in seen:
            raise Reject("REJECT_PRECONDITION", f"duplicate lane '{lane_name}'")
        seen.add(lane_name)
    repo = _repo_root()
    inside_argv = [git_bin, "-C", repo, "rev-parse", "--is-inside-work-tree"]
    proc_inside = _run(inside_argv)
    if proc_inside.returncode != 0 or (proc_inside.stdout or "").strip() != "true":
        raise Reject("REJECT_PRECONDITION", f"not a git worktree: {repo}")
    branch_argv = [git_bin, "-C", repo, "rev-parse", "--abbrev-ref", "HEAD"]
    proc_branch = _run(branch_argv)
    if proc_branch.returncode != 0 or not (proc_branch.stdout or "").strip():
        raise Reject("REJECT_PRECONDITION", f"cannot read HEAD branch in {repo}")
    branch_val = (proc_branch.stdout or "").strip()
    if branch_val != "spec-comp":
        raise Reject("REJECT_PRECONDITION", f"worktree {repo} is on '{branch_val}', not 'spec-comp' (no merge)")
    status_argv = [git_bin, "-C", repo, "status", "--porcelain"]
    proc_status = _run(status_argv)
    if proc_status.returncode != 0:
        raise Reject("REJECT_PRECONDITION", f"status check failed exit {proc_status.returncode}: {_snippet(proc_status.stderr or proc_status.stdout)}")
    dirty = (proc_status.stdout or "").strip()
    if dirty and not whatif:
        raise Reject("REJECT_PRECONDITION", f"worktree {repo} is dirty; commit or stash before reconciling")
    if whatif:
        stdout = ""
        if dirty:
            stdout += "# note: worktree is dirty; a real run would refuse\n"
        for lane_name in lanes_list:
            stdout += f"git -C \"{repo}\" merge --no-ff {lane_name}\n"
        evidence = _evidence(branch_argv, proc_branch.returncode, proc_branch.stdout or "")
        return {
            "tool": "worktrees.reconcile",
            "executed": True,
            "lane": lane,
            "dry_run": True,
            "stdout": stdout,
            "stderr": "",
            "evidence": evidence,
        }
    combined_stdout = ""
    combined_stderr = ""
    last_merge_argv: list[str] | None = None
    last_merge_code = 0
    for lane_name in lanes_list:
        verify_argv = [git_bin, "-C", repo, "rev-parse", "--verify", f"refs/heads/{lane_name}"]
        proc_verify = _run(verify_argv)
        if proc_verify.returncode != 0 or not (proc_verify.stdout or "").strip():
            raise Reject("REJECT_PRECONDITION", f"{lane_name} not found")
        # Choose flag: --ff-only where already ahead (HEAD ancestor of lane or lane ancestor of HEAD), else --no-ff.
        ancestor_argv = [git_bin, "-C", repo, "merge-base", "--is-ancestor", "HEAD", lane_name]
        proc_head_ancestor = _run(ancestor_argv)
        if proc_head_ancestor.returncode == 0:
            merge_flag = "--ff-only"
        else:
            lane_ancestor_argv = [git_bin, "-C", repo, "merge-base", "--is-ancestor", lane_name, "HEAD"]
            proc_lane_ancestor = _run(lane_ancestor_argv)
            if proc_lane_ancestor.returncode == 0:
                merge_flag = "--ff-only"
            else:
                merge_flag = "--no-ff"
        merge_argv = [git_bin, "-C", repo, "merge", merge_flag, lane_name]
        last_merge_argv = merge_argv
        proc_merge = _run(merge_argv)
        combined_stdout += proc_merge.stdout or ""
        combined_stderr += proc_merge.stderr or ""
        last_merge_code = proc_merge.returncode
        if proc_merge.returncode != 0:
            diff_argv = [git_bin, "-C", repo, "diff", "--name-only", "--diff-filter=U"]
            proc_diff = _run(diff_argv)
            conflict_text = (proc_diff.stdout or "").strip()
            abort_argv = [git_bin, "-C", repo, "merge", "--abort"]
            try:
                _run(abort_argv)
            except Reject:
                pass
            if conflict_text:
                raise Reject("REJECT_PRECONDITION", f"CONFLICT: {conflict_text}")
            raise Reject("REJECT_PRECONDITION", f"merge of {lane_name} failed exit {proc_merge.returncode}: {_snippet(proc_merge.stderr or proc_merge.stdout)}")
        sha_argv = [git_bin, "-C", repo, "rev-parse", "HEAD"]
        proc_sha = _run(sha_argv)
        sha = (proc_sha.stdout or "").strip() if proc_sha.returncode == 0 else ""
        combined_stdout += f"merged {lane_name}: {sha}\n"
    head_argv = [git_bin, "-C", repo, "rev-parse", "HEAD"]
    proc_head = _run(head_argv)
    head_sha = (proc_head.stdout or "").strip() if proc_head.returncode == 0 else ""
    tree_argv = [git_bin, "-C", repo, "rev-parse", "HEAD^{tree}"]
    proc_tree = _run(tree_argv)
    tree_sha = (proc_tree.stdout or "").strip() if proc_tree.returncode == 0 else ""
    combined_stdout += f"reconciled head: {head_sha}\nreconciled tree: {tree_sha}\nreconcile complete: {', '.join(lanes_list)} merged into spec-comp (no push)\n"
    if last_merge_argv is not None:
        evidence = _evidence(last_merge_argv, last_merge_code, combined_stdout)
    else:
        evidence = _evidence(head_argv, proc_head.returncode, combined_stdout)
    return {
        "tool": "worktrees.reconcile",
        "executed": True,
        "lane": lane,
        "dry_run": False,
        "stdout": combined_stdout,
        "stderr": _snippet(combined_stderr),
        "evidence": evidence,
    }


def _execute_worktrees_reconcile(server, args: dict) -> dict:
    if _use_native():
        return _execute_worktrees_reconcile_native(server, args)
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
