"""Git tool execution. 6B-1, hardened 6B-fix2, real handlers P3a.

git.commit is a real host-side handler, not a stub: it runs
`git diff --cached --name-only --no-renames` against the live index,
verifies HEAD == capability.head and branch == task_branch (when a
capability is bound to the Server) plus args.tree == HEAD^{tree}
(stale-tree check), rejects any staged path matching the
scope/deny globs (.env*, pytest.ini, tox.ini, .coveragerc,
.github/**, .gitleaks.toml, conftest.py, tests_gate*.py, plus the
universal deny set), and then runs `git commit` with shell=False
and never --no-verify.

All other git tools are real argv-only handlers (shell=False,
cwd = repo via -C, 30s timeout via _timeout):
  git.state  -> rev-parse HEAD, rev-parse HEAD^{tree},
                rev-parse --abbrev-ref HEAD, status --porcelain,
                merge-base <rev> HEAD,
                merge-base --is-ancestor <rev> HEAD,
                ls-tree -r <rev> [-- <path>]
  git.status -> status --porcelain=v2 --branch (parsed)
  git.log    -> log -n <limit> --format=%H%x09%an%x09%aI%x09%s
                [<ref>] [-- <path>]
  git.diff   -> diff --no-ext-diff --no-textconv <base> <head>
                [-- <path>]; name_only=true -> diff --name-only
                <base>..<head> and paths only (no blob content)
  git.read_file -> cat-file blob <rev>:<path>
  git.push_ref  -> rev-parse <ref> must equal expected_head, then
                   push --porcelain origin <ref>:<ref>
  evidence.hash -> cat-file blob <rev>:<path>, sha256 of the bytes
  code.write    -> real write under deny.check_code_write scope,
                   utf-8, size cap

An optional `lane` arg resolves through
files/policies/worktree-map.json (lane/a, lane/b, spec-comp) for every
git/check/code.write target; omitted lane means the factory root unless
``CARBON_WORKSPACE`` is set, in which case it is REJECT_AMBIGUOUS_LANE.

Every real result carries executed:true and
evidence:{argv, exit_code, stdout_sha256}. Non-zero exit maps to
Reject("REJECT_PRECONDITION") with the stderr tail.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

from ..core.validate import Reject, is_traversal_or_absolute

from .deny import check_code_write, get_capability, is_commit_denied, is_denied_path, is_in_scope
from .lane import (
    LANE_PATTERN,
    factory_root,
    is_lane_name,
    resolve_required_lane,
)

_LANE_RE = re.compile(LANE_PATTERN)

_TIMEOUT_FALLBACK = 30
_CODE_WRITE_MAX_BYTES = 262144


def _is_absolute_or_escape(path: str) -> bool:
    """True for absolute, drive, UNC, traversal or non-normalised paths.

    Absolute deny on the staged set: the index is authoritative, and a
    staged path that is absolute or escapes the repo root is denied
    unconditionally, regardless of capability/scope state.
    """
    if not isinstance(path, str):
        return True
    if is_traversal_or_absolute("git.commit", "paths", path):
        return True
    return False


def _is_placeholder(rev: str | None) -> bool:
    return not rev or rev == "0" * 40


def _repo_cwd(lane: str | None = None) -> str:
    """Working directory from which git discovers the harness repo.

    The factory root is files/tools/mcp/git/handlers.py -> parents[4]
    (parents[3] is files/). With ``lane`` the root comes from
    worktree-map.json instead, so product sessions target their lane
    worktree rather than the factory. The root is required so
    repo-relative path filters (ls-tree/log/diff -- <path> with
    files/... paths) resolve correctly under `git -C <cwd>`.
    """
    return str(resolve_required_lane(lane, factory_root()))


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


def _run_git(server, argv: list[str], lane: str | None = None) -> subprocess.CompletedProcess:
    """Run one git command with shell=False. Never --no-verify."""
    exe = _git_exe(server)
    return subprocess.run(
        [exe, "-C", _repo_cwd(lane), *argv],
        shell=False,
        capture_output=True,
        text=True,
        timeout=_timeout(server),
        env=_env(server),
    )


def _full_argv(server, subargv: list[str], lane: str | None = None) -> list[str]:
    """Full argv as executed: [git, -C, repo_cwd, *subargv]."""
    return [_git_exe(server), "-C", _repo_cwd(lane), *subargv]


def _sha256_str(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _evidence_entry(
    server,
    subargv: list[str],
    proc: subprocess.CompletedProcess,
    lane: str | None = None,
) -> dict:
    return {
        "argv": _full_argv(server, subargv, lane),
        "exit_code": proc.returncode,
        "stdout_sha256": _sha256_str(proc.stdout or ""),
    }


def _stderr_tail(proc: subprocess.CompletedProcess) -> str:
    raw = ((proc.stderr or "").strip() or (proc.stdout or "").strip())
    # Tail (no secrets): last 200 chars.
    if len(raw) > 200:
        raw = raw[-200:]
    return raw


def _run_checked(server, subargv: list[str], lane: str | None = None) -> subprocess.CompletedProcess:
    """Run git subargv with shell=False; non-zero exit -> REJECT_PRECONDITION."""
    try:
        proc = _run_git(server, subargv, lane)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as exc:
        raise Reject("REJECT_PRECONDITION", f"git {subargv[0]} spawn failed: {exc}")
    except Exception as exc:
        raise Reject("REJECT_PRECONDITION", f"git {subargv[0]} spawn failed: {exc}")
    if proc.returncode != 0:
        tail = _stderr_tail(proc)
        raise Reject("REJECT_PRECONDITION", f"git {' '.join(subargv)} failed (exit {proc.returncode}): {tail}")
    return proc


def _repo_root(server, lane: str | None = None) -> Path:
    """Authoritative repo toplevel for code.write destinations.

    A supplied lane resolves through worktree-map.json; otherwise the
    factory toplevel is used (backward compatible).
    """
    if lane is not None or os.environ.get("CARBON_WORKSPACE"):
        return resolve_required_lane(lane, factory_root())
    try:
        proc = _run_git(server, ["rev-parse", "--show-toplevel"])
        if proc.returncode == 0 and (proc.stdout or "").strip():
            return Path(proc.stdout.strip())
    except Exception:
        pass
    # Fallback: handlers.py is files/tools/mcp/git/handlers.py, parents[4] is root.
    return Path(__file__).resolve().parents[4]


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


def _git_rev_parse(server, rev: str, lane: str | None = None) -> str:
    """Run git rev-parse <rev> and return stripped output; fail closed."""
    try:
        out = _run_git(server, ["rev-parse", "--verify", "--quiet", rev], lane)
    except Exception:
        raise Reject("REJECT_PRECONDITION", f"git rev-parse {rev} failed")
    if out.returncode != 0 or not out.stdout.strip():
        raise Reject("REJECT_PRECONDITION", f"git rev-parse {rev} failed: {out.stderr.strip()}")
    return out.stdout.strip()


def _git_head(server, lane: str | None = None) -> tuple[str, str, str]:
    """Return (head, tree, branch) for the live HEAD; fail closed."""
    # HEAD must be a commit; ^{tree} must resolve; branch must resolve.
    head = _git_rev_parse(server, "HEAD", lane)
    tree = _git_rev_parse(server, "HEAD^{tree}", lane)
    try:
        out = _run_git(server, ["rev-parse", "--abbrev-ref", "HEAD"], lane)
    except Exception:
        raise Reject("REJECT_PRECONDITION", "git rev-parse --abbrev-ref HEAD failed")
    if out.returncode != 0:
        raise Reject("REJECT_PRECONDITION", "git rev-parse --abbrev-ref HEAD failed")
    branch = out.stdout.strip()
    return head, tree, branch


def _staged_paths(server, lane: str | None = None) -> list[str]:
    """Live staged paths via git diff --cached --name-only --no-renames."""
    try:
        out = _run_git(server, ["diff", "--cached", "--name-only", "--no-renames"], lane)
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


def _enforce_lane_binding(capability: dict, lane: str | None) -> None:
    """A supplied lane must agree with capability.task_branch when that
    branch names a lane (lane/a, lane/b, spec-comp). A task/<id> branch
    does not name a lane and is left to the normal branch binding.
    """
    if lane is None:
        return
    cap_branch = capability.get("task_branch") or capability.get("branch")
    if isinstance(cap_branch, str) and cap_branch and is_lane_name(cap_branch):
        if cap_branch != lane:
            raise Reject(
                "REJECT_PRECONDITION",
                f"lane {lane!r} != capability.task_branch {cap_branch!r}",
            )


def _execute_commit(server, args: dict) -> dict:
    message = args.get("message")
    tree_arg = args.get("tree")
    lane = args.get("lane")
    if not isinstance(message, str) or not isinstance(tree_arg, str):
        raise Reject("REJECT_ARG", "git.commit requires message and tree")
    if message.lstrip().startswith("-"):
        raise Reject("REJECT_PATTERN", "message must not start with a dash")

    # 0) Fail closed on an unknown/missing lane before any git spawn.
    resolve_required_lane(lane, factory_root())

    # 1) HEAD / tree / branch binding (scope/deny absolute). A bound
    # capability is mandatory: without one there is no scope allowlist,
    # so the commit fails closed instead of silently skipping scope.
    # HEAD == capability.head and branch == task_branch are enforced
    # strictly; args.tree must always equal HEAD^{tree} (stale tree).
    # With a lane, all three checks run against the lane repo.
    head, live_tree, branch = _git_head(server, lane)
    capability = get_capability(server)
    if not isinstance(capability, dict):
        raise Reject(
            "REJECT_PRECONDITION",
            "git.commit requires a bound capability (no silent scope skip)",
        )
    _enforce_lane_binding(capability, lane)
    # Scope allowlist is mandatory and absolute.
    _cap_scope = capability.get("scope") if isinstance(capability, dict) else None
    if not _cap_scope:
        raise Reject(
            "REJECT_PRECONDITION",
            "git.commit requires a non-empty capability.scope (no silent scope skip)",
        )
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
    # declaration still rejects here. Deny and scope are absolute:
    # absolute/escape paths are denied unconditionally, deny globs
    # apply to every staged path, and every staged path must be in
    # capability.scope (no optional-scope skip).
    staged = _staged_paths(server, lane)
    if not staged:
        raise Reject("REJECT_PRECONDITION", "nothing staged to commit")
    scope = capability.get("scope") if isinstance(capability, dict) else None
    for s_idx, staged_path in enumerate(staged):
        if not isinstance(staged_path, str) or _is_absolute_or_escape(staged_path):
            raise Reject(
                "REJECT_PATH",
                f"staged path is absolute/escaped, denied: {staged_path!r}",
            )
        if is_commit_denied(staged_path):
            raise Reject("REJECT_PATH", f"staged path denied: {staged_path!r}")
        if not is_in_scope(staged_path, scope):
            raise Reject(
                "REJECT_PATH",
                f"staged path outside capability.scope: {staged_path!r}",
            )
    # Re-validate declared paths against the same predicates so a
    # path-only bypass that skips deny.check_extra still rejects.
    # Absolute/escape declared paths are denied here too (defense in
    # depth; generic validation already rejected them before this
    # handler, but a direct handler call must still fail closed).
    for declared in args.get("paths", []) or []:
        if not isinstance(declared, str):
            continue
        if _is_absolute_or_escape(declared):
            raise Reject(
                "REJECT_PATH",
                f"commit path is absolute/escaped, denied: {declared!r}",
            )
        if is_commit_denied(declared):
            raise Reject("REJECT_PATH", f"commit path denied: {declared!r}")
        if not is_in_scope(declared, scope):
            raise Reject(
                "REJECT_PATH",
                f"commit path outside capability.scope: {declared!r}",
            )

    # 3) Commit with hooks (never --no-verify, never shell).
    try:
        out = _run_git(server, ["commit", "-m", message], lane)
    except Exception as exc:
        raise Reject("REJECT_PRECONDITION", f"git commit failed: {exc}")
    if out.returncode != 0:
        raise Reject(
            "REJECT_PRECONDITION",
            f"git commit failed: {(out.stderr or out.stdout).strip()[:200]}",
        )
    new_head = _git_rev_parse(server, "HEAD", lane)
    new_tree = _git_rev_parse(server, "HEAD^{tree}", lane)
    result = {
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
    if lane is not None:
        result["lane"] = lane
    return result


def _execute_state(server, args: dict) -> dict:
    rev = args.get("rev")
    path = args.get("path")
    lane = args.get("lane")
    resolve_required_lane(lane, factory_root())
    if path is not None:
        if not isinstance(path, str):
            raise Reject("REJECT_ARG", "path must be a string")
        if is_traversal_or_absolute("git.state", "path", path):
            raise Reject("REJECT_PATH", f"path: non-normalized or out-of-tree path")
        if is_denied_path(path):
            raise Reject("REJECT_PATH", f"path denied: {path!r}")
    if rev is not None and not isinstance(rev, str):
        raise Reject("REJECT_ARG", "rev must be a string")

    executed: list[tuple[list[str], subprocess.CompletedProcess]] = []

    def run(subargv: list[str]) -> subprocess.CompletedProcess:
        proc = _run_checked(server, subargv, lane)
        executed.append((subargv, proc))
        return proc

    head = run(["rev-parse", "HEAD"]).stdout.strip()
    tree = run(["rev-parse", "HEAD^{tree}"]).stdout.strip()
    branch = run(["rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    porcelain = run(["status", "--porcelain"]).stdout
    dirty = bool(porcelain.strip())

    merge_base: str | None = None
    ancestor: bool | None = None
    files: list[str] = []
    if rev is not None:
        merge_base = run(["merge-base", rev, "HEAD"]).stdout.strip() or None
        # --is-ancestor: exit 0 => True, exit 1 => False, else fail.
        subargv = ["merge-base", "--is-ancestor", rev, "HEAD"]
        try:
            proc = _run_git(server, subargv, lane)
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as exc:
            raise Reject("REJECT_PRECONDITION", f"git merge-base spawn failed: {exc}")
        executed.append((subargv, proc))
        if proc.returncode == 0:
            ancestor = True
        elif proc.returncode == 1:
            ancestor = False
        else:
            tail = _stderr_tail(proc)
            raise Reject("REJECT_PRECONDITION", f"git {' '.join(subargv)} failed (exit {proc.returncode}): {tail}")
        ls_argv = ["ls-tree", "-r", rev]
        if path is not None:
            ls_argv = ["ls-tree", "-r", rev, "--", path]
        ls_out = run(ls_argv).stdout
        for line in ls_out.splitlines():
            line = line.strip()
            if not line:
                continue
            # "<mode> <type> <sha>\t<path>"
            if "\t" in line:
                files.append(line.split("\t", 1)[1])
            else:
                parts = line.split()
                if parts:
                    files.append(parts[-1])

    combined_stdout = "".join((proc.stdout or "") for _, proc in executed)
    commands = [_evidence_entry(server, subargv, proc, lane) for subargv, proc in executed]
    evidence = {
        "argv": [c["argv"] for c in commands],
        "exit_code": 0,
        "stdout_sha256": _sha256_str(combined_stdout),
        "commands": commands,
    }
    return {
        "tool": "git.state",
        "head": head,
        "tree": tree,
        "branch": branch,
        "dirty": dirty,
        "merge_base": merge_base,
        "ancestor": ancestor,
        "files": files,
        "executed": True,
        "evidence": evidence,
    }


def _execute_status(server, args: dict) -> dict:
    ref = args.get("ref")
    lane = args.get("lane")
    resolve_required_lane(lane, factory_root())
    subargv = ["status", "--porcelain=v2", "--branch"]
    proc = _run_checked(server, subargv, lane)
    raw = proc.stdout or ""
    branch_oid: str | None = None
    branch_head: str | None = None
    upstream: str | None = None
    ahead = 0
    behind = 0
    entries: list[dict] = []
    for line in raw.splitlines():
        if line.startswith("# branch.oid "):
            branch_oid = line[len("# branch.oid "):].strip()
        elif line.startswith("# branch.head "):
            branch_head = line[len("# branch.head "):].strip()
        elif line.startswith("# branch.upstream "):
            upstream = line[len("# branch.upstream "):].strip()
        elif line.startswith("# branch.ab "):
            rest = line[len("# branch.ab "):].strip()
            try:
                plus, minus = rest.split()
                ahead = int(plus.lstrip("+"))
                behind = int(minus.lstrip("-"))
            except Exception:
                pass
        elif line.startswith("? "):
            entries.append({"kind": "untracked", "path": line[2:]})
        elif line.startswith("! "):
            entries.append({"kind": "ignored", "path": line[2:]})
        elif line.startswith("1 "):
            # 1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>
            parts = line.split(" ", 8)
            if len(parts) >= 9:
                entries.append({"kind": "tracked", "xy": parts[1], "path": parts[8]})
            elif len(parts) >= 2:
                entries.append({"kind": "tracked", "xy": parts[1], "path": ""})
        elif line.startswith("2 "):
            # 2 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <Xstep> <path><sep><orig>
            parts = line.split(" ", 9)
            if len(parts) >= 10:
                raw_path = parts[9]
                p = raw_path.split("\t")[0] if "\t" in raw_path else raw_path
                entries.append({"kind": "renamed", "xy": parts[1], "path": p})
            elif len(parts) >= 2:
                entries.append({"kind": "renamed", "xy": parts[1], "path": ""})
        elif line.startswith("u "):
            parts = line.split(" ", 10)
            if len(parts) >= 11:
                entries.append({"kind": "unmerged", "xy": parts[1], "path": parts[10]})
            elif len(parts) >= 2:
                entries.append({"kind": "unmerged", "xy": parts[1], "path": ""})
    evidence = _evidence_entry(server, subargv, proc, lane)
    return {
        "tool": "git.status",
        "ref": ref,
        "branch_oid": branch_oid,
        "branch": branch_head,
        "upstream": upstream,
        "ahead": ahead,
        "behind": behind,
        "entries": entries,
        "executed": True,
        "evidence": evidence,
    }


def _execute_log(server, args: dict) -> dict:
    limit = args.get("limit")
    if limit is None:
        limit = 10
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise Reject("REJECT_ARG", "limit must be an integer")
    ref = args.get("ref")
    path = args.get("path")
    lane = args.get("lane")
    resolve_required_lane(lane, factory_root())
    if path is not None:
        if not isinstance(path, str):
            raise Reject("REJECT_ARG", "path must be a string")
        if is_traversal_or_absolute("git.log", "path", path):
            raise Reject("REJECT_PATH", f"path: non-normalized or out-of-tree path")
        if is_denied_path(path):
            raise Reject("REJECT_PATH", f"path denied: {path!r}")
    if ref is not None and not isinstance(ref, str):
        raise Reject("REJECT_ARG", "ref must be a string")
    subargv = ["log", "-n", str(limit), "--format=%H%x09%an%x09%aI%x09%s"]
    if ref is not None:
        subargv.append(ref)
    if path is not None:
        subargv.extend(["--", path])
    proc = _run_checked(server, subargv, lane)
    entries: list[dict] = []
    for line in (proc.stdout or "").splitlines():
        if not line:
            continue
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        entries.append({"sha": parts[0], "author": parts[1], "date": parts[2], "subject": parts[3]})
    evidence = _evidence_entry(server, subargv, proc, lane)
    result: dict = {
        "tool": "git.log",
        "entries": entries,
        "count": len(entries),
        "limit": limit,
        "executed": True,
        "evidence": evidence,
    }
    if ref is not None:
        result["ref"] = ref
    if path is not None:
        result["path"] = path
    return result


def _execute_diff(server, args: dict) -> dict:
    base = args.get("base")
    head = args.get("head")
    path = args.get("path")
    lane = args.get("lane")
    name_only = args.get("name_only", False)
    resolve_required_lane(lane, factory_root())
    if not isinstance(base, str) or not isinstance(head, str):
        raise Reject("REJECT_ARG", "git.diff requires base and head")
    if not isinstance(name_only, bool):
        raise Reject("REJECT_ARG", "name_only must be a boolean")
    if path is not None:
        if not isinstance(path, str):
            raise Reject("REJECT_ARG", "path must be a string")
        if is_traversal_or_absolute("git.diff", "path", path):
            raise Reject("REJECT_PATH", f"path: non-normalized or out-of-tree path")
        if is_denied_path(path):
            raise Reject("REJECT_PATH", f"path denied: {path!r}")
    if name_only:
        # Paths only: no blob content is read, so content redaction is
        # intentionally skipped (there is nothing to redact).
        subargv = ["diff", "--name-only", f"{base}..{head}"]
        if path is not None:
            subargv.extend(["--", path])
        proc = _run_checked(server, subargv, lane)
        evidence = _evidence_entry(server, subargv, proc, lane)
        paths = [
            line.strip()
            for line in (proc.stdout or "").splitlines()
            if line.strip()
        ]
        result: dict = {
            "tool": "git.diff",
            "base": base,
            "head": head,
            "name_only": True,
            "paths": paths,
            "count": len(paths),
            "executed": True,
            "evidence": evidence,
        }
        if path is not None:
            result["path"] = path
        return result
    subargv = ["diff", "--no-ext-diff", "--no-textconv", base, head]
    if path is not None:
        subargv.extend(["--", path])
    proc = _run_checked(server, subargv, lane)
    evidence = _evidence_entry(server, subargv, proc, lane)
    return {
        "tool": "git.diff",
        "base": base,
        "head": head,
        "diff": proc.stdout or "",
        "executed": True,
        "evidence": evidence,
    }


def _execute_read_file(server, args: dict) -> dict:
    rev = args.get("rev")
    path = args.get("path")
    lane = args.get("lane")
    resolve_required_lane(lane, factory_root())
    if not isinstance(rev, str) or not isinstance(path, str):
        raise Reject("REJECT_ARG", "git.read_file requires rev and path")
    if is_traversal_or_absolute("git.read_file", "path", path):
        raise Reject("REJECT_PATH", f"path: non-normalized or out-of-tree path")
    # Defence in depth: deny globs already applied upstream.
    if is_denied_path(path):
        raise Reject("REJECT_PATH", f"path denied: {path!r}")
    subargv = ["cat-file", "blob", f"{rev}:{path}"]
    proc = _run_checked(server, subargv, lane)
    content = proc.stdout or ""
    evidence = _evidence_entry(server, subargv, proc, lane)
    return {
        "tool": "git.read_file",
        "rev": rev,
        "path": path,
        "content": content,
        "bytes": len(content.encode("utf-8")),
        "sha256": _sha256_str(content),
        "executed": True,
        "evidence": evidence,
    }


def _execute_evidence_hash(server, args: dict) -> dict:
    """sha256 of the blob bytes at <rev>:<path> in the factory or lane."""
    rev = args.get("rev")
    path = args.get("path")
    lane = args.get("lane")
    resolve_required_lane(lane, factory_root())
    if not isinstance(rev, str) or not re.fullmatch(r"[a-f0-9]{40}", rev):
        raise Reject("REJECT_ARG", f"rev must be 40-hex: {rev!r}")
    if not isinstance(path, str) or not path:
        raise Reject("REJECT_ARG", "path must be a non-empty string")
    if is_traversal_or_absolute("evidence.hash", "path", path):
        raise Reject("REJECT_PATH", f"path: non-normalized or out-of-tree path: {path!r}")
    if is_denied_path(path):
        raise Reject("REJECT_PATH", f"path denied for evidence.hash: {path!r}")
    exe = _git_exe(server)
    argv = [exe, "-C", _repo_cwd(lane), "cat-file", "blob", f"{rev}:{path}"]
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Reject("REJECT_PRECONDITION", f"git cat-file blob failed to run: {exc}") from exc
    if proc.returncode != 0:
        raw = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        tail = raw[-200:] if len(raw) > 200 else raw
        raise Reject(
            "REJECT_PRECONDITION",
            f"git cat-file blob {rev}:{path} failed (exit {proc.returncode}): {tail}",
        )
    blob = proc.stdout or b""
    sha = hashlib.sha256(blob).hexdigest()
    evidence = {"argv": argv, "exit_code": 0, "stdout_sha256": sha}
    return {
        "tool": "evidence.hash",
        "rev": rev,
        "path": path,
        "sha256": sha,
        "bytes": len(blob),
        "executed": True,
        "evidence": evidence,
    }


def _execute_push_ref(server, args: dict) -> dict:
    ref = args.get("ref")
    expected_head = args.get("expected_head")
    lane = args.get("lane")
    resolve_required_lane(lane, factory_root())
    if not isinstance(ref, str) or not isinstance(expected_head, str):
        raise Reject("REJECT_ARG", "git.push_ref requires ref and expected_head")
    if not ref.startswith("refs/heads/"):
        raise Reject("REJECT_PATH", f"push ref must be refs/heads/*: {ref!r}")
    # resolvable, must equal expected_head.
    subargv_parse = ["rev-parse", ref]
    try:
        proc_parse = _run_git(server, subargv_parse, lane)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as exc:
        raise Reject("REJECT_PRECONDITION", f"git rev-parse spawn failed: {exc}")
    if proc_parse.returncode != 0:
        tail = _stderr_tail(proc_parse)
        raise Reject("REJECT_PRECONDITION", f"git {' '.join(subargv_parse)} failed (exit {proc_parse.returncode}): {tail}")
    resolved = (proc_parse.stdout or "").strip()
    if resolved.lower() != expected_head.lower():
        raise Reject("REJECT_PRECONDITION", f"ref {ref} resolves to {resolved} != expected_head {expected_head}")
    # push --porcelain origin <ref>:<ref>; no force flag exists.
    subargv_push = ["push", "--porcelain", "origin", f"{ref}:{ref}"]
    try:
        proc_push = _run_git(server, subargv_push, lane)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as exc:
        raise Reject("REJECT_PRECONDITION", f"git push spawn failed: {exc}")
    if proc_push.returncode != 0:
        tail = _stderr_tail(proc_push)
        raise Reject("REJECT_PRECONDITION", f"git {' '.join(subargv_push)} failed (exit {proc_push.returncode}): {tail}")
    parse_entry = _evidence_entry(server, subargv_parse, proc_parse, lane)
    push_entry = _evidence_entry(server, subargv_push, proc_push, lane)
    evidence = {
        "argv": push_entry["argv"],
        "exit_code": push_entry["exit_code"],
        "stdout_sha256": push_entry["stdout_sha256"],
        "commands": [parse_entry, push_entry],
    }
    return {
        "tool": "git.push_ref",
        "ref": ref,
        "expected_head": expected_head,
        "resolved": resolved,
        "pushed": True,
        "fast_forward_only": True,
        "force": False,
        "executed": True,
        "evidence": evidence,
    }


def _execute_code_write(server, role: str, args: dict) -> dict:
    path = args.get("path")
    content = args.get("content")
    encoding = args.get("encoding", "utf-8") or "utf-8"
    if not isinstance(path, str):
        raise Reject("REJECT_ARG", "code.write requires path")
    if not isinstance(content, str):
        raise Reject("REJECT_ARG", "code.write requires content")
    if encoding != "utf-8":
        raise Reject("REJECT_ARG", f"encoding must be utf-8: {encoding!r}")
    if is_traversal_or_absolute("code.write", "path", path):
        raise Reject("REJECT_PATH", f"path: non-normalized or out-of-tree path")
    # Real scope enforcement under deny.check_code_write.
    check_code_write(role, path)
    # Defence in depth: universal deny also checked here.
    if is_denied_path(path):
        raise Reject("REJECT_PATH", f"path denied for code.write: {path!r}")
    data = content.encode("utf-8")
    if len(data) > _CODE_WRITE_MAX_BYTES:
        raise Reject("REJECT_ARG", f"content exceeds {_CODE_WRITE_MAX_BYTES} bytes")
    root = _repo_root(server, args.get("lane"))
    dest = (root / Path(path)).resolve()
    try:
        dest.relative_to(root.resolve())
    except ValueError:
        raise Reject("REJECT_PATH", f"path escapes repo: {path!r}")
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    except OSError as exc:
        raise Reject("REJECT_PRECONDITION", f"code.write failed: {exc}")
    sha = hashlib.sha256(data).hexdigest()
    evidence = {
        "argv": ["code.write", path],
        "exit_code": 0,
        "stdout_sha256": sha,
    }
    return {
        "tool": "code.write",
        "path": path,
        "bytes": len(data),
        "sha256": sha,
        "encoding": "utf-8",
        "written": True,
        "executed": True,
        "evidence": evidence,
    }


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if not tool.startswith("git.") and tool not in ("code.write", "evidence.hash"):
        return None
    if tool == "git.commit":
        return _execute_commit(server, args)
    if tool == "git.state":
        return _execute_state(server, args)
    if tool == "git.status":
        return _execute_status(server, args)
    if tool == "git.log":
        return _execute_log(server, args)
    if tool == "git.diff":
        return _execute_diff(server, args)
    if tool == "git.read_file":
        return _execute_read_file(server, args)
    if tool == "git.push_ref":
        return _execute_push_ref(server, args)
    if tool == "code.write":
        return _execute_code_write(server, role, args)
    if tool == "evidence.hash":
        return _execute_evidence_hash(server, args)
    return None

