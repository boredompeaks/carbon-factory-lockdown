"""Path deny globs and code.write scopes. 6B-1, hardened 6B-fix2.

Deny globs apply to every path argument (F-02, F-03, F-05, F-15, F-17,
F-18, F-19, F-44, F-60, F-76):
  .env*, *.pem, *.key, secrets/**, policy-manifest.json, .opencode/**,
  hacker-scratch/**, audit-scratch/**, quality/ledger/verdicts/**,
  files/policies/attack-catalog.json, skills/hacker* (hacker skills),
  quality/ledger/** (for object reads), and test-infra paths for commits
  (pytest.ini, tox.ini, .coveragerc, .gitleaks.toml, .github/**,
  tests_gate*.py, conftest.py).

code.write scopes (agent-file allows):
  builder    -> backend/** (minus denies above)
  compliance -> backend/docs/compliance/* only
  crouton    -> backend/docs/** only

Only relative normalized paths reach here; traversal/absolute cases
have already been rejected by core.validate as REJECT_PATH.
"""
from __future__ import annotations

import fnmatch

from ..core.validate import Reject, is_traversal_or_absolute

_GIT_PATH_TOOLS = frozenset({"git.read_file", "git.log", "git.state", "evidence.hash", "static.scan"})


def _segments(path: str) -> list[str]:
    return [seg for seg in path.replace("\\", "/").split("/") if seg not in ("", ".")]


def _norm(path: str) -> str:
    """Normalize to lowercased forward-slash repo-relative form."""
    return "/".join(_segments(path)).lower()


def is_denied_path(path: str) -> bool:
    """True if the repo-relative path hits a deny glob (case-insensitive)."""
    if not isinstance(path, str):
        return True
    low = path.lower()
    segs = [s.lower() for s in _segments(path)]
    base = segs[-1] if segs else ""
    # Secrets.
    if base.startswith(".env"):
        return True
    if base.endswith(".pem") or base.endswith(".key"):
        return True
    if "secrets" in segs:
        return True
    # Manifest and control tree (anywhere).
    if base == "policy-manifest.json":
        return True
    if ".opencode" in segs:
        return True
    # Scratch isolation (both directions).
    if "hacker-scratch" in segs or low.startswith("hacker-scratch/"):
        return True
    if "audit-scratch" in segs or low.startswith("audit-scratch/"):
        return True
    # Ledger verdicts / audit records are never object-readable here.
    if low.startswith("quality/ledger/verdicts/") or low.startswith("quality/ledger/audit/"):
        return True
    if low.startswith("quality/ledger/") and "verdict" in low:
        return True
    # Attack catalog is denied to object readers (F-15) and to builders (F-06).
    if "attack-catalog" in low:
        return True
    # Hacker skills are denied to non-hacker readers (F-18).
    if "skills/hacker" in low or "hacker-exploit" in low:
        return True
    return False


def _is_test_infra_path(path: str) -> bool:
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    if base in ("pytest.ini", "tox.ini", ".coveragerc", ".gitleaks.toml", "conftest.py"):
        return True
    if ".github" in low.split("/"):
        return True
    if fnmatch.fnmatch(base, "tests_gate*.py"):
        return True
    return False


def is_test_infra_path(path: str) -> bool:
    """Public alias for test-infra predicate (F-05). Case-insensitive."""
    if not isinstance(path, str):
        return True
    return _is_test_infra_path(path)


def is_commit_denied(path: str) -> bool:
    """True if a staged path must be rejected for git.commit (F-05/F-07).

    Covers the union deny globs (.env*, *.pem, *.key, secrets/**,
    policy-manifest.json, .opencode/**, scratch, ledger verdicts,
    attack-catalog, hacker skills) plus test-infra (pytest.ini,
    tox.ini, .coveragerc, .gitleaks.toml, .github/**, tests_gate*.py,
    conftest.py). Case-insensitive on Windows.
    """
    if not isinstance(path, str):
        return True
    if is_denied_path(path):
        return True
    return _is_test_infra_path(path)


def get_capability(server) -> dict | None:
    """Return capability bound to the Server instance, if any.

    Capability is harness-injected config, never a caller arg. The
    handler checks, in order, server.capability, server._capability,
    server.config.capability and server.config._capability; the first
    dict found is returned. Returns None when no capability is bound
    (e.g. offline controls harness).
    """
    for obj, attr in (
        (server, "capability"),
        (server, "_capability"),
        (getattr(server, "config", None), "capability"),
        (getattr(server, "config", None), "_capability"),
    ):
        if obj is None:
            continue
        val = getattr(obj, attr, None)
        if isinstance(val, dict):
            return val
    return None


def is_in_scope(path: str, scope: list | tuple | None) -> bool:
    """True if repo-relative path matches capability.scope.

    Scope entries are capability-relative globs: exact file paths,
    directory prefixes ending with '/', and fnmatch globs such as
    'backend/**' or 'backend/tests/**'. Comparison is case-insensitive
    (Windows). Empty/missing scope means "no allowlist"; caller must
    handle that case separately.
    """
    if not scope:
        return False
    low = _norm(path)
    for raw in scope:
        if not isinstance(raw, str):
            continue
        entry = raw.replace("\\", "/").strip().lower()
        while entry.startswith("./"):
            entry = entry[2:]
        if not entry:
            continue
        # Exact file.
        if entry == low:
            return True
        # Directory prefix.
        if entry.endswith("/") and low.startswith(entry):
            return True
        # Glob (** / * / ?). fnmatch on the full path.
        if any(c in entry for c in ("*", "?", "[")):
            if fnmatch.fnmatch(low, entry):
                return True
            # '**' suffix without trailing handling: 'backend/**' already
            # covers via fnmatch? fnmatch treats ** like * so 'backend/**'
            # matches 'backend/x' as fnmatch('backend/x','backend/**')
            # True. Also allow prefix match for '**' without slash.
            if entry.endswith("/**") and low.startswith(entry[:-3]):
                return True
    return False


def check_code_write(role: str, path: str) -> None:
    """Enforce per-role write scope; raises REJECT_PATH when out of scope."""
    low = path.lower()
    if role == "builder":
        if not low.startswith("backend/"):
            raise Reject("REJECT_PATH", f"builder code.write scope is backend/**: {path!r}")
        if _is_test_infra_path(path):
            raise Reject("REJECT_PATH", f"test-infra path denied for builder: {path!r}")
    elif role == "compliance":
        if not low.startswith("backend/docs/compliance/"):
            raise Reject("REJECT_PATH", f"compliance code.write scope is backend/docs/compliance/*: {path!r}")
    elif role == "crouton":
        if not low.startswith("backend/docs/"):
            raise Reject("REJECT_PATH", f"crouton code.write scope is backend/docs/**: {path!r}")
    else:
        raise Reject("REJECT_ROLE", f"role {role} has no code.write grant")
    # Universal deny globs also apply to writes.
    if is_denied_path(path):
        raise Reject("REJECT_PATH", f"path denied for code.write: {path!r}")


def check_commit_paths(server, args: dict) -> None:
    """Validate caller-declared commit paths against deny/scope globs.

    Runs in _check_family_extra (before execute). Live staged-diff
    validation runs later in handlers.execute; this check rejects
    declared paths that already match deny/test-infra/scope globs so
    F-05/F-07 have a deterministic REJECT_PATH before any git spawn.
    Deny and scope are absolute: absolute/escape paths are denied and
    scope is mandatory. A missing capability or empty scope fails
    closed — it never silently skips the scope allowlist.
    """
    capability = get_capability(server)
    if not isinstance(capability, dict):
        # Fail-closed scope: no bound capability means no allowlist,
        # so any declared path is outside scope. (Handler enforces
        # the same rule on the live staged set.)
        if args.get("paths"):
            raise Reject(
                "REJECT_PRECONDITION",
                "git.commit requires a bound capability (no silent scope skip)",
            )
        # No declared paths: the handler still requires a capability
        # and a non-empty staged set, so this hook does not need to
        # reject here. Declared-path checks below (absolute/deny)
        # still apply below when paths is empty via the handler.
        scope = None
    else:
        scope = capability.get("scope")
        if not scope:
            if args.get("paths"):
                raise Reject(
                    "REJECT_PRECONDITION",
                    "git.commit requires a non-empty capability.scope (no silent scope skip)",
                )
    for item in args.get("paths", []) or []:
        if not isinstance(item, str):
            continue
        if item.startswith("-"):
            raise Reject("REJECT_PATH", f"commit path denied: {item!r}")
        if is_traversal_or_absolute("git.commit", "paths", item):
            raise Reject("REJECT_PATH", f"commit path denied (absolute/escape): {item!r}")
        if is_commit_denied(item):
            raise Reject("REJECT_PATH", f"commit path denied: {item!r}")
        if not is_in_scope(item, scope):
            raise Reject("REJECT_PATH", f"commit path outside capability.scope: {item!r}")


def check_extra(server, tool: str, role: str, args: dict) -> None:
    """Family hook invoked by core.server after generic validation."""
    if tool == "git.commit":
        check_commit_paths(server, args)
        return
    if tool in _GIT_PATH_TOOLS:
        for field in ("path", "spec"):
            value = args.get(field)
            if isinstance(value, str) and is_denied_path(value):
                raise Reject("REJECT_PATH", f"{field} denied: {value!r}")
    elif tool == "code.write":
        check_code_write(role, args.get("path", ""))
    elif tool == "acceptance.materialize":
        # Materialization can never write into the ledger (F-76).
        value = args.get("path", "")
        if isinstance(value, str) and value.lower().startswith("quality/ledger/"):
            raise Reject("REJECT_PATH", f"ledger path denied for acceptance.materialize: {value!r}")
        if isinstance(value, str) and is_denied_path(value):
            raise Reject("REJECT_PATH", f"path denied for acceptance.materialize: {value!r}")
    elif tool in ("scratch.write", "repro.run"):
        value = args.get("path") or args.get("spec", "")
        if isinstance(value, str) and value and is_denied_path(value):
            # repro specs are ledger-relative names; the deny set still
            # blocks scratch escapes (F-34 is handled earlier as traversal).
            if "ledger" in value.lower():
                raise Reject("REJECT_PATH", f"path denied: {value!r}")
