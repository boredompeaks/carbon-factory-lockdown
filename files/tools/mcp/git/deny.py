"""Path deny globs and code.write scopes. 6B-1.

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

from ..core.validate import Reject

_GIT_PATH_TOOLS = frozenset({"git.read_file", "git.log", "git.state", "evidence.hash", "static.scan"})


def _segments(path: str) -> list[str]:
    return [seg for seg in path.replace("\\", "/").split("/") if seg not in ("", ".")]


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


def check_extra(server, tool: str, role: str, args: dict) -> None:
    """Family hook invoked by core.server after generic validation."""
    if tool in _GIT_PATH_TOOLS:
        for field in ("path", "spec"):
            value = args.get(field)
            if isinstance(value, str) and is_denied_path(value):
                raise Reject("REJECT_PATH", f"{field} denied: {value!r}")
        # git.log / git.state carry an optional path; git.read_file requires it.
        if tool == "git.commit":
            for item in args.get("paths", []) or []:
                if isinstance(item, str) and (is_denied_path(item) or _is_test_infra_path(item)):
                    raise Reject("REJECT_PATH", f"commit path denied: {item!r}")
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
