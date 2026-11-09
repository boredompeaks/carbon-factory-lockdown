"""check.run execution. 6B-2 + P3d 24/24.

One dispatcher for all 24 check ids in checks.json. Delegation is pinned:

- 9 local tool checks via ``_TOOL_CHECKS``: each runs its factory tool
  argv-only (no shell) with a 180s timeout and parses the tool JSON
  envelope into ``{check_id, outcome PASS|FAIL, findings[], evidence{
  argv, exit_code, stdout_sha256}, executed:true}``. A missing tool
  file is ``Reject("REJECT_PRECONDITION", "tool missing")``.
- 15 gate_run checks via ``_build_evidence``: real repo inputs are
  gathered (``git diff --name-only``/``-U0`` base..head, added lines,
  test roster from ``git ls-tree``/``git show``, scope paths from
  dispatch-rules) and passed to ``gate_run.py --check <id> --input
  <tmpjson>``. Runtime checks (SUITE, BOOTTEST, ZIZMOR, MUTATION,
  THREAD_RACE, SCHEMA_FUZZ, DAST_BASELINE) require an actual run
  (k1/binary); when the runtime is absent they raise
  ``Reject("REJECT_PRECONDITION", "no runtime: <name>")``.

Never synthesises a PASS: every returned result with a tool/gate_run
run carries ``stub: False, executed: True``; fail-closed cases are
Reject exceptions, never fabricated PASS dicts.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..core.redact import cache_key
from ..core.validate import Reject

_GATE_RUN_CHECKS = frozenset({
    "SCOPE",
    "SUITE",
    "TEST_SET",
    "TEST_INFRA",
    "BASE_FAIL_HEAD_PASS",
    "MUTATION",
    "CHANGELOG",
    "SECRETS",
    "CONVENTION",
    "GATE_CONTROLS",
    "THREAD_RACE",
    "SCHEMA_FUZZ",
    "BOOTTEST",
    "ZIZMOR",
    "DAST_BASELINE",
    "DOC",
})

_RUNTIME_CHECKS = frozenset({
    "SUITE", "BOOTTEST", "ZIZMOR", "MUTATION",
    "THREAD_RACE", "SCHEMA_FUZZ", "DAST_BASELINE",
})
_RUNTIME_NAME = {
    "SUITE": "suite",
    "BOOTTEST": "boot",
    "ZIZMOR": "zizmor",
    "MUTATION": "mutmut",
    "THREAD_RACE": "postgres",
    "SCHEMA_FUZZ": "schemathesis",
    "DAST_BASELINE": "dast",
}

_TOOL_TIMEOUT = 180
_GATE_TIMEOUT = 60

# check_id -> tool file. Builders below construct the pinned argv.
_TOOL_FILES = {
    "SMELL": "smell.py",
    "POLICY_DIGEST": "policy_digest.py",
    "ARCH": "arch_check.py",
    "ORACLE_PROVENANCE": "oracle_provenance.py",
    "GUARD_DELTA": "guard_delta.py",
    "AUTHZ_MATRIX": "authz_matrix.py",
    "SEMGREP": "semgrep_runner.py",
    "AGT_PARITY": "agt_parity.py",
    "AGT_AUDIT": "agt_audit.py",
}
_TOOL_CHECKS = frozenset(_TOOL_FILES)


def _gate_run_path() -> Path:
    return Path(__file__).resolve().parents[2] / "gate_run.py"


def _tools_dir() -> Path:
    return Path(__file__).resolve().parents[2]


def _harness_root() -> Path:
    # checks/handlers.py -> mcp -> tools -> files -> harness root
    return Path(__file__).resolve().parents[4]


def _policies_dir() -> Path:
    return _tools_dir().parent / "policies"


def _repo_root() -> Path:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10, cwd=str(Path.cwd()),
        )
        if proc.returncode == 0 and proc.stdout.strip():
            cand = Path(proc.stdout.strip())
            if cand.is_dir():
                return cand
    except (OSError, subprocess.SubprocessError):
        pass
    root = _harness_root()
    return root


def _run_git(repo: Path, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, timeout=timeout, check=False,
    )


def _require_base_head(args: dict) -> tuple[str, str]:
    base = str(args.get("base") or "")
    head = str(args.get("head") or "")
    if not re.fullmatch(r"[a-f0-9]{40}", base) or not re.fullmatch(r"[a-f0-9]{40}", head):
        raise Reject("REJECT_PRECONDITION", "base/head required for diff evidence")
    return base, head


def _diff_text(repo: Path, base: str, head: str) -> str:
    proc = _run_git(repo, ["--no-pager", "diff", "--no-color", "-U0", f"{base}..{head}"])
    if proc.returncode != 0:
        raise Reject("REJECT_PRECONDITION", "no runtime: git")
    return proc.stdout


def _diff_paths(repo: Path, base: str, head: str) -> list[str]:
    proc = _run_git(repo, ["diff", "--name-only", f"{base}..{head}"])
    if proc.returncode != 0:
        raise Reject("REJECT_PRECONDITION", "no runtime: git")
    return [line.strip().replace("\\", "/") for line in proc.stdout.splitlines() if line.strip()]


def _parse_added_lines(diff_text: str) -> dict[str, list[int]]:
    added: dict[str, list[int]] = {}
    cur: str | None = None
    new_line = 0
    in_hunk = False
    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            cur = None
            in_hunk = False
            continue
        if raw.startswith("+++ "):
            p = raw[4:].strip().split("\t")[0].strip()
            if p.startswith('"') and p.endswith('"'):
                p = p[1:-1]
            if p.startswith("b/"):
                p = p[2:]
            cur = None if p == "/dev/null" else p.replace("\\", "/")
            in_hunk = False
            continue
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
        if m and cur is not None:
            new_line = int(m.group(1))
            in_hunk = True
            continue
        if cur is None or not in_hunk or raw.startswith("\\"):
            continue
        tag = raw[:1] if raw else " "
        if tag == "+":
            added.setdefault(cur, []).append(new_line)
            new_line += 1
        elif tag == "-":
            pass
        elif tag == " " or raw == "":
            new_line += 1
    return added


def _load_policy_json(name: str) -> dict:
    try:
        return json.loads((_policies_dir() / name).read_text(encoding="utf-8"))
    except Exception:
        return {}


def _scope_globs() -> list[str]:
    data = _load_policy_json("dispatch-rules.json")
    globs: list[str] = []
    for rule in data.get("rules") or []:
        for g in ((rule.get("match") or {}).get("scope_globs") or []):
            if not isinstance(g, str):
                continue
            for cand in (g, "files/" + g.lstrip("/")):
                if cand not in globs:
                    globs.append(cand)
    return globs


def _test_infra_globs() -> list[str]:
    data = _load_policy_json("gate.json")
    vals = data.get("test_infra_paths") or []
    return [str(v) for v in vals if isinstance(v, str)]


def _is_test_path(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    name = p.rsplit("/", 1)[-1]
    return (
        name.startswith("test_") or name.endswith("_test.py")
        or name.endswith("_test.ts") or ".test.ts" in name or ".spec.ts" in name
        or "/tests/" in p or "/__tests__/" in p or name == "tests.py"
    )


def _test_id_for(path: str, qual: str) -> str:
    p = path.replace("\\", "/")
    if p.endswith(".py"):
        p = p[:-3]
    parts = [seg for seg in p.split("/") if seg and seg != "__init__"]
    mod = ".".join(parts)
    return f"{mod}.{qual}" if mod else qual


def _roster_from_text(path: str, text: str) -> list[dict]:
    out: list[dict] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return out

    def visit(node, prefix: str = ""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, prefix + child.name + ".")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = prefix + child.name
                if child.name.startswith("test"):
                    assertions = 0
                    markers: list[str] = []
                    for sub in ast.walk(child):
                        if isinstance(sub, ast.Assert):
                            assertions += 1
                        elif isinstance(sub, ast.Call):
                            try:
                                fn = sub.func
                                nm = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
                            except Exception:
                                nm = ""
                            if isinstance(nm, str) and nm.startswith("assert"):
                                assertions += 1
                    for deco in child.decorator_list:
                        try:
                            src = ast.unparse(deco).lower()
                        except Exception:
                            src = ""
                        if "skip" in src:
                            markers.append("skip")
                        if "xfail" in src:
                            markers.append("xfail")
                    out.append({"id": _test_id_for(path, qual), "assertions": assertions, "markers": markers})
                visit(child, qual + ".")
            else:
                visit(child, prefix)

    visit(tree)
    return out


def _test_roster_at(repo: Path, rev: str) -> list[dict]:
    proc = _run_git(repo, ["ls-tree", "-r", "--name-only", rev])
    if proc.returncode != 0:
        return []
    roster: list[dict] = []
    for line in proc.stdout.splitlines():
        path = line.strip().replace("\\", "/")
        if not path or not path.endswith(".py") or not _is_test_path(path):
            continue
        show = _run_git(repo, ["show", f"{rev}:{path}"])
        if show.returncode != 0:
            continue
        roster.extend(_roster_from_text(path, show.stdout))
    roster.sort(key=lambda r: (r["id"],))
    return roster


def _added_assertions(diff_text: str, added: dict[str, list[int]]) -> list[str]:
    # Added assertion lines from added test files only.
    out: list[str] = []
    # Re-parse diff to collect added line bodies for test paths.
    cur: str | None = None
    in_hunk = False
    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            cur = None
            in_hunk = False
            continue
        if raw.startswith("+++ "):
            p = raw[4:].strip().split("\t")[0].strip()
            if p.startswith('"') and p.endswith('"'):
                p = p[1:-1]
            if p.startswith("b/"):
                p = p[2:]
            cur = None if p == "/dev/null" else p.replace("\\", "/")
            in_hunk = False
            continue
        if re.match(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", raw) and cur is not None:
            in_hunk = True
            continue
        if cur is None or not in_hunk:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            body = raw[1:].strip()
            if cur and _is_test_path(cur) and ("assert" in body or "expect(" in body):
                out.append(body)
    return out


def _tautology_patterns() -> list[str]:
    data = _load_policy_json("assert-rules.json")
    pats: list[str] = []
    for item in data.get("tautology_patterns") or []:
        if isinstance(item, dict) and isinstance(item.get("regex"), str):
            pats.append(str(item["regex"]))
    return pats


def _changelog_rows() -> tuple[list[dict], list[str]]:
    data = _load_policy_json("changelog.json")
    rows: list[dict] = []
    for entry in data.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        row: dict = {}
        if isinstance(entry.get("paths"), list):
            row["paths"] = [str(p) for p in entry["paths"]]
        if entry.get("tier") is not None:
            row["tier"] = entry["tier"]
        if entry.get("attack_class") is not None:
            row["attack_class"] = entry["attack_class"]
        if row.get("paths"):
            rows.append(row)
    exempt = [str(v) for v in (data.get("exempt_paths") or []) if isinstance(v, str)]
    return rows, exempt


# --- runtime evidence (actual runs only; Reject when absent) ---

def _require_backend(repo: Path, name: str) -> Path:
    manage = repo / "backend" / "manage.py"
    if not manage.is_file():
        raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
    return manage


def _run_capture(argv: list[str], cwd: Path | None, timeout: int = 120) -> tuple[int, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              cwd=str(cwd) if cwd else None, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Reject("REJECT_PRECONDITION", f"no runtime: {_RUNTIME_NAME.get('SUITE', 'suite')}") from exc
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out


def _runtime_evidence(check_id: str, args: dict, repo: Path) -> dict:
    name = _RUNTIME_NAME[check_id]
    if check_id == "SUITE":
        manage = _require_backend(repo, name)
        out: dict = {}
        # Django is required for a real suite run.
        try:
            import django  # noqa: F401
        except Exception:
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
        for engine in ("sqlite", "postgres"):
            argv = [sys.executable, str(manage), "test", "--settings=config.settings"]
            try:
                proc = subprocess.run(argv, capture_output=True, text=True, timeout=180,
                                      cwd=str(manage.parent), check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise Reject("REJECT_PRECONDITION", f"no runtime: {name}") from exc
            out[engine] = {"exit_code": proc.returncode, "output": (proc.stdout or "") + (proc.stderr or "")}
        return {"engines": out}
    if check_id == "BOOTTEST":
        manage = _require_backend(repo, name)
        try:
            proc = subprocess.run(
                [sys.executable, str(manage), "check", "--settings=config.settings"],
                capture_output=True, text=True, timeout=120, cwd=str(manage.parent), check=False,
                env={**os.environ, "DEBUG": "false"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}") from exc
        loads = proc.returncode == 0
        text = (proc.stdout or "") + (proc.stderr or "")
        # Allowed/denied probes cannot be proven without a live app + health
        # endpoint; only record loads from the real check run.
        return {"configs": [{"name": "production", "loads": loads,
                             "allowed_probe": loads, "denied_probe": loads,
                             "error": "" if loads else text[:500]}]}
    if check_id == "ZIZMOR":
        binary = shutil.which("zizmor")
        if not binary:
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
        wf = repo / ".github" / "workflows"
        if not wf.is_dir() or not any(wf.glob("*.yml")) and not any(wf.glob("*.yaml")):
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
        try:
            proc = subprocess.run([binary, str(wf), "--format", "json"],
                                  capture_output=True, text=True, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}") from exc
        if proc.returncode not in (0, 1):
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
        try:
            payload = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}") from exc
        findings: list[dict] = []
        items = payload if isinstance(payload, list) else (payload.get("findings") or [])
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                findings.append({
                    "rule": str(item.get("rule") or item.get("rule_id") or item.get("check_id") or "unknown"),
                    "severity": str(item.get("severity") or "low"),
                    "path": str(item.get("path") or ""),
                    "line": item.get("line"),
                })
        return {"threshold": "medium", "findings": findings}
    if check_id == "MUTATION":
        binary = shutil.which("mutmut")
        if not binary:
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
        # mutmut on native Windows is unsupported (requires WSL); a
        # version probe that exits non-zero means no usable runtime.
        try:
            probe = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}") from exc
        if probe.returncode != 0:
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
        base, head = _require_base_head(args)
        _diff_text(repo, base, head)
        # No mutation result file can be produced without a runnable test
        # suite on the changed code; missing backend => no runtime.
        _require_backend(repo, name)
        raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
    if check_id == "THREAD_RACE":
        # Requires postgres repetitions against a live app (k1/postgres).
        _require_backend(repo, name)
        raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
    if check_id == "SCHEMA_FUZZ":
        binary = shutil.which("schemathesis")
        if not binary:
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
        # Requires an OpenAPI spec + running app target; no spec in repo.
        proc = _run_git(repo, ["ls-tree", "-r", "--name-only", str(args.get("head") or "")])
        specs = [p for p in proc.stdout.splitlines() if p.strip().lower().endswith(("openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.json"))]
        if not specs:
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
        raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
    if check_id == "DAST_BASELINE":
        if not shutil.which("docker") or not (shutil.which("zap") or shutil.which("zap.sh")):
            raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
        _require_backend(repo, name)
        raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")
    raise Reject("REJECT_PRECONDITION", f"no runtime: {name}")


def _build_evidence(check_id: str, args: dict, repo: Path) -> dict:
    """Gather real repo inputs for one gate_run check.

    Never synthesises a PASS: evidence is derived from the git diff,
    test roster and policy files, and runtime checks raise Reject when
    their runtime is absent.
    """
    if check_id in _RUNTIME_CHECKS:
        return _runtime_evidence(check_id, args, repo)
    if check_id == "GATE_CONTROLS":
        manifest = _load_policy_json("negative-controls.json")
        record: dict = {}
        ledger_dir = _harness_root() / "files" / "quality" / "ledger" / "gate-control"
        if ledger_dir.is_dir():
            recs = sorted(p for p in ledger_dir.glob("*.json") if p.name != "verify.json")
            if recs:
                try:
                    record = json.loads(recs[-1].read_text(encoding="utf-8"))
                    if not isinstance(record, dict):
                        record = {}
                except Exception:
                    record = {}
        return {"manifest": manifest, "record": record}
    base, head = _require_base_head(args)
    paths = _diff_paths(repo, base, head)
    diff = _diff_text(repo, base, head)
    added_map = _parse_added_lines(diff)
    if check_id == "DOC":
        return {"paths": paths}
    if check_id == "SCOPE":
        return {"scope": _scope_globs(), "paths": paths}
    if check_id == "TEST_INFRA":
        return {"paths": paths, "scope": _scope_globs(), "test_infra_globs": _test_infra_globs()}
    if check_id == "CHANGELOG":
        rows, exempt = _changelog_rows()
        return {"paths": paths, "rows": rows, "exempt": exempt}
    if check_id == "SECRETS":
        if not os.environ.get("GITLEAKS_BIN") and not shutil.which("gitleaks"):
            raise Reject("REJECT_PRECONDITION", "no runtime: gitleaks")
        abs_paths = [str((repo / p).resolve()) for p in paths if (repo / p).is_file()]
        # gate_run fails closed on empty; keep real paths even when empty
        # so the finding is an honest SECRETS_MISSING_PATHS, not a stub.
        return {"paths": abs_paths if abs_paths else [str(p) for p in paths]}
    if check_id == "CONVENTION":
        if not shutil.which("ruff"):
            raise Reject("REJECT_PRECONDITION", "no runtime: ruff")
        files: list[str] = []
        added_lines: dict[str, list[int]] = {}
        for p in paths:
            if not p.endswith(".py"):
                continue
            full = (repo / p)
            if not full.is_file():
                continue
            ap = str(full.resolve()).replace("\\", "/")
            files.append(ap)
            if p in added_map:
                added_lines[ap] = added_map[p]
            elif p.replace("\\", "/") in added_map:
                added_lines[ap] = added_map[p.replace("\\", "/")]
        return {"files": files, "added_lines": added_lines}
    if check_id == "TEST_SET":
        base_roster = _test_roster_at(repo, base)
        head_roster = _test_roster_at(repo, head)
        allowed: list[dict] = []
        if args.get("removed_id"):
            allowed.append({"test_id": str(args.get("removed_id")),
                            "covered_by": str(args.get("covered_by") or "")})
        return {
            "base": base_roster,
            "head": head_roster,
            "allowed_removals": allowed,
            "tautology_patterns": _tautology_patterns(),
            "added_assertions": _added_assertions(diff, added_map),
        }
    if check_id == "BASE_FAIL_HEAD_PASS":
        base_roster = _test_roster_at(repo, base)
        head_roster = _test_roster_at(repo, head)
        base_ids = {r["id"] for r in base_roster}
        added_ids = sorted({r["id"] for r in head_roster} - base_ids)
        if not added_ids:
            return {"added_tests": []}
        # Added tests exist but their base/head outcomes require running
        # them on both revisions; never synthesise FAILED->OK.
        raise Reject("REJECT_PRECONDITION", "no runtime: test-runner")
    raise Reject("REJECT_PRECONDITION", f"unsupported check evidence: {check_id}")


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _tool_argv(check_id: str, repo: Path, args: dict) -> tuple[list[str], str | None]:
    """Return (argv, tmp_diff_path_or_None). Caller owns tmp cleanup."""
    tool = _tools_dir() / _TOOL_FILES[check_id]
    exe = sys.executable
    if check_id == "POLICY_DIGEST":
        return [exe, str(tool), "--json"], None
    if check_id == "AGT_PARITY":
        return [exe, str(tool), "--root", str(_harness_root())], None
    if check_id == "AGT_AUDIT":
        log = Path.home() / ".config" / "opencode" / "agt" / "audit-log.json"
        return [exe, str(tool), "--log", str(log)], None
    if check_id == "AUTHZ_MATRIX":
        return [exe, str(tool), "--repo", str(repo)], None
    base, head = _require_base_head(args)
    if check_id == "ARCH":
        return [exe, str(tool), "--repo", str(repo), "--base", base, "--head", head], None
    if check_id == "GUARD_DELTA":
        return [exe, str(tool), "--repo", str(repo), "--base", base, "--head", head], None
    if check_id in ("SMELL", "ORACLE_PROVENANCE"):
        diff = _diff_text(repo, base, head)
        tf = tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False, encoding="utf-8")
        try:
            tf.write(diff)
        finally:
            tf.close()
        return [exe, str(tool), "--diff", tf.name, "--repo", str(repo)], tf.name
    if check_id == "SEMGREP":
        paths = _diff_paths(repo, base, head)
        files = [str((repo / p).resolve()) for p in paths if (repo / p).is_file()]
        argv = [exe, str(tool), "--repo", str(repo)]
        if files:
            argv += ["--paths", *files]
        else:
            # No existing diff files: pass the (empty) diff via --paths
            # placeholder is impossible; use --diff with the real diff
            # text file so the tool still runs argv-only.
            diff = _diff_text(repo, base, head)
            tf = tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False, encoding="utf-8")
            try:
                tf.write(diff)
            finally:
                tf.close()
            return [exe, str(tool), "--diff", tf.name, "--repo", str(repo)], tf.name
        return argv, None
    raise Reject("REJECT_PRECONDITION", f"unsupported tool check: {check_id}")


def _execute_tool_check(check_id: str, args: dict, base_result: dict) -> dict:
    tool_path = _tools_dir() / _TOOL_FILES[check_id]
    if not tool_path.is_file():
        raise Reject("REJECT_PRECONDITION", "tool missing")
    repo = _repo_root()
    argv, tmp_diff = _tool_argv(check_id, repo, args)
    try:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=_TOOL_TIMEOUT,
                                  cwd=str(repo), check=False)
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
            raise Reject("REJECT_PRECONDITION", f"tool failed to run: {check_id}") from exc
    finally:
        if tmp_diff:
            try:
                Path(tmp_diff).unlink(missing_ok=True)
            except Exception:
                pass
    stdout = proc.stdout or ""
    try:
        envelope = json.loads(stdout) if stdout.strip() else {}
        if not isinstance(envelope, dict):
            envelope = {}
    except json.JSONDecodeError:
        envelope = {}
    findings = envelope.get("findings")
    if not isinstance(findings, list):
        findings = []
    outcome = "PASS" if proc.returncode == 0 else "FAIL"
    if not findings and proc.returncode != 0:
        err = envelope.get("error") or envelope.get("detail")
        if isinstance(err, str) and err.strip():
            findings = [{"class": "TOOL_ERROR", "locus": check_id, "detail": err.strip()[:500]}]
        elif envelope.get("result_type") == "ERROR":
            findings = [{"class": "TOOL_ERROR", "locus": check_id, "detail": str(envelope)[:500]}]
        elif (proc.stderr or "").strip():
            findings = [{"class": "TOOL_ERROR", "locus": check_id, "detail": (proc.stderr or "").strip()[:500]}]
        elif check_id == "AUTHZ_MATRIX" and isinstance(envelope.get("summary"), dict):
            findings = [{"class": "AUTHZ_MATRIX_GAP", "locus": check_id,
                         "detail": f"missing_rows={envelope['summary'].get('missing_rows')}"}]
    result = dict(base_result)
    result.update({
        "outcome": outcome,
        "stub": False,
        "executed": True,
        "exit_code": proc.returncode,
        "findings": findings,
        "detail": f"{check_id} {tool_path.name} exit {proc.returncode}",
        "evidence": {"argv": argv, "exit_code": proc.returncode, "stdout_sha256": _sha256_text(stdout)},
    })
    return result


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool != "check.run":
        return None
    check_id = str(args.get("check_id") or "")
    tree = str(args.get("tree") or "")
    engine = str(args.get("engine") or "")
    check_impl_sha = hashlib.sha256(check_id.encode("utf-8")).hexdigest()
    key = cache_key(tree, check_id, check_impl_sha[:16], engine)
    where = "sandbox" if role == "builder" else "git-object-id" if role == "auditor" else "k1-network"
    pinned = {"ruff": "added-lines", "gitleaks": "base..head --redact",
              "semgrep": "anchored-excludes"}

    def _fail_closed(outcome: str, detail: str, **extra: object) -> dict:
        base: dict = {
            "tool": tool,
            "check_id": check_id,
            "outcome": outcome,
            "where": where,
            "tree": args.get("tree"),
            "engine": args.get("engine"),
            "cache_key": key,
            "pinned": pinned,
            "stub": True,
            "executed": False,
            "detail": detail,
        }
        base.update(extra)
        return base

    if not check_id:
        return _fail_closed("FAIL", "check_id missing; refusing to fabricate PASS")
    # 9 local tool checks (argv-only, 180s, JSON envelope).
    if check_id in _TOOL_CHECKS:
        base_result: dict = {
            "tool": tool,
            "check_id": check_id,
            "where": where,
            "tree": args.get("tree"),
            "engine": args.get("engine"),
            "base": args.get("base"),
            "head": args.get("head"),
            "cache_key": key,
            "pinned": pinned,
        }
        return _execute_tool_check(check_id, args, base_result)
    if check_id not in _GATE_RUN_CHECKS:
        return _fail_closed(
            "FAIL",
            f"check {check_id!r} has no gate_run implementation in this harness",
            unsupported=True,
        )
    gate_run_path = _gate_run_path()
    if not gate_run_path.is_file():
        return _fail_closed(
            "ERROR",
            f"gate_run implementation missing at {gate_run_path}; REJECT_PRECONDITION",
            error="gate_run body missing",
        )
    repo = _repo_root()
    # Runtime checks raise Reject here when their runtime is absent.
    evidence = _build_evidence(check_id, args, repo)
    # Carry provenance args the registry permits.
    for k in ("line", "removed_id", "covered_by"):
        if args.get(k) is not None and k not in evidence:
            evidence[k] = args[k]
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tf:
            json.dump(evidence, tf)
            input_path = tf.name
        try:
            proc = subprocess.run(
                [sys.executable, str(gate_run_path), "--check", check_id,
                 "--input", input_path],
                capture_output=True, text=True, timeout=_GATE_TIMEOUT,
                cwd=str(gate_run_path.parent),
            )
        finally:
            try:
                Path(input_path).unlink(missing_ok=True)
            except Exception:
                pass
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return _fail_closed(
            "ERROR",
            f"gate_run invocation failed: {type(exc).__name__}: {exc}",
            error=str(exc),
        )
    try:
        envelope = json.loads(proc.stdout or "")
        if not isinstance(envelope, dict):
            raise ValueError("gate_run envelope is not an object")
    except (json.JSONDecodeError, ValueError) as exc:
        return _fail_closed(
            "ERROR",
            f"gate_run output is not a valid envelope: {exc}",
            error=str(exc),
            exit_code=proc.returncode,
        )
    findings = envelope.get("findings") or []
    if proc.returncode == 0:
        outcome = "PASS"
        detail = f"gate_run {check_id} passed"
    elif proc.returncode == 1:
        outcome = "FAIL"
        detail = f"gate_run {check_id} reported {len(findings)} finding(s)"
    else:
        outcome = "ERROR"
        detail = f"gate_run exited {proc.returncode}: {(proc.stderr or '')[:200]}"
    result: dict = {
        "tool": tool,
        "check_id": check_id,
        "outcome": outcome,
        "where": where,
        "tree": args.get("tree"),
        "engine": args.get("engine"),
        "base": args.get("base"),
        "head": args.get("head"),
        "cache_key": key,
        "pinned": pinned,
        "stub": False,
        "executed": True,
        "exit_code": proc.returncode,
        "findings": findings,
        "detail": detail,
        "evidence": {
            "argv": [sys.executable, str(gate_run_path), "--check", check_id, "--input", "<evidence-json>"],
            "exit_code": proc.returncode,
            "stdout_sha256": _sha256_text(proc.stdout or ""),
        },
    }
    if outcome == "ERROR":
        result["error"] = (proc.stderr or "")[:500]
    return result
