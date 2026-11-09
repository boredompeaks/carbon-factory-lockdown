"""Ledger tool execution. 6B-5 + P2 durable store + P4 real extras.

``ledger.append`` performs a real durable write via ``ledger.store``
(atomic, fsync'd, hash-chained, schema-validated, role-checked) and
returns the on-disk path plus the new ``record_hash`` and the
``prev_hash`` it chained from. Every result carries ``executed: True``.

P4 makes the five P2 "executed:true but stub" handlers real (never
``executed:true`` + a fabricated result; fail-closed cases raise
``Reject`` with the canonical code):

- ``scratch.write`` -> real utf-8 file under
  ``<scratch>/<capability_id>/<path>`` (hacker -> ``hacker-scratch``,
  auditor -> ``audit-scratch`` to match ``files/auditor.md`` and the deny
  globs), size/extension caps, traversal + deny validated; returns
  ``{path, bytes, sha256, executed}`` where ``path`` is the repo-relative
  destination.
- ``acceptance.materialize`` -> reads a ``repro-spec/1`` JSON (``spec``
  resolved like ``repro.run``: harness root / ``files/`` /
  ``files/drain`` with ``.json`` appended) and writes a deterministic
  test file at ``path``; same spec -> same bytes; returns
  ``{path, content_sha256, deterministic, executed}``.
- ``drain.validate`` -> real ``files/tools/validatedrain.py --drain-dir
  <drain_dir> --repo <repo> --json`` subprocess; missing drain dir ->
  ``REJECT_PRECONDITION``; maps ``{result, records_checked_by_stage,
  problems}`` to ``{valid: result=="PASS", executed, evidence{...}}``.
- ``evidence.hash`` -> ``git cat-file blob <rev>:<path>`` then sha256 of
  the **bytes** (never of the ``"rev:path"`` string); denied path ->
  ``REJECT_PATH``; git failure -> ``REJECT_PRECONDITION``; returns
  ``{sha256, bytes, executed}``.
- ``harness.verify`` -> ``scripts/check_harness_config.py``
  (``harness_config``) and ``scripts/policy_manifest.py --verify --json``
  (``policy_manifest``); ``verified`` is exactly ``exit==0`` (never
  fabricated); returns ``{verified, exit_code, problems[], executed}``.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from ..core.validate import Reject, is_traversal_or_absolute
from ..git.deny import is_denied_path
from .store import append as store_append

# handlers.py -> ledger -> mcp -> tools -> files -> harness root
_HARNESS_ROOT = Path(__file__).resolve().parents[4]
_FILES_ROOT = Path(__file__).resolve().parents[3]
_TOOLS_DIR = Path(__file__).resolve().parents[2]

_SCRATCH_DIR = {"hacker": "hacker-scratch", "auditor": "audit-scratch"}
_SCRATCH_ALLOWED_EXTENSIONS = frozenset({"py", "json", "md", "txt"})
_SCRATCH_MAX_BYTES = 262144

_DEFAULT_DRAIN_DIR = _FILES_ROOT / "drain" / "refund-cluster"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes((value or "").encode("utf-8"))


def _harness_root() -> Path:
    return _HARNESS_ROOT


def _validatedrain_path() -> Path:
    return _TOOLS_DIR / "validatedrain.py"


def _check_harness_path() -> Path:
    return _HARNESS_ROOT / "scripts" / "check_harness_config.py"


def _policy_manifest_path() -> Path:
    return _HARNESS_ROOT / "scripts" / "policy_manifest.py"


def _git_exe(server) -> str:
    cfg = getattr(server, "config", None) if server is not None else None
    if cfg is not None:
        try:
            exe = cfg.resolve("git")
            if isinstance(exe, str) and exe and not exe.lower().endswith((".cmd", ".bat", ".ps1")):
                return exe
        except Exception:
            pass
    found = shutil.which("git")
    if found and not found.lower().endswith((".cmd", ".bat", ".ps1")):
        return found
    return "git"


# ---------------------------------------------------------------------------
# scratch.write
# ---------------------------------------------------------------------------


def _execute_scratch_write(role: str, args: dict) -> dict:
    namespace = args.get("namespace")
    capability_id = args.get("capability_id")
    rel_path = args.get("path")
    content = args.get("content")
    extension = args.get("extension")

    if not isinstance(namespace, str) or namespace not in _SCRATCH_DIR:
        raise Reject("REJECT_ARG", f"namespace must be one of {sorted(_SCRATCH_DIR)}: {namespace!r}")
    if namespace != role:
        raise Reject("REJECT_ROLE", f"namespace {namespace!r} != caller role {role!r}")
    if not isinstance(capability_id, str) or not re.fullmatch(r"[a-z0-9-]{1,64}", capability_id):
        raise Reject("REJECT_ARG", f"capability_id must match ^[a-z0-9-]{{1,64}}$: {capability_id!r}")
    if not isinstance(rel_path, str) or not rel_path:
        raise Reject("REJECT_ARG", "path must be a non-empty string")
    if not isinstance(content, str):
        raise Reject("REJECT_ARG", "content must be a string")
    if is_traversal_or_absolute("scratch.write", "path", rel_path):
        raise Reject("REJECT_PATH", f"path: non-normalized or out-of-tree path: {rel_path!r}")
    if "ledger" in rel_path.lower():
        raise Reject("REJECT_PATH", f"path denied for scratch.write: {rel_path!r}")
    if is_denied_path(rel_path):
        raise Reject("REJECT_PATH", f"path denied for scratch.write: {rel_path!r}")
    if namespace == "hacker" and "audit-scratch" in rel_path:
        raise Reject("REJECT_PATH", "hacker scratch may not touch audit-scratch")
    if namespace == "auditor" and "hacker-scratch" in rel_path:
        raise Reject("REJECT_PATH", "auditor scratch may not touch hacker-scratch")

    suffix = Path(rel_path).suffix.lower().lstrip(".")
    if suffix not in _SCRATCH_ALLOWED_EXTENSIONS:
        raise Reject(
            "REJECT_ARG",
            f"extension must be one of {sorted(_SCRATCH_ALLOWED_EXTENSIONS)}: {rel_path!r}",
        )
    if extension is not None:
        if not isinstance(extension, str) or extension not in _SCRATCH_ALLOWED_EXTENSIONS:
            raise Reject("REJECT_ARG", f"extension must be one of {sorted(_SCRATCH_ALLOWED_EXTENSIONS)}: {extension!r}")
        if extension != suffix:
            raise Reject(
                "REJECT_ARG",
                f"extension {extension!r} does not match path extension {suffix!r}",
            )

    data = content.encode("utf-8")
    if len(data) > _SCRATCH_MAX_BYTES:
        raise Reject("REJECT_ARG", f"content exceeds {_SCRATCH_MAX_BYTES} bytes")

    scratch_root = (_harness_root() / _SCRATCH_DIR[namespace]).resolve()
    dest = (scratch_root / capability_id / rel_path).resolve()
    try:
        dest.relative_to(scratch_root)
    except ValueError:
        raise Reject("REJECT_PATH", f"path escapes scratch namespace: {rel_path!r}") from None
    try:
        dest.relative_to(_harness_root().resolve())
    except ValueError:
        raise Reject("REJECT_PATH", f"path escapes the harness root: {rel_path!r}") from None
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    except OSError as exc:
        raise Reject("REJECT_PRECONDITION", f"scratch.write failed: {exc}") from exc
    sha = _sha256_bytes(data)
    dest_rel = dest.relative_to(_harness_root().resolve()).as_posix()
    return {
        "tool": "scratch.write",
        "namespace": namespace,
        "capability_id": capability_id,
        "path": dest_rel,
        "bytes": len(data),
        "sha256": sha,
        "executed": True,
    }


# ---------------------------------------------------------------------------
# acceptance.materialize
# ---------------------------------------------------------------------------


def _load_repro_spec(spec_name: str) -> dict:
    if not isinstance(spec_name, str) or not spec_name:
        raise Reject("REJECT_ARG", "spec must be a non-empty string")
    if is_traversal_or_absolute("acceptance.materialize", "spec", spec_name):
        raise Reject("REJECT_PATH", f"spec: non-normalized or out-of-tree path: {spec_name!r}")
    harness_root = _harness_root()
    candidates: list[Path] = []
    for base in (harness_root, harness_root / "files", harness_root / "files" / "drain"):
        candidates.append(base / spec_name)
        if not spec_name.endswith(".json"):
            candidates.append(base / (spec_name + ".json"))
    found: Path | None = None
    seen: set[str] = set()
    for cand in candidates:
        key = str(cand)
        if key in seen:
            continue
        seen.add(key)
        try:
            resolved = cand.resolve()
        except (OSError, RuntimeError):
            continue
        try:
            resolved.relative_to(harness_root.resolve())
        except ValueError:
            continue
        if resolved.is_file():
            found = resolved
            break
    if found is None:
        raise Reject("REJECT_PRECONDITION", f"repro spec not found: {spec_name!r}")
    try:
        data = json.loads(found.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Reject("REJECT_PRECONDITION", f"repro spec unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise Reject("REJECT_PRECONDITION", f"repro spec is not an object: {spec_name!r}")
    if data.get("schema") not in (None, "repro-spec/1"):
        raise Reject("REJECT_PRECONDITION", f"repro spec schema is not repro-spec/1: {spec_name!r}")
    command = data.get("command")
    if not isinstance(command, list) or not command:
        raise Reject("REJECT_PRECONDITION", f"repro spec has no command[]: {spec_name!r}")
    if not all(isinstance(item, str) and item for item in command):
        raise Reject("REJECT_PRECONDITION", f"repro spec command[] must be non-empty strings: {spec_name!r}")
    return data


def _render_materialized(spec_name: str, spec: dict) -> bytes:
    ref = str(spec.get("ref") or "")
    fixture_ref = str(spec.get("fixture_ref") or "")
    repro_id = str(spec.get("repro_id") or "")
    kind = str(spec.get("kind") or "")
    engine = str(spec.get("engine") or "")
    command = spec.get("command") or []
    canonical_spec = json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    lines = [
        "# Deterministic materialization of repro-spec/1",
        f"# repro_id: {repro_id}",
        f"# kind: {kind}",
        f"# engine: {engine}",
        f"# ref: {ref}",
        f"# fixture_ref: {fixture_ref}",
        f"# command: {json.dumps(list(command), separators=(',', ':'), ensure_ascii=False)}",
        f"REPRO_SPEC = {canonical_spec}",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _execute_acceptance_materialize(role: str, args: dict) -> dict:
    spec_name = args.get("spec")
    rel_path = args.get("path")
    if not isinstance(spec_name, str) or not spec_name:
        raise Reject("REJECT_ARG", "spec must be a non-empty string")
    if not isinstance(rel_path, str) or not rel_path:
        raise Reject("REJECT_ARG", "path must be a non-empty string")
    if is_traversal_or_absolute("acceptance.materialize", "path", rel_path):
        raise Reject("REJECT_PATH", f"path: non-normalized or out-of-tree path: {rel_path!r}")
    if rel_path.lower().startswith("quality/ledger/") or rel_path.lower() == "quality/ledger":
        raise Reject("REJECT_PATH", f"ledger path denied for acceptance.materialize: {rel_path!r}")
    if is_denied_path(rel_path):
        raise Reject("REJECT_PATH", f"path denied for acceptance.materialize: {rel_path!r}")
    spec = _load_repro_spec(spec_name)
    data = _render_materialized(spec_name, spec)
    dest = (_harness_root() / rel_path).resolve()
    try:
        dest.relative_to(_harness_root().resolve())
    except ValueError:
        raise Reject("REJECT_PATH", f"path escapes the harness root: {rel_path!r}") from None
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    except OSError as exc:
        raise Reject("REJECT_PRECONDITION", f"acceptance.materialize failed: {exc}") from exc
    sha = _sha256_bytes(data)
    return {
        "tool": "acceptance.materialize",
        "spec": spec_name,
        "path": rel_path,
        "content_sha256": sha,
        "deterministic": True,
        "executed": True,
    }


# ---------------------------------------------------------------------------
# drain.validate
# ---------------------------------------------------------------------------


def _execute_drain_validate(server, role: str, args: dict) -> dict:
    stage = args.get("stage")
    if not isinstance(stage, str) or stage not in ("R1", "R2", "R3", "R4", "R5"):
        raise Reject("REJECT_ARG", f"stage must be one of R1-R5: {stage!r}")
    mode = args.get("mode", "verify")
    if mode != "verify":
        raise Reject("REJECT_ARG", f"mode must be 'verify': {mode!r}")
    raw_drain = args.get("drain_dir") or args.get("drainDir") or args.get("drain") or str(_DEFAULT_DRAIN_DIR)
    raw_repo = args.get("repo") or str(_harness_root())
    if not isinstance(raw_drain, str) or not raw_drain:
        raise Reject("REJECT_ARG", "drain_dir must be a non-empty string")
    if not isinstance(raw_repo, str) or not raw_repo:
        raise Reject("REJECT_ARG", "repo must be a non-empty string")
    drain_dir = raw_drain if Path(raw_drain).is_absolute() else str((_harness_root() / raw_drain).resolve())
    repo = raw_repo if Path(raw_repo).is_absolute() else str((_harness_root() / raw_repo).resolve())
    drain_path = Path(drain_dir)
    if not drain_path.is_dir():
        raise Reject("REJECT_PRECONDITION", f"drain directory not found: {drain_dir}")
    script = _validatedrain_path()
    if not script.is_file():
        raise Reject("REJECT_PRECONDITION", "tool missing: validatedrain.py")
    argv = [sys.executable, str(script), "--drain-dir", str(drain_dir), "--repo", str(repo), "--json"]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            cwd=str(_harness_root()),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Reject("REJECT_PRECONDITION", f"drain.validate failed to run: {exc}") from exc
    stdout = proc.stdout or ""
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError as exc:
        tail = ((proc.stderr or "").strip() or stdout.strip())[:500]
        raise Reject("REJECT_PRECONDITION", f"drain.validate output unparseable: {tail}") from exc
    if not isinstance(envelope, dict):
        raise Reject("REJECT_PRECONDITION", "drain.validate output is not an object")
    result = envelope.get("result")
    problems = envelope.get("problems")
    if not isinstance(problems, list):
        problems = []
    by_stage = envelope.get("records_checked_by_stage")
    if not isinstance(by_stage, dict):
        by_stage = {}
    records_checked = envelope.get("records_checked")
    if not isinstance(records_checked, int) or isinstance(records_checked, bool):
        records_checked = sum(v for v in by_stage.values() if isinstance(v, int) and not isinstance(v, bool))
    evidence = {
        "argv": argv,
        "exit_code": proc.returncode,
        "stdout_sha256": _sha256_text(stdout),
    }
    return {
        "tool": "drain.validate",
        "stage": stage,
        "mode": mode,
        "record_hash": args.get("record_hash"),
        "drain_dir": str(drain_dir),
        "valid": result == "PASS",
        "result": result,
        "records_checked": records_checked,
        "records_checked_by_stage": by_stage,
        "problems": problems,
        "executed": True,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# evidence.hash
# ---------------------------------------------------------------------------


def _execute_evidence_hash(server, role: str, args: dict) -> dict:
    rev = args.get("rev")
    rel_path = args.get("path")
    if not isinstance(rev, str) or not re.fullmatch(r"[a-f0-9]{40}", rev):
        raise Reject("REJECT_ARG", f"rev must be 40-hex: {rev!r}")
    if not isinstance(rel_path, str) or not rel_path:
        raise Reject("REJECT_ARG", "path must be a non-empty string")
    if is_traversal_or_absolute("evidence.hash", "path", rel_path):
        raise Reject("REJECT_PATH", f"path: non-normalized or out-of-tree path: {rel_path!r}")
    if is_denied_path(rel_path):
        raise Reject("REJECT_PATH", f"path denied for evidence.hash: {rel_path!r}")
    exe = _git_exe(server)
    argv = [exe, "-C", str(_harness_root()), "cat-file", "blob", f"{rev}:{rel_path}"]
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
            f"git cat-file blob {rev}:{rel_path} failed (exit {proc.returncode}): {tail}",
        )
    blob = proc.stdout or b""
    sha = _sha256_bytes(blob)
    evidence = {"argv": argv, "exit_code": 0, "stdout_sha256": sha}
    return {
        "tool": "evidence.hash",
        "rev": rev,
        "path": rel_path,
        "sha256": sha,
        "bytes": len(blob),
        "executed": True,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# harness.verify
# ---------------------------------------------------------------------------


def _parse_harness_config_problems(stdout: str) -> list[str]:
    lines = (stdout or "").splitlines()
    problems: list[str] = []
    in_result = False
    for line in lines:
        if line.startswith("RESULT:"):
            in_result = True
            continue
        if in_result and line.strip().startswith("- "):
            problems.append(line.strip()[2:].strip())
    if problems:
        return problems
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("FAIL "):
            detail = stripped[4:].strip()
            if detail and detail not in problems:
                problems.append(detail)
    return problems


def _execute_harness_verify(server, role: str, args: dict) -> dict:
    scope = args.get("scope")
    if scope not in ("harness_config", "policy_manifest"):
        raise Reject("REJECT_ARG", f"scope must be harness_config or policy_manifest: {scope!r}")
    if scope == "harness_config":
        script = _check_harness_path()
        if not script.is_file():
            raise Reject("REJECT_PRECONDITION", "tool missing: check_harness_config.py")
        argv = [sys.executable, str(script)]
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=120,
                cwd=str(_harness_root()),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Reject("REJECT_PRECONDITION", "harness.verify failed to run harness_config") from exc
        problems = _parse_harness_config_problems(proc.stdout or "")
        evidence = {
            "argv": argv,
            "exit_code": proc.returncode,
            "stdout_sha256": _sha256_text(proc.stdout or ""),
        }
        return {
            "tool": "harness.verify",
            "scope": scope,
            "verified": bool(proc.returncode == 0),
            "exit_code": proc.returncode,
            "result": "PASS" if proc.returncode == 0 else "FAIL",
            "problems": problems,
            "executed": True,
            "evidence": evidence,
        }
    script = _policy_manifest_path()
    if not script.is_file():
        raise Reject("REJECT_PRECONDITION", "tool missing: policy_manifest.py")
    argv = [sys.executable, str(script), "--verify", "--json"]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            cwd=str(_harness_root()),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Reject("REJECT_PRECONDITION", "harness.verify failed to run policy_manifest") from exc
    stdout = proc.stdout or ""
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError as exc:
        tail = ((proc.stderr or "").strip() or stdout.strip())[:500]
        raise Reject("REJECT_PRECONDITION", f"policy_manifest output unparseable: {tail}") from exc
    if not isinstance(envelope, dict):
        raise Reject("REJECT_PRECONDITION", "policy_manifest output is not an object")
    problems = envelope.get("problems")
    if not isinstance(problems, list):
        problems = []
    evidence = {
        "argv": argv,
        "exit_code": proc.returncode,
        "stdout_sha256": _sha256_text(stdout),
    }
    return {
        "tool": "harness.verify",
        "scope": scope,
        "verified": bool(proc.returncode == 0),
        "exit_code": proc.returncode,
        "result": envelope.get("result"),
        "problems": problems,
        "executed": True,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool == "ledger.append":
        record_type = str(args.get("record_type", ""))
        record = args.get("record", {})
        if not isinstance(record, dict):
            record = {}
        expected_prev_hash = str(args.get("expected_prev_hash", ""))
        result = store_append(
            role=role,
            record_type=record_type,
            record=record,
            expected_prev_hash=expected_prev_hash,
        )
        path = result["path"]
        return {
            "tool": tool,
            "record_type": record_type,
            "path": str(path),
            "record_hash": result["record_hash"],
            "prev_hash": result["prev_hash"],
            "sequence": result["sequence"],
            "executed": True,
        }
    if tool == "scratch.write":
        return _execute_scratch_write(role, args)
    if tool == "acceptance.materialize":
        return _execute_acceptance_materialize(role, args)
    if tool == "drain.validate":
        return _execute_drain_validate(server, role, args)
    if tool == "evidence.hash":
        return _execute_evidence_hash(server, role, args)
    if tool == "harness.verify":
        return _execute_harness_verify(server, role, args)
    return None
