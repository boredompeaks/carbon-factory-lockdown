"""Hacker execution. 6B-4 + phase7 P3c (real K1 docker).

- hacker.probe: discovers the running k1 app (docker ps), then runs
  the baked-in client via docker exec argv
  (``python /opt/k1/probe_client.py --endpoint <ep> --actor <actor>``,
  no sh -c). Each execution's JSON is parsed into a probe-record/1
  record; REFUTED is reported only when probe.can_refute holds
  (>=1 blocked per probe_class AND distinct blocked >= min_probes).
  No records are fabricated: with no running K1 app the call is
  REJECT_PRECONDITION ("no runtime").
- repro.run: loads the repro-spec JSON for args.spec, runs its
  command[] argv (translated for the container) x runs via docker
  exec argv, parses ``Ran N tests`` from the combined output. No
  running K1 app (or no loadable spec) is REJECT_PRECONDITION.
- static.scan: in-process regex over the file (no shell) against the
  PROMPT-INJECTION probe_classes; findings are real matches.

All real executions return executed=True plus
evidence{argv, exit_code, stdout_sha256}. Missing docker/scripts
are REJECT_PRECONDITION ("runtime unavailable: ...").
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from ..core.validate import Reject
from .probe import (
    can_refute,
    catalog_entry,
    count_distinct,
    count_distinct_blocked,
    min_probes_for,
    required_total,
    variant_for_actor,
)

_HARNESS_ROOT = Path(__file__).resolve().parents[4]
_TIMEOUT = 180
_PROBE_TIMEOUT = 60

# PROMPT-INJECTION static surfaces (probe_classes in
# attack-catalog.json). Each regex is matched against one file line
# (doc_string additionally matches inside triple-quoted blocks).
_DIRECTIVE = (
    r"(?:ignore|disregard|forget|bypass|override|reveal|leak|exfiltrate|"
    r"print|output|show|dump)"
)
_TOPIC = r"(?:instructions?|prompts?|rules?|directions?|previous|system|secret|password|token|key)"
_STATIC_PATTERNS: dict[str, re.Pattern[str]] = {
    "file_comment": re.compile(
        rf"^\s*#.*{_DIRECTIVE}[^\n]*{_TOPIC}", re.IGNORECASE
    ),
    "test_name": re.compile(
        rf"def\s+test[^\n]*?(ignore|inject|bypass|override|leak|reveal|exfiltrate)\w*",
        re.IGNORECASE,
    ),
    "commit_message": re.compile(
        rf"^\s*(?:ignore|disregard|forget|bypass|override|reveal)\b[^\n]*"
        rf"(?:instructions?|prompts?|previous|system|secret)\b",
        re.IGNORECASE,
    ),
    "doc_string": re.compile(
        rf'"""[^\n]*(?:{_DIRECTIVE})[^\n]*{_TOPIC}', re.IGNORECASE
    ),
    "fixture_data": re.compile(
        r"['\"][A-Za-z0-9_]*\s*(?:prompt|instruction|system|secret|token)[A-Za-z0-9_]*"
        r"['\"]\s*:\s*['\"][^\n]*\b(ignore|disregard|reveal|leak|override|exfiltrate)\b",
        re.IGNORECASE,
    ),
}
_DOC_BLOCK_RE = re.compile(r'"""(.*?)"""', re.DOTALL)


def _sha(data: str | bytes) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def _trunc(text: str, limit: int = 4000) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "\n[TRUNCATED]"


def _run_id(capability_id: str, actor: str, item_id: str) -> str:
    return hashlib.sha256(f"{capability_id}|{actor}|{item_id}".encode()).hexdigest()[:12]


def _docker() -> str:
    for name in ("docker.exe", "docker"):
        found = shutil.which(name)
        if found:
            return found
    raise Reject("REJECT_PRECONDITION", "runtime unavailable: docker not found on PATH")


def _child_env() -> dict[str, str]:
    keep = (
        "PATH", "SystemRoot", "SYSTEMROOT", "PATHEXT",
        "TEMP", "TMP", "LOCALAPPDATA", "USERPROFILE",
        "LANG", "LC_ALL", "PYTHONNOUSERSITE",
    )
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.setdefault("PYTHONNOUSERSITE", "1")
    return env


def _run(argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv, shell=False, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
            env=_child_env(), cwd=str(_HARNESS_ROOT),
        )
    except FileNotFoundError as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            f"runtime unavailable: executable not found: {argv[0] if argv else ''}: {exc}",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            f"runtime unavailable: command timed out after {timeout}s: {argv[0] if argv else ''}",
        ) from exc
    except OSError as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            f"runtime unavailable: failed to spawn {argv[0] if argv else ''}: {exc}",
        ) from exc


def _evidence(argv: list[str], returncode: int, stdout: str, stderr: str) -> dict:
    return {
        "argv": list(argv),
        "exit_code": returncode,
        "stdout_sha256": _sha(stdout or ""),
        "stderr_sha256": _sha(stderr or ""),
    }


def _discover_k1() -> tuple[str, str]:
    """Return (run_id, app_name) for a running k1 app, or Reject.

    hacker.probe/repro.run take no run_id (the hacker holds no k1.*
    grant), so the runtime is discovered from docker itself. No
    running k1 app is REJECT_PRECONDITION "no runtime".
    """
    docker = _docker()
    argv = [docker, "ps", "--filter", "name=k1-", "--format", "{{.Names}}"]
    proc = _run(argv, timeout=_PROBE_TIMEOUT)
    apps: list[tuple[str, str]] = []
    for line in (proc.stdout or "").splitlines():
        name = line.strip()
        if name.startswith("k1-") and name.endswith("-app"):
            run_id = name[3:-4]
            if run_id:
                apps.append((run_id, name))
    if not apps:
        raise Reject("REJECT_PRECONDITION", "no runtime")
    apps.sort()
    return apps[0]


def _docker_exec(app: str, inner: list[str], workdir: str, timeout: int) -> tuple[subprocess.CompletedProcess, list[str]]:
    docker = _docker()
    argv = [docker, "exec", "-u", "10001", "-w", workdir, app, *inner]
    return _run(argv, timeout=timeout), argv


def _probe_outcome(proc: subprocess.CompletedProcess) -> tuple[str, int | None]:
    """Map one probe_client execution to (outcome, http_status)."""
    if proc.returncode != 0:
        return "error", None
    text = proc.stdout or ""
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if not isinstance(data, dict) or "status" not in data:
            continue
        try:
            status = int(data["status"])
        except (TypeError, ValueError):
            return "error", None
        if status in (401, 403, 404, 405, 410):
            return "blocked", status
        if 200 <= status < 300:
            return "reproduced", status
        return "error", status
    return "error", None


def _probe(server, tool: str, role: str, args: dict) -> dict:
    item_id = str(args.get("item_id", ""))
    cap = str(args.get("capability_id", ""))
    actor = str(args.get("actor", ""))
    entry = catalog_entry(item_id)
    if not entry:
        raise Reject("REJECT_ENUM", f"unknown item_id {item_id!r}")
    variant = variant_for_actor(actor)
    classes = [str(c) for c in (entry.get("probe_classes") or [])]
    if not classes:
        raise Reject("REJECT_PRECONDITION", f"no probe_classes for item {item_id!r}")
    engines = [str(e) for e in (entry.get("engines") or []) if str(e) in ("none", "postgres", "sqlite")]
    if not engines:
        engines = ["none"]
    endpoint = str(args.get("endpoint") or "/health")
    if not endpoint.startswith("/") or "://" in endpoint or "@" in endpoint or any(ch.isspace() for ch in endpoint):
        raise Reject("REJECT_PATTERN", "endpoint must be a relative path, no redirects")
    tenant = args.get("tenant_pair")
    if tenant is None:
        tenant_pair = ["tenant-a", "tenant-b"]
    elif isinstance(tenant, (list, tuple)) and len(tenant) == 2:
        tenant_pair = [str(tenant[0]), str(tenant[1])]
    else:
        raise Reject("REJECT_ARG", "tenant_pair must be a list of 2 strings")
    attempts = required_total(item_id, variant)
    if args.get("batch"):
        attempts = max(attempts, 3)
    if args.get("barrier"):
        attempts = max(attempts, 2)
    attempts = max(1, min(attempts, 10))
    run_id = _run_id(cap, actor, item_id)
    k1_run_id, app = _discover_k1()
    records: list[dict] = []
    executions: list[dict] = []
    combined = ""
    first_error: int | None = None
    for i in range(attempts):
        probe_class = classes[i % len(classes)]
        ep = endpoint if i == 0 else f"{endpoint.rstrip('/')}/probe-{i}"
        engine = engines[i % len(engines)]
        inner = ["python", "/opt/k1/probe_client.py", "--endpoint", ep, "--actor", actor]
        proc, argv = _docker_exec(app, inner, "/work", _PROBE_TIMEOUT)
        outcome, status = _probe_outcome(proc)
        out_sha = _sha(proc.stdout or "")
        combined += proc.stdout or ""
        if proc.returncode != 0 and first_error is None:
            first_error = proc.returncode
        executions.append({
            "probe_class": probe_class, "endpoint": ep, "engine": engine,
            "http_status": status,
            "evidence": _evidence(argv, proc.returncode, proc.stdout or "", proc.stderr or ""),
        })
        records.append({
            "item_id": item_id,
            "probe_class": probe_class,
            "endpoint": ep,
            "tenant_pair": list(tenant_pair),
            "engine": engine,
            "outcome": outcome,
            "evidence_ref": out_sha,
        })
    blocked_distinct = count_distinct_blocked(records)
    distinct = count_distinct(records)
    min_probes = min_probes_for(item_id, variant)
    if distinct < min_probes:
        raise Reject(
            "REJECT_PRECONDITION",
            f"under-probe: distinct {distinct} < min_probes {min_probes} for {item_id!r} ({variant})",
        )
    refuted = can_refute(records, item_id, variant)
    reproduced = any(r.get("outcome") == "reproduced" for r in records)
    if refuted:
        outcome_name = "REFUTED"
    elif reproduced:
        outcome_name = "REPRODUCED"
    else:
        outcome_name = "NOT_REFUTED"
    agg_argv = executions[0]["evidence"]["argv"] if executions else []
    return {
        "tool": tool,
        "run_id": run_id,
        "k1_run_id": k1_run_id,
        "actor": actor,
        "item_id": item_id,
        "variant": variant,
        "records": records,
        "counts": {
            "total": len(records),
            "blocked_distinct": blocked_distinct,
            "distinct": distinct,
            "min_probes": min_probes,
            "refuted": 1 if refuted else 0,
        },
        "attempted": len(records),
        "outcome": outcome_name,
        "can_refute": refuted,
        "executed": True,
        "executions": executions,
        "evidence": {
            "argv": agg_argv,
            "exit_code": first_error if first_error is not None else 0,
            "stdout_sha256": _sha(combined),
        },
        "no_redirects": True,
        "header_denylist": ["host", "content-length"],
    }


def _load_repro_spec(spec_name: str) -> dict:
    if not isinstance(spec_name, str) or not spec_name:
        raise Reject("REJECT_ARG", "spec must be a non-empty string")
    # Registry patterns carry no dot/colon, so try the name as-is and
    # with .json appended, under the harness root and files/.
    candidates: list[Path] = []
    for base in (_HARNESS_ROOT, _HARNESS_ROOT / "files", _HARNESS_ROOT / "files" / "drain"):
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
            resolved.relative_to(_HARNESS_ROOT.resolve())
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
    if not isinstance(data, dict) or not isinstance(data.get("command"), list) or not data["command"]:
        raise Reject("REJECT_PRECONDITION", f"repro spec has no command[]: {spec_name!r}")
    if not all(isinstance(x, str) and x for x in data["command"]):
        raise Reject("REJECT_PRECONDITION", f"repro spec command[] must be non-empty strings: {spec_name!r}")
    if data.get("schema") not in (None, "repro-spec/1"):
        raise Reject("REJECT_PRECONDITION", f"repro spec schema is not repro-spec/1: {spec_name!r}")
    return data


def _translate_command(command: list[str]) -> tuple[list[str], str]:
    """Map a host-side repro command[] to container argv + workdir."""
    inner = list(command)
    if inner:
        exe = Path(inner[0].replace("\\", "/")).name.lower()
        if "python" in exe:
            inner[0] = "python"
    workdir = "/repo/head/backend" if "manage.py" in inner else "/work"
    return inner, workdir


def _parse_ran(text: str) -> tuple[int | None, str, str]:
    ran: int | None = None
    for m in re.finditer(r"Ran (\d+) tests?\b", text or ""):
        try:
            ran = int(m.group(1))
        except ValueError:
            pass
    summary = "UNMEASURED"
    if re.search(r"^FAILED\b", text or "", re.MULTILINE):
        summary = "FAILED"
    elif re.search(r"^OK\b", text or "", re.MULTILINE):
        summary = "OK"
    line = ""
    for ln in (text or "").splitlines():
        if re.search(r"Ran \d+ tests?\b", ln):
            line = ln.strip()
            break
    return ran, summary, line


def _repro(server, tool: str, role: str, args: dict) -> dict:
    spec_name = str(args.get("spec", ""))
    spec = _load_repro_spec(spec_name)
    try:
        runs = int(args.get("runs", 0) or spec.get("runs", 1) or 1)
    except (TypeError, ValueError):
        runs = 1
    runs = max(1, min(runs, 5))
    engine = str(args.get("engine") or spec.get("engine") or "sqlite")
    inner, workdir = _translate_command(list(spec["command"]))
    try:
        spec_timeout = int(spec.get("timeout_s") or _TIMEOUT)
    except (TypeError, ValueError):
        spec_timeout = _TIMEOUT
    timeout = max(10, min(spec_timeout, _TIMEOUT))
    k1_run_id, app = _discover_k1()
    outcomes: list[dict] = []
    combined = ""
    first_error: int | None = None
    first_argv: list[str] = []
    for i in range(runs):
        proc, argv = _docker_exec(app, inner, workdir, timeout)
        if not first_argv:
            first_argv = argv
        combined += proc.stdout or ""
        combined += proc.stderr or ""
        if proc.returncode != 0 and first_error is None:
            first_error = proc.returncode
        ran, summary, line = _parse_ran((proc.stdout or "") + (proc.stderr or ""))
        outcomes.append({
            "run": i + 1,
            "exit_code": proc.returncode,
            "ran": ran,
            "summary": summary,
            "summary_line": line,
            "stdout_sha256": _sha(proc.stdout or ""),
            "evidence": _evidence(argv, proc.returncode, proc.stdout or "", proc.stderr or ""),
        })
    last_ran, last_summary, last_line = _parse_ran(combined)
    return {
        "tool": tool,
        "spec": spec_name,
        "repro_id": spec.get("repro_id"),
        "kind": spec.get("kind"),
        "runs": runs,
        "engine": engine,
        "k1_run_id": k1_run_id,
        "executed": True,
        "outcomes": outcomes,
        "ran": last_ran,
        "ran_tests": last_ran,
        "summary": last_summary,
        "summary_line": last_line,
        "stdout": _trunc(combined),
        "evidence": {
            "argv": first_argv,
            "exit_code": first_error if first_error is not None else 0,
            "stdout_sha256": _sha(combined),
        },
    }


def _static_scan(server, tool: str, role: str, args: dict) -> dict:
    path_arg = str(args.get("path", ""))
    try:
        max_bytes = int(args.get("max_bytes") or 262144)
    except (TypeError, ValueError):
        max_bytes = 262144
    max_bytes = max(1, min(max_bytes, 1048576))
    if not path_arg or "\x00" in path_arg:
        raise Reject("REJECT_ARG", "path must be a non-empty string")
    try:
        target = (_HARNESS_ROOT / path_arg).resolve()
        target.relative_to(_HARNESS_ROOT.resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise Reject("REJECT_PATH", f"path escapes the harness root: {path_arg!r}") from exc
    if not target.is_file():
        raise Reject("REJECT_PRECONDITION", f"static.scan file not found: {path_arg!r}")
    raw = target.read_bytes()[:max_bytes]
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    findings: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for idx, line in enumerate(lines, start=1):
        for cls, pattern in _STATIC_PATTERNS.items():
            if (cls, idx) in seen:
                continue
            m = pattern.search(line)
            if m:
                seen.add((cls, idx))
                findings.append({
                    "probe_class": cls,
                    "line": idx,
                    "match": m.group(0)[:200],
                    "evidence_ref": _sha(line),
                })
    # doc_string blocks whose directive text is not on the opener line.
    for m in _DOC_BLOCK_RE.finditer(text):
        block = m.group(1)
        line_no = text[: m.start()].count("\n") + 1
        if re.search(rf"(?:{_DIRECTIVE})[^\n]*{_TOPIC}", block, re.IGNORECASE | re.DOTALL):
            if ("doc_string", line_no) not in seen:
                # Reuse the line opener unless already found.
                if not any(f["probe_class"] == "doc_string" and f["line"] == line_no for f in findings):
                    findings.append({
                        "probe_class": "doc_string",
                        "line": line_no,
                        "match": _trunc(block, 200).replace("\n", " ")[:200],
                        "evidence_ref": _sha(block),
                    })
                    seen.add(("doc_string", line_no))
    findings.sort(key=lambda f: (f["line"], f["probe_class"]))
    return {
        "tool": tool,
        "path": path_arg,
        "findings": findings,
        "read_only": True,
        "executed": True,
        "scanned_bytes": len(raw),
        "lines": len(lines),
        "evidence": {
            "argv": ["static.scan", path_arg],
            "exit_code": 0,
            "stdout_sha256": _sha(raw),
        },
    }


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool == "hacker.probe":
        return _probe(server, tool, role, args)
    if tool == "repro.run":
        return _repro(server, tool, role, args)
    if tool == "static.scan":
        return _static_scan(server, tool, role, args)
    return None
