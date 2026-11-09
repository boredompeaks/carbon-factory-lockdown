"""check.run execution. 6B-2.

One dispatcher for all 24 check ids in checks.json. Engines are
pinned: ruff with the pinned config on added lines, gitleaks
--redact with the pinned config and baseline over base..head,
semgrep with anchored excludes. Builder code runs only in the
sandbox; the auditor runs at the git object id. Engines never run
builder code on the host.

Fail-closed contract: this handler NEVER fabricates a PASS without
real gate_run execution. It wraps the real ``gate_run.py``
implementation (files/tools/gate_run.py --check <ID> --input
<json>). Where evidence is absent or the check id has no
gate_run body, the outcome is FAIL / ERROR with ``stub``/``executed``
flags set — a fabricated PASS is impossible. The ``stub`` flag is
False only when gate_run actually ran; every non-executed result
carries ``stub: True`` so callers cannot mistake a fail-closed
result for real engine evidence.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from ..core.redact import cache_key
from ..core.validate import Reject

# Check ids implemented by gate_run.py (CHECKS tuple). All other
# registry ids (SMELL, POLICY_DIGEST, ARCH, ORACLE_PROVENANCE,
# GUARD_DELTA, AUTHZ_MATRIX, SEMGREP, AGT_PARITY, AGT_AUDIT) have no
# gate_run body in this harness; check.run for those ids fails
# closed as unsupported rather than fabricating a PASS.
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


def _gate_run_path() -> Path:
    # checks/handlers.py -> mcp -> tools/gate_run.py
    return Path(__file__).resolve().parents[2] / "gate_run.py"


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
            # Fail-closed markers: never mistaken for real evidence.
            "stub": True,
            "executed": False,
            "detail": detail,
        }
        base.update(extra)
        return base

    if not check_id:
        return _fail_closed("FAIL", "check_id missing; refusing to fabricate PASS")
    if check_id not in _GATE_RUN_CHECKS:
        # No gate_run body for this id in this harness; fail closed.
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
    # Build minimal evidence from the typed args. gate_run requires
    # full evidence JSON (paths, added_tests, engines, ...); with
    # only tree/engine available the evidence is necessarily
    # incomplete, so the real gate_run — now fail-closed on missing
    # evidence — will report FAIL instead of a fabricated PASS.
    evidence: dict = {"tree": tree, "engine": engine}
    for k in ("base", "head"):
        if args.get(k):
            evidence[k] = args[k]
    # Carry through any provenance args the registry permits so
    # policy checks inside gate_run see the same context.
    for k in ("line", "removed_id", "covered_by"):
        if args.get(k) is not None:
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
                capture_output=True,
                text=True,
                timeout=30,
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
    # Parse the gate_run envelope. exit 0 = PASS, 1 = FAIL, 2 = ERROR.
    # Anything else (or unparseable stdout) is ERROR, never PASS.
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
        "cache_key": key,
        "pinned": pinned,
        "stub": False,
        "executed": True,
        "exit_code": proc.returncode,
        "findings": findings,
        "detail": detail,
    }
    if outcome == "ERROR":
        result["error"] = (proc.stderr or "")[:500]
    return result
