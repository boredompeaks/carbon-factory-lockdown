#!/usr/bin/env python3
"""Single control gate (WAVE 3 / A7).

Runs BOTH evaluators and prints one summary:

    {"dispatch": {"passed": P, "total": T}, "config": {"passed": P, "total": T},
     "overall": "PASS"|"FAIL", "idempotence": {"mutated": bool, "detail": str}}

- dispatch: only dispatchable controls (``REJECT_*`` / ``ACCEPT``) are
  dispatched. The declarative subset (``ASK_ONLY`` / ``NOT_GRANTED`` /
  ``ROLE_MATRIX`` / ``EMPTY`` / ``ROLE_ALLOWED``) is excluded here both
  from counting AND from dispatching (it is evaluated by
  config_controls.py instead, so dispatch total + config total ==
  len(controls)). Dispatching declarative controls would be a side
  effect (e.g. gate.control run --write); V1/F3 requires controls to be
  side-effect free, so dispatch is filtered to dispatchable expects
  *before* any Server.dispatch is called.
- config: ``scripts/config_controls.py --json`` spawned argv-only (no
  shell) and parsed. Any non-zero config exit (1 failure, 2 evaluator
  error) forces overall FAIL.
- idempotence: snapshot of ``files/quality/ledger/gate-control/*.json``
  names+mtimes before and after the run. Any change FAILS the gate with
  ``CONTROLS_MUTATED_LEDGER`` (controls must not mutate the ledger).

Exit 0 only when BOTH are 100% (passed == total, total > 0) and the
ledger is unchanged. Exit 1 when either is below 100% (or the ledger
mutated); exit 2 on a gate evaluator error (cannot run an evaluator at all).
This is the single control gate used by the verifier and by ``harness.verify``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parent.parent
CONTROLS_PATH = HARNESS_ROOT / "files" / "tools" / "mcp" / "controls.json"
CONFIG_SCRIPT = HARNESS_ROOT / "scripts" / "config_controls.py"
LEDGER_DIR = HARNESS_ROOT / "files" / "quality" / "ledger" / "gate-control"


def is_dispatchable(expect: str | None) -> bool:
    return expect == "ACCEPT" or (isinstance(expect, str) and expect.startswith("REJECT_"))


def _snapshot_ledger() -> dict[str, int]:
    """Ledger snapshot: name -> mtime_ns for gate-control/*.json."""
    try:
        return {
            p.name: p.stat().st_mtime_ns
            for p in sorted(LEDGER_DIR.glob("*.json"))
            if p.is_file()
        }
    except OSError:
        return {}


def _ledger_idempotence(before: dict[str, int], after: dict[str, int]) -> tuple[bool, str]:
    """(mutated, detail). Detail names CONTROLS_MUTATED_LEDGER on change."""
    if before == after:
        return False, f"LEDGER_UNCHANGED: {len(after)} gate-control records unchanged"
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    modified = sorted(k for k in set(before) & set(after) if before[k] != after[k])
    return True, (
        f"CONTROLS_MUTATED_LEDGER: "
        f"added={added} removed={removed} modified={modified} "
        f"before={len(before)} after={len(after)}"
    )


def run_dispatch() -> tuple[int, int]:
    """Run dispatchable controls only; never dispatch declarative ones.

    Server.run_controls() dispatches every control in controls.json; calling
    it here would execute declarative side-effectful entries (V1/F3:
    gate.control mode run --write). Instead filter to dispatchable
    expects *before* dispatch, with a fresh Server per control (same
    isolation as Server.run_controls, so pr.watch state cannot leak).
    """
    import copy

    if str(HARNESS_ROOT) not in sys.path:
        sys.path.insert(0, str(HARNESS_ROOT))
    from files.tools.mcp.core.server import Reject, Server

    controls = json.loads(CONTROLS_PATH.read_text(encoding="utf-8"))
    control_list = controls.get("controls", [])
    dispatchable_controls = [c for c in control_list if is_dispatchable(c.get("expect"))]
    base = Server("auditor")
    total = len(dispatchable_controls)
    passed = 0
    for ctl in dispatchable_controls:
        probe = Server(
            ctl.get("role", "auditor"),
            registry=base.registry,
            config=base.config,
        )
        try:
            probe.dispatch(ctl["tool"], copy.deepcopy(ctl.get("args", {})))
            got = "ACCEPT"
        except Reject as r:
            got = r.code
        except Exception as exc:  # pragma: no cover - diagnostic
            got = f"ERROR: {exc}"
        if got == ctl.get("expect"):
            passed += 1
    return passed, total


def run_config() -> tuple[int, int, int]:
    """Spawn config_controls.py (argv only) and return (passed, total, rc)."""
    proc = subprocess.run(  # argv only, no shell
        [sys.executable, str(CONFIG_SCRIPT), "--json"],
        cwd=str(HARNESS_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        shell=False,
        check=False,
        timeout=300,
    )
    if proc.stderr:
        print(proc.stderr.strip(), file=sys.stderr)
    try:
        data = json.loads(proc.stdout)
    except Exception as exc:
        # Fall back to the declarative count so the gate still reports a
        # denominator instead of masking the evaluator failure.
        try:
            controls = json.loads(CONTROLS_PATH.read_text(encoding="utf-8"))
            total = sum(1 for c in controls.get("controls", []) if not is_dispatchable(c.get("expect")))
        except Exception:
            total = 0
        print(f"error: config_controls.py output unparseable: {exc}", file=sys.stderr)
        return 0, total, 2
    passed = int(data.get("passed") or 0)
    total = int(data.get("total") or 0)
    return passed, total, int(proc.returncode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gate all controls (dispatch + config).")
    parser.add_argument("--json", action="store_true", help="print JSON summary (default behaviour)")
    parser.parse_args(argv)
    before = _snapshot_ledger()
    try:
        d_passed, d_total = run_dispatch()
    except Exception as exc:
        mutated, detail = _ledger_idempotence(before, _snapshot_ledger())
        print(f"error: dispatch evaluator failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(json.dumps({"dispatch": {"passed": 0, "total": 0}, "config": {"passed": 0, "total": 0}, "overall": "FAIL", "idempotence": {"mutated": mutated, "detail": detail}}))
        return 2
    try:
        c_passed, c_total, c_rc = run_config()
    except subprocess.TimeoutExpired:
        mutated, detail = _ledger_idempotence(before, _snapshot_ledger())
        print("error: config_controls.py timed out", file=sys.stderr)
        print(json.dumps({"dispatch": {"passed": d_passed, "total": d_total}, "config": {"passed": 0, "total": 0}, "overall": "FAIL", "idempotence": {"mutated": mutated, "detail": detail}}))
        return 2
    except Exception as exc:
        mutated, detail = _ledger_idempotence(before, _snapshot_ledger())
        print(f"error: config evaluator spawn failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(json.dumps({"dispatch": {"passed": d_passed, "total": d_total}, "config": {"passed": 0, "total": 0}, "overall": "FAIL", "idempotence": {"mutated": mutated, "detail": detail}}))
        return 2
    mutated, detail = _ledger_idempotence(before, _snapshot_ledger())
    passed_ok = d_total > 0 and c_total > 0 and d_passed == d_total and c_passed == c_total and c_rc == 0 and not mutated
    overall = "PASS" if passed_ok else "FAIL"
    print(json.dumps({"dispatch": {"passed": d_passed, "total": d_total}, "config": {"passed": c_passed, "total": c_total}, "overall": overall, "idempotence": {"mutated": mutated, "detail": detail}}, indent=2))
    if overall == "PASS":
        return 0
    # A config evaluator error (rc==2) is reported as a gate failure with a
    # distinct exit so it is not confused with ordinary control failures.
    if c_rc == 2:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
