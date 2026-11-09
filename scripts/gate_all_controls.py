#!/usr/bin/env python3
"""Single control gate (WAVE 3 / A7).

Runs BOTH evaluators and prints one summary:

    {"dispatch": {"passed": P, "total": T}, "config": {"passed": P, "total": T},
     "overall": "PASS"|"FAIL"}

- dispatch: ``Server.run_controls()`` restricted to the dispatchable
  subset (``REJECT_*`` / ``ACCEPT``). The declarative subset
  (``ASK_ONLY`` / ``NOT_GRANTED`` / ``ROLE_MATRIX`` / ``EMPTY``) is
  excluded here because the dispatcher cannot evaluate it -- counting it
  would silently skip it. It is evaluated by config_controls.py instead,
  so dispatch total + config total == len(controls) == 221.
- config: ``scripts/config_controls.py --json`` spawned argv-only (no
  shell) and parsed. Any non-zero config exit (1 failure, 2 evaluator
  error) forces overall FAIL.

Exit 0 only when BOTH are 100% (passed == total, total > 0). Exit 1 when
either is below 100%; exit 2 on a gate evaluator error (cannot run an
evaluator at all). This is the single control gate used by the verifier
and by ``harness.verify``.
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


def is_dispatchable(expect: str | None) -> bool:
    return expect == "ACCEPT" or (isinstance(expect, str) and expect.startswith("REJECT_"))


def run_dispatch() -> tuple[int, int]:
    """Run Server.run_controls() over the dispatchable subset only."""
    if str(HARNESS_ROOT) not in sys.path:
        sys.path.insert(0, str(HARNESS_ROOT))
    from files.tools.mcp.core.server import Server

    probe = Server("auditor")
    results = probe.run_controls()
    dispatchable = [r for r in results if is_dispatchable(r.get("expect"))]
    total = len(dispatchable)
    passed = sum(1 for r in dispatchable if r.get("pass"))
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
    try:
        d_passed, d_total = run_dispatch()
    except Exception as exc:
        print(f"error: dispatch evaluator failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(json.dumps({"dispatch": {"passed": 0, "total": 0}, "config": {"passed": 0, "total": 0}, "overall": "FAIL"}))
        return 2
    try:
        c_passed, c_total, c_rc = run_config()
    except subprocess.TimeoutExpired:
        print("error: config_controls.py timed out", file=sys.stderr)
        print(json.dumps({"dispatch": {"passed": d_passed, "total": d_total}, "config": {"passed": 0, "total": 0}, "overall": "FAIL"}))
        return 2
    except Exception as exc:
        print(f"error: config evaluator spawn failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(json.dumps({"dispatch": {"passed": d_passed, "total": d_total}, "config": {"passed": 0, "total": 0}, "overall": "FAIL"}))
        return 2
    passed_ok = d_total > 0 and c_total > 0 and d_passed == d_total and c_passed == c_total and c_rc == 0
    overall = "PASS" if passed_ok else "FAIL"
    print(json.dumps({"dispatch": {"passed": d_passed, "total": d_total}, "config": {"passed": c_passed, "total": c_total}, "overall": overall}, indent=2))
    if overall == "PASS":
        return 0
    # A config evaluator error (rc==2) is reported as a gate failure with a
    # distinct exit so it is not confused with ordinary control failures.
    if c_rc == 2:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
