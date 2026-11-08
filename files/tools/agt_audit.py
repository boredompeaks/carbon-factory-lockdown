#!/usr/bin/env python3
"""AGT_AUDIT -- verify the AGT audit log keeps deny evidence intact.

The plugin writes the audit log as a pretty-printed JSON array (v5.0.0) or, in
other builds, one JSON object per line. Both shapes are accepted. Every entry
whose decision is "deny" must carry a non-empty action and decision. When a
golden expectation beside the log says a deny occurred, at least one deny entry
must be present; a missing deny is class AGT_AUDIT_GAP.

`--log <file>` defaults to ~/.config/opencode/agt/audit-log.json. `--control`
runs the two fixtures and prints the control envelope used by gate_control.py.

Exit codes: 0 accept, 1 reject, 2 tool error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

TOOL = "agt_audit"
VERSION = "1.0.0"
HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures" / "agt_audit"
DEFAULT_LOG = Path.home() / ".config" / "opencode" / "agt" / "audit-log.json"
EXPECT_SUFFIX = ".expect.json"


def finding(locus: str, detail: str) -> dict:
    return {"class": "AGT_AUDIT_GAP", "locus": locus, "detail": detail}


def parse_entries(path: Path) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [finding(str(path), f"audit log is not readable: {exc}")]
    if not text.strip():
        return [], [finding(str(path), "audit log is empty")]

    entries: list[dict] = []
    if text.lstrip().startswith("["):
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            return [], [finding(str(path), f"audit log is not valid JSON: {exc}")]
        if not isinstance(value, list):
            return [], [finding(str(path), "audit log JSON root is not an array")]
        for index, entry in enumerate(value):
            if not isinstance(entry, dict):
                findings.append(
                    finding(f"{path}:{index}", "audit entry is not a JSON object")
                )
                continue
            entries.append(entry)
        return entries, findings

    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            findings.append(
                finding(f"{path}:{number}", f"line is not valid JSONL: {exc}")
            )
            continue
        if not isinstance(entry, dict):
            findings.append(
                finding(f"{path}:{number}", "audit entry is not a JSON object")
            )
            continue
        entries.append(entry)
    return entries, findings


def expectation_for(log: Path, expect_deny: bool) -> tuple[bool, str | None]:
    sidecar = Path(str(log) + EXPECT_SUFFIX)
    if sidecar.is_file():
        try:
            value = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return True, f"golden expectation {sidecar} is unreadable: {exc}"
        if isinstance(value, dict) and value.get("deny_required") is True:
            return True, str(sidecar)
    if expect_deny:
        return True, "--expect-deny"
    return False, None


def check(log: Path, expect_deny: bool = False) -> list[dict]:
    entries, findings = parse_entries(log)
    denies = 0
    for index, entry in enumerate(entries):
        if entry.get("decision") != "deny":
            continue
        denies += 1
        action = entry.get("action")
        decision = entry.get("decision")
        if not isinstance(action, str) or not action:
            findings.append(
                finding(f"{log}:{index}", "deny entry has no non-empty action field")
            )
        if not isinstance(decision, str) or not decision:
            findings.append(
                finding(f"{log}:{index}", "deny entry has no non-empty decision field")
            )
    required, source = expectation_for(log, expect_deny)
    if required and denies == 0:
        findings.append(
            finding(
                str(log),
                f"golden expectation says a deny occurred ({source}), but no deny entry exists",
            )
        )
    return findings


def control() -> dict:
    cases = []
    for name in ("audit-complete.jsonl", "audit-missing-deny.jsonl"):
        log = FIXTURES / name
        findings = check(log)
        expected = "PASS" if name == "audit-complete.jsonl" else "FAIL"
        actual = "FAIL" if findings else "PASS"
        cases.append(
            {
                "name": f"agt_audit/{name}",
                "expected": expected,
                "actual": {
                    "outcome": actual,
                    "findings": len(findings),
                    "details": findings,
                },
                "passed": actual == expected,
            }
        )
    return {"ran": True, "passed": all(case["passed"] for case in cases), "cases": cases}


def envelope(findings: list[dict], control_doc: dict | None, code: int) -> dict:
    return {
        "schema": "factory-tool/1",
        "tool": TOOL,
        "version": VERSION,
        "interpreter": sys.executable,
        "result_type": "RESULT" if code == 0 else ("CONTROL_FAIL" if control_doc else "REJECT"),
        "exit_code": code,
        "findings": findings,
        "control": control_doc,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", default=str(DEFAULT_LOG), help="audit log path")
    parser.add_argument(
        "--expect-deny",
        action="store_true",
        help="require at least one deny entry even without a golden sidecar",
    )
    parser.add_argument("--control", action="store_true", help="run fixture cases")
    args = parser.parse_args(argv)

    if args.control:
        try:
            control_doc = control()
        except Exception as exc:  # noqa: BLE001 - CLI boundary
            print(
                json.dumps(
                    {
                        "schema": "factory-tool/1",
                        "tool": TOOL,
                        "version": VERSION,
                        "result_type": "ERROR",
                        "error": f"{type(exc).__name__}: {exc}",
                        "exit_code": 2,
                    },
                    sort_keys=True,
                )
            )
            return 2
        code = 0 if control_doc["passed"] else 1
        print(json.dumps(envelope([], control_doc, code), sort_keys=True))
        return code

    try:
        findings = check(Path(args.log).expanduser(), args.expect_deny)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(
            json.dumps(
                {
                    "schema": "factory-tool/1",
                    "tool": TOOL,
                    "version": VERSION,
                    "result_type": "ERROR",
                    "error": f"{type(exc).__name__}: {exc}",
                    "exit_code": 2,
                },
                sort_keys=True,
            )
        )
        return 2
    code = 1 if findings else 0
    print(json.dumps(envelope(findings, None, code), sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
