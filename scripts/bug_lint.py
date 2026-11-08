#!/usr/bin/env python3
"""Gate 0 register lint: machine-check the QUALITY-BUGS.md arithmetic.

The register has three tables that begin with a ``QC-`` id:

* the findings register            -> unique findings
* Appendix A (merged duplicates)   -> duplicate re-statements
* the severity-correction table    -> decisions about a finding, not findings

Counting every ``^| QC-`` line as a finding is what produced the wrong
"263 physical / 256 unique" figure. The true structure is::

    251 findings + 7 appendix duplicates + 5 correction rows = 263 QC-prefixed rows

Checks
------
* ``qc_prefixed_rows == 263``
* ``register_rows == unique_findings == 251``
* ``appendix_duplicates == 7`` and each one names an id present in the register
* ``severity_correction_rows == 5``
* ``count(P0) > 0``
* every finding row carries a 40-hex ``verified_at_sha``
* a row whose sha is >10 commits behind HEAD is reported ``STALE``

Exit 0 only when every structural check passes. Staleness is reported but
does not fail the lint: a stale row is a routing fact, not a broken register.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTER = HARNESS_ROOT / "quality-scan" / "QUALITY-BUGS.md"
QC_ID = re.compile(r"^QC-\d+$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.split("|")][1:-1]


def _section_rows(lines: list[str], start_prefix: str) -> list[str]:
    start = None
    for index, line in enumerate(lines):
        if line.startswith(start_prefix):
            start = index + 1
            break
    if start is None:
        return []
    rows = []
    for line in lines[start:]:
        if re.match(r"^#{2,3} ", line):
            break
        if re.match(r"^\|\s*QC-", line):
            rows.append(line)
    return rows


def _severity(cells: list[str]) -> str:
    # Misaligned appendix rows are "| QC-old | QC-canonical | P3 LOW | ...".
    if len(cells) > 1 and QC_ID.match(cells[1]):
        return cells[2].split()[0] if len(cells) > 2 else ""
    return cells[1].split()[0] if len(cells) > 1 else ""


def _canonical_id(cells: list[str]) -> str:
    if len(cells) > 1 and QC_ID.match(cells[1]):
        return cells[1]
    return cells[0]


def _last_sha(cells: list[str]) -> str:
    for cell in reversed(cells):
        if SHA.match(cell):
            return cell
    return ""


def _commits_behind(repo: Path, sha: str) -> int | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-list", "--count", f"{sha}..HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def discover_repo() -> Path | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    out = result.stdout.strip()
    return Path(out) if out else None


def resolve_repo(explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit)
    return discover_repo()


def require_repo(explicit: str | None) -> Path:
    repo = resolve_repo(explicit)
    if not repo:
        raise FileNotFoundError("no repository: provide --repo or run inside a git worktree")
    return repo


def lint(register: Path, repo: Path, threshold: int = 10) -> dict:
    lines = register.read_text(encoding="utf-8").splitlines()

    findings = _section_rows(lines, "## Findings register")
    appendix = _section_rows(lines, "## Appendix A")
    corrections = _section_rows(lines, "### Orchestrator severity corrections")

    finding_cells = [_cells(line) for line in findings]
    appendix_cells = [_cells(line) for line in appendix]

    finding_ids = [cells[0] for cells in finding_cells]
    canonical = [_canonical_id(cells) for cells in appendix_cells]
    all_finding_cells = finding_cells + appendix_cells

    shas = {_last_sha(cells) for cells in all_finding_cells}
    shas.discard("")
    behind = {sha: _commits_behind(repo, sha) for sha in shas}
    stale = sum(
        1
        for cells in all_finding_cells
        if (behind.get(_last_sha(cells)) or 0) > threshold
    )
    missing_sha = sum(1 for cells in all_finding_cells if not _last_sha(cells))

    p0 = sum(1 for cells in all_finding_cells if _severity(cells) == "P0")
    orphan_duplicates = [cid for cid in canonical if cid not in finding_ids]

    result = {
        "register": str(register),
        "qc_prefixed_rows": len(findings) + len(appendix) + len(corrections),
        "register_rows": len(findings),
        "unique_findings": len(set(finding_ids)),
        "appendix_duplicates": len(appendix),
        "appendix_all_named_in_register": not orphan_duplicates,
        "orphan_duplicates": orphan_duplicates,
        "severity_correction_rows": len(corrections),
        "p0_rows": p0,
        "findings_missing_sha": missing_sha,
        "distinct_verified_sha": sorted(shas),
        "commits_behind_head": behind,
        "stale_rows": stale,
        "stale_threshold": threshold,
        "stated_claim": "263 physical / 256 unique",
        "claim_refuted": (
            "the 5 severity-correction rows are not findings and the 7 appendix "
            "rows are duplicates; unique findings = 251"
        ),
    }

    result["checks"] = {
        "qc_prefixed_rows == 263": result["qc_prefixed_rows"] == 263,
        "register_rows == 251": result["register_rows"] == 251,
        "unique_findings == 251": result["unique_findings"] == 251,
        "appendix_duplicates == 7": result["appendix_duplicates"] == 7,
        "appendix ids exist in register": not orphan_duplicates,
        "severity_correction_rows == 5": result["severity_correction_rows"] == 5,
        "count(P0) > 0": result["p0_rows"] > 0,
        "every finding has verified_at_sha": result["findings_missing_sha"] == 0,
    }
    result["verdict"] = "PASS" if all(result["checks"].values()) else "FAIL"
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--register", default=None, help="QUALITY-BUGS.md (default: <harness>/quality-scan/QUALITY-BUGS.md)")
    parser.add_argument("--repo", default=None, help="repo root (default: git root of cwd)")
    parser.add_argument("--threshold", type=int, default=10)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        repo = require_repo(args.repo)
    except FileNotFoundError as exc:
        print(f"bug_lint: {exc}", file=sys.stderr)
        return 2
    register = Path(args.register) if args.register else DEFAULT_REGISTER
    if not register.is_file():
        print(f"bug_lint: register not found: {register}", file=sys.stderr)
        return 2
    try:
        result = lint(register, repo, args.threshold)
    except OSError as exc:
        print(f"bug_lint: cannot read register {register}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for key, value in result.items():
            if key == "checks":
                continue
            print(f"{key}: {value}")
        print("checks:")
        for name, ok in result["checks"].items():
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        print(f"verdict: {result['verdict']}")
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
