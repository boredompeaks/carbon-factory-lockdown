#!/usr/bin/env python3
"""Single-source policy generator: checks.json is the source of truth.

Canonical source (files/policies/checks.json): each check MUST carry
  min_tier: one of none|high|max   (tier at which the check becomes required)
  required_in_ci: bool             (whether CI must run it)
No defaults are invented. If either field is missing/invalid for any check,
this tool FAILS loudly listing every offending check (exit 2, no writes).

Derived files (this tool rewrites ONLY these fields, preserving all others):
  tiers.json         <- {tier: required_checks = [id where min_tier <= tier]}
  gate.json          <- gate_checks = max required_checks (= all checks)
  ci.json            <- required_checks / not_run_in_ci partition by flag
  check-runners.json <- ci_self_audit + checks[].required_in_ci mirror

Usage (from harness root):
  python scripts/generate_policies.py --check   # dry-run: report drift, write nothing, exit 1 on drift
  python scripts/generate_policies.py           # write derived files (owner runs after canonical lands)
Stdlib json only, no new deps. Do NOT run the write mode until the canonical
min_tier edit in checks.json has landed; the seal stays owner's job.

Validator wiring spec for check_harness_config (FINALIZER: wire this in,
do not load it here). Insert before the final RESULT summary, using the
existing check() helper and json loads of the four files under
files/policies/. Assert at minimum:
  checks = json.loads((POLICIES / "checks.json").read_text())["checks"]
  gate = json.loads((POLICIES / "gate.json").read_text())
  ci = json.loads((POLICIES / "ci.json").read_text())
  tiers = json.loads((POLICIES / "tiers.json").read_text())
  runners = json.loads((POLICIES / "check-runners.json").read_text())
  check(set(gate["gate_checks"]) == set(checks), "gate covers exactly all checks")
  ci_req, ci_not = set(ci["required_checks"]), set(ci["not_run_in_ci"])
  check(ci_req | ci_not == set(checks) and ci_req & ci_not == set(),
        "ci buckets partition all checks disjointly")
  check(set(runners["checks"]) == set(checks), "check-runners mirror all checks")
  check(set(runners["ci_self_audit"]) == ci_req, "ci_self_audit matches ci required")
  check(set(tiers["none"]["required_checks"]) <= set(tiers["high"]["required_checks"])
        <= set(tiers["max"]["required_checks"]) == set(checks),
        "tiers required_checks monotonic to max == all checks")
Print the mismatched sets in the detail arg so drift is debuggable. Exit
remains 0 only when every assertion passes (existing harness behaviour).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ROOT / "files" / "policies"
TIERS = ("none", "high", "max")
TIER_IDX = {tier: i for i, tier in enumerate(TIERS)}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_canonical(checks: dict) -> list[str]:
    """Return loud errors for missing/invalid canonical fields (never defaults)."""
    errors: list[str] = []
    for cid, meta in checks.items():
        if "min_tier" not in meta:
            errors.append(f"{cid}: missing min_tier (none|high|max required)")
        elif meta["min_tier"] not in TIER_IDX:
            errors.append(f"{cid}: invalid min_tier {meta['min_tier']!r} (want none|high|max)")
        if "required_in_ci" not in meta:
            errors.append(f"{cid}: missing required_in_ci (bool required)")
        elif not isinstance(meta["required_in_ci"], bool):
            errors.append(f"{cid}: required_in_ci must be bool, got {type(meta['required_in_ci']).__name__}")
    return errors


def derive(checks: dict) -> dict:
    """Derived values in canonical checks.json order (stable)."""
    tier_lists = {
        tier: [cid for cid, m in checks.items() if TIER_IDX[m["min_tier"]] <= TIER_IDX[tier]]
        for tier in TIERS
    }
    ci_req = [cid for cid, m in checks.items() if m["required_in_ci"] is True]
    ci_not = [cid for cid, m in checks.items() if m["required_in_ci"] is False]
    return {
        "tiers": tier_lists,
        "gate_checks": tier_lists["max"][:],  # max includes every valid min_tier
        "ci_required": ci_req,
        "ci_not_run": ci_not,
        "runner_mirror": {cid: m["required_in_ci"] for cid, m in checks.items()},
    }


def compare_derived(checks: dict, derived: dict) -> list[str]:
    """Compare derived values to on-disk files; return drift lines (no writes)."""
    drift: list[str] = []
    for tier in TIERS:
        path = POLICIES / "tiers.json"
        data = load_json(path) if path.is_file() else {}
        current = ((data.get(tier) or {}).get("required_checks"))
        if current != derived["tiers"][tier]:
            drift.append(f"tiers.json:{tier}.required_checks DRIFT current={current} expected={derived['tiers'][tier]}")
    path = POLICIES / "gate.json"
    data = load_json(path) if path.is_file() else {}
    if data.get("gate_checks") != derived["gate_checks"]:
        drift.append(f"gate.json gate_checks DRIFT current={data.get('gate_checks')} expected={derived['gate_checks']}")
    path = POLICIES / "ci.json"
    data = load_json(path) if path.is_file() else {}
    if data.get("required_checks") != derived["ci_required"]:
        drift.append(f"ci.json required_checks DRIFT current={data.get('required_checks')} expected={derived['ci_required']}")
    if data.get("not_run_in_ci") != derived["ci_not_run"]:
        drift.append(f"ci.json not_run_in_ci DRIFT current={data.get('not_run_in_ci')} expected={derived['ci_not_run']}")
    path = POLICIES / "check-runners.json"
    data = load_json(path) if path.is_file() else {}
    if data.get("ci_self_audit") != derived["ci_required"]:
        drift.append(f"check-runners.json ci_self_audit DRIFT current={data.get('ci_self_audit')} expected={derived['ci_required']}")
    on_disk = (data.get("checks") or {})
    for cid, want in derived["runner_mirror"].items():
        have = (on_disk.get(cid) or {}).get("required_in_ci", "<missing entry>")
        if have != want:
            drift.append(f"check-runners.json checks.{cid}.required_in_ci DRIFT current={have} expected={want}")
    return drift


def apply_write(checks: dict, derived: dict) -> list[str]:
    """Rewrite ONLY derived fields in place (other keys preserved verbatim)."""
    written: list[str] = []
    path = POLICIES / "tiers.json"
    data = load_json(path) if path.is_file() else {"version": 1}
    for tier in TIERS:
        data.setdefault(tier, {})["required_checks"] = derived["tiers"][tier]
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    written.append("tiers.json")
    path = POLICIES / "gate.json"
    data = load_json(path) if path.is_file() else {"version": 1}
    data["gate_checks"] = derived["gate_checks"]
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    written.append("gate.json")
    path = POLICIES / "ci.json"
    data = load_json(path) if path.is_file() else {"version": 1}
    data["required_checks"] = derived["ci_required"]
    data["not_run_in_ci"] = derived["ci_not_run"]
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    written.append("ci.json")
    path = POLICIES / "check-runners.json"
    data = load_json(path) if path.is_file() else {"version": 1}
    data["ci_self_audit"] = derived["ci_required"]
    entries = data.setdefault("checks", {})
    for cid, want in derived["runner_mirror"].items():
        entry = entries.setdefault(cid, {"runners": list(checks[cid].get("runners", [])), "required_in_ci": want})
        entry["required_in_ci"] = want  # mirror only; runners/scope/emits untouched
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    written.append("check-runners.json")
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate derived policies from canonical checks.json.")
    parser.add_argument("--check", action="store_true", help="dry-run: report drift, write nothing")
    args = parser.parse_args(argv)
    checks_path = POLICIES / "checks.json"
    canonical = load_json(checks_path)
    checks = canonical.get("checks") or {}
    errors = validate_canonical(checks)
    if errors:
        print("FAIL canonical checks.json incomplete; no defaults invented, nothing written:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 2
    derived = derive(checks)
    if args.check:
        drift = compare_derived(checks, derived)
        if drift:
            print(f"DRIFT ({len(drift)} items):")
            for line in drift:
                print(f"  - {line}")
            return 1
        print("PASS no drift")
        return 0
    written = apply_write(checks, derived)
    print("WROTE " + ", ".join(written) + f" ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
