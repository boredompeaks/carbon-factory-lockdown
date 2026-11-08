#!/usr/bin/env python3
"""VALIDATEDRAIN -- read-only validator for the drain lineage and dispatch evidence.

Checks the R1 -> R2 -> R3 -> R4 -> R5 record chain (schema, canonical hash
continuity, tree identity, live policy digest), the capability and dispatch
records, every dispatch evidence reference, the R3 repro reference, and the
newest gate-control seal. R4-audit.json and R4-audit-addendum.json (when present)
plus every R5-*.json file are part of the counted canonical hash/schema lineage.
capability.json trees are verified via git rev-parse <base>^{tree} and
<head>^{tree}; git being unavailable or failing is a fail-closed problem.
jsonschema is required: if it is missing the validator exits 2 (no fallback).

Outputs records_checked as a total int and records_checked_by_stage as a
per-stage dict (R1-R5 plus addendum).

Exit codes: 0 PASS, 1 FAIL, 2 tool error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

SCHEMA = "validatedrain/1"
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DRAIN = ROOT / "drain" / "refund-cluster"
ZERO_HASH = "0" * 64
RECORD_NAMES = ("R1-confirm.json", "R2-exploit-spec.json", "R3-red.json")
R4_NAME = "R4-audit.json"
ADDENDUM_NAME = "R4-audit-addendum.json"


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def record_hash(record: dict) -> str:
    body = {key: value for key, value in record.items() if key != "record_hash"}
    return sha256_bytes(canonical(body).encode("utf-8"))


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def live_policy_digest() -> str:
    sys.path.insert(0, str(ROOT / "tools"))
    import policy_digest as pd  # noqa: PLC0415 - local tool import

    value, _ = pd.digest(str(ROOT / "policies"))
    return value


def validate_schema(record: dict, schema: dict, label: str, problems: list[str]) -> None:
    try:
        import jsonschema  # noqa: PLC0415 - required dependency (fail closed)
    except ImportError as exc:
        # No required-keys fallback: missing jsonschema is a tool error (exit 2).
        raise RuntimeError("jsonschema is required but not installed") from exc
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(record), key=lambda error: list(error.path))
    for error in errors:
        where = "/".join(str(part) for part in error.path) or "<root>"
        problems.append(f"{label}: schema {where}: {error.message}")


def is_record_ref(name: str) -> bool:
    posix = name.replace("\\", "/")
    base = Path(posix).name
    if base in RECORD_NAMES or base in (R4_NAME, ADDENDUM_NAME):
        return True
    if base.startswith("R5-") and base.endswith(".json"):
        return True
    return "gate-control/" in posix and posix.endswith(".json")


def resolve_ref(name: str, repo: Path) -> Path | None:
    candidate = Path(name)
    if candidate.is_absolute():
        return candidate if candidate.is_file() else None
    for base in (ROOT, repo):
        target = (base / candidate).resolve()
        if target.is_file():
            return target
    return None


def _git_tree(repo: Path, commit: str) -> str | None:
    """Resolve <commit>^{tree} via git; None on any git failure (fail closed)."""
    try:
        process = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", f"{commit}^{{tree}}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
    except OSError:
        return None
    if process.returncode != 0:
        return None
    value = process.stdout.strip()
    return value or None


def discover_git_root() -> Path | None:
    try:
        process = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
    except (OSError, ValueError):
        return None
    if process.returncode != 0:
        return None
    value = process.stdout.strip()
    if not value:
        return None
    return Path(value).resolve()


def resolve_repo(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    discovered = discover_git_root()
    if discovered is not None:
        return discovered
    raise RuntimeError(
        "no --repo provided and no git repository found from cwd "
        "(git rev-parse --show-toplevel failed)"
    )


def run(drain_dir: Path, repo: Path) -> tuple[list[str], int, dict[str, int]]:
    problems: list[str] = []
    schema = load_json(ROOT / "policies" / "schemas" / "drain-record.json")
    live = live_policy_digest()

    records: dict[str, dict] = {}
    per_stage: dict[str, int] = {"R1": 0, "R2": 0, "R3": 0, "R4": 0, "R5": 0, "addendum": 0}
    stage_of = {"R1-confirm.json": "R1", "R2-exploit-spec.json": "R2", "R3-red.json": "R3"}
    for name in RECORD_NAMES:
        path = drain_dir / name
        if not path.is_file():
            problems.append(f"{name}: missing")
            continue
        try:
            record = load_json(path)
        except json.JSONDecodeError as exc:
            problems.append(f"{name}: invalid JSON: {exc}")
            continue
        records[name] = record
        per_stage[stage_of[name]] += 1
        validate_schema(record, schema, name, problems)

    if len(records) == len(RECORD_NAMES):
        expected_prev = ZERO_HASH
        for name in RECORD_NAMES:
            record = records[name]
            if record.get("prev_hash") != expected_prev:
                problems.append(
                    f"{name}: prev_hash {record.get('prev_hash')!r} != {expected_prev}"
                )
            recomputed = record_hash(record)
            if record.get("record_hash") != recomputed:
                problems.append(f"{name}: record_hash does not recompute")
            expected_prev = str(record.get("record_hash", ""))

    trees = {name: records[name].get("tree_sha") for name in RECORD_NAMES if name in records}
    if len(set(trees.values())) > 1:
        problems.append("tree_sha differs across drain records: " + json.dumps(trees, sort_keys=True))

    for name in RECORD_NAMES:
        if name in records and records[name].get("policy_digest") != live:
            problems.append(f"{name}: policy_digest differs from live narrowed digest")

    capability_path = drain_dir / "capability.json"
    if not capability_path.is_file():
        problems.append("capability.json: missing")
    else:
        try:
            capability = load_json(capability_path)
        except json.JSONDecodeError as exc:
            problems.append(f"capability.json: invalid JSON: {exc}")
        else:
            if capability.get("sig_status") != "unsigned_local":
                problems.append("capability.json: sig_status is not unsigned_local")
            if capability.get("policy_digest") != live:
                problems.append("capability.json: policy_digest differs from live narrowed digest")
            # acceptance_derived: family is derived from the canonical role in
            # policies/models.json, never free text. The refund-cluster is
            # grandfathered (deepseek + note with re-derivation).
            try:
                models_policy = load_json(ROOT / "policies" / "models.json")
            except (OSError, json.JSONDecodeError) as exc:
                problems.append(f"capability.json: acceptance_derived cannot be evaluated (models.json: {exc})")
            else:
                roles = models_policy.get("roles") or {}
                aliases = models_policy.get("acceptance_author_role_aliases") or {}
                raw_role = capability.get("acceptance_author_policy") or models_policy.get("acceptance_author_role")
                canonical_role = aliases.get(raw_role, raw_role)
                if canonical_role == "human":
                    expected_family = "human"
                elif canonical_role in roles:
                    expected_family = roles[canonical_role].get("family")
                else:
                    expected_family = None
                family = capability.get("acceptance_author_family")
                if family != expected_family:
                    note = str(capability.get("acceptance_author_note") or "")
                    is_refund_cluster = drain_dir.name == "refund-cluster"
                    if is_refund_cluster and family == "deepseek" and raw_role == "hacker" and "re-derivation" in note:
                        # Grandfathered: hand-authored deepseek test on the
                        # refund-cluster; auditor re-derivation stays mandatory
                        # per acceptance_author_note. New capabilities must use
                        # the derived family for the canonical role.
                        pass
                    else:
                        problems.append(
                            "capability.json: acceptance_author_family does not match derived family "
                            f"for acceptance_author_policy {raw_role!r} "
                            f"(expected {expected_family!r}, got {family!r})"
                        )
            if capability.get("record_hash") != record_hash(capability):
                problems.append("capability.json: record_hash does not recompute")
            # Tree verification via git: base^{tree} must equal the R1-R3
            # tree_sha and head^{tree} must equal capability.tree. Git being
            # unavailable or failing is a fail-closed problem (never skipped).
            _cap_base = capability.get("base")
            _cap_head = capability.get("head")
            _cap_tree = capability.get("tree")
            if isinstance(_cap_base, str) and _cap_base:
                _base_tree = _git_tree(repo, _cap_base)
                if _base_tree is None:
                    problems.append(
                        "capability.json: git rev-parse <base>^{tree} failed (git unavailable or base unknown; fail closed)"
                    )
                else:
                    for _n in RECORD_NAMES:
                        if _n in records and records[_n].get("tree_sha") != _base_tree:
                            problems.append(
                                f"{_n}: tree_sha {records[_n].get('tree_sha')!r} "
                                f"!= git rev-parse <base>^{{tree}} {_base_tree!r}"
                            )
            else:
                problems.append("capability.json: base missing (cannot verify tree via git)")
            if isinstance(_cap_head, str) and _cap_head:
                _head_tree = _git_tree(repo, _cap_head)
                if _head_tree is None:
                    problems.append(
                        "capability.json: git rev-parse <head>^{tree} failed (git unavailable or head unknown; fail closed)"
                    )
                elif isinstance(_cap_tree, str) and _cap_tree and _cap_tree != _head_tree:
                    problems.append(
                        f"capability.json: tree {_cap_tree!r} != git rev-parse <head>^{{tree}} {_head_tree!r}"
                    )
            else:
                problems.append("capability.json: head missing (cannot verify tree via git)")

    dispatch_path = drain_dir / "dispatch.json"
    if not dispatch_path.is_file():
        problems.append("dispatch.json: missing")
    else:
        try:
            dispatch = load_json(dispatch_path)
        except json.JSONDecodeError as exc:
            problems.append(f"dispatch.json: invalid JSON: {exc}")
        else:
            if dispatch.get("action") != "DISPATCH":
                problems.append("dispatch.json: action is not DISPATCH")
            if dispatch.get("reason_code") != "OK":
                problems.append("dispatch.json: reason_code is not OK")
            predicates = dispatch.get("predicate_ids") or []
            if "P-CTRL" not in predicates:
                problems.append("dispatch.json: predicate_ids does not include P-CTRL")
            for ref in dispatch.get("evidence_refs") or []:
                name = str(ref.get("ref", ""))
                claimed = ref.get("sha256")
                if name == "policies":
                    if claimed != live:
                        problems.append(
                            "dispatch.json: evidence_ref 'policies' sha256 differs from live narrowed digest"
                        )
                    continue
                resolved = resolve_ref(name, repo)
                if resolved is None:
                    problems.append(f"dispatch.json: evidence_ref {name!r} does not resolve")
                    continue
                if is_record_ref(name):
                    try:
                        target = load_json(resolved)
                    except json.JSONDecodeError:
                        problems.append(f"dispatch.json: evidence_ref {name!r} is not valid JSON")
                        continue
                    if claimed != target.get("record_hash"):
                        problems.append(
                            f"dispatch.json: evidence_ref {name!r} sha256 != record_hash"
                        )
                elif claimed != sha256_file(resolved):
                    problems.append(
                        f"dispatch.json: evidence_ref {name!r} sha256 != file sha256"
                    )

    if "R3-red.json" in records:
        repro = records["R3-red.json"].get("repro_ref")
        if not isinstance(repro, str) or not repro:
            problems.append("R3-red.json: repro_ref is missing")
        else:
            repro_file = repro.split("::", 1)[0]
            if not (repo / repro_file).is_file():
                problems.append(
                    f"R3-red.json: repro_ref file not found under repo: {repro_file}"
                )

    # R4/R5 (policies/drain.json exit_when): fail closed; structural guard
    # check (guard file bytes in repo) so removal/skip reopens R1.
    # R4-audit.json, the addendum and every R5-*.json are part of the counted
    # canonical hash/schema lineage: each present file that parses counts in
    # per_stage and must recompute its record_hash and pass schema checks.
    try: _cap = load_json(capability_path)
    except (OSError, json.JSONDecodeError): _cap = {}
    _guard = _cap.get("guard_ref") or {} if isinstance(_cap.get("guard_ref"), dict) else {}
    _node, _gsha = str(_guard.get("node_id") or ""), str(_guard.get("sha256") or "")
    if not _node or not _gsha: problems.append("R4/R5: capability guard_ref missing (Q-GUARD absent)")
    _vp = drain_dir / R4_NAME; _vd = None
    if not _vp.is_file(): problems.append("R4-audit.json: missing (verdict fields absent)")
    else:
        try: _vd = load_json(_vp)
        except json.JSONDecodeError as exc: problems.append(f"R4-audit.json: invalid JSON: {exc}")
        else:
            per_stage["R4"] += 1
            if _vd.get("record_hash") != record_hash(_vd):
                problems.append("R4-audit.json: record_hash does not recompute")
            _verdict_schema = load_json(ROOT / "policies" / "schemas" / "auditor-verdict.json")
            # audit_extension is the documented out-of-schema carrier (the
            # file's schema_extension_note): validate the verdict core without
            # the extension so the documented field is not a schema failure.
            _vd_core = {k: v for k, v in _vd.items() if k != "audit_extension"}
            validate_schema(_vd_core, _verdict_schema, "R4-audit.json", problems)
    _ap = drain_dir / ADDENDUM_NAME
    if _ap.is_file():
        try: _ad = load_json(_ap)
        except json.JSONDecodeError as exc: problems.append(f"R4-audit-addendum.json: invalid JSON: {exc}")
        else:
            per_stage["addendum"] += 1
            if _ad.get("record_hash") != record_hash(_ad):
                problems.append("R4-audit-addendum.json: record_hash does not recompute")
            if _ad.get("schema") != "R4-audit-addendum/1":
                problems.append('R4-audit-addendum.json: schema is not R4-audit-addendum/1')
            if _ad.get("parent_record_hash") != (_vd.get("record_hash") if isinstance(_vd, dict) else None):
                problems.append("R4-audit-addendum.json: parent_record_hash != R4-audit.json record_hash")
    if isinstance(_vd, dict):
        if _vd.get("verdict") != "PASS": problems.append("R4: verdict is not PASS")
        if _vd.get("head") != _cap.get("head") or _vd.get("tree") != _cap.get("tree"): problems.append("R4: verdict head/tree != capability head/tree")
        _suite = next((c for c in _vd.get("checks") or [] if c.get("id") == "SUITE"), None)
        if _suite is None: problems.append("R4: verdict SUITE result absent (Q-GUARD passing unverified)")
        elif _suite.get("outcome") != "PASS": problems.append("R4: verdict SUITE is not PASS")
        if _node:
            _ok = any(r.get("ref") == _node and r.get("head_outcome") == "PASS" for r in _vd.get("acceptance_rederived") or [])
            if not _ok: problems.append("R4: guard node does not pass in verdict (acceptance_rederived)")
    _rdir = ROOT / "quality" / "ledger" / "release"; _rel = None
    if _rdir.is_dir():
        for _pp in sorted(_rdir.rglob("*.json")):
            try: _dd = load_json(_pp)
            except (OSError, json.JSONDecodeError): continue
            if _dd.get("capability_id") == _cap.get("capability_id"): _rel = _dd; break
    if _rel is None: problems.append("R4/R5: release record missing (merged_tree unavailable)")
    elif isinstance(_vd, dict):
        if _rel.get("merged_tree") != _vd.get("tree"): problems.append("R4: release merged_tree != verdict tree")
        if _rel.get("guard_ref") != _guard: problems.append("R4: release guard_ref != capability guard_ref")
    if _node and _gsha:
        _gf = repo / _node.split("::", 1)[0]
        if not _gf.is_file(): problems.append("R4/R5: guard file absent at head/merged_tree (reopens R1)")
        elif sha256_file(_gf) != _gsha: problems.append("R4/R5: guard file sha differs (reopens R1)")
        elif any(m in _gf.read_text(encoding="utf-8", errors="ignore").lower() for m in ("@skip", "@xfail", "skiptest", "expectedfailure", "pytest.mark.skip", "pytest.mark.xfail")): problems.append("R4/R5: guard skipped/xfailed (reopens R1)")
    _r5s = sorted(drain_dir.glob("R5-*.json"))
    if not _r5s: problems.append("R5-*.json: missing (post-merge permanence unverified)")
    for _r5p in _r5s:
        try: _r5d = load_json(_r5p)
        except json.JSONDecodeError as exc: problems.append(f"{_r5p.name}: invalid JSON: {exc}"); continue
        per_stage["R5"] += 1
        if _r5d.get("record_hash") != record_hash(_r5d):
            problems.append(f"{_r5p.name}: record_hash does not recompute")
        if _r5d.get("schema") == "drain-record/1":
            validate_schema(_r5d, schema, _r5p.name, problems)
        else:
            # Permanence record (policies/drain.json R5 required_fields).
            for _k in ("guard_present_at_merged_tree", "guard_not_skipped", "guard_passes"):
                if _r5d.get(_k) is not True: problems.append(f"{_r5p.name}: {_k} is not true")
            _ev = _r5d.get("evidence_ref") or ""
            if not isinstance(_ev, str) or not _ev or resolve_ref(_ev, repo) is None: problems.append(f"{_r5p.name}: evidence_ref does not resolve")
        if _guard and _r5d.get("guard_ref") != _guard: problems.append(f"{_r5p.name}: guard_ref != capability guard_ref")

    gate_dir = ROOT / "quality" / "ledger" / "gate-control"
    gate_records = sorted(
        item for item in gate_dir.glob("*.json") if item.name != "verify.json"
    )
    if not gate_records:
        problems.append("gate-control: no records found")
    else:
        newest = gate_records[-1]
        process = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "gate_control.py"), "--verify", str(newest)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        if process.returncode != 0:
            problems.append(
                f"gate-control: newest record {newest.name} did not verify (exit {process.returncode})"
            )
        try:
            verification = json.loads(process.stdout)
        except json.JSONDecodeError:
            problems.append("gate-control: verify output is not JSON")
        else:
            for item in verification.get("problems") or []:
                problems.append(f"gate-control: {newest.name}: {item}")

    records_checked = sum(per_stage.values())
    return problems, records_checked, per_stage


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drain-dir", default=str(DEFAULT_DRAIN), help="drain cluster directory")
    parser.add_argument("--repo", default=None, help="audited repository (default: git toplevel of cwd)")
    parser.add_argument("--json", action="store_true", help="emit compact JSON")
    args = parser.parse_args(argv)

    drain_dir = Path(args.drain_dir).resolve()
    if not drain_dir.is_dir():
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "result": "ERROR",
                    "problems": [f"drain directory not found: {drain_dir}"],
                    "records_checked": 0,
                    "records_checked_by_stage": {"R1": 0, "R2": 0, "R3": 0, "R4": 0, "R5": 0, "addendum": 0},
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    try:
        repo = resolve_repo(args.repo)
        problems, records_checked, per_stage = run(drain_dir, repo)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "result": "ERROR",
                    "problems": [f"{type(exc).__name__}: {exc}"],
                    "records_checked": 0,
                    "records_checked_by_stage": {"R1": 0, "R2": 0, "R3": 0, "R4": 0, "R5": 0, "addendum": 0},
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    payload = {
        "schema": SCHEMA,
        "result": "PASS" if not problems else "FAIL",
        "problems": problems,
        "records_checked": records_checked,
        "records_checked_by_stage": per_stage,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
