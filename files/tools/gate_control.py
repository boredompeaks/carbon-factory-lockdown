#!/usr/bin/env python3
"""Run the resolved negative-control manifest and seal a gate-control record.

A gate-control record is the P-CTRL evidence: it names the gate commit, the
live policy digest, the control-set hash, and the observed outcome of every
control. This host has no signing authority; records are content-addressed and
carry sig_status "unsigned_local". Chain continuity is prev_hash -> record_hash
across records in the output directory.

Exit codes: 0 PASS, 1 FAIL, 2 tool error.

Semgrep handling decision: local control self-tests pass ``--allow-fallback``
for ``semgrep_runner.py --control``; live scans stay strict (no flag added to
non-control invocations). gate_control only invokes manifest ``--control``
runners, never live ``--diff``/``--paths`` scans, so strict BLOCKED (exit 2)
for live scans is untouched and P0 ERROR handling is unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL = "gate_control"
VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent.parent
POLICIES = ROOT / "policies"
ZERO_HASH = "0" * 64

# Check bodies whose bytes produced a control outcome. Everything else under
# tools/ (harness glue, caches, reports) is not part of gate_impl_digest.
CHECK_BODY_FILES = (
    "tools/authz_matrix.py",
    "tools/arch_check.py",
    "tools/guard_delta.py",
    "tools/oracle_provenance.py",
    "tools/semgrep_runner.py",
    "tools/smell.py",
    "tools/gate_run.py",
    "tools/policy_digest.py",
    # The AGT OpenCode adapter body (single plugin artifact) lives outside
    # files/; the path is relative to this tools root.
    "../.opencode/plugins/agt.js",
)
FIXTURE_EXCLUDES = {
    "tools/fixtures/authz_control/control-matrix.json",
    "tools/fixtures/authz_control/control-missing.json",
}


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def policy_digest() -> str:
    sys.path.insert(0, str(ROOT / "tools"))
    import policy_digest as pd  # noqa: PLC0415 - local tool import

    files = pd.collect(str(POLICIES))
    return sha256_text(canonical(files))


def gate_impl_digest() -> str:
    """Hash only the check bodies and fixtures that produced the control outcomes.

    Additional AGT check bodies and harness-level inputs are stored relative to
    the harness root (the parent of files/) with forward slashes.

    6C-4 (F-77): the MCP server (files/tools/mcp/**: registry.json,
    controls.json, core/server.py, family handlers, gen_perms.py) and the K1
    probe client are sealed here. Harness files absent on disk are skipped
    (opencode.json is gitignored after purge-prep 71d0137), matching
    policy_manifest.collect() so the digest is reproducible from tracked files.
    """
    harness_files = (
        "files/tools/agt_parity.py",
        "files/tools/agt_audit.py",
        ".agt/policy.json",
        "opencode.json",
        ".opencode/package.json",
        ".opencode/package-lock.json",
    )
    files = []
    for rel in CHECK_BODY_FILES:
        path = ROOT / rel
        if not path.is_file():
            continue
        files.append(
            {
                "path": rel,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    fixtures = ROOT / "tools" / "fixtures"
    for base, dirs, names in os.walk(fixtures):
        dirs[:] = sorted(name for name in dirs if name != "__pycache__")
        for name in sorted(names):
            if name.endswith(".pyc"):
                continue
            path = Path(base) / name
            rel = path.relative_to(ROOT).as_posix()
            if rel in FIXTURE_EXCLUDES:
                continue
            files.append(
                {
                    "path": rel,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    harness_root = ROOT.parent
    for rel in harness_files:
        path = harness_root / rel
        if not path.is_file():
            continue
        files.append(
            {
                "path": rel,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    # 6C-4 MCP server seal: the whole files/tools/mcp tree plus the K1 probe
    # client. Skips __pycache__/*.pyc like the fixtures walk above.
    mcp_root = harness_root / "files" / "tools" / "mcp"
    if mcp_root.is_dir():
        for base, dirs, names in os.walk(mcp_root):
            dirs[:] = sorted(name for name in dirs if name != "__pycache__")
            for name in sorted(names):
                if name.endswith(".pyc"):
                    continue
                path = Path(base) / name
                rel = path.relative_to(harness_root).as_posix()
                files.append(
                    {
                        "path": rel,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )
    for rel in ("files/docker/k1/probe_client.py",):
        path = harness_root / rel
        if not path.is_file():
            continue
        files.append(
            {
                "path": rel,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    files.sort(key=lambda item: item["path"])
    return sha256_text(canonical(files))


def resolved_manifest(manifest: dict) -> list[dict]:
    entries = []
    for check_id, parent in sorted((manifest.get("controls") or {}).items()):
        min_count = int(parent.get("min_count", 0))
        for control in parent.get("controls") or []:
            entries.append(
                {
                    "check_id": check_id,
                    "control_id": control["control_id"],
                    "fixture_ref": control["fixture_ref"],
                    "runner": control["runner"],
                    "expected_outcome": control["expected_outcome"],
                    "min_count": min_count,
                }
            )
    entries.sort(key=lambda item: (item["check_id"], item["control_id"]))
    return entries


# Phase 3 decision 1 -- split counts. Two different counts used to share the
# name controls_total: the manifest header meant the DECLARED count (53) while
# gate-control records use controls_total for the KNOWN-BAD count (28). The
# canonical manifest keys are now controls_declared (53) and known_bad_total
# (28); record.controls_total keeps the known-bad meaning (== len(bad)).
# Transition: readers accept the legacy manifest.controls_total as an alias for
# controls_declared until every writer has migrated. New code must use
# manifest_declared() and never confuse it with record.controls_total.
def manifest_declared(manifest: dict) -> int:
    for key in ("controls_declared", "controls_total"):
        if key in manifest:
            return int(manifest[key])
    active = sum(
        len(parent.get("controls") or [])
        for parent in (manifest.get("controls") or {}).values()
    )
    return active + len(manifest.get("retired_controls") or [])


# Retirement slack (tombstone buffer). A control is retired by deleting it from
# controls and appending a tombstone to retired_controls; tombstones preserve
# every count (per-check min_count, known_bad_min, total_min, declared header),
# so one sanctioned retirement fires none of those checks. A silent deletion
# (no tombstone) still undercounts and fails -- that is the point: the buffer
# makes a deliberate retirement cheap without making deletion free. Tombstones
# are hashed, so counts cannot be faked by forging tombstones.
def resolved_tombstones(manifest: dict) -> list[dict]:
    tombstones = [
        {"check_id": tomb["check_id"], "control_id": tomb["control_id"]}
        for tomb in manifest.get("retired_controls") or []
    ]
    tombstones.sort(key=lambda item: (item["check_id"], item["control_id"]))
    return tombstones


def thresholds(manifest: dict) -> dict:
    entries = resolved_manifest(manifest)
    tombstones = resolved_tombstones(manifest)
    known_bad_total = manifest.get("known_bad_total")
    if known_bad_total is None:
        known_bad_total = (
            sum(1 for entry in entries if entry["expected_outcome"] == "FAIL")
            + len(tombstones)
        )
    return {
        "controls_declared": manifest_declared(manifest),
        "known_bad_total": int(known_bad_total),
        "known_bad_min": int(
            manifest.get("known_bad_min", manifest.get("total_min", 0))
        ),
        "total_min": int(manifest.get("total_min", 0)),
    }


def control_set_sha(manifest: dict) -> str:
    payload = {
        "controls": resolved_manifest(manifest),
        "retired_controls": resolved_tombstones(manifest),
        "thresholds": thresholds(manifest),
    }
    return sha256_text(canonical(payload))


def gate_sha(repo: Path, gate: dict) -> str:
    paths = list(gate.get("gate_paths") or [])
    # This harness nests the factory under files/ (gate_paths such as
    # "tools/**" are files/-relative), while the default repo is the
    # harness toplevel. When the repo root has no tools/ but repo/files/
    # does, run git from files/ so the pathspecs resolve there. In the
    # audited factory repo (tools/ at root) behavior is unchanged.
    cwd = repo
    if not (repo / "tools").is_dir() and (repo / "files" / "tools").is_dir():
        cwd = repo / "files"
    process = subprocess.run(
        ["git", "-C", str(cwd), "log", "-1", "--format=%H", "--", *paths],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    value = process.stdout.strip()
    if process.returncode != 0 or not value:
        raise RuntimeError(
            "git log for gate paths failed: "
            + (process.stderr.strip() or f"exit {process.returncode}")
        )
    return value


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


def run_command(command: str) -> tuple[int, str, str]:
    parts = shlex.split(command)
    # Semgrep control self-tests run with --allow-fallback so they pass on
    # binary-less hosts; live scans (no --control) stay strict and untouched.
    if (
        parts
        and parts[0].endswith("semgrep_runner.py")
        and "--control" in parts
        and "--allow-fallback" not in parts
    ):
        parts.append("--allow-fallback")
    if parts and parts[0].endswith(".py"):
        parts = [sys.executable, str(ROOT / parts[0]), *parts[1:]]
    try:
        process = subprocess.Popen(
            parts,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
    except OSError as exc:
        return 2, "", f"ERROR: failed to start command: {exc}"
    try:
        # 6C-4: semgrep --control runs the binary plus AST/regex
        # fallbacks and takes ~60s on this host; 180 keeps the bound
        # finite without changing any control semantics or outcomes.
        stdout, stderr = process.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", ""
        message = "ERROR: command timed out after 180s"
        return 2, stdout or "", (stderr or "") + ("\n" if stderr else "") + message
    return process.returncode, stdout or "", stderr or ""


def case_outcome(case: dict) -> str | None:
    actual = case.get("actual") or {}
    if isinstance(actual, dict):
        if actual.get("outcome") in {"PASS", "FAIL"}:
            return str(actual["outcome"])
        if "findings" in actual:
            return "FAIL" if int(actual["findings"]) > 0 else "PASS"
        if "exit_code" in actual:
            return "FAIL" if int(actual["exit_code"]) != 0 else "PASS"
    # No actual envelope (outcome/findings/exit_code): do not infer from the
    # case's own passed flag.
    return None


def match_case(cases: list[dict], fixture_ref: str) -> dict | None:
    """Pick the case whose trailing path segments match the fixture ref best.

    Two fixtures can share a basename (bad/bad_key.py vs baseline/bad_key.py),
    so a basename-only match is ambiguous. Score each case by how many trailing
    path segments of the normalized ref it matches; the highest scorer wins.
    """
    ref_segments = [part for part in fixture_ref.replace("\\", "/").split("/") if part]
    best: dict | None = None
    best_score = 0
    for case in cases:
        segments = [part for part in str(case.get("name", "")).replace("\\", "/").split("/") if part]
        score = 0
        for ref_part, case_part in zip(reversed(ref_segments), reversed(segments)):
            if ref_part.lower() != case_part.lower():
                break
            score += 1
        if score > best_score:
            best_score = score
            best = case
    return best


def observed_for(entry: dict) -> tuple[str, str | None]:
    # P0: keep ERROR handling intact. A strict live BLOCKED (exit 2, no control
    # cases) still surfaces as ERROR via the no-match branch below; the
    # --allow-fallback injection in run_command only affects --control runners.
    code, stdout, stderr = run_command(entry["runner"])
    if "authz_matrix.py" in entry["runner"]:
        return ("FAIL" if code != 0 else "PASS"), (stderr.strip() or None)
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError:
        return "ERROR", (stderr.strip() or stdout.strip() or "runner output is not JSON")
    control = envelope.get("control") or {}
    cases = list(control.get("cases") or [])
    case = match_case(cases, entry["fixture_ref"])
    if case is None:
        return "ERROR", f"no control case matched {entry['fixture_ref']!r}"
    outcome = case_outcome(case)
    if outcome is None:
        # No actual envelope: never infer observed from passed/expected.
        return "ERROR", (
            f"no actual envelope in control case for {entry['fixture_ref']!r}: "
            "missing outcome/findings/exit_code; passed-only outputs are rejected"
        )
    return outcome, None


def previous_hash(out_dir: Path, before: Path | None = None) -> str:
    records = sorted(
        path for path in out_dir.glob("*.json") if path.name != "verify.json"
    )
    if before is not None:
        try:
            index = records.index(before)
        except ValueError:
            index = len(records)
        records = records[:index]
    if not records:
        return ZERO_HASH
    last = load_json(records[-1])
    value = str(last.get("record_hash", ""))
    if len(value) != 64:
        raise RuntimeError(f"previous record {records[-1]} has no record_hash")
    return value


def seal(record: dict) -> dict:
    body = {key: value for key, value in record.items() if key != "record_hash"}
    record["record_hash"] = sha256_text(canonical(body))
    return record


def build(repo: Path, manifest: dict, gate: dict) -> dict:
    entries = resolved_manifest(manifest)
    tombstones = resolved_tombstones(manifest)
    tomb_by_check: dict[str, int] = {}
    for tomb in tombstones:
        tomb_by_check[tomb["check_id"]] = tomb_by_check.get(tomb["check_id"], 0) + 1
    controls = []
    errors: list[str] = []
    for entry in entries:
        observed, error = observed_for(entry)
        if error:
            errors.append(f"{entry['control_id']}: {error}")
            observed = "ERROR"
        controls.append(
            {
                "check_id": entry["check_id"],
                "control_id": entry["control_id"],
                "fixture_ref": entry["fixture_ref"],
                "expected_outcome": entry["expected_outcome"],
                "observed_outcome": observed,
                "rejected": observed == "FAIL",
            }
        )
    bad = [item for item in controls if item["expected_outcome"] == "FAIL"]
    rejected = [item for item in bad if item["rejected"] is True]
    matched = all(
        item["observed_outcome"] == item["expected_outcome"] for item in controls
    )
    minima = {
        check_id: int(parent.get("min_count", 0))
        for check_id, parent in (manifest.get("controls") or {}).items()
    }
    counts = {
        check: sum(1 for item in bad if item["check_id"] == check)
        + tomb_by_check.get(check, 0)
        for check in minima
    }
    under = [
        f"{check}:{counts[check]}/{minimum}"
        for check, minimum in minima.items()
        if counts[check] < minimum
    ]
    total_min = int(manifest.get("total_min", 0))
    known_bad_min = int(manifest.get("known_bad_min", total_min))
    total = len(bad)
    effective_total = total + len(tombstones)
    effective_declared = len(entries) + len(tombstones)
    ok = (
        matched
        and len(rejected) == total
        and effective_total >= known_bad_min
        and effective_declared >= total_min
        and not under
        and not errors
    )
    out_dir = ROOT / "quality" / "ledger" / "gate-control"
    record = {
        "schema": "gate-control/1",
        "gate_sha": gate_sha(repo, gate),
        "gate_impl_digest": gate_impl_digest(),
        "policy_digest": policy_digest(),
        "control_set_sha": control_set_sha(manifest),
        "controls_total": total,
        "controls_rejected": len(rejected),
        "controls_declared": effective_declared,
        "known_bad_min": known_bad_min,
        "all_rejected": matched and len(rejected) == total,
        "result": "PASS" if ok else "FAIL",
        "state": "PASS",
        "superseded_by": None,
        "controls": controls,
        "engine": "none",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "sig_status": "unsigned_local",
        "prev_hash": previous_hash(out_dir),
    }
    if errors:
        record["errors"] = errors
    return seal(record)


def verify(
    path: Path,
    manifest: dict,
    gate: dict,
    repo: Path,
    _seen: set[str] | None = None,
) -> dict:
    record = load_json(path)
    body = {key: value for key, value in record.items() if key != "record_hash"}
    problems: list[str] = []
    if sha256_text(canonical(body)) != record.get("record_hash"):
        problems.append("record_hash does not recompute")
    if record.get("prev_hash") != previous_hash(path.parent, before=path):
        problems.append("prev_hash does not match the previous record")

    if record.get("state") == "SUPERSEDED":
        # A superseded record is a historical link only. Its policy/impl hashes
        # are expected to be stale; only chain integrity and a verified newest
        # record matter.
        target_name = record.get("superseded_by")
        if not isinstance(target_name, str) or not target_name:
            problems.append("superseded_by is not a file name")
        else:
            target = path.parent / target_name
            siblings = sorted(
                item for item in path.parent.glob("*.json") if item.name != "verify.json"
            )
            newest = siblings[-1] if siblings else None
            if target.parent.resolve() != path.parent.resolve() or not target.is_file():
                problems.append(
                    f"superseded_by {target_name!r} is not a file in this directory"
                )
            elif newest is None or target.resolve() != newest.resolve():
                problems.append(
                    f"superseded_by {target_name!r} does not name the newest record"
                )
            else:
                seen = set(_seen or ())
                key = path.resolve().as_posix()
                if key in seen:
                    problems.append("superseded_by chain contains a cycle")
                else:
                    seen.add(key)
                    nested = verify(target, manifest, gate, repo, seen)
                    if nested["result"] != "PASS":
                        problems.append(
                            "superseded_by record does not verify: "
                            + "; ".join(nested["problems"])
                        )
    else:
        if record.get("sig_status") != "unsigned_local":
            problems.append("sig_status is not unsigned_local")
        if record.get("policy_digest") != policy_digest():
            problems.append("policy_digest differs from the live policies tree")
        if record.get("gate_impl_digest") != gate_impl_digest():
            problems.append("gate_impl_digest differs from the live tools tree")
        if record.get("control_set_sha") != control_set_sha(manifest):
            problems.append("control_set_sha differs from the resolved manifest")
        if record.get("gate_sha") != gate_sha(repo, gate):
            problems.append("gate_sha differs from git log over the gate paths")
        controls = list(record.get("controls") or [])
        bad = [item for item in controls if item.get("expected_outcome") == "FAIL"]
        rejected = [item for item in bad if item.get("rejected") is True]
        if record.get("controls_total") != len(bad):
            problems.append("controls_total does not match the known-bad controls")
        if record.get("controls_rejected") != len(rejected):
            problems.append("controls_rejected does not match the rejected controls")
        if len(rejected) != len(bad):
            problems.append("not every known-bad control was rejected")
        # Tombstones (retired controls) preserve counts; see resolved_tombstones.
        tombstones = resolved_tombstones(manifest)
        tomb_by_check: dict[str, int] = {}
        for tomb in tombstones:
            tomb_by_check[tomb["check_id"]] = tomb_by_check.get(tomb["check_id"], 0) + 1
        active_ids = {str(item.get("control_id")) for item in controls}
        for tomb in tombstones:
            if tomb["check_id"] not in (manifest.get("controls") or {}):
                problems.append(
                    f"tombstone {tomb['control_id']} names unknown check "
                    f"{tomb['check_id']}"
                )
            if tomb["control_id"] in active_ids:
                problems.append(
                    f"tombstone {tomb['control_id']} is also an active control"
                )
        if len({(t["check_id"], t["control_id"]) for t in tombstones}) != len(
            tombstones
        ):
            problems.append("duplicate retired_controls tombstones")
        minima = {
            check: int(parent.get("min_count", 0))
            for check, parent in (manifest.get("controls") or {}).items()
        }
        for check, minimum in minima.items():
            count = (
                sum(1 for item in bad if item.get("check_id") == check)
                + tomb_by_check.get(check, 0)
            )
            if count < minimum:
                problems.append(f"{check} has {count} controls, minimum {minimum}")
        known_bad_min = int(
            manifest.get("known_bad_min", manifest.get("total_min", 0))
        )
        effective_total = len(bad) + len(tombstones)
        if effective_total < known_bad_min:
            problems.append("controls_total is below known_bad_min")
        effective_declared = len(controls) + len(tombstones)
        if record.get("controls_declared") != effective_declared:
            problems.append("controls_declared does not match the control list")
        if record.get("controls_declared") != manifest_declared(manifest):
            problems.append("controls_declared differs from the manifest controls_declared")
        total_min = int(manifest.get("total_min", 0))
        if effective_declared < total_min:
            problems.append("effective declared total is below total_min")
        if record.get("result") != "PASS" or record.get("all_rejected") is not True:
            problems.append("record did not pass")

    controls = list(record.get("controls") or [])
    return {
        "schema": "gate-control-verify/1",
        "record": str(path),
        "record_hash": record.get("record_hash"),
        "state": record.get("state"),
        "result": "PASS" if not problems else "FAIL",
        "problems": problems,
        "controls_total": record.get("controls_total"),
        "controls_rejected": record.get("controls_rejected"),
        "controls": len(controls),
        "exit_code": 0 if not problems else 1,
    }


def verify_chain(out_dir: Path, manifest: dict, gate: dict, repo: Path) -> dict:
    records = sorted(
        item for item in out_dir.glob("*.json") if item.name != "verify.json"
    )
    problems: list[str] = []
    superseded: list[str] = []
    if not records:
        return {
            "schema": "gate-control-chain/1",
            "chain_size": 0,
            "superseded": [],
            "newest": None,
            "newest_result": "ERROR",
            "problems": ["no gate-control records found"],
            "exit_code": 2,
        }
    newest = records[-1]
    for path in records[:-1]:
        superseded.append(path.name)
        record = load_json(path)
        if record.get("state") != "SUPERSEDED":
            problems.append(f"{path.name}: state is not SUPERSEDED")
        if record.get("superseded_by") != newest.name:
            problems.append(
                f"{path.name}: superseded_by does not name {newest.name}"
            )
        result = verify(path, manifest, gate, repo)
        if result["result"] != "PASS":
            problems.extend(f"{path.name}: {item}" for item in result["problems"])
    newest_result = verify(newest, manifest, gate, repo)
    if newest_result["result"] != "PASS":
        problems.extend(f"{newest.name}: {item}" for item in newest_result["problems"])
    return {
        "schema": "gate-control-chain/1",
        "chain_size": len(records),
        "superseded": superseded,
        "newest": newest.name,
        "newest_result": newest_result["result"],
        "problems": problems,
        "exit_code": 0 if not problems else 1,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=None, help="audited repository (default: git toplevel of cwd)")
    parser.add_argument("--manifest", default=str(POLICIES / "negative-controls.json"))
    parser.add_argument("--gate", default=str(POLICIES / "gate.json"))
    parser.add_argument("--out", default=str(ROOT / "quality" / "ledger" / "gate-control"))
    parser.add_argument("--write", action="store_true", help="append the sealed record")
    parser.add_argument("--verify", default=None, help="verify a sealed record")
    parser.add_argument(
        "--verify-chain",
        action="store_true",
        help="verify every record in the chain: older records SUPERSEDED, newest PASS",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    manifest = load_json(Path(args.manifest))
    gate = load_json(Path(args.gate))

    try:
        repo = resolve_repo(args.repo)
        if args.verify_chain:
            result = verify_chain(Path(args.out).resolve(), manifest, gate, repo)
        elif args.verify:
            result = verify(Path(args.verify).resolve(), manifest, gate, repo)
        else:
            record = build(repo, manifest, gate)
            if args.write:
                out_dir = Path(args.out).resolve()
                out_dir.mkdir(parents=True, exist_ok=True)
                sequence = len(list(out_dir.glob("*.json"))) + 1
                path = out_dir / f"{sequence:04d}-{record['gate_sha'][:12]}.json"
                path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
                result = {
                    "schema": "gate-control-run/1",
                    "record": str(path),
                    "record_hash": record["record_hash"],
                    "result": record["result"],
                    "controls_total": record["controls_total"],
                    "controls_rejected": record["controls_rejected"],
                    "controls": len(record["controls"]),
                    "exit_code": 0 if record["result"] == "PASS" else 1,
                }
            else:
                result = record
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(
            json.dumps(
                {
                    "schema": "gate-control-run/1",
                    "result": "ERROR",
                    "error": f"{type(exc).__name__}: {exc}",
                    "exit_code": 2,
                },
                sort_keys=True,
            )
        )
        return 2

    if args.json or True:
        print(json.dumps(result, indent=2, sort_keys=True))
    return int(result.get("exit_code", 0))

if __name__ == "__main__":
    raise SystemExit(main())
