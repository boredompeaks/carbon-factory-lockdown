#!/usr/bin/env python3
"""POLICY_MANIFEST -- full inventory of the factory contract, not just the gate digest.

Two tiers are deliberately different:

* The narrow gate invalidation digest (`files/tools/policy_digest.py`) covers
  only the five files a gate check reads. Changing one of them requires a new
  gate-control seal.
* This manifest covers every policy file, schema, agent contract, installed
  twin, skill, wrapper, tool body, fixture, `opencode.json`, and `.agt/policy.json`.
  It is a drift/audit artifact: it does not feed the gate cache key.

The manifest is owner/FDE-only. Every factory agent is denied read/edit/write
on `**/policy-manifest.json`; the harness tool below may read it to verify.

Usage:
  python scripts/policy_manifest.py --write
  python scripts/policy_manifest.py --verify [--allow-drift]
  python scripts/policy_manifest.py --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ROOT / "files" / "policies"
TOOLS = ROOT / "files" / "tools"
MANIFEST = POLICIES / "policy-manifest.json"
LEDGER = ROOT / "files" / "quality" / "ledger" / "gate-control"
ZERO = "0" * 64

COVERED = (
    "tiers.json",
    "severity.json",
    "negative-controls.json",
    "check-runners.json",
    "layers.json",
)

TOOL_BODIES = (
    "files/tools/authz_matrix.py",
    "files/tools/arch_check.py",
    "files/tools/guard_delta.py",
    "files/tools/oracle_provenance.py",
    "files/tools/semgrep_runner.py",
    "files/tools/smell.py",
    "files/tools/gate_run.py",
    "files/tools/policy_digest.py",
    "files/tools/agt_parity.py",
    "files/tools/agt_audit.py",
    "files/tools/gate_control.py",
    "files/tools/validatedrain.py",
)

HARNESS_FILES = (
    "opencode.json",
    ".agt/policy.json",
    ".opencode/plugins/agt.js",
    ".opencode/package.json",
    ".opencode/package-lock.json",
)


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def add_file(rows: dict[str, str], path: Path, label: str, base: Path = ROOT) -> None:
    if not path.is_file():
        return
    if path.resolve() == MANIFEST.resolve():
        return
    rel = path.resolve().relative_to(base.resolve()).as_posix()
    rows[f"{label}:{rel}"] = sha256_file(path)


def collect() -> dict[str, str]:
    rows: dict[str, str] = {}

    # Every policy file and schema.
    for path in sorted(POLICIES.rglob("*")):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.resolve() == MANIFEST.resolve():
            continue
        add_file(rows, path, "policy")

    # Agent contracts (source + installed twin) and SOPs.
    for path in sorted((ROOT / "files").glob("*.md")):
        add_file(rows, path, "agent")
    for path in sorted((ROOT / "files" / "sop").glob("*.md")):
        add_file(rows, path, "sop")
    for path in sorted((ROOT / "files" / "docker").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            add_file(rows, path, "docker")
    for path in sorted((ROOT / "requests").glob("*.md")):
        add_file(rows, path, "request")
    for path in sorted((ROOT / ".opencode" / "agents").glob("*.md")):
        add_file(rows, path, "installed_agent")

    # Skills: every file under each skill directory (SKILL.md plus assets).
    for path in sorted((ROOT / ".opencode" / "skills").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            add_file(rows, path, "skill")

    # Wrappers and harness scripts.
    for path in sorted((ROOT / "scripts").glob("*.py")):
        add_file(rows, path, "script")
    for path in sorted((ROOT / "scripts").glob("*.ps1")):
        add_file(rows, path, "wrapper")

    # Tool bodies and fixtures that produce gate outcomes.
    for rel in TOOL_BODIES:
        add_file(rows, ROOT / rel, "tool")
    for path in sorted((TOOLS / "fixtures").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            add_file(rows, path, "fixture")

    # Harness config.
    for rel in HARNESS_FILES:
        add_file(rows, ROOT / rel, "harness")

    return dict(sorted(rows.items()))


def live_digests() -> dict:
    sys.path.insert(0, str(TOOLS))
    import gate_control as gc  # noqa: PLC0415
    import policy_digest as pd  # noqa: PLC0415

    policy_digest, _ = pd.digest(str(POLICIES))
    manifest = json.loads((POLICIES / "negative-controls.json").read_text(encoding="utf-8"))
    return {
        "policy_digest": policy_digest,
        "control_set_sha": gc.control_set_sha(manifest),
        "gate_impl_digest": gc.gate_impl_digest(),
    }


def newest_record() -> dict:
    records = sorted(
        path for path in LEDGER.glob("*.json") if path.name != "verify.json"
    )
    if not records:
        return {}
    record = json.loads(records[-1].read_text(encoding="utf-8"))
    return {
        "record": records[-1].name,
        "record_hash": record.get("record_hash"),
        "gate_sha": record.get("gate_sha"),
        "policy_digest": record.get("policy_digest"),
        "control_set_sha": record.get("control_set_sha"),
        "gate_impl_digest": record.get("gate_impl_digest"),
        "result": record.get("result"),
    }


DEPENDENCIES = {
    "policy_digest": {
        "covers": list(COVERED),
        "invalidates": [
            "gate-control.policy_digest",
            "drain R1/R2/R3.policy_digest",
            "capability.policy_digest",
            "dispatch.evidence_refs[policies]",
            "SIGNING.md",
            "policy-manifest.digests.policy_digest",
        ],
    },
    "control_set_sha": {
        "covers": "resolved negative-controls.json (check_id, control_id, fixture_ref, runner, expected_outcome, min_count)",
        "invalidates": [
            "gate-control.control_set_sha",
            "release-result.control_set_sha",
            "policy-manifest.digests.control_set_sha",
        ],
    },
    "gate_impl_digest": {
        "covers": list(TOOL_BODIES) + list(HARNESS_FILES) + ["files/tools/fixtures/**", "files/tools/agt_parity.py", "files/tools/agt_audit.py"],
        "invalidates": [
            "gate-control.gate_impl_digest",
            "policy-manifest.digests.gate_impl_digest",
        ],
    },
    "gate_sha": {
        "covers": "git log -1 over policies/gate.json gate_paths in the audited repo",
        "invalidates": ["gate-control.gate_sha", "policy-manifest.gate_control.gate_sha"],
    },
    "agent_permission": {
        "covers": [
            "files/<role>.md",
            ".opencode/agents/<role>.md",
            ".opencode/skills/*/SKILL.md",
            ".agt/policy.json allowedTools",
            "opencode.json (no widening override)",
        ],
        "invalidates": [
            "check_harness_config.py",
            "policy-manifest.files[agent|installed_agent|skill|harness]",
        ],
    },
    "schema": {
        "covers": "files/policies/schemas/*.json",
        "invalidates": ["the validator named by the schema (capability, drain-record, release-result, hacker-result, repro-spec)"],
    },
}


def build() -> dict:
    files = collect()
    digests = live_digests()
    record = newest_record()
    drift = []
    for key in ("policy_digest", "control_set_sha", "gate_impl_digest"):
        if record.get(key) and record.get(key) != digests.get(key):
            drift.append(f"{key}: live {digests.get(key)} != record {record.get(key)}")
    body = {
        "schema": "policy-manifest/2",
        "version": 2,
        "owner_only": True,
        "read_deny_rule": "**/policy-manifest.json",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "file_count": len(files),
        "files": [{"path": key, "sha256": value} for key, value in files.items()],
        "digests": digests,
        "gate_control": record,
        "drift": drift,
        "dependencies": DEPENDENCIES,
    }
    body["manifest_sha"] = sha256_bytes(canonical(body).encode("utf-8"))
    return body


def verify(path: Path, allow_drift: bool) -> dict:
    problems: list[str] = []
    if not path.is_file():
        return {"result": "FAIL", "problems": ["manifest missing"]}
    manifest = json.loads(path.read_text(encoding="utf-8"))
    body = {key: value for key, value in manifest.items() if key != "manifest_sha"}
    expected_sha = sha256_bytes(canonical(body).encode("utf-8"))
    if manifest.get("manifest_sha") != expected_sha:
        problems.append("manifest_sha does not recompute")
    current = collect()
    recorded = {row["path"]: row["sha256"] for row in manifest.get("files", [])}
    added = sorted(set(current) - set(recorded))
    removed = sorted(set(recorded) - set(current))
    changed = sorted(key for key in set(current) & set(recorded) if current[key] != recorded[key])
    if added:
        problems.append(f"files added since manifest: {added[:8]}{'...' if len(added) > 8 else ''}")
    if removed:
        problems.append(f"files removed since manifest: {removed[:8]}{'...' if len(removed) > 8 else ''}")
    if changed:
        problems.append(f"files changed since manifest: {changed[:8]}{'...' if len(changed) > 8 else ''}")
    live = live_digests()
    if manifest.get("digests") != live:
        problems.append("digests differ from the live tree")
    if not allow_drift and manifest.get("drift"):
        problems.append("manifest recorded gate-control drift: " + "; ".join(manifest["drift"]))
    return {
        "result": "PASS" if not problems else "FAIL",
        "manifest_sha": manifest.get("manifest_sha"),
        "file_count": manifest.get("file_count"),
        "problems": problems,
        "exit_code": 0 if not problems else 1,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--allow-drift", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.verify:
        result = verify(MANIFEST, args.allow_drift)
    else:
        result = build()
        if args.write:
            if MANIFEST.exists():
                os.chmod(MANIFEST, 0o666)
            MANIFEST.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            # Owner-only artifact: read-only on disk as accidental-write protection.
            os.chmod(MANIFEST, 0o444)
            result = {
                "result": "WROTE",
                "manifest": str(MANIFEST),
                "manifest_sha": result["manifest_sha"],
                "file_count": result["file_count"],
                "digests": result["digests"],
                "drift": result["drift"],
                "exit_code": 0,
            }

    print(json.dumps(result, indent=2, sort_keys=True))
    return int(result.get("exit_code", 0))


if __name__ == "__main__":
    raise SystemExit(main())
