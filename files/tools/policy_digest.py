#!/usr/bin/env python3
"""POLICY_DIGEST -- deterministic hash of the policy contract inputs.

The gate-control cache key is (gate_sha, control_set_sha, policy_digest). A
changed policy artifact invalidates a cached control run: the digest below must
match the one in the gate-control record before any dispatch.

The digest covers all security-deciding files discovered dynamically under
policies/**: every ``*.json`` file plus ``semgrep.yml`` (except the
owner-only ``policy-manifest.json`` inventory and the ``schemas/`` subtree).
A new policy file is therefore covered automatically with no code change;
``schemas/`` and the inventory itself are covered by the policy manifest.

Discovery is recursive: any ``*.json`` or ``semgrep.yml`` at any depth under
the policies root is included unless it is ``policy-manifest.json`` at the
root or under ``schemas/``. Relative POSIX paths (for example,
``subdir/new-policy.json``) are used, sorted, so top-level files keep the
plain file-name paths used historically.

Hash rule: sorted (relative POSIX path, sha256(file bytes)) pairs, serialized as
canonical JSON, then sha256. Raw bytes, so CRLF/LF differences are real policy
changes and are not normalized away. A missing policies directory or an empty
discovery set (no covered files) is a tool error (FileNotFoundError, caught
as OSError in main and reported with exit code 2).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

VERSION = "1.3.0"

# Root-relative POSIX path of the inventory, excluded from the digest.
EXCLUDED_REL_PATHS = frozenset({"policy-manifest.json"})
# Top-level subtree names excluded from the digest (policies/schemas/**).
EXCLUDED_TOP_LEVEL_DIRS = frozenset({"schemas"})


def collect(root: str) -> list[dict]:
    """Discover covered files under ``root`` and hash each file's raw bytes.

    Include: ``**/*.json`` plus ``**/semgrep.yml``.
    Exclude: ``policy-manifest.json`` (root-relative) and ``schemas/**``.

    Raises FileNotFoundError when ``root`` is missing/not a directory or
    when no covered file is discovered (empty directory semantics).
    """
    root_path = Path(root)
    if not root_path.is_dir():
        raise FileNotFoundError(f"policies directory not found: {root}")
    candidates = list(root_path.rglob("*.json")) + list(root_path.rglob("semgrep.yml"))
    by_path: dict[str, dict] = {}
    for path in candidates:
        rel = path.relative_to(root_path)
        rel_posix = rel.as_posix()
        if rel_posix in EXCLUDED_REL_PATHS:
            continue
        if rel.parts and rel.parts[0] in EXCLUDED_TOP_LEVEL_DIRS:
            continue
        if not path.is_file():
            continue
        with open(path, "rb") as handle:
            file_digest = hashlib.sha256(handle.read()).hexdigest()
        by_path[rel_posix] = {"path": rel_posix, "sha256": file_digest}
    files = sorted(by_path.values(), key=lambda item: item["path"])
    if not files:
        raise FileNotFoundError(f"no policy files discovered under {root}")
    return files


def digest(root: str) -> tuple[str, list[dict]]:
    files = collect(root)
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest(), files


def control() -> dict:
    """Prove the digest notices a byte change and a missing file, and stays stable."""
    cases: list[dict] = []
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        # Minimal representative set; "extra-policy.json" is a novel name that
        # a static list would never cover, proving dynamic auto-inclusion.
        (root / "tiers.json").write_text('{"a":1}', encoding="utf-8")
        (root / "severity.json").write_text('{"a":1}', encoding="utf-8")
        (root / "semgrep.yml").write_text("rules: []\n", encoding="utf-8")
        (root / "extra-policy.json").write_text('{"x":1}', encoding="utf-8")
        # Excluded inputs that must never enter the discovery set.
        (root / "policy-manifest.json").write_text('{"inventory": true}', encoding="utf-8")
        schemas = root / "schemas"
        schemas.mkdir()
        (schemas / "ignored.json").write_text('{"ignored": true}', encoding="utf-8")
        first, first_files = digest(str(root))
        second, _ = digest(str(root))
        discovered = {item["path"] for item in first_files}
        auto_included = "extra-policy.json" in discovered
        exclusions_ok = "policy-manifest.json" not in discovered and "schemas/ignored.json" not in discovered
        clean_passed = first == second and auto_included and exclusions_ok
        cases.append(
            {
                "name": "policy-clean",
                "expected": "PASS",
                "actual": {"outcome": "PASS" if clean_passed else "FAIL"},
                "passed": clean_passed,
            }
        )
        (root / "tiers.json").write_text('{"a":2}', encoding="utf-8")
        mutated, _ = digest(str(root))
        cases.append(
            {
                "name": "policy-byte-change",
                "expected": "FAIL",
                "actual": {"outcome": "FAIL" if mutated != first else "PASS"},
                "passed": mutated != first,
            }
        )
        empty = root / "empty"
        empty.mkdir()
        try:
            digest(str(empty))
        except FileNotFoundError:
            missing_detected = True
        else:
            missing_detected = False
        cases.append(
            {
                "name": "policy-missing-file",
                "expected": "FAIL",
                "actual": {"outcome": "FAIL" if missing_detected else "PASS"},
                "passed": missing_detected,
            }
        )
    return {"ran": True, "passed": all(case["passed"] for case in cases), "cases": cases}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policies",
        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policies"),
        help="directory holding the covered policy files",
    )
    parser.add_argument("--check", default=None, help="expected digest")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--control",
        action="store_true",
        help="run the digest control cases (clean, byte change, missing file)",
    )
    args = parser.parse_args(argv)

    if args.control:
        control_doc = control()
        code = 0 if control_doc["passed"] else 1
        print(
            json.dumps(
                {
                    "schema": "factory-tool/1",
                    "tool": "policy_digest",
                    "version": VERSION,
                    "interpreter": sys.executable,
                    "result_type": "RESULT" if code == 0 else "CONTROL_FAIL",
                    "control": control_doc,
                    "exit_code": code,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return code

    try:
        value, files = digest(args.policies)
    except OSError as exc:
        print(json.dumps({"schema": "factory-tool/1", "tool": "policy_digest",
                          "version": VERSION, "result_type": "ERROR",
                          "error": str(exc), "exit_code": 2}, sort_keys=True))
        return 2

    mismatch = args.check is not None and args.check != value
    result = {
        "schema": "factory-tool/1",
        "tool": "policy_digest",
        "version": VERSION,
        "interpreter": sys.executable,
        "result_type": "RESULT",
        "digest": value,
        "files": files,
        "check": args.check,
        "match": not mismatch,
        "exit_code": 1 if mismatch else 0,
    }
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(f"digest: {value}")
        print(f"files: {len(files)}")
        if args.check is not None:
            print(f"check: {'MATCH' if not mismatch else 'MISMATCH'}")
    return 1 if mismatch else 0


if __name__ == "__main__":
    raise SystemExit(main())
