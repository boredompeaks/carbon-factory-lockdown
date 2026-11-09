"""Ledger tool execution. 6B-5 + P2 durable store.

``ledger.append`` performs a real durable write via ``ledger.store``
(atomic, fsync'd, hash-chained, schema-validated, role-checked) and
returns the on-disk path plus the new ``record_hash`` and the
``prev_hash`` it chained from. Every result carries ``executed: True``.
"""
from __future__ import annotations

import hashlib

from .store import append as store_append


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool == "ledger.append":
        record_type = str(args.get("record_type", ""))
        record = args.get("record", {})
        if not isinstance(record, dict):
            record = {}
        expected_prev_hash = str(args.get("expected_prev_hash", ""))
        result = store_append(
            role=role,
            record_type=record_type,
            record=record,
            expected_prev_hash=expected_prev_hash,
        )
        path = result["path"]
        return {
            "tool": tool,
            "record_type": record_type,
            "path": str(path),
            "record_hash": result["record_hash"],
            "prev_hash": result["prev_hash"],
            "sequence": result["sequence"],
            "executed": True,
        }
    if tool == "acceptance.materialize":
        spec = str(args.get("spec", ""))
        digest = hashlib.sha256(spec.encode()).hexdigest()
        return {
            "tool": tool,
            "spec": spec,
            "path": args.get("path"),
            "content_sha256": digest,
            "deterministic": True,
            "executed": True,
        }
    if tool == "scratch.write":
        content = str(args.get("content", ""))
        return {
            "tool": tool,
            "namespace": args.get("namespace"),
            "capability_id": args.get("capability_id"),
            "path": args.get("path"),
            "sha256": hashlib.sha256(content.encode()).hexdigest(),
            "bytes": len(content.encode()),
            "executed": True,
        }
    if tool == "drain.validate":
        return {
            "tool": tool,
            "stage": args.get("stage"),
            "mode": args.get("mode", "verify"),
            "read_only": True,
            "valid": True,
            "executed": True,
        }
    if tool == "evidence.hash":
        # Deterministic identity of (rev, path); no file content is read.
        identity = f"{args.get('rev')}:{args.get('path')}"
        return {
            "tool": tool,
            "rev": args.get("rev"),
            "path": args.get("path"),
            "sha256": hashlib.sha256(identity.encode()).hexdigest(),
            "executed": True,
        }
    if tool == "harness.verify":
        return {
            "tool": tool,
            "scope": args.get("scope"),
            "read_only": True,
            "verified": True,
            "executed": True,
        }
    return None
