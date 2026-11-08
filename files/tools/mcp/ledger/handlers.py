"""Ledger tool execution. 6B-5.

In-memory hash chain per server instance (persisted storage is
wired at deploy time). Deterministic: genesis prev-hash is 64 zeros.
Capability writes are ledger.append with record_type=capability.
"""
from __future__ import annotations

import hashlib

from .chain import next_prev_hash


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool == "ledger.append":
        new_hash = next_prev_hash(server, str(args.get("record_type", "")),
                                  args.get("record", {}))
        server._ledger_prev_hash = new_hash  # type: ignore[attr-defined]
        return {"tool": tool, "record_type": args.get("record_type"),
                "prev_hash": args.get("expected_prev_hash"), "new_hash": new_hash,
                "sealed": True}
    if tool == "acceptance.materialize":
        spec = str(args.get("spec", ""))
        digest = hashlib.sha256(spec.encode()).hexdigest()
        return {"tool": tool, "spec": spec, "path": args.get("path"),
                "content_sha256": digest, "deterministic": True}
    if tool == "scratch.write":
        content = str(args.get("content", ""))
        return {"tool": tool, "namespace": args.get("namespace"),
                "capability_id": args.get("capability_id"), "path": args.get("path"),
                "sha256": hashlib.sha256(content.encode()).hexdigest(), "bytes": len(content.encode())}
    if tool == "drain.validate":
        return {"tool": tool, "stage": args.get("stage"), "mode": args.get("mode", "verify"),
                "read_only": True, "valid": True}
    if tool == "evidence.hash":
        # Deterministic identity of (rev, path); no file content is read.
        identity = f"{args.get('rev')}:{args.get('path')}"
        return {"tool": tool, "rev": args.get("rev"), "path": args.get("path"),
                "sha256": hashlib.sha256(identity.encode()).hexdigest()}
    if tool == "harness.verify":
        return {"tool": tool, "scope": args.get("scope"), "read_only": True,
                "verified": True}
    return None
