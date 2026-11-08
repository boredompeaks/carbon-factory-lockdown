"""Hacker execution. 6B-4.

Deterministic stubs: run ids derive from the capability + actor +
item, probe records conform to the probe-record schema
(item_id, probe_class, endpoint, tenant_pair, engine, outcome,
evidence_ref), batch/barrier race modes are honoured as bounded
repeats, and scan/repro results are capped and redacted.
"""
from __future__ import annotations

import hashlib


def _run_id(capability_id: str, actor: str, item_id: str) -> str:
    return hashlib.sha256(f"{capability_id}|{actor}|{item_id}".encode()).hexdigest()[:12]


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool == "hacker.probe":
        item_id = str(args.get("item_id", ""))
        cap = str(args.get("capability_id", ""))
        actor = str(args.get("actor", ""))
        repeats = 3 if args.get("batch") else 1
        if args.get("barrier"):
            repeats = max(repeats, 2)
        records = []
        for i in range(repeats):
            records.append({
                "item_id": item_id,
                "probe_class": item_id,
                "endpoint": args.get("endpoint", "/api/health"),
                "tenant_pair": args.get("tenant_pair", ["tenant-a", "tenant-b"]),
                "engine": "k1",
                "outcome": "REFUTED",
                "evidence_ref": f"probe:{_run_id(cap, actor, item_id)}:{i}",
            })
        return {"tool": tool, "run_id": _run_id(cap, actor, item_id),
                "actor": actor, "item_id": item_id, "records": records,
                "counts": {"total": repeats, "refuted": repeats},
                "no_redirects": True, "header_denylist": ["host", "content-length"]}
    if tool == "repro.run":
        runs = int(args.get("runs", 1))
        return {"tool": tool, "spec": args.get("spec"), "runs": runs,
                "engine": args.get("engine", "sqlite"), "outcomes": ["PASS"] * runs}
    if tool == "static.scan":
        # Read-only scan: report static_match findings without executing.
        path = str(args.get("path", ""))
        return {"tool": tool, "path": path,
                "findings": [{"class": "PROMPT_INJECTION_ATTEMPT", "path": path,
                              "static_match": True}], "read_only": True}
    return None
