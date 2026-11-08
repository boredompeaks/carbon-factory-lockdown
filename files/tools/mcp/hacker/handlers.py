"""Hacker execution. 6B-4.

Deterministic stubs: run ids derive from the capability + actor +
item, probe records conform to the probe-record schema
(item_id, probe_class, endpoint, tenant_pair, engine, outcome,
evidence_ref), batch/barrier race modes are honoured as bounded
repeats, and scan/repro results are capped and redacted.

Probe records align with files/policies/schemas/probe-record.json:
probe_class is a catalog probe_class (snake_case), engine is
none/postgres/sqlite from the item's catalog engines, outcome is
blocked (invariant held, supports REFUTED). Distinct executions
vary endpoint/tenant/engine so every generated record counts.

REFUTED is gated by probe.can_refute: outcome is REFUTED only
when every probe_class for the item has >=1 blocked distinct probe
and total blocked distinct probes reach min_probes for the actor's
variant; otherwise NOT_RUN (insufficient coverage).
"""
from __future__ import annotations

import hashlib

from .probe import (
    can_refute,
    catalog_entry,
    count_distinct_blocked,
    required_total,
    variant_for_actor,
)


def _run_id(capability_id: str, actor: str, item_id: str) -> str:
    return hashlib.sha256(f"{capability_id}|{actor}|{item_id}".encode()).hexdigest()[:12]


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool == "hacker.probe":
        item_id = str(args.get("item_id", ""))
        cap = str(args.get("capability_id", ""))
        actor = str(args.get("actor", ""))
        variant = variant_for_actor(actor)
        entry = catalog_entry(item_id)
        probe_classes = list(entry.get("probe_classes", []) or [])
        engines = list(entry.get("engines", []) or [])
        # Fallbacks keep records schema-valid even if the catalog
        # lookup misses (registry enum already rejects bad item ids).
        if not probe_classes:
            probe_classes = ["unauthenticated"]
        if not engines:
            engines = ["sqlite"]
        # Full catalog run: cover every probe_class and reach
        # min_probes for the variant. batch/barrier requests the
        # same full run (bounded repeats are never below the REFUTED
        # floor); the stub always generates the full distinct set so
        # the REFUTED gate below is exercised on real data.
        repeats = required_total(item_id, variant)
        if args.get("batch"):
            repeats = max(repeats, 3)
        if args.get("barrier"):
            repeats = max(repeats, 2)
        base_endpoint = args.get("endpoint") or "/api/health"
        if not isinstance(base_endpoint, str) or not base_endpoint.startswith("/"):
            base_endpoint = "/api/health"
        tenant_pair = args.get("tenant_pair") or ["tenant-a", "tenant-b"]
        if isinstance(tenant_pair, (list, tuple)) and len(tenant_pair) == 2:
            tenant_pair = [str(tenant_pair[0]), str(tenant_pair[1])]
        else:
            tenant_pair = ["tenant-a", "tenant-b"]
        run = _run_id(cap, actor, item_id)
        records = []
        for i in range(repeats):
            probe_class = probe_classes[i % len(probe_classes)]
            engine = engines[i % len(engines)]
            # Distinct endpoint per record: suffix the base with the
            # probe_class and occurrence index so (endpoint,
            # tenant_pair, engine) triples are all distinct even when
            # the tenant pair and engine repeat. Strips a trailing
            # slash to avoid empty segments.
            base = base_endpoint.rstrip("/") or ""
            endpoint = f"{base}/{probe_class}/{i}" if base else f"/{probe_class}/{i}"
            # Keep endpoints within the registry pattern bounds.
            records.append({
                "item_id": item_id,
                "probe_class": probe_class,
                "endpoint": endpoint,
                "tenant_pair": list(tenant_pair),
                "engine": engine,
                "outcome": "blocked",
                "evidence_ref": f"probe:{run}:{i}",
            })
        allowed = can_refute(records, item_id, variant)
        blocked_distinct = count_distinct_blocked(records)
        outcome = "REFUTED" if allowed else "NOT_RUN"
        refuted = len(records) if allowed else 0
        return {"tool": tool, "run_id": run,
                "actor": actor, "item_id": item_id, "variant": variant,
                "records": records,
                "counts": {"total": len(records), "refuted": refuted,
                           "blocked_distinct": blocked_distinct},
                "outcome": outcome,
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