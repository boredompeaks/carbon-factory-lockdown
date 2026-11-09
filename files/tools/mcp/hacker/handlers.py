"""Hacker execution. 6B-4, hardened phase7 (silent-skip fix).

The hacker probe path is a STUB: no K1 runtime probes execute from
this module, so it must never fabricate a REFUTED verdict. A stub
probe returns ``outcome: "NOT_RUN"``, ``stub: True``,
``executed: False`` and no blocked records. REFUTED is attainable
only through real K1 execution at deploy time (the baked-in probe
client); the stub never claims it.

Run ids still derive deterministically from capability + actor +
item, and the probe-record schema alignment (item_id, probe_class,
endpoint, tenant_pair, engine, outcome, evidence_ref) is preserved
for the real deploy path. repro.run and static.scan are likewise
explicit stubs (marked ``stub: True``) and do not claim real
execution.
"""
from __future__ import annotations

import hashlib

from .probe import (
    catalog_entry,
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
        # Catalog context is retained for determinism/audit, but the
        # stub executes NO probes: no blocked records are fabricated
        # and REFUTED is never returned.
        repeats = required_total(item_id, variant)
        if args.get("batch"):
            repeats = max(repeats, 3)
        if args.get("barrier"):
            repeats = max(repeats, 2)
        run = _run_id(cap, actor, item_id)
        return {
            "tool": tool,
            "run_id": run,
            "actor": actor,
            "item_id": item_id,
            "variant": variant,
            # Fail-closed stub: no probes ran, so no blocked records
            # and no REFUTED verdict. Callers must require real K1
            # execution for REFUTED coverage (probe.can_refute on
            # real records).
            "records": [],
            "counts": {"total": 0, "refuted": 0, "blocked_distinct": 0},
            "attempted": repeats,
            "outcome": "NOT_RUN",
            "stub": True,
            "executed": False,
            "detail": (
                "stub: no K1 runtime probes executed; REFUTED requires "
                "real K1 execution (deploy probe client), not this stub"
            ),
            "no_redirects": True,
            "header_denylist": ["host", "content-length"],
        }
    if tool == "repro.run":
        runs = int(args.get("runs", 1))
        return {
            "tool": tool,
            "spec": args.get("spec"),
            "runs": runs,
            "engine": args.get("engine", "sqlite"),
            "outcomes": [],
            "stub": True,
            "executed": False,
            "detail": "stub: no sandbox repro executed",
        }
    if tool == "static.scan":
        # Read-only scan stub: no static analysis executed.
        path = str(args.get("path", ""))
        return {
            "tool": tool,
            "path": path,
            "findings": [],
            "read_only": True,
            "stub": True,
            "executed": False,
            "detail": "stub: no static scan executed",
        }
    return None
