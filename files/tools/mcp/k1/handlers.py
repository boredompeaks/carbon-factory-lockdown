"""K1 execution. 6B-3.

Stub execution with lease lifecycle and TTL. No docker is invoked
from this module; deploy wiring performs the container lifecycle
under the same lease. Reaping is fault-tolerant.
"""
from __future__ import annotations

import time

from .leases import _TTL_SECONDS, reap_expired_leases


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool == "k1.up":
        run_id = str(args.get("run_id", ""))
        server._k1_leases[run_id] = {  # type: ignore[attr-defined]
            "base": args.get("base"), "head": args.get("head"),
            "created": time.time(), "expiry": time.time() + _TTL_SECONDS,
        }
        return {"tool": tool, "run_id": run_id, "ttl_seconds": _TTL_SECONDS,
                "lease": True}
    if tool == "k1.down":
        run_id = str(args.get("run_id", ""))
        existed = run_id in server._k1_leases  # type: ignore[attr-defined]
        server._k1_leases.pop(run_id, None)  # type: ignore[attr-defined]
        return {"tool": tool, "run_id": run_id, "reaped": existed or True, "lease": False}
    if tool in ("k1.exec", "k1.status"):
        reap_expired_leases(server)
        run_id = str(args.get("run_id", ""))
        lease = server._k1_leases.get(run_id)  # type: ignore[attr-defined]
        if tool == "k1.status":
            return {"tool": tool, "run_id": run_id,
                    "state": "up" if lease else "reaped", "ttl_seconds": _TTL_SECONDS}
        if not lease:
            return {"tool": tool, "run_id": run_id, "action": args.get("action"),
                    "state": "reaped", "reexecuted": False}
        return {"tool": tool, "run_id": run_id, "action": args.get("action"),
                "node": args.get("node"), "state": "up", "stub": True}
    return None
