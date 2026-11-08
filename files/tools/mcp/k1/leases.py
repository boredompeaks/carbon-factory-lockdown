"""K1 lease policy. 6B-3.

k1.up/down/exec/status are auditor-only (registry). exec actions are
an enum (django test, migrate, makemigrations check, boot test) and
run/node args are anchored by the registry. Every lease has a TTL;
the reaper removes expired leases under fault injection, so
containers are always reaped.
"""
from __future__ import annotations

import time

_TTL_SECONDS = 600


def reap_expired_leases(server, now: float | None = None) -> list[str]:
    """Reap expired leases. Returns the list of reaped run ids."""
    now = time.time() if now is None else now
    leases: dict = getattr(server, "_k1_leases", {})
    expired = [rid for rid, lease in leases.items() if lease.get("expiry", 0) <= now]
    for rid in expired:
        leases.pop(rid, None)
    return expired


def check_extra(server, tool: str, role: str, args: dict) -> None:
    if tool not in ("k1.up", "k1.down", "k1.exec", "k1.status"):
        return
    # Reap before acting so an expired lease never grants execution.
    reap_expired_leases(server)
    # No extra reject codes beyond the registry here: run validity is
    # decided at execution (unknown run => status reports reaped).
    return None
