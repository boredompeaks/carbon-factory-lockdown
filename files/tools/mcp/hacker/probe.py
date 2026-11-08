"""Hacker probe policy. 6B-4 (wave 3, after 6B-3).

hacker.probe: actor enum with server-side credentials (no caller
supplies secrets); run id derived from capability and nonce; no
redirects; relative paths only; header denylist; body cap; batch +
barrier race modes; per-probe records. repro.run carries a runs
parameter. static.scan is read-only.

F-10 is resolved: the hacker gains no k1.exec/k1.up grant, but the
probe path runs on the K1 network via the baked-in client, so
runtime attacks are attainable without a shell.
"""
from __future__ import annotations

from ..core.validate import Reject

_HEADER_DENYLIST = ("host", "content-length", "transfer-encoding", "authorization")


def check_extra(server, tool: str, role: str, args: dict) -> None:
    if tool == "hacker.probe":
        # No redirects and no out-of-band channels: endpoint is already
        # anchored by the registry pattern; an interior "://" or "@"
        # would be a smuggled absolute URL.
        endpoint = args.get("endpoint", "")
        if isinstance(endpoint, str) and ("://" in endpoint or "@" in endpoint):
            raise Reject("REJECT_PATTERN", "endpoint must be a relative path, no redirects")
    elif tool == "repro.run":
        # runs is bound by the registry (1..5); nothing extra to deny.
        return None
    elif tool == "static.scan":
        return None
