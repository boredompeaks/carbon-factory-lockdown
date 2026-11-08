"""Per-call trace records. 6B-0.

Every dispatch appends one trace entry (tool, role, args-hash, outcome,
reject-code, cache-key, timestamp). The trace feeds K3 probe counting
upstream; it never stores raw secrets (args are hashed, never echoed).
"""
from __future__ import annotations

import hashlib
import json
import time


class TraceLog:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def append(self, tool: str, role: str, args: dict, outcome: str,
               reject_code: str | None = None, cache_key: str | None = None) -> dict:
        args_hash = hashlib.sha256(
            json.dumps(args, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        ).hexdigest()
        rec = {
            "ts": time.time(),
            "tool": tool,
            "role": role,
            "args_sha256": args_hash,
            "outcome": outcome,  # "ok" | "reject"
            "reject_code": reject_code,
            "cache_key": cache_key,
        }
        self.records.append(rec)
        return rec

    def __len__(self) -> int:
        return len(self.records)
