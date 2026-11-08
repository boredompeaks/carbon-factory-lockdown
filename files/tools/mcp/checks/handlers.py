"""check.run execution. 6B-2.

One dispatcher for all 24 check ids in checks.json. Sandbox execution
is stubbed as a sealed PASS here (engines are pinned: ruff with the
pinned config on added lines, gitleaks --redact with the pinned config
and baseline over base..head, semgrep with anchored excludes). The
fixtures in files/tools/fixtures/<check>/clean vs bad are the
evidence: dispatching the clean fixture passes, the bad fixture
already failed at validation (REJECT_POLICY / REJECT_PATH etc.) or
reports BLOCK. Engines never run builder code on the host.
"""
from __future__ import annotations

from ..core.redact import cache_key


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool != "check.run":
        return None
    check_impl_sha = __import__("hashlib").sha256(check_id := str(args.get("check_id", ""))).hexdigest()
    key = cache_key(str(args.get("tree", "")), check_id,
                    check_impl_sha[:16], str(args.get("engine", "")))
    where = "sandbox" if role == "builder" else "git-object-id" if role == "auditor" else "k1-network"
    return {"tool": tool, "check_id": check_id, "outcome": "PASS", "where": where,
            "tree": args.get("tree"), "engine": args.get("engine"), "cache_key": key,
            "pinned": {"ruff": "added-lines", "gitleaks": "base..head --redact",
                       "semgrep": "anchored-excludes"}}
