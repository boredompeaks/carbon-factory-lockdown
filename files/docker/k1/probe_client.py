#!/usr/bin/env python3
"""Baked-in K1 probe client. 6B-7.

Runs from /opt/k1 (read-only) so /work can stay noexec. Stdlib only;
binds to 127.0.0.1:8081 (loopback inside the container). Usage:

    python probe_client.py --endpoint /api/orders --actor hacker-high

The server-side hacker.probe tool (files/tools/mcp/hacker/) drives
this client through k1.exec; the client itself takes only typed args.
"""
from __future__ import annotations

import argparse
import json
import urllib.request
import urllib.error

_BASE = "http://127.0.0.1:8081"
_ACTORS = ("hacker-high", "hacker-max")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True, help="anchored path, e.g. /api/orders")
    ap.add_argument("--actor", required=True, choices=_ACTORS)
    args = ap.parse_args()
    if not args.endpoint.startswith("/") or "?" in args.endpoint or ".." in args.endpoint:
        raise SystemExit("endpoint must be an anchored relative path without query")
    req = urllib.request.Request(_BASE + args.endpoint, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(json.dumps({"actor": args.actor, "endpoint": args.endpoint,
                          "status": e.code, "body_sha256_len": len(body)}))
        return 0
    print(json.dumps({"actor": args.actor, "endpoint": args.endpoint,
                      "status": 200, "body_sha256_len": len(body)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
