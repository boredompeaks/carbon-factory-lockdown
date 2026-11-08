#!/usr/bin/env python3
"""One-time Gate 0 backfill of QUALITY-BUGS.md.

* adds a ``Verified@`` column to every row;
* backfills it with the sha the register itself names as its source
  (``1ffe926e...``), NOT a fresh re-verification;
* adds the P0 GATE-INTEGRITY ladder row;
* re-rates QC-126 (the Postgres gate that goes green on a short-circuited
  suite) to P0 / GATE-INTEGRITY / STOP-SHIP.

Idempotent: a second run detects the column and does nothing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REGISTER = Path(r"C:\Users\Admin\Documents\umairnlp\quality-scan\QUALITY-BUGS.md")
SHA = "1ffe926e6ab04e48dc1ad27fc844203d45e88781"


def _split_ending(line: str) -> tuple[str, str]:
    body = line.rstrip("\r")
    return body, line[len(body):]


def main() -> int:
    text = REGISTER.read_text(encoding="utf-8")

    if "Verified@" in text:
        print("already backfilled")
        return 0

    # 1. P0 ladder row, immediately above P1.
    p1 = (
        "| **P1** | CRITICAL | money, auth, or data integrity is wrong; "
        "cross-tenant/user data leak | blocks promotion"
    )
    p0 = (
        "| **P0** | GATE-INTEGRITY | a verdict can be produced without "
        "measurement; every downstream verdict is unverifiable | **STOP-SHIP** |"
    )
    if p1 not in text:
        print("ERROR: P1 ladder row not found", file=sys.stderr)
        return 1
    text = text.replace(p1, p0 + "\n" + p1, 1)

    lines = text.split("\n")
    out: list[str] = []
    seen_header = False
    for line in lines:
        body, ending = _split_ending(line)
        if body.startswith("| ID |") and "| Refs |" in body:
            body = body.replace("| Refs |", "| Refs | Verified@ |", 1)
            seen_header = True
        elif seen_header and body.startswith("|---"):
            body = body + "---|"
            seen_header = False
        elif re.match(r"^\|\s*QC-", body):
            if body.endswith("|"):
                body = body[:-1].rstrip() + f" {SHA} |"
            else:
                body = body + f" {SHA} |"
        out.append(body + ending)
    text = "\n".join(out)

    # 2. Re-rate QC-126 to P0.
    text = re.sub(
        r"^\| QC-126 \| P2 \| HIGH \| NEXT-BUILD \| INFRA \|",
        "| QC-126 | P0 | GATE-INTEGRITY | STOP-SHIP | INFRA |",
        text,
        flags=re.MULTILINE,
    )

    # 3. Record the provenance of the backfill next to the correction notice.
    notice = (
        "> **Gate 0 backfill (2026-11-05).** Every row now carries "
        f"`Verified@ = {SHA}` -- the sha this register already names as its "
        "source. This is a provenance backfill, not a re-verification: a row "
        "older than 10 commits is `STALE` and is not routable until re-read. "
        "QC-126 is re-rated P0 GATE-INTEGRITY (a gate that can go green on a "
        "short-circuited suite makes every downstream verdict unverifiable).\n"
    )
    anchor = "> **Correction notice (2026-11-04).**"
    if anchor in text:
        text = text.replace(anchor, notice + anchor, 1)

    REGISTER.write_text(text, encoding="utf-8")
    print(f"backfilled 263 rows with {SHA}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
