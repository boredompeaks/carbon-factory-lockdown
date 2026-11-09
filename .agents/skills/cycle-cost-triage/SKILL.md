---
name: cycle-cost-triage
description: Use at the top of every builder or auditor cycle on the perfume-store repo, and before committing any doc prose - sorts the cycle into DOC-ONLY, CODE or INFRA so a small delta is closed cheaply instead of consuming the 3-cycle budget, and names the local claim-scan command that CI cannot be relied on to run.
---

# Cycle-cost triage

The 3-cycle cap is the scarcest resource in the run. This skill only classifies
the cycle and gives the doc-only fast path. Cap, escalation, context-reuse rules,
mutation-proving and the bias traps are in `audit-cycle-protocol` — do not
re-derive them here.

## Calibration — where the budget actually went

| Task | Cycles | What the findings were |
|---|---|---|
| SPEC-1-B07b | 4 | byte-corrupted changelog, 3xP3 stale figures, 5x wrong quoted test names, a vacuous pin, a broken clock-scan helper. **Product code AST-equal on all 5 files at every cycle.** |
| SPEC-1-B07d | 3 | inflated mutation counts (7→6, 2→3), a quoted test name that did not exist, one word of prose |
| SPEC-1-B05 | 3 | one wrong digit in changelog prose; code verified correct, push withheld |
| SPEC-1-B07a | 3 | 2 genuine P2s then real tracking gaps — the healthy shape |

Ten of the thirteen cycles above were prose. Prose has no suite, so it drifts
silently until an auditor re-derives every figure by hand. That re-derivation is
the real cost, and it is what the classification below avoids.

## Classify in one word, first line of the report

| Class | Signal | Spend |
|---|---|---|
| **DOC-ONLY** | every finding is a quoted name, a count, a citation, or a byte figure | cheap path. Do **not** re-run the suite, do **not** re-read the implementation — nothing about it is in question |
| **CODE** | a behaviour, a 500, a wrong value, a missing lock | targeted fresh context on the named files, then the full suite on both engines |
| **INFRA** | the gate or harness is itself unsound | measure first, change nothing, report verbatim. PG-1 bundled nothing: it ran the suite on Postgres and fixed none of the 74 problems it found, which is the only reason they could be attributed |

`CYCLE <task> -- DOC-ONLY | CODE | INFRA` in the first line tells the next agent how much context to rebuild. It is also the number that shows when the budget is being spent on the wrong thing.

## DOC-ONLY fast path

1. Fix only what was named. Do not re-audit axes nobody attacked — a P3 alone does not earn a 4th cycle; escalate instead.
2. Re-derive **every** figure with your own command. A reviewer's number is a hypothesis. In B07d cycle 2 a builder restated 4 of 6 supplied counts without re-deriving, and 2 of the 5 the brief supplied were themselves wrong.
3. **Run the gates yourself before committing:**
   ```powershell
   backend\venv\Scripts\python.exe scripts\doc_claims.py --base <last-promoted-sha>
   backend\venv\Scripts\python.exe scripts\changelog_figures.py check --base <last-promoted-sha>
   ```
   CI runs both now (GATE-7 wired in `f89d121`, made honest in `457993d`; the
   prose classifier was made fail-closed in `50a03b6` after BUG-5's zero-claims
   scan), but a gate you did not run locally is a claim, not a check. Do not
   assume CI will catch you before your push does.
4. Never write a doc through a shell — use the edit tool. `Set-Content`,
   `Out-File`, `ReadAllText`/`WriteAllText` and `>` have corrupted `changes.md`
   by eating bytes invisibly, twice, each costing a cycle.
5. Never let a document count its own occurrences — a self-count is false the moment the citation is written. That was BUG-7: one word, one whole cycle. Describe instead.

## Cheap is not unverified

A DOC-ONLY cycle still owes: a re-read of its own diff as the auditor will read
it, a byte check on the committed blob if the diff is larger than the change,
and an explicit statement of what you did **not** re-read and why. The recorded
good outcome is "product code correct on every axis attacked" — credible only
because the axes were enumerated.