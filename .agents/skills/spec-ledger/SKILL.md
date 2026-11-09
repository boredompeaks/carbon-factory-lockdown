---
name: spec-ledger
description: Use when you need to find the authoritative requirement, finding, status, or floor for a task in this perfume-store repo. Maps the 100KB+ doc set (spec-run-state.md, docs/run/section-NN.md, fix-plan.md, audit.md, vulnerabilities.md, test-gaps.md, changes.md, conventions.md, architecture.md) and says which file answers which question and which one you must not edit.
---

# Doc set map

This repo carries several generations of ledger at once. **Check which branch you
are on before assuming a layout** — they differ.

```bash
git branch --show-current
ls backend/docs/run/ 2>/dev/null || echo "no per-section ledger on this branch"
```

| Branch | Ledger layout | Size |
|---|---|---|
| `UI/UX` (older layout) | `backend/docs/spec-run-state.md`, 4 sections: Section index, Task ledger, Baseline, Escalations | 31 KB |
| `origin/spec-comp` (current) | `backend/docs/run/section-NN.md` (25 files incl. evidence reports) + `backend/docs/compliance/S<n>.md` pre/post-sweeps; `spec-run-state.md` still present as the index | 196 KB |
| `origin/spec-ui` | forked at the PR #19 merge (`74c6669`); design tokens + its own run ledger | see `run-topology` |

The migration is recorded in `6745760` ("restructure split-layout migration to
backend/docs/run/"). Per-section evidence files also live there
(e.g. `PG-1-damage-report.md`). On `spec-comp`, ledger commits touch
`changes.md` 160×, `spec-run-state.md` 134×, `run/section-01.md` 30×,
`run/section-08.md` 20×.

## Which file answers which question

| Question | File | Notes |
|---|---|---|
| What exactly does the spec require? | `Saturday, Jul 25, 2026 at 5_23 AM.txt` (repo root) | 5,734 lines, git-ignored by design. Tasks cite spec line ranges like `2263-2453`. Read only the cited range. |
| What is the status / queue / floor? | `spec-run-state.md` or `run/section-NN.md` | Section index maps spec sections → spec lines → status. |
| What did the reviewer already find? | `spec-run-state.md` cycle rows, `changes.md` | Cycle rows are the audit history. Grep `BUGS-FOUND`, `cycle`, `BUG-`. |
| What are the rules for the code I write? | **`backend/docs/conventions.md`** | 96 lines (rewritten 2026-10-06, includes the printed-figures rule). The single source of truth. Read before EVERY task. Do not paraphrase it from memory. |
| What are the known defects? | `audit.md` (F-01..F-29), `vulnerabilities.md` (V-01..V-21) | Both have a `Status` column — check it, findings get closed. |
| What is the ordered remediation plan? | `fix-plan.md` | Phases 0–6, each item states *why*. Phase 1 = payment path, Phase 2 = throttling. |
| What tests are missing? | `test-gaps.md` | Header says FLAGGED → IMPLEMENTED. Written against the old 178-test tree; re-measure. |
| What did compliance already prove for this section? | `backend/docs/compliance/S20..S22.md` | Pre- and post-compliance sweep tables (2026-10-08 directive). Read the section's file before queueing it; earlier sections have none yet. |
| How does the system fit together? | `architecture.md` | Hybrid auth table is the key part: orders = JWT, cart = session cookie, no merge on login. |
| What did we change and why? | `changes.md` | Append-only, **782 KB**. Newest entry at the top. Grep, never read whole — see Sizes below. |
| What is the frontend supposed to do? | `frontend/PLAN.md` | 241 lines: route map, verified API surface, money rules, failure paths, build sequence. |
| What does the frontend team need from us? | `BACKEND_REQUESTS.md` (repo root) | Cross-repo gaps they logged. |
| Full test evidence from a run? | `backend/docs/run/<TASK-ID>-evidence.md` | Disk is cheaper than context. Long logs go here, summary in the report. |

## Sizes — the largest avoidable context cost in this run

The doc set is ~880KB. Whole-file reads are the reason agents re-derive facts
that are already written down.

| File | Size (`spec-comp`, 2026-10-13) | Read it? |
|---|---|---|
| `backend/docs/changes.md` | **782 KB** | never — grep only |
| `backend/docs/spec-run-state.md` | **196 KB** | headings + targeted grep only |
| `backend/docs/deploy-runbook.md` | 58 KB | grep only |
| `backend/docs/run/PG-1-damage-report.md` | 30 KB | only when the task is PG-* |
| `backend/docs/api-contract.md` | 16 KB | the one section you need is fine |
| `backend/docs/run/section-NN.md` | 1–28 KB | the one section for your task |
| `backend/docs/conventions.md` | **7 KB** | yes — every task |

Lookups:

```powershell
git grep -n "SPEC-1-B07a" -- backend/docs/spec-run-state.md
Select-String -Path backend\docs\spec-run-state.md -Pattern "^#{1,4} "     # structure only
Select-String -Path backend\docs\spec-run-state.md -Pattern "^## Baseline" -Context 0,2
git grep -c "SPEC-17-10" -- backend/docs/changes.md                       # has this row been written before
```

Prefer `git grep` over `grep`: it reads the committed blob, which is LF, while
the worktree is CRLF (`core.autocrlf` is on, there is no `.gitattributes`). Line
numbers measured in the worktree can be off from the line numbers a committed
doc cites.

Bulky output goes to `backend/docs/run/<TASK-ID>-evidence.md`, referenced by
path. Never paste a previous agent's report forward — relay structured fields
plus a path.

## Editing rules — who owns what

| File | Owner | You may edit? |
|---|---|---|
| `conventions.md` | human | **No.** It is quoted into every handoff. |
| `spec-run-state.md`, `docs/run/*` | orchestrator / auditor | **No.** Editing the ledger is fraud, same as a stub. |
| `changes.md` | every agent, append-only | **Yes** — append exactly one row per task. Never rewrite history above your row. |
| `audit.md`, `vulnerabilities.md`, `test-gaps.md`, `fix-plan.md` | human / auditor | Only if your task explicitly says so. |

`builder.md` states this as a hard failure: *"NO ledger tampering … Editing it is
fraud, same as a stub."*

## Status vocabulary

```
PENDING → IN-COMPLIANCE → BUILDING → IN-AUDIT → BUGS-FOUND → SHIPPED → PR-OPENED
                                                                       | ESCALATED
                                                                       | NOT-APPLICABLE
```

**Max 3 builder↔auditor fix cycles per task**, then ESCALATE.

Deferral policy: a gap whose detail lives in a later spec section is recorded
`PENDING` with `Owner: S<n>` and built during that section's loop. It is not
skipped, it is scheduled.

## Ledger rows are re-derived, not inherited

`dc04100` is the cautionary row: *"S1 re-derived: 15/18 deferred rows genuinely
OPEN (owners all closed), 3 rows found already-BUILT, 2 DEVIATES; 19-task queue
sized (4 splits)."* Ledger claims about *other* rows went stale and had to be
re-checked from the code.

So: **trust the ledger about the task in front of you, re-derive anything else
you depend on.** Check `git log` and the actual files rather than a status cell.

## Changelog row format

```
| YYYY-MM-DD | <TASK-ID> | builder | <comma-separated files> | <what + why, one line> | <N passed, cov X% | frontend: test/e2e/build green> | <shipped> |
```

Re-derive the numbers from a command. "3xP3 stale figures" and "unreproducible
figures" are recurring findings in this repo — carried-forward numbers are a
known defect class.

## Current verified numbers

**Do not trust a number without its branch.** The figures below were measured
on `UI/UX` @ `1d91a28`, which stopped moving at the PR #19 merge. The live run
is on `spec-comp`, roughly 1500 tests further along, and its floor is a
SQLite + PostgreSQL **pair**. See `run-topology` for the current pair and the
command that reproduces it.

- `UI/UX` @ `1d91a28`: backend **273 tests, OK (6 expectedFailure), coverage
  100.00% (1182 stmts)**; frontend vitest **4 files / 22 tests**.
- `spec-comp` @ `92139d0`: ~1790 tests per engine, coverage 100.00%, 4
  expectedFailure on both. PostgreSQL carries known open failures. **This
  figure is itself superseded** — the two-lane era (2026-10-06+) quotes floors
  as pairs measured **per lane** at the parallel-build anchor, and PR #23
  (TWO-LANE INTEGRATION) promoted `51bbd97` to `feat/add-frontend` (`e445bdc`)
  on 2026-10-09. Quote the `## Baseline` pair for the branch/lane you are on.

Re-measure on your own branch before quoting. It moves, and the ledger keeps
superseded figures next to current ones.