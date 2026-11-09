---
name: run-topology
description: Use when you need to know which branch or worktree you are in, which measured numbers belong to it, or how to report a backend test result on the perfume-store repo. Covers the spec-comp integration tree and the lane/a + lane/b build lanes, why the UI/UX checkout's numbers are stale, and the two-engine (SQLite + PostgreSQL) floor that no single-engine report can satisfy.
---

# Run topology

Which numbers belong to which tree. Nothing here restates the commit rhythm
(see `commit-cadence`), the cycle protocol (see `audit-cycle-protocol`), or the
doc map (see `spec-ledger`).

## The trees are not interchangeable

| Path | Branch | Holds |
|---|---|---|
| `C:\Users\Admin\Downloads\backend` | `UI/UX` | integration checkout. **Stale** — frozen at the PR #19 era |
| `...\Temp\opencode\comp-wt` | `spec-comp` | integration branch; lane merges land here before the promotion PR |
| `...\Temp\opencode\spec-comp-wt` | `lane/a` | Lane A — async/notification substrate |
| `...\Temp\opencode\wt-async` | `lane/b` | Lane B — slug/product path |
| `...\Temp\opencode\ui-wt` | `spec-ui` | forked at the PR #19 merge; design tokens + its own run ledger |
| `~/.gemini/antigravity/worktrees/backend/luxury_perfume_storefront` | `luxury_perfume_storefront` | separate UI effort, has no spec ledger |

`git worktree list` is the authority. Never `checkout`/`switch` between them — each is its own directory. The lane branches (`lane/a`, `lane/b`) are **generic and permanent** per the 2026-10-08 directive: a task commits onto its lane branch, never a per-task branch. Detached scratch trees (`pre-854`, …) are measurement leftovers, not work surfaces. `ui-wt` carries **its own** `.opencode/agents`; worktrees created after 2026-10-03 may or may not carry a junction to the integration checkout's `.opencode` — run the `Test-Path` check below before dispatching.

## Why the UI/UX numbers in the other skills are stale

`spec-ledger` and `audit-cycle-protocol` quote a floor of **273 tests / 6 expectedFailure / 1182 stmts**. That was measured on `UI/UX`, which stopped moving at the PR #19 merge. `spec-comp` is ~1500 tests further along. An agent that reads a `UI/UX` figure while working in `spec-comp-wt` will report a floor that is off by an order of magnitude.

Rule: **a number is valid only for the branch it was measured on.** If your handoff did not name the branch, run `git branch --show-current` before quoting anything.

## The floor is a PAIR

Since PG-1 the suite is read on both engines. SQLite alone is not a green report.

```powershell
# workdir: backend\
venv\Scripts\python -m coverage run manage.py test --verbosity 0
venv\Scripts\python -m coverage report

# same two commands with the engine selected:
$env:DATABASE_URL = "postgres://<user>:<pw>@localhost:5432/perfume_store"
venv\Scripts\python -m coverage run manage.py test --verbosity 0
Remove-Item Env:\DATABASE_URL
```

`config/settings.py` honours `DATABASE_URL`; unset or unparseable silently falls back to `backend/db.sqlite3`, so confirm which engine ran before quoting. `## Baseline` in the ledger holds the current pair, each with its own expectedFailure count, plus a superseded pair — quote only the current one.

Two-lane era (2026-10-08+): the pair is measured **per lane**. Lane A owns container `pg2a` (port 5432, database `perfume_store_a`); lane B owns `pg2b` (port 5433, database `perfume_store_b`). Two suites aimed at one server destroy each other's test database mid-run — measured, not assumed. Never point a lane at the other lane's container, and pass `DATABASE_URL` as a process env var for one command rather than typing credentials.

Shape of the pair as of 2026-10-02 (`4336ba6`), for calibration only:

```
SQLite     1790 tests, 1786 pass + 4 expectedFailure, cov 100.00% (8828 stmts)
PostgreSQL 1790 tests, FAILED (failures=6, errors=1), 4 expectedFailure, cov 100.00% (8828 stmts)
```

Note that the red engine sits inside an otherwise-green report. Quote both, labelled. A single number is not a report.

SQLite serialises writes, which is how 67 `NotSupportedError`s and a payment-verification 500 survived a 100% coverage run. Any concurrency claim measured on SQLite alone is unmeasured — see the bias table in `audit-cycle-protocol`.

## Agent config reach

`.opencode/` is git-ignored and unversioned, so it is absent from a fresh worktree — and on 2026-10-04 `agents\`, `agent\` and `skills\` inside it were wiped by a process outside opencode; everything was restored byte-exact from the session database, but the lesson stands: **treat `.opencode` as fragile**. If you launched opencode from a tree with no `.opencode\`, you have **no agents and no skills** — check before dispatching a subagent:

```powershell
Test-Path .opencode\skills\run-topology\SKILL.md   # must be True
```