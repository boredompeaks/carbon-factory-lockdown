---
name: ui-cycle-cost
description: Use at the top of every ui-builder or ui-auditor cycle on the spec-ui storefront, and before committing any doc prose in frontend/docs. Sorts the cycle into DOC-ONLY, CODE or INFRA so a small delta is closed cheaply instead of consuming the 3-cycle budget, and names the local frontend gates that no CI can be relied on to run. Carry-over of the backend cycle-cost-triage, re-scoped to vitest/playwright/build/stylesheet-size.
---

# UI cycle-cost triage

The 3-cycle cap is the scarcest resource in the run. This skill only classifies
the cycle and gives the doc-only fast path. Cap, escalation, context-reuse and
bias traps are in `ui-audit-protocol` — do not re-derive them here. Backend
counterpart: `cycle-cost-triage` (same shape, different gates).

## Calibration — where UI cycles actually went

The batch-A/B audit that ran before wave 1 burned most of its cycles on prose
and on **numbers asserted instead of measured** (the ledger's "Process rules"
section names three false numbers that shipped as comments: a z-index count, a
preload byte total, a contrast ratio against a retired token). Plus one currency
fabrication (yen glyph written into a commerce spec that the refs render in
rupees). Root cause each time: asserted, not measured.

## Classify in one word, first line of the report

| Class | Signal | Spend |
|---|---|---|
| **DOC-ONLY** | every finding is a quoted name, a count, a citation, a byte figure, or a comment number | cheap path. Do **not** re-run the build, do **not** re-read the implementation — nothing about it is in question |
| **CODE** | a behaviour, a broken gate, a wrong value, a missing state, a token violation, a contrast failure | targeted fresh context on the named files, then the **full frontend gate** (below) |
| **INFRA** | the gate or harness itself is unsound (e2e can't reach servers, a test is vacuous, Tailwind source-detection is scanning docs) | measure first, change nothing, report verbatim |

`CYCLE <task> -- DOC-ONLY | CODE | INFRA` on the first line tells the next agent
how much context to rebuild.

## DOC-ONLY fast path

1. Fix only what was named. Do not re-audit axes nobody attacked — a P3 alone
   does not earn a 4th cycle; escalate instead.
2. Re-derive **every** figure with your own command. A reviewer's number is a
   hypothesis. Contrast ratios are recomputed from the literal channel values;
   byte totals come from a build, not from a comment.
3. **Run the gates yourself before committing** (the local floor; no CI is
   assumed):
   ```powershell
   cd frontend; npm run build          # exit 0, note the route count + stylesheet B
   cd frontend; npx vitest run         # pass/fail/expectedFailure counts
   ```
   If the cycle touches tokens, colours or focus, also recompute the specific
   contrast from the hex literals (see §2.1) rather than restating a prior ratio.
   A gate you did not run locally is a claim, not a check.
4. **Never write a doc through a shell** — use the edit tool. `Set-Content`,
   `Out-File`, `ReadAllText`/`WriteAllText` and `>` corrupted `changes.md` twice
   on the backend run, each costing a cycle. The UI ledger is written the same
   way (edit tool only). Compare `UI-UX-SPEC.md` §14 with `cmd` redirection +
   byte-exact compare, never `Out-File -Encoding utf8` (the harness corrupts
   UTF-8 em dashes through a PowerShell pipeline — recorded in the ledger).
5. **Never let a document count its own occurrences** — a self-count is false
   the moment the citation is written. Describe instead.

## The full frontend gate (CODE cycles)

Run all of these against your own tree and report what each printed. All-or-
nothing; no partial credit.

```powershell
cd frontend
npm run build            # exit 0; record route count + production stylesheet bytes
npx vitest run           # pass / fail / expectedFailure counts
```
Plus, named per finding (do not blanket-run what you did not touch):
- token-existence / no-hardcoded guard (the `ui.test.ts` false-pass fix + the
  token-existence guard from B2 — proven non-vacuous by deliberate breakage)
- the specific contrast recompute from literals
- `npx playwright test` **only** if the task is e2e and the backend is up —
  if servers are down it is `UNPROVEN`, never "passing" (BUG-4)

## Cheap is not unverified

A DOC-ONLY cycle still owes: a re-read of its own diff as the auditor will read
it, a byte check on the committed blob if the diff is larger than the change,
and an explicit statement of what you did **not** re-read and why. The good
outcome — "product code correct on every axis attacked" — is credible only
because the axes were enumerated.
