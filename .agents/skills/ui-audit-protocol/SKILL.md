---
name: ui-audit-protocol
description: Use during any build-audit-fix cycle on the spec-ui storefront (RE-AUDIT, BUGS-FOUND, "cycle 2", escalation, or a handoff to a fresh ui-builder). Encodes the 3-cycle cap, delta-audit context-reuse, the UI quantitative floor (build routes + stylesheet bytes + vitest counts), mutation-proving of guards, and the recorded UI bias traps (green vitest hiding a visual regression, vacuous guards, fabricated comment numbers). Carry-over of audit-cycle-protocol.
---

# UI audit cycle protocol

Backend counterpart: `audit-cycle-protocol` (same rules, Django-flavoured).
This is the storefront version. The loop is identical: **delta audits over
inherited context, capped at 3 cycles, escalating rather than opening a 4th.**

## Rule 1 — cycles are capped at 3, then you ESCALATE

Escalation is mandatory and not a judgement call, even for trivia (the backend
run escalated twice over a one-word / one-digit prose error rather than editing
around a gate). **On escalation: withhold the push.** Do not open/merge a PR.
Record the finding in the ledger, state that product code was verified correct,
and stop. P3 alone does not justify a 4th cycle — a P3 **travels with the next
build** (folded into the next builder's task), never given its own cycle.

## Rule 2 — reuse context for the delta; you may NOT re-derive what you already read

An audit at cycle *N* inherits cycle *N-1*'s report. It re-reads **only**:
1. `git diff <cycle-N-1 sha>..HEAD` — the actual delta.
2. **The complement** of the surface cycle *N-1* attacked, not the same surface
   again.
3. The quantitative floor (below), re-measured rather than re-argued.

It must **explicitly declare what it did not re-read and why**. A cycle-2 auditor
that silently re-audits cycle-1's surface burns context and finds nothing; the
recorded good outcome is "correct on every axis attacked", credible *because*
the axes were enumerated.

### When to abandon inherited context and start fresh

| Trigger | What it looked like on the backend run |
|---|---|
| Defect lies outside the changed delta | the rescued-builder rescue found a P1 in the inherited diff |
| Environment/harness bias suspected | 74 problems on Postgres, 0 on SQLite |
| Ledger claims proved stale | S1 re-derived: 19-task queue, 4 splits |
| Prior report contained unreproducible claims | cycle 2 corrected four claims that did not reproduce |
| Byte-level corruption suspected | PowerShell backtick-escape put a literal 0x08 in a file |
| 3 cycles consumed | escalate; do not open a 4th audit |

## Rule 3 — every audit states a quantitative UI floor, and it only moves up

Copy the format exactly, and label **which tree** it was measured on (ui-wt vs
a lane worktree are different trees — a number is valid only for the tree it was
measured on):

```
floor build=<exit 0|n> routes=<N> stylesheet=<B raw>/<B gz> vitest=<P pass>/<F fail>/<X xfail> origin/spec-ui <sha>
```

Current shape for calibration (batch A/B audit-A2, for calibration only): build
exit 0, 23 routes, 61 tests / 8 files, stylesheet 44,564 B production. Quote
only what you re-measured. Invariants that are ledger-level, not opinion:
- build exits 0
- vitest pass count never decreases; expectedFailure count never grows
- the production stylesheet does not grow without a named, budgeted reason
- the token-existence guard stays non-vacuous
- `UI-UX-SPEC.md` §14 stays **byte-identical** (the UI side never edits §14 —
  that is the backend orchestrator's; verify with `cmd` byte-exact compare)

## Rule 4 — "mutation-proven" or it did not happen

A fix is not closed because the suite is green. It is closed when someone
**broke it on purpose and watched it fail**. The token-existence test (B2) is
the recorded example: it now fails on a typo'd token and returns clean on 19
layout utilities — proven non-vacuous by deliberate breakage. **Never weaken a
gate to make a cycle pass**; the backend run withheld a push over a one-digit
prose error rather than editing around it.

## Rule 5 — the recorded UI failure modes, in order

1. **Shell-based file editing corrupts bytes.** PowerShell pipeline corrupts
   UTF-8 em dashes (the R1 recovery); a backtick-escape put a literal 0x08 in a
   file. **Use the edit tool, never shell redirection, for files in this repo.**
   Compare §14 with `cmd` redirection + ordinal compare.
2. **Fabricated currency glyph.** R4 wrote 16 yen (U+00A5) signs into a commerce
   spec that the 17 refs render in 0 yen / 53 rupee (U+20B9). Root cause: the
   PowerShell console rendered U+20B9 as `?` and the misreading was written as
   fact. **Re-derive non-ASCII codepoints from bytes, not from console output.**
3. **Fabricated numbers in comments.** Three false numbers shipped as
   justification (a z-index count, a preload byte total, a contrast ratio
   against a retired token). **A number in a comment is a claim and is audited
   like code** — recompute it; cite a token that exists.
4. **Stale self-report.** A builder's first two `write` calls both errored
   (truncated payload) and its self-report said otherwise. **Verify the tree
   state; never trust an agent's self-report.**
5. **Vacuous guard.** A guard that cannot fail is not a guard. Prove it
   non-vacuous by breaking it.

## Rule 6 — the UI bias traps, and the detection that worked

| Bias | What it hid | Detection |
|---|---|---|
| **Green vitest, unproven e2e** | BUG-4: e2e could not reach the servers (`ECONNREFUSED`), so the batch that repainted every route had **zero** visual-regression gate. "Servers down" is environmental, but it is **UNPROVEN, not passing** | run e2e with the backend up before A-14; do not waive |
| **100% coverage** | the backend run's coverage was 100% and still missed a half-tracked state machine | coverage is a floor, never evidence of correctness |
| **vacuous guard** | a token-existence test that passed on everything | break it deliberately; it must fail on a typo |
| **design prose becoming shipped CSS** | BUG-10: Tailwind v4 auto source-detection scanned `frontend/docs/design/*.md`, injecting 5,818 B (13.1%) of dead rules | pin an explicit `@source` allowlist |
| **comment numbers** | three false numbers shipped as code comments | recompute from a command; a self-count is false |
| **auditor's named attack surface** | cycle 1 attacked 5 axes, found it correct — then cycle 3 found more | audit the **complement**, not the named list |

## Rule 7 — severity discipline (ledger vocabulary)

- **P1** — money, auth, or data integrity is wrong.
- **P2** — a real functional or security defect with a bounded blast radius.
- **P3** — prose, figure, naming, or dead-code hygiene.

P2 and P1 get a builder fix cycle. **P3 alone does not justify a 4th cycle.**

## Ledger row vocabulary

Use the ledger's own words so the next auditor can grep state:
`PENDING → IN-COMPLIANCE → BUILDING → IN-AUDIT → BUGS-FOUND → SHIPPED → PR-OPENED | ESCALATED | NOT-APPLICABLE`.

A cycle row names: task id, cycle number, findings by severity, which are
**closed and mutation-proven**, which are **open**, the floor delta, whether the
**push was withheld**, and any newly recorded hazard. **The ui-auditor never
edits the ledger** — the ui-orchestrator does. The auditor returns a structured
report; the orchestrator writes the row.

## Escalate (return BLOCKED) rather than guess when

- the delta touches more than ~5 files or needs >1 new shared component
- the spec is ambiguous and the reading changes a public API / contract
- the reported defect does not reproduce
- the fix would require weakening an existing test, gate, or assertion
- the floor cannot be held (build regressed, routes dropped, stylesheet grew
  without a named reason, vitest pass count fell)
