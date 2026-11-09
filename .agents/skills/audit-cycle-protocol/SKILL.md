---
name: audit-cycle-protocol
description: Use during any build-audit-fix cycle in this repo (RE-AUDIT, BUGS-FOUND, "cycle 2", escalation, or a handoff to a fresh builder). Encodes the delta-audit context-reuse rules, the 3-cycle cap, when to escalate versus start fresh context, and the recorded bias traps where 100% coverage and green xfails hid whole classes of real defects.
---

# Audit cycle protocol

The pipeline that produced this repo's 349 `spec-comp` commits was **not** a
sequence of independent full audits. It was a chain of **delta audits over
inherited context**, capped at 3 cycles. This skill records how that worked and
where it went wrong.

## The canonical loop (verbatim from real history)

`SPEC-1-B07a`, 2026-10-02, six commits in 3h10m:

```
e29dfbe 06:54  feat(orders): SPEC-1-B07a - ReturnRequest lifecycle core
fd53b05 07:19  chore: ledger - BUGS-FOUND cycle 1 (P2 non-string body 500s the view;
                  P2 eligibility gate contradicts its own rationale; 3xP3) ... push withheld
5e0a4db 07:36  fix(orders): SPEC-1-B07a cycle 2 - refuse non-string return bodies,
                  derive the eligibility gate, drop the inventory-403 pin
1f3422b 09:36  chore: ledger - cycle 2 (3 closed ...; BUG-5 P2 open - the payment axis
                  tracks only half the machine, and 100% coverage missed it)
cef9f1c 09:50  fix(orders): SPEC-1-B07a cycle 3 - widen the return eligibility money half
6021138 10:04  chore: ledger - SHIPPED (3 cycles, RE-AUDIT c3; floor 1698->1706,
                  cov 100%, 8059 stmts, origin/spec-comp cef9f1c)
```

Cycle counts across all 404 commits: **cycle1 = 20, cycle2 = 20, cycle3 = 10,
cycle4 = 1**. `wip:` appears **0 times**. There are **0 reverts**.

## Rule 1 — cycles are capped at 3, then you ESCALATE

Escalation is mandatory and is not a judgement call, even for trivia:

- `aea302d` — "SPEC-1-B07d ESCALATED at cycle 3 of 3 (BUG-7 P3, documentation-only, one word...)"
- `d0ef611` — "SPEC-1-B05 ESCALATED at cycle 3/3 (BUG-7 P3: one wrong digit in changelog prose; code verified correct, **push withheld**)"

**On escalation: withhold the push.** Do not open the promotion PR. Record the
finding in the ledger, state that product code was verified correct, and stop.
The only cycle-4 commit in history (`6aed507`) exists because a byte-corrupted
changelog made cycle 3 report a defect that was not real — see Rule 5.

## Rule 2 — reuse context for the delta; you may NOT re-derive what you already read

An audit at cycle *N* inherits cycle *N-1*'s report. It re-reads **only**:

1. `git diff <cycle-N-1 sha>..HEAD` — the actual delta.
2. **The complement** of the surface cycle *N-1* attacked, not the same surface again.
3. The quantitative floor (below), re-measured rather than re-argued.

It must **explicitly declare in the ledger row what it did not re-read and why**.
A cycle-2 auditor that silently re-audits cycle-1's surface burns context and
finds nothing; the recorded good outcome is the opposite —
`7a556f8` (SPEC-1-B07b cycle 1) closed with "product code correct on every axis
attacked", which was only credible because the attacked axes were enumerated.

Two-lane era (2026-10-08+): task-scope audits run **per lane**, and the section
boundary gets ONE integration audit on the merged tree — combined or per-lane
at the orchestrator's discretion; the RE owns the integration merge either way.

### When to abandon inherited context and start fresh

Inherited context is valid only while the delta is small and the previous
audit's assumptions still hold. Start fresh, and say so in the ledger, when:

| Trigger | Recorded example |
|---|---|
| Defect lies outside the changed delta | `0c7a93f`: "the killed-builder rescue found a P1 in the inherited diff" |
| Environment/harness bias suspected | `415e8cd`: "74 problems on Postgres, 0 on SQLite; 67 tests short-circuit at it so `OversellRaceTests`/`CouponRaceTests` are unmeasured, not passing; xfail ceiling proven blind to the class" |
| Ledger claims proved stale | `dc04100`: "S1 re-derived: 15/18 deferred rows genuinely OPEN (owners all closed), 3 rows found already-BUILT, 2 DEVIATES; 19-task queue sized (4 splits)" |
| Prior report contained unreproducible claims | `e9946de`: cycle 2 had to "correct four claims that did not reproduce" |
| Byte-level corruption suspected | `bc3c30b`, `d26bc6d` — see Rule 5 |
| 3 cycles consumed | escalate; do not open a 4th audit |

## Rule 3 — every audit states a quantitative floor, and the floor only moves up

Auditors emit a machine-checkable line every cycle. Copy the format exactly:

```
floor <before>-><after>, cov <NN.NN>%, <N> stmts, origin/spec-comp <sha>
```

Current floor, `UI/UX` @ `1d91a28`: **273 tests OK (6 expectedFailure), cov
100.00% (1182 stmts)** — measured on a branch that stopped moving at the PR #19
merge. The live `spec-comp` floor is a **SQLite + PostgreSQL pair**; in the
two-lane era (2026-10-06+) floors are quoted **as pairs measured per lane** at
the parallel-build anchor, labelled with the lane that produced them (lane A's
pair is not lane B's pair — they were measured at different commits). Do not
quote a `UI/UX` figure from a `spec-comp` cycle; see `run-topology` for the
pair and the command that reproduces it. The
`## Baseline` block in the ledger holds the auditor-verified floor for the
branch you are on, each with its own expectedFailure count, next to a
superseded entry.

Invariants that are ledger-level, not opinion:
- passing test count never decreases **on either engine**
- `expectedFailure` count never grows
- coverage never drops
- `makemigrations --check --dry-run` stays clean

Classify each cycle before spending it — `cycle-cost-triage` has the DOC-ONLY /
CODE / INFRA split and the local `doc_claims.py` + `changelog_figures.py check`
commands (CI runs both now; run them locally before the push anyway).

## Rule 4 — "mutation-proven" or it did not happen

A fix is not closed because the suite is green. It is closed when someone
**broke it on purpose and watched it fail**. `147c8c1` records all five cycle-1
findings "closed and mutation-proven". The tooling self-fix loop
(`3b84367` → `6497beb` → `46a5eee` → `a0b35f2`) ended with `58c22a8`:
"gate strictness byte-identical across all three cycles (274 error lines, zero
retired, zero new)" — i.e. the gate was proven not to have been weakened.

Corollary: never weaken a gate to make a cycle pass. `d0ef611` withheld a push
over a one-digit prose error rather than editing around it.

## Rule 5 — the recorded failure modes, in the order they actually happened

1. **Shell-based file editing corrupts bytes.** `bc3c30b` had to redo
   `e5a8788` because "a PowerShell backtick-escape put a literal 0x08 in the
   file"; `d26bc6d` had to "restore UTF-8 no-BOM bytes from `6a9c7db^` via
   byte-level rewrite". Both cost extra cycles. **Use file-editing tools, never
   shell redirection, for files inside this repo. Verify bytes on the committed
   blob when a diff looks larger than the change.**
2. **`black --quiet` as a measurement tool is a hazard** (recorded in
   `147c8c1`). Black rewrites files; running it to *measure* mutates the tree.
   Black 26.5.1 exists in `venv/` but is unpinned in `requirements.txt`, has no
   config, and is invoked by no CI step — and the legacy code is single-quoted
   throughout, so `black --check .` produces large meaningless diffs. Do not
   introduce it as a gate.
3. **Dead audit claims cost a full cycle.** `e9946de` spent cycle 2 correcting
   "four claims that did not reproduce". Reproduce a reported defect before
   fixing it; report `unreproducible` rather than fixing a phantom.
4. **Prose figures drift.** Repeated "3xP3 stale figures" and "unreproducible
   figures" findings. Numbers quoted in `changes.md` must be re-derived from a
   command, never carried forward from a previous report.

## Rule 6 — the bias traps, and how the pipeline eventually caught them

These are the cases where every mechanical signal was green and the code was
still wrong. Check each explicitly before declaring a task SHIPPED.

| Bias | What it hid | Detection that worked |
|---|---|---|
| **SQLite serialises writes** | every concurrency defect. `select_for_update` over a nullable FK 500s payment verification on Postgres; 0 of 74 problems appear on SQLite | `415e8cd` ran the suite against Postgres (`PG-1`). Ordering constraint recorded in `59f7a17`: "harnesses before PG-1 would be theatre" |
| **100% coverage** | `1f3422b`: coverage was 100% and still "missed" that the payment axis tracked only half the state machine | coverage is a floor, never evidence of correctness |
| **green `expectedFailure`** | the xfail ceiling was blind to an entire defect class (`415e8cd`) | ask what the xfail pins *cannot* fail on |
| **auditor's named attack surface** | `7a556f8` cycle 1 attacked 5 axes and found the product correct — then cycle 3 found more anyway | audit the **complement**, not the named list |
| **`DEBUG=true` in CI** | `V-02` fails open; `tests/test_settings_security.py` covers it only via subprocess | never trust in-process settings assertions |
| **nominal ordering** | `1f3422b` "floor" prose; `F-11` coupon quantize: preview said 599.997, checkout stored 600.00 | assert on rendered output, not intent |

## Rule 7 — severity discipline (used verbatim across the ledger)

- **P1** — money, auth, or data integrity is wrong.
- **P2** — a real functional or security defect with a bounded blast radius.
- **P3** — prose, figure, naming, or dead-code hygiene.

P2 and P1 get a builder fix cycle. **P3 alone does not justify a 4th cycle** —
per the 2026-10-08 directive, a P3 **travels with the next build**: it is
folded into the next builder's task, never given its own cycle. Cycle 3 closed
with "documentation-only, one word" escalations twice in a row, so this is a
live pattern, not a theoretical one.

## Ledger row vocabulary

Use the ledger's own words so the next auditor can grep for state:
`PENDING → IN-COMPLIANCE → BUILDING → IN-AUDIT → BUGS-FOUND → SHIPPED → PR-OPENED | ESCALATED | NOT-APPLICABLE`.

A cycle row names: task id, cycle number, findings by severity, which are
**closed and mutation-proven**, which are **open**, the floor delta, whether
the **push was withheld**, and any newly recorded hazard. Example shape:

```
chore: ledger - SPEC-1-B07a cycle 2 (3 closed incl a genuinely machine-tracking
eligibility derivation; BUG-5 P2 open - the payment axis tracks only half the
machine, and 100% coverage missed it)
```

## Escalate (return BLOCKED) rather than guess when

- the delta touches more than ~5 files or needs >1 new model
- the spec is ambiguous and the reading changes the public API
- the reported defect does not reproduce
- the fix would require weakening an existing test, gate, or assertion
- the floor cannot be held