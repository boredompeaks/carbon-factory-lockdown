# S-B restatement — outcome extraction (S5a)

**Supersedes:** “251 masked, 239 with a success claim.”
**Method:** parse the runner's own summary, never the wrapper exit code.
**Parser:** `scripts/outcome_parse.py` (16 tests, `scripts/test_outcome_parse.py`).
**Scan:** `scripts/scan_sessions.py` over 563 sessions whose last bash command matched a test runner.

## Measured result

| Measurement | Old method (any failure text) | S5a parser |
|---|---:|---:|
| Sessions with a test command | 563 | 563 |
| Runner summary OK | — | 424 |
| Runner summary FAILED | — | 65 |
| No runner summary (UNMEASURED) | — | 74 |
| Exit non-zero | 94 | 94 |
| Exit non-zero **and** summary FAILED | 15 | 15 |
| Exit 0 **and** summary FAILED (masked) | 251 | **50** |
| Masked **and** final text claims success | 239 | **45** |
| Delta | — | **−201 masked / −194 claim** |

## Why the old figure was high

The old regex searched the whole output for any failure text. The parser reads
the **last** runner summary. Of the 233 sessions the old method called failed
but which end with a green summary:

- **203** have exactly one green `Ran … OK` block; the failure text came from a
  coverage report, a deliberate mutation probe, or a quoted earlier log;
- **24** have no `Ran` block but a line-start `OK` from the final run;
- **4** contain two or more `Ran` blocks — an earlier red run, a later green one;
- **2** are explicit mutation probes (`MUTATED … FAILED … restored … OK`).

None of those is a masked suite failure: the suite's final summary is green.

## What survives

The mechanism in Chain 1 is unchanged and still measured:

- **50** sessions recorded a failing suite while the wrapper exited 0;
- **45** of those end with a success claim (`SHIP`, `DONE`, `clean`, `verified`).

Examples: `ses_e977ccb1` (`Ran 7 tests … FAILED (failures=1, errors=3)`, exit 0,
report begins `AUDIT FULL SPEC-16-T4 cycle 1 -- SHIP`); `ses_ea6f29507`
(`Ran 2253 tests … FAILED (failures=6, errors=196, skipped=2)`, exit 0);
`ses_ea832c319` (`Ran 13 tests … FAILED (failures=7)`, exit 0, report
`TASK SPEC-D-01 -- DONE`).

## Bounds

- **Lower bound 50** — every one has a final `FAILED` summary and exit 0.
- **Upper bound 50** for “masked”, **45** for “masked + success claim”.
- 74 sessions are **UNMEASURED**: no runner summary in the retained output
  (typically `Select-Object -Last N` cut the summary, or the command only
  listed fixtures). Under S5a these are FAIL, not green. They are not counted
  as masked because there is no measured failure either.

The replacement sentence for the report is:

> *50 sessions recorded a failing suite while the wrapper exited 0; 45 of them
> then claimed success. A further 74 sessions ran a test command whose summary
> was not retained and are UNMEASURED.*
