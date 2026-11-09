# R05-03 — Schedule AGT_PARITY and AGT_AUDIT at high+

- **Date:** 2026-11-06
- **Requested by:** CARBON (FDE) under the R05 brief (Gate 6d)
- **Affects:** `files/policies/tiers.json`
- **Status:** APPROVED — applied (shadow for one cycle)

## Finding

`AGT_PARITY` and `AGT_AUDIT` exist as checks with auditor runners, executable
negative controls (AGT-PARITY-01/02, AGT-AUDIT-01), and sealed evidence in the
newest gate-control record — but they appear in **no tier's `required_checks`**.
A check that records and affects no verdict rots: it can be red while every
tier still passes, which is precisely the "advisory control" failure the
factory is meant to exclude.

## Change

Add both ids to `required_checks` for `high` and `max`, with a one-cycle shadow
entry each (`shadow: true, cycles: 1`), per the standing rule "shadow one
cycle, then alarm; nothing enforces on first landing". `none` (low) keeps
neither: AGT is a second boundary layer for elevated tiers, and its prompt
scan/output redaction costs are not justified for the low lane. No other tier
field changes. No deletion alternative is taken because both checks have
working controls and sealed evidence.

## FDE evaluation

- Both checks are auditor-run, closure-scoped, and already carry BLOCK-class
  fail actions; scheduling them creates no new runner and no new policy file.
- Shadow means the first cycle records without failing the tier; the next
  cycle flips to enforcing by removing the shadow entry. This is an explicit,
  dated step, not a silent ratchet.
- `tiers.json` is one of the five gated policy files, so this changes
  `policy_digest`; a fresh gate-control record (0005) must be written after the
  Gate 6 control run, and the drain records re-sealed against the new digest.
  The request does not touch any existing ledger record.
- If the AGT adapter fails to load at boot, AGT_PARITY's own predicate is what
  catches it — scheduling it is what makes that failure verdict-affecting.

**Decision: APPROVED.** Verification: `check_harness_config.py` PASS after the
edit; `tiers.json` loads; both ids present in `high`/`max` required and shadow
lists; `gate_run.py --check`/`agt_parity.py` still runnable; the re-seal step
is recorded in the Gate 6 output.
