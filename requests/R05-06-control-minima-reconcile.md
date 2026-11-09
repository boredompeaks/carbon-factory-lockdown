# R05-06 — control minima reconciliation (`known_bad_min`, ORACLE floor)

Date: 2026-11-07
Requester: CARBON (FDE), under the owner's factory-hardening directive (PUNCH-02)
Status: APPLIED

## Problem

`gate_control --write` compared the known-bad control count to `total_min`.
The manifest declares 53 entries (28 known-bad, 25 clean-discrimination), and
`total_min` was 53, so the comparison was unsatisfiable: 28 < 53. The old
record `0004` used `total_min=13`, which was a known-bad floor, not an entry
count.

A second, independent inconsistency surfaced after the first fix: the
`ORACLE_PROVENANCE` group declared `min_count=5` but contains 3 known-bad
controls (`ORACLE-01`, `ORACLE-03`, `ORACLE-05`) and 2 clean-discrimination
controls (`ORACLE-02`, `ORACLE-04`). `enforcement.per_check_rule` counts only
`expected_outcome == FAIL`, so the group was permanently under its own floor
(`3/5`) and `gate_control` refused to PASS.

## Change

`files/policies/negative-controls.json`

- add `known_bad_min: 28` (the number of controls whose `expected_outcome` is
  `FAIL`);
- keep `controls_total: 53` and `total_min: 53` as the declared-entry floor;
- set `ORACLE_PROVENANCE.min_count` from `5` to `3` (its actual known-bad
  count; the two PASS controls remain discrimination fixtures and are not
  counted);
- update `enforcement.rule` / `control_set_sha_rule.exclude` accordingly;
- recompute `control_set_sha` from the resolved manifest.

`files/tools/gate_control.py`

- `build()` compares `total >= known_bad_min` (falling back to `total_min` only
  if the field is absent);
- the record carries `known_bad_min` and `controls_declared`;
- `verify()` checks `controls_total >= known_bad_min`, `controls_declared ==
  len(controls)`, and `controls_declared == manifest.controls_total`.

`files/tools/gate_run.py`

- `GATE_CONTROLS` compares `controls_total` to `known_bad_min`, not `total_min`;
- the synthetic control manifest carries `known_bad_min`.

Prose predicates in `policies/checks.json` and `policies/invariants.json`, and
the GATE_CONTROLS paragraphs in `files/{auditor,orchestrator}.md`, now name
`known_bad_min` and state that `total_min` is the declared-entry floor.

## Evidence (commands run before sealing)

```
python -c "... counts ..."
53 53 28 28

python ... control_audit.py
UNDER: []
sum_fail 28

python files\tools\gate_control.py   (dry run)
result=PASS state=PASS controls_total=28 controls_declared=53
controls_rejected=28 known_bad_min=28 all_rejected=True errors=None
policy_digest=c847118644fa18d704773ba3f9a8892b13b756f9c67afb322607d6f927f631a8
gate_impl_digest=862407a53de1ca8ffd7a48943ceddb3a9c2a544c0136da3707810910200c2a0b
control_set_sha=971f1fdac1698a8b43265de31b13dca97126848dedf56bb8aed7eff0cb481267
gate_sha=7567ce1902de1fb57b908d2341ba8812337c5ee2
```

Control-set hash moved `c15e5ee7…` → `971f1fda…` only because the ORACLE
`min_count` is part of the resolved manifest. No control was added, removed, or
had its `expected_outcome` changed; 53 entries and 28 known-bad controls remain.

## FDE evaluation

The change corrects the floor semantics; it does not weaken the gate. The
known-bad total is unchanged (28), every known-bad fixture is still required to
be rejected, and the clean-discrimination fixtures are still required to be
accepted. `ORACLE_PROVENANCE` retains all five controls; only its known-bad
floor is corrected to the number that actually exists.
