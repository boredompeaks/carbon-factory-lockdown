# R05-02 — Align ORACLE_PROVENANCE's classes with the written rule

- **Date:** 2026-11-06
- **Requested by:** CARBON (FDE) after the Gate 3 GLM audit
- **Affects:** `files/tools/oracle_provenance.py`, `files/tools/fixtures/oracle/*`,
  `files/policies/negative-controls.json` (ORACLE entries)
- **Status:** APPROVED — applied and re-verified

## Finding

`assert-rules.json` defines `ORACLE_BY_COPY` as "flag when the expected constant
or expression also appears in the added implementation lines", and `MOCK_ECHO`
as "asserts a value configured on a mock". The tool adds two undocumented
branches:

1. ORACLE_BY_COPY fires when the asserted literal appears **anywhere in the
   test as an input** (including fixture helpers such as `total="900.00"`).
   On the R4/R4.1 diff this produced 33 findings — every one an ordinary money
   assertion (`refundable_remaining == 300.00`, `refund_total == 0.00`, ...).
2. MOCK_ECHO fires on `len(calls)` where `calls` is a list the test itself
   appends to inside a `side_effect`. `assertEqual(len(calls), 1)` is the
   double-spend invariant — it counts calls to the product's dependency, not a
   value the fake was configured to return.

Both make a correct money/concurrency suite unpassable: any test that names an
amount it also passes in, or asserts the gateway was called once, is flagged.
The permanent control `ORACLE-03` encodes branch 1, so the tool and its own
control agree with each other and disagree with the policy text.

## Change

- ORACLE_BY_COPY: keep identical-call (`f(x) == f(x)`), implementation-constant,
  and implementation-value branches; delete the test-input-literal branch.
- MOCK_ECHO: keep comparisons against a mock's configured `return_value` /
  `side_effect` value and against configured mock attributes; delete the
  "test-owned container / call-count" branch.
- `mirror_refund_race.py` becomes a genuine echo fixture: it asserts the
  patched gateway's configured `return_value`, keeps `len(calls) == 1` and the
  `Decimal("600.00")` balance assertion as assertions that must now be CLEAN.
  `ORACLE-03` expects exactly `{"MOCK_ECHO"}`.
- New `ORACLE-04` fixture (`call_count_test.py`): only a call-count assertion
  plus money literals → expected PASS. This is the guard against silently
  broadening the class back.
- `negative-controls.json`: ORACLE_PROVENANCE min_count 4; ORACLE-04 added.

## FDE evaluation

- This aligns the tool with the policy text; it does not weaken a stated rule.
  The classes that catch real self-referential oracles (identical call, copied
  implementation constant/value, echo of a configured mock value) are intact,
  and `bad_test.py` still exercises all three classes.
- The new negative control proves the narrowed class still rejects a real echo
  and does not over-block the legitimate call-count/money assertions. Gate 6c
  will mutate this tool; if a neutered version survives a control, that is a
  finding independent of this change.
- Because the tool body is in `CHECK_BODY_FILES` / hashed into
  `gate_impl_digest`, the next gate-control seal (after Gate 6) must be
  regenerated; this request does not rewrite any existing ledger record.
- No product code is touched by this request.

**Decision: APPROVED.** Verification: `oracle_provenance.py --control` all
cases pass; the R4/R4.1 added-test scan returns 0 findings; `ORACLE-04` PASS.
