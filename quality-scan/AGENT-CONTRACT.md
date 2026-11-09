# Quality scan — shared agent contract (read this first)

SOURCE WORKTREE (READ-ONLY, has uncommitted work owned by another agent):
`C:\Users\Admin\AppData\Local\Temp\opencode\comp-wt` — branch `spec-comp`, HEAD `1ffe926`, 4 untracked files.
You may NOT create, modify, delete, or format anything inside it. You may NOT run `git`.

WRITE TARGET: exactly one file, the report path given in your brief, under
`C:\Users\Admin\Documents\umairnlp\quality-scan\reports\`. Use write/edit tools, never shell redirection.

## Axes — cover all five explicitly

1. INVARIANTS. Name each invariant the flow must hold, then check enforcement (not intent). Money = Decimal + quantize, no float on the wire. Side-effectful flows = `transaction.atomic` + `select_for_update` on the rows that gate concurrency, consistent lock order. Authz = permission classes / object scope, never inline `is_staff`. State machines = one source of truth, no state write outside it. Uniqueness = IntegrityError retry, not check-then-act.
2. CORRECTNESS. Wrong values/status codes, swallowed exceptions, check-then-act races, immutable-field writes, `update_fields` omissions, timezone, non-string bodies, pagination ordering, partial failure mid-loop.
3. SAST. Missing permission_classes, IDOR, mass assignment, secrets in code/logs, unsafe deserialization, SSRF, raw SQL, error leakage, log injection, unbounded queries/loops, PII to third parties.
4. ARCHITECTURE / SMELLS. Layering, duplication, dead code, god modules, hidden I/O, naming vs `backend/docs/conventions.md`, import cycles, module-level side effects.
5. TEST SIDE. Would the test fail if the guard were deleted? Tautological assertions, asserts on `res.data` instead of the rendered wire, skipped/xfail pins, over-mocking, isolation, missing negative/authz/concurrency cases. Name which axis-1 invariants have NO test.

Known-tracked — do not re-report as new: `backend/docs/audit.md` (F-01..F-29), `backend/docs/vulnerabilities.md` (V-01..V-21), `backend/docs/test-gaps.md`. Confirmed by other flows already: V-03 (capture-then-409 no refund), QC-022 (refund gateway call inside the transaction), QC-003 (unpaid pending→confirmed). Only report a NEW mechanism.

## Probes (non-mutating only)

`python -B` with cwd `C:\Users\Admin\AppData\Local\Temp\opencode\q-scan`; `ruff check --no-cache --no-fix <abs file>`; grep/read/ast.parse on absolute paths.
FORBIDDEN: `manage.py test|migrate|makemigrations`, pytest, black, pip install, any git command, shell redirects into the worktree, creating `__pycache__` inside it.

## Severity — the fix-triage key

- **P1 CRITICAL** money, auth, or data integrity is wrong → `FIX-NOW`
- **P2 HIGH** real functional/security defect reachable by users → `NEXT-BUILD`
- **P2 MEDIUM** real defect, bounded blast radius → `NEXT-BUILD`
- **P3 LOW** naming, dead code, duplication, hygiene, weak assertion → `FOLD-INTO-NEXT`
- **P4 INFO** architecture observation

Also give `Class` (CODE / DOC-ONLY / INFRA) and `Confidence` H/M/L. No style nits that break no documented rule. No finding without a line number. Do not claim DB/Postgres behaviour you only inferred — mark source-read reasoning.

## Return form (max 55 lines)

```
FLOW <ID> -- CLASS: CODE
COUNTS: P1=n P2=n P3=n P4=n CONFIRMED=n KNOWN=n
<ID>-01 | P2 | HIGH | CODE | file:line | claim | evidence | H|M|L | NEXT-BUILD
... up to 12 rows ...
OUT-OF-SCOPE HANDOFFS: <file:line -> owning flow>   (max 3)
UNCHECKED AXES: <what you did not verify and why>
WORKTREE WRITES: none
```

Reproduce every claim against the source before writing it. Full detail goes in the report file; the returned table is the bounded summary.
