# Builder SOP — extracted from R4 / R4.1 / R4.2 (2026-11-06)

**Host:** OS-agnostic — typed tools are canonical (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is Windows-only (powershell) — the Windows implementation; the POSIX implementation is native.

Every step names a command that ran in this lineage. Paths: `$REPO` = the
audited worktree; `$PY` = `$REPO/backend/venv/bin/python` on Linux, `$REPO\backend\venv\Scripts\python.exe` on Windows;
`$H` = the harness root.

0. **Docker preflight (only if the lane database is down).**
   `docker.ensure({ action: "ensure" })` — prefer the typed tool (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is the Windows implementation, the POSIX implementation is native.
   Expected: `docker engine: ready <version>` then `container pg2a: running`
   and `container pg2b: running`; exit 0. Parse: the engine version and each
   container line. Failure: exit 2 → stop; do not pull, build, create, or run a
   container. This wrapper is the only Docker action granted to this role.

   **Ask, do not bypass.** When a command matches an `ask` rule, request it
   once through the tool. If the human denies, return BLOCKED with the denied
   command. Do not try alternate paths, shell tricks, or a different image
   source.

1. **Pin the tree.** `git -C $REPO rev-parse HEAD` and `git -C $REPO branch --show-current`.
   Expected: the exact dispatch SHA; a branch, not `HEAD` detached.
   Parse: the 40-char SHA string. Stop if it differs from the capability record.

2. **Fingerprint the acceptance test before touching anything.**
   `evidence.hash({ rev: "<capability.head>", path: "backend/orders/tests_gate0_refund_race.py" })`.
   Expected: a SHA-256. Parse: the hash. Stop if the file is absent.

3. **Map the call sites you will touch.**
   `basemind_code` (`code.search{mode:grep}`) for `issue_refund\(` in `backend/orders/*.py` and for `refund_payment\(` in `backend/orders/**/*.py` (cross-platform; `grep`/`glob` tools are equivalent).
   Expected: every production caller and its key source. Parse: `path:line`.
   Decision: a production caller with no operator action id is a BLOCK (refuse
   or derive one), never a silent keyless path.

4. **Implement the smallest change that satisfies the ticket.**
   Command: the `edit`/`write` tool on the scoped files only.
   Expected: `git -C $REPO status --porcelain` lists only scoped paths.
   Parse: the porcelain lines. Stop if an out-of-scope file appears.

5. **Migration state.** `cd $REPO/backend; $PY manage.py makemigrations --check --dry-run`.
   Expected: `No changes detected`, exit 0. Parse: that line.
   Stop if it proposes a change you did not write by hand.

6. **Targeted suites.** `$PY manage.py test <ticket labels> --noinput`.
   Expected: `Ran <N> tests in <t>s` followed by `OK`.
   Parse: the summary pair; the shell exit is corroboration, never the verdict.
   Stop if `FAILED (...)` or if the summary is missing.

7. **Full app suite.** `$PY manage.py test orders --noinput`.
   Expected: `OK`; pre-existing unrelated failures are named verbatim and not
   chased. Stop only on failures inside the touched surface.

8. **Format and lint the touched Python.**
   `$PY -m ruff check <touched .py>` and `$PY -m ruff format --check <touched .py>`.
   Expected: `All checks passed!` and `N files already formatted`. Parse both.

9. **Concurrency on the real engine.**
   `DATABASE_URL='postgresql://perfume:pg2a_local_test_only@127.0.0.1:5432/perfume_store' $PY manage.py test <race class> --keepdb -v 2 --noinput`.
   Expected per run: `Ran 1 test` + `OK`. Repeat N times (high: 5 builder reps).
   Decision: any flake or red rep is a BLOCK; do not average it away.

10. **Prove the acceptance test is untouched.**
    `evidence.hash({ rev: "<capability.head>", path: "backend/orders/tests_gate0_refund_race.py" })`.
    Expected: identical to step 2. Stop if it differs.

11. **Commit only the change set.**
    `git -C $REPO add -- <explicit paths>` then
    `git -C $REPO commit -m "<scope>: <summary>"`. Verify `git log --oneline -1`.
    Expected: one commit, the staged paths only. Stop before any merge.

12. **Hand off.** Report per step: command, exit code, parsed line. Name the
    tree SHA and the acceptance-test hash. No prose claims without a line.

**Stop conditions (any one):** tree SHA mismatch; acceptance-test hash change;
a red test returns green with no explanation; a money-state divergence in a
suite; a required check red or BLOCKED that you have not named.

## Lane / integration topology (permanent)

- Worktrees: `lane/a` at `<lane-a-worktree>`, `lane/b` at `wt-async`, integration
  `spec-comp` at `<worktree>`. `feat/add-frontend` is the promotion target and is
  never committed or pushed directly.
- Work only in the worktree/branch named by the capability. Never cut a
  per-task branch; lanes and `spec-comp` are permanent.
- Commit the scoped change set on that branch. Never push, merge, rebase,
  cherry-pick, or create/comment/merge a PR. The auditor pushes the audited
  branch on SHIP; the release engineer reconciles and promotes.
- A lane builder never reads another lane's worktree, the hacker exploit
  source, or the audit report.
