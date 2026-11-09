# Auditor SOP — extracted from the GLM R4 / R4.1 / R4.2 audit (2026-11-06)

**Host:** OS-agnostic — typed tools are canonical (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is Windows-only (powershell) — the Windows implementation; the POSIX implementation is native.

The auditor receives the artifact and the requirements, never the builder's
reasoning. Paths: `$REPO` = audited worktree; `$PY` = `$REPO/backend/venv/bin/python` on Linux, `$REPO\backend\venv\Scripts\python.exe` on Windows;
`$H` = the harness root.

1. **Pin the tree.** `git.state({ fields: ["head", "branch", "clean"] })`.
   Expected: the exact audited SHA, the branch, and only known WIP paths.
   Parse: 40-char SHA + branch. Stop if the SHA differs from the dispatch record.

1a. **Docker preflight (before DAST/THREAD_RACE).**
   `docker.ensure({ action: "ensure" })` — prefer the typed tool (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is the Windows implementation, the POSIX implementation is native.
   Expected: `docker engine: ready <version>`, `container pg2a: running`,
   `container pg2b: running`; exit 0. Parse: the engine version and each
   container line. Failure: exit 2 → BLOCKED, not PASS; do not pull, build,
   create, or run a container. This wrapper is the only Docker action granted
   to this role.

1b. **K1 lifecycle (mandatory around the hacker).**
    Before `hacker_dispatch`, run
    `k1.up({ run_id: "<task_id>-<cycle>", base: "<capability.base>", head: "<capability.head>" })` — prefer the typed tool (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is the Windows implementation, the POSIX implementation is native.
    Expected: exit 0 and the `k1-<id>-app`/`k1-<id>-pg` containers on the
    internal network. Parse: the run id and both container names.
    Failure: exit non-zero → record BLOCKED `K1_UP_FAILED` and dispatch nothing.
    After the hacker returns, times out, or errors, run
    `k1.down({ run_id: "<id>" })` — prefer the typed tool (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is the Windows implementation, the POSIX implementation is native, in a
    `finally` block. Expected: exit 0 with both containers and the network
    removed. Parse: the removed container/network names. `k1_down` removes only
    that run's `k1-<id>-app`/`k1-<id>-pg` pair and its network; it never stops
    Docker, never touches `pg2a`/`pg2b`, and never prunes images or volumes.
    Never run `docker system prune`, `docker volume prune`, `docker stop`, or
    any Docker-down command. A failed `k1_down` is recorded, not retried with a
    pruner.

2. **Read the requirement, not the implementation narrative.**
   Commands: `read` the capability/request file and the acceptance test node id.
   Expected: a written predicate you can test. Parse: the property list.
   Decision: if the requirement has no observable assertion, BLOCK.

3. **Semgrep.** `check.run({ check_id: "SEMGREP", tree: "<capability.tree>", engine: "none" })`.
   Expected: `"engine":"semgrep"`, `"findings":[]`, exit 0.
   Parse: the JSON fields. Stop/FAIL if the engine is `fallback` or a finding
   remains; a missing binary is BLOCKED, never PASS.

4. **Oracle provenance.** `check.run({ check_id: "ORACLE_PROVENANCE", tree: "<capability.tree>", engine: "none" })`.
   Expected: every control case passes; `findings":[]` on the diff.
   Parse: `passed`, per-case classes, `assertions_scanned`.
   Decision: a finding is a BLOCK unless the policy text itself exempts it —
   "the heuristic looked wrong" is not an exemption.

5. **Architecture.** `check.run({ check_id: "ARCH", tree: "<capability.tree>", engine: "none" })`.
   Expected: `findings":[]`, exit 0. Parse: files/imports scanned + findings.

6. **Guard delta.** `check.run({ check_id: "GUARD_DELTA", tree: "<capability.tree>", engine: "none" })`.
   Expected: `guard_removals` all covered, `findings":[]`. Parse: covered/total.

7. **Test set.** `check.run({ check_id: "TEST_SET", tree: "<capability.tree>", engine: "postgres" })`.
   Expected: `removals` only allowed ones, `findings":[]`. Parse: base/head counts.
   Decision: an unexplained removal is a BLOCK; an allowed one cites
   `test-removal-reasons.json`.

8. **Authz matrix.** `check.run({ check_id: "AUTHZ_MATRIX", tree: "<capability.tree>", engine: "none" })`.
   Expected: `missing=0`, `UNKNOWN=0`, exit 0. Parse: routes/rows; check any new
   route's derivation.

9. **Thread race.** With the PG URL above:
   `check.run({ check_id: "THREAD_RACE", tree: "<capability.tree>", engine: "postgres" })`, 3 workers × 20 reps
   (auditor tier). Expected per run: `Ran 1 test` + `OK`.
   Parse: pass count. Any red rep or flake is FAIL, not a retry candidate.

10. **Re-derive one acceptance property.** Write your own transient test (do not
    copy the ticket), `check.run({ check_id: "SUITE", tree: "<capability.tree>", engine: "postgres" })`, then
    delete it and re-run `git.state({ fields: ["clean"] })`.
    Expected: `OK` and the pre-audit status restored. Parse: `Ran 1` + `OK`.
    Report MATCH/MISMATCH against the written property; MISMATCH is a BLOCK.

11. **Verdict artifact.** Write `files/drain/<cluster>/<stage>-audit.json` with
    the audited tree, model provider/model, per-check command/exit/evidence, and
    SHIP/REJECT/BLOCKED. Hash it; never edit a previous record.
    Parse: re-load the JSON and confirm the hash round-trips.

12. **Report.** Per check: CMD / EXIT / parsed line; the verdict; every check you
    could not run as BLOCKED. Do not merge; the release engineer does that.

**Stop conditions (any one):** SHA mismatch; semgrep/oracle undecidable;
a race rep fails; re-derivation MISMATCH; a required check BLOCKED and the
verdict would be SHIP.

## Lane / integration topology (permanent)

- Audit the branch the capability names: `lane/a` (`worktree-map.json#lane/a`),
  `lane/b` (`worktree-map.json#lane/b`), or `spec-comp`
  (`worktree-map.json#spec-comp`). `feat/add-frontend` is never
  audited directly.
- On SHIP, push exactly the audited branch once:
  `git.push_ref({ ref: "refs/heads/<branch>", expected_head: "<head>" })` — prefer the typed tool (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is the Windows implementation, the POSIX implementation is native. Lane branches get no PR;
  `spec-comp` is the promotion PR head.
- Never merge, never create/close/comment a PR, never push
  `feat/add-frontend` or any ref other than the audited branch.
- The only subagent the auditor may dispatch is its child `hacker`; every other
  subagent stays denied.
