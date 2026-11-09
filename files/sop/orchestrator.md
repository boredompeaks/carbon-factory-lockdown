# Orchestrator SOP — extracted, with unproven parts marked

Status legend: **PROVEN** = a command below ran in the R4 lineage;
**UNPROVEN** = no successful execution exists yet (kept explicit, not dressed
as procedure). The orchestrator dispatches; it does not write product code and
does not merge.

1. **Load check.** `cd $H; python scripts/check_harness_config.py`.
   Expected: `RESULT: PASS (<n> checks)`, exit 0. Parse: that line. PROVEN.
   Stop if FAIL — a role/model/permission invariant is broken.

2. **Lineage check.** `python files\tools\validatedrain.py`.
   Expected: PASS with the newest gate-control seal named. Parse: the summary +
   `problems:[]`. PROVEN at seal time — PASS against the newest gate-control
   record (live `policy_digest` / `gate_impl_digest` / `control_set_sha` per
   the newest record; see SIGNING.md). Live PASS is **UNPROVEN** until a
   re-seal verifies PASS against the live tree (seal->verify->declare,
   SIGNING.md): a live FAIL stops dispatch; do not treat a historical PASS
   as live.
   Stop on FAIL.

3. **Policy-change intake (owner authority only).** The factory writes a request
   to `requests/<id>-<slug>.md`; CARBON evaluates it as FDE and applies it with
   owner permissions. The orchestrator never edits `files/policies/**` and never
   edits gate tool bodies. PROVEN (R05-01/02/03 this session).

4. **Dispatch.** Only when the capability record and its `policy_digest` match
   the live tree. Expected record: `DISPATCH / OK` with the tier, scope, and
   acceptance refs. Parse: the verdict token. PROVEN for record shape; **the
   written dispatch command is UNPROVEN** (no `dispatch.py` exists in this
   tree — records were authored directly). Stop if the model families are not
   distinct in `files/policies/models.json`.

5. **Builder stage.** Hand the builder the ticket + acceptance node id only.
   Collect: tree SHA, per-step CMD/EXIT/parsed line, acceptance hash. The
   builder's "done" is a claim until the auditor reproduces it. PROVEN.

6. **Auditor stage.** Hand the auditor the artifact + requirements only (never
   the builder's rationale). Require the auditor's verdict artifact under
   `files/drain/<cluster>/`. A BLOCKED check may not be reported as PASS.
   PROVEN.

7. **Verdict gate.** SHIP only if every required check for the tier is green or
   explicitly shadowed for one cycle; any BLOCKED required check keeps the
   stage open. Parse: the verdict field, not prose. PROVEN.

8. **Release.** `merge_pr --match-head-commit <sha>` from the release-engineer
   role, with admin/auto/force denied. Expected: merged tree == verdict tree,
   `guard_ref` written on the release record. **UNPROVEN** — first attempt is
   the R05 pilot; do not claim it works until the release record exists.

9. **Guard.** The acceptance test becomes a permanent guard (`guard_ref` on the
   release), never edited after landing. Verify: `git -C $REPO log --oneline -1`
   and the release record's `guard_ref`. PROVEN for the hash/immutability rule;
   **UNPROVEN for the `merge_pr` half** until step 8 runs.

10. **Report.** Per gate: MET/BLOCKED, command, exit, parsed line. Divergences
    from this SOP become SOP corrections, not blame. PROVEN.

**Known unproven dependencies (do not pretend otherwise):**
- `merge_pr --match-head-commit` and its `guard_ref` side effect (Gate 7 pilot).
- Service-booted orchestrator (the CLI-booted path is what ran; the service
  path is untested).
- `subagent` permission on the orchestrator: no permission block authorises it
  yet; dispatch of child sessions is unproven from inside the factory.
- Gate-control re-seal after a policy byte changes; the newest gate-control
  record names the live `policy_digest` / `gate_impl_digest` /
  `control_set_sha` (see SIGNING.md). A further policy or gate-impl byte
  requires a new seal; a live verify FAIL stops dispatch until re-seal and
  re-verify PASS.

## Lane / integration topology (permanent)

- Expected worktree set: `<worktree>` -> `spec-comp`, `<lane-a-worktree>` -> `lane/a`,
  `wt-async` -> `lane/b`. `lane/c` and `lane/d` are dormant and are not
  dispatched.
- Dispatch at most two builders in parallel, one per active lane. They commit
  locally and never push.
- At a section boundary, hand the lane heads to the release engineer in one
  invocation. The orchestrator does not reconcile, push, open a PR, or merge.
- Worktree sync (reverse-merging `origin` into the local worktrees) is
  release-engineer-owned. The orchestrator never runs git sync; it requests it
  at a section boundary (folded into the single RE invocation, no extra cycle)
  or standalone (one RE invocation = one cycle).
- Release order: reconcile `origin/lane/a` and `origin/lane/b` into
  `<worktree>/spec-comp` (`--no-ff`), push `spec-comp`, reuse/create
  `spec-comp -> feat/add-frontend`, run one `gh pr checks --watch`, then merge
  head-pinned. No lane PRs.
