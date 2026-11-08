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
   `problems:[]`. PROVEN at seal time — PASS at record `0008-7567ce1902de`
   (`policy_digest` `c8471186…`, `gate_impl_digest` `224cbf99…`,
   `control_set_sha` `971f1fda…`, `record_hash` `3722fb89…`). Live PASS is
   **UNPROVEN** until a re-seal verifies PASS against the live tree (seal->
   verify->declare, SIGNING.md): the live tree has drifted past `0008`, so a
   live FAIL stops dispatch; do not treat the historical PASS as live.
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
- Gate-control re-seal after a policy byte changes; record `0008` seals the
  `c8471186` lineage through `0005` (`2d34342d -> c8471186`) plus the
  `gate_impl_digest` lineage `862407a5 -> 0fe32eea -> 34ffd85b -> 224cbf99`
  (SIGNING.md re-seals 0005-0008). A further policy or gate-impl byte
  requires a new seal; the live tree has drifted past `0008`, so re-seal and
  re-verify before claiming PASS.

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
