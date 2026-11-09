# Release Engineer SOP — section-boundary promotion (2026-11-07)

**Host:** OS-agnostic — typed tools are canonical (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is Windows-only (powershell) — the Windows implementation; the POSIX implementation is native.

One long invocation per section boundary. `$H` = the harness root;
`$REPO` = `files/policies/worktree-map.json#spec-comp` (worktree on spec-comp).
Permanent topology (resolve via `files/policies/worktree-map.json`):
`#spec-comp` -> spec-comp; `#lane/a` -> lane/a; `#lane/b` ->
lane/b; promotion head spec-comp -> base feat/add-frontend; no per-task branch,
no lane PR, no second watch, no bare `git push` or bare `gh`.
Worktree sync is release-engineer-owned. The orchestrator never syncs; it
requests one release-engineer invocation, folded into this section-boundary
invocation (no extra cycle) or standalone (one invocation = one cycle).
Status: PROVEN = ran in this lineage; UNPROVEN = no successful execution yet.

0. **Sync the permanent worktrees from origin (reverse merge, no push).**
   `worktrees.sync({ lane: "<lane>" })` for each permanent worktree
   (`worktree-map.json#spec-comp`, `#lane/a`, `#lane/b`).
   Optional equivalent: `worktrees.list({})` to enumerate the set first.
   Expected: one line per worktree — `up-to-date <branch> @ <40-hex>` or
   `synced <branch>: <before> -> <after> (behind N)`; exit 0.
   Parse: branch, before/after SHA, behind count; record the three results.
   Failure: exit 2 = refusal (missing worktree, wrong branch, dirty; the path is
   named) => stop; do not clean, stash, or force. exit 3 = conflict (conflicted
   paths printed) => stop; resolve or `git merge --abort`, do not continue to
   reconcile, do not push. Other exit => stop. UNPROVEN.

1. **Preflight — pin integration state.**
   `git.state({ fields: ["branch"] })`; `git.state({ fields: ["clean"] })`;
   `git.state({ fields: ["head"] })`.
   Expected: `spec-comp`; no porcelain lines; a 40-hex SHA.
   Parse: branch, porcelain, full SHA; record `$HEAD0`.
   Failure: another branch => REFUSED STATE_MISMATCH; any porcelain line =>
   REFUSED DIRTY_TREE; stop; no reconcile.
   PROVEN read-only 2026-11-07 (spec-comp, clean); re-read live, never trust a prior SHA.

2. **Reconcile both lanes into spec-comp.**
   `worktrees.reconcile({ lane: "lane/a" })` then
   `worktrees.reconcile({ lane: "lane/b" })`.
   Expected: `merged lane/a: <40-hex>`, `merged lane/b: <40-hex>`, `reconciled head: <40-hex>`,
   `reconciled tree: <40-hex>`, `reconcile complete: ... (no push)`; exit 0.
   Parse: every merge SHA plus `$RECON_HEAD` and `$RECON_TREE`.
   Gate: each `origin/lane/*` tip equals its sealed PASS verdict head/tree, with live
   `policy_digest` / `control_set_sha` / `gate_impl_digest` per the newest
   gate-control record (see SIGNING.md); a moved lane or drift is
   STATE_MISMATCH/POLICY_DRIFT — stop. A live verify FAIL stops promotion;
   do not treat a historical PASS as live — **UNPROVEN** until re-seal +
   verify, see SIGNING.md seal->verify->declare order.
   Failure: exit 3 = conflict => REFUSED MERGE_REJECTED (leave worktree; no resolve/force);
   exit 2 = dirty/branch => DIRTY_TREE/STATE_MISMATCH; other exit => stop; no push. UNPROVEN.

3. **Push spec-comp (fast-forward only, explicit refspec).**
   `git.push_ref({ ref: "refs/heads/spec-comp", expected_head: "<reconciled head>" })` — prefer the typed tool (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is the Windows implementation, the POSIX implementation is native.
   Expected: `pushed sha: <40-hex>` equal to `$RECON_HEAD`; exit 0.
   Parse: the pushed SHA; record `$HEAD1`.
   Failure: exit 2 (branch/location/refusal) => REFUSED STATE_MISMATCH; a non-zero
   git exit => stop; no retry, no force, no `+`, no second ref. UNPROVEN.

4. **Open or reuse the promotion PR (never merge here).**
   `pr.open({ head: "<$HEAD1>", title: "spec-comp -> feat/add-frontend promotion" })`.
   Expected one line: `reuse PR #<n> <url> head=<40-hex> base=<40-hex>` or
   `created PR #<n> <url> head=<40-hex> base=<40-hex>`; exit 0.
   Parse: PR number, head OID, base OID; Q-PRHEAD: head == `$HEAD1`; Q-BASE: base
   branch is `ci.json.promotion_branch` (feat/add-frontend); the base OID is the
   live `feat/add-frontend` tip and is recorded, not compared to capability.base.
   Failure: exit 2 => REFUSED; missing number or head/base mismatch => BASE_MOVED/STATE_MISMATCH;
   no merge, no lane PR. UNPROVEN.

5. **Watch required checks exactly once.**
   `pr.watch({ pr: <n>, head: "<$HEAD1>" })`.
   Expected: exit 0; every required name — SUITE, SECRETS, BOOTTEST,
   POLICY_DIGEST, ZIZMOR, CHANGELOG, CONVENTION — shows success for `$HEAD1`.
   Parse: exit code and each name/conclusion; one invocation only, no second poll.
   Failure: exit 1 => REFUSED CHECKS_FAILED; exit 8 => CHECKS_TIMEOUT; exit 2 => REFUSED;
   other => stop. A red or pending check past this watch is terminal. UNPROVEN.

6. **Merge head-pinned; verify the merged tree.**
   `git.state({ fields: ["head"] })` must still equal `$HEAD1`.
   `pr.merge({ pr: <n>, head: "<$HEAD1>" })`.
   Expected: `merged sha: <40-hex>` then `merged tree: <40-hex>`; exit 0.
   Parse: `$MERGE_SHA`, `$MERGED_TREE`; require `$MERGED_TREE` == `$RECON_TREE`
   (the audited integration tree).
   Failure: exit 2 head-pin mismatch => STATE_MISMATCH; non-zero `gh` =>
   MERGE_REJECTED; missing/non-40-hex SHA (including `merged sha: (none reported)` +
   exit 0) or missing tree => STATE_MISMATCH/UNPROVEN; stop, never proceed to
   release record / never write MERGED. No admin, auto-merge, force, or delete-branch; never re-merge. UNPROVEN.

7. **Record only after the merge.**
   `guard_ref` = `capability.guard_ref` (acceptance node id + sha256) on DRAIN, null
   otherwise; confirm present at the audited head, unskipped, passing in verdict SUITE.
   Write the release record under `quality/ledger/release/<task_id>/` with head=$HEAD1,
   merge_sha=$MERGE_SHA, merged_tree=$MERGED_TREE, pr_number=<n>, checks, policy_digest,
   control_set_sha, guard_ref, sig_status=unsigned_local, record_hash; append-only, no edits.
   Expected: the sealed record re-reads with the same `record_hash`; `guard_ref` is set on DRAIN.
   Parse: re-read and recompute `record_hash`.
   Failure: POLICY_DRIFT, GUARD_REMOVED, or STATE_MISMATCH => REFUSED; never
   downgrade and never write MERGED. UNPROVEN.

**Stop conditions (any one):** dirty tree; HEAD moved after audit; a lane head or
tree differs from its audited verdict; policy/control-set drift; a required check
red or pending after the single watch; the branch-protection record is stale or
mismatched; a step needs a bare `git push` or bare `gh`; merged tree != audited
tree. Refuse with the matching code and stop.

## Lane / integration topology (permanent)

- `worktree-map.json#spec-comp` -> `spec-comp` (integration); `#lane/a` -> `lane/a`;
  `#lane/b` -> `lane/b`; `feat/add-frontend` moves only through `merge_pr`.
- Builders commit on their lane; the auditor pushes the audited lane on SHIP. This
  role reconciles both into `spec-comp` in one invocation; no per-task branch, no lane PR.
- `pr.merge` (Windows implementation: `merge_pr.ps1`) now projects `.mergeCommit.oid` and, on an empty/`null`/non-SHA
  oid, prints `merged sha: (none reported)` with exit 0 (it does not reject);
  `merged sha`/`merged tree` remain UNPROVEN until a real merge prints them. The
  caller must treat `merged sha: (none reported)` + exit 0 as STATE_MISMATCH/
  UNPROVEN — a hard stop, never proceed to release record / never write MERGED.
- Open issue (not resolved here): `merged_tree == audited spec-comp tree` is not
  guaranteed when `feat/add-frontend` has commits that `spec-comp` lacks. The
  promotion must either reconcile the base into `spec-comp` before audit, or the
  audit must cover the merge result. Do not claim tree equality without measuring it.
