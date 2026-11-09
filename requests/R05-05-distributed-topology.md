# R05-05 — Ingest the distributed two-lane factory topology

- **Date:** 2026-11-07
- **Requested by:** orchestration directive (R05 program)
- **Prepared by:** factory config ingest
- **Affects:** `scripts/*.ps1` (release wrappers), `files/{builder,auditor,release-engineer,orchestrator}.md`, installed twins under `.opencode/agents/`, `.opencode/skills/*`, `files/skills/*`, `files/policies/ci.json`
- **Status:** APPROVED — applied

## Finding

The role contract still describes one task branch per task (`task/<task_id>`),
one push tool, and a squash merge. The live topology is different:

- Permanent lanes: `lane/a` in `spec-comp-wt`, `lane/b` in `wt-async`; `lane/c`
  and `lane/d` are dormant. Integration is `spec-comp` in `comp-wt`; the
  promotion base is `feat/add-frontend`.
- Builder commits on the assigned lane or integration branch and never pushes.
- Auditor on SHIP pushes the branch it audited as a durability/PR-head update.
- Release-engineer, in one long invocation at a section boundary, reconciles
  both lanes into `comp-wt/spec-comp` with `--no-ff`, pushes `spec-comp`, opens
  or reuses the promotion PR, watches checks once, and merges.
- No reconciler existed. `push_branch.ps1` only accepts `task/*`.
  `merge_pr.ps1` trusted the repository default merge method, while `ci.json`
  said `squash` and the last promotion PR (#50) was a merge commit.

## Change

- `scripts/push_ref.ps1`: explicit `refs/heads/<Branch>:refs/heads/<Branch>`
  push for `spec-comp`, `lane/a`, or `lane/b` only; ff-only (no `+`, no
  `--force`); refuses any other branch and any worktree whose HEAD differs;
  prints `pushed sha`. Default worktrees are per branch (`comp-wt`,
  `spec-comp-wt`, `wt-async`).
- `scripts/reconcile_lanes.ps1`: requires `comp-wt` on `spec-comp` and a clean
  worktree, fetches `origin`, merges `origin/lane/a` and `origin/lane/b` with
  `--no-ff`, prints each merge sha plus the reconciled head/tree, stops at the
  first conflict with exit 3, and never pushes. `-WhatIf` prints the fetch and
  merge commands.
- `scripts/open_pr.ps1`: reuses an open PR for the base/head pair and exits 0,
  otherwise runs one `gh pr create`. The body is compact JSON containing only
  `schema`, `base`, `head`, `head_sha`, and `head_tree`. No merge path.
- `scripts/watch_checks.ps1`: exactly one
  `gh pr checks <n> --watch --interval 30` invocation, exit status returned
  unchanged; `-Help` and `-WhatIf`.
- `scripts/merge_pr.ps1`: unchanged head-pin and refusal surface; now reads
  `merge_method` from `files/policies/ci.json` and passes the matching
  `--merge`, `--squash`, or `--rebase`. Still no admin, auto-merge, force, or
  delete-branch option. Also prints the merged tree when resolvable.
- Role contracts: builder is lane-worktree-only and commit-only; auditor gains
  the SHIP durability push; release-engineer is one section-boundary invocation
  (reconcile → push → PR → one watch → pinned merge) and records `guard_ref`;
  orchestrator declares permanent lanes A/B, parallel dispatch, the
  `comp-wt`/`spec-comp-wt`/`wt-async` expected set, and no push/merge.
- Skills: updated `push-branch`, `merge-pr`, and `dispatch`; added `push-ref`,
  `reconcile-lanes`, `open-pr`, and `watch-checks` under `.opencode/skills/`
  with `opencode/autoinvoke: false`. Source mirrors added under `files/skills/`.
- Permissions: auditor shell is now deny `*` then allow `*push_ref.ps1*` only.
  Release-engineer shell is deny `*` then allow `*push_ref.ps1*`,
  `*reconcile_lanes.ps1*`, `*open_pr.ps1*`, `*watch_checks.ps1*`, and
  `*merge_pr.ps1*`. The stale `push-branch` grant was removed from
  release-engineer; auditor gained `push-ref`; release-engineer gained
  `push-ref`, `reconcile-lanes`, `open-pr`, `watch-checks`, and kept
  `merge-pr`. Read permissions are unchanged.
- `ci.json`: `base_branch: spec-comp`, `promotion_branch: feat/add-frontend`,
  `merge_method: merge` (matches #50's merge commit). `--match-head-commit`
  semantics remain in the wrapper.

## FDE evaluation

- `push_ref` is deliberately narrower than a general push: the branch allowlist
  and the worktree-HEAD equality check make it impossible to push `master`,
  `feat/add-frontend`, or a lane from the wrong worktree. The refspec has no
  leading `+`, so a non-fast-forward update is rejected rather than forced.
- `reconcile_lanes` changes only the integration worktree and only through
  `--no-ff` merges of the audited lane refs. It refuses a dirty tree, refuses a
  worktree that is not on `spec-comp`, and exits before the next lane on
  conflict. It has no push call at all.
- `open_pr` makes reuse the default and keeps the PR body machine-checkable
  (ids/hashes only). It cannot merge; the only merge path remains
  `merge_pr.ps1`.
- `watch_checks` enforces the one-watch rule mechanically: there is no loop in
  the wrapper, so a second observation is a new release decision.
- `merge_pr` keeps the strongest existing guard (`--match-head-commit`) and
  removes the repository-default ambiguity by reading `ci.json`. `merge` is
  correct for this repository's history, not a weakening: the method is now
  explicit policy instead of an implicit repo setting.
- The permission split is intentional. Auditor can no longer run git read
  commands directly; A-STATE is sampled by the harness. Release-engineer can
  run only the five wrappers, and no role has a bare `git push` or `gh` grant.
- `--no-ff` creates an integration head that no single lane verdict covers, so
  Q-VERDICT requires one PASS per lane, Q-LANEHEADS binds each `origin/lane/*`
  ref to its verdict head/tree, and P-MERGE now compares
  `release.merged_tree` to the reconciled integration tree rather than to a
  single lane tree. CI on the reconciled PR head is the final gate.
- `files/skills` is a source mirror only; `.opencode/skills` is the installed
  tree. Both copies are byte-identical.

**Decision: APPROVED.**

## Verification

- `python scripts/check_harness_config.py` → `RESULT: PASS (47 checks)`,
  exit 0.
- `reconcile_lanes.ps1 -Repo ...comp-wt -Lanes lane/a,lane/b -WhatIf` printed
  the fetch and both `--no-ff` merges, exit 0. The dirty note is expected:
  `comp-wt` carries unrelated local modifications at the time of this run, so
  a real reconcile would refuse until they are committed or stashed.
- `push_ref.ps1 -Branch master` → `push_ref: refused: Branch 'master' is not
  one of spec-comp, lane/a, lane/b`, exit 2.
- `push_ref.ps1 -Branch lane/a -WhatIf` printed
  `git -C "...spec-comp-wt" push origin "refs/heads/lane/a:refs/heads/lane/a"`,
  exit 0.
- `open_pr.ps1 -Base feat/add-frontend -Head spec-comp -WhatIf` printed
  `create PR: ...` plus the exact create command (no open PR existed), exit 0.
- `watch_checks.ps1 -Help` and `-Number 50 -WhatIf` printed the usage and the
  single watch command, exit 0.
- `merge_pr.ps1` with a sentinel `gh` on PATH issued
  `pr merge 1 --match-head-commit <sha> --merge` and `pr view ...`; no real
  merge occurred. Head-pin refusal still exits 2 before `gh`.
- `opencode debug agents` resolved auditor shell to `deny *` +
  `allow *push_ref.ps1*`; release-engineer shell to `deny *` plus the five
  wrapper allows. Skill lists resolve to the expected ids only.
- No live push, PR create, or merge was performed.

## Remaining contradictions

1. `policies/schemas/capability.json` still patterns `task_branch` as
   `^task/[A-Za-z0-9._-]+$`; it cannot represent `lane/a`, `lane/b`, or
   `spec-comp`. The role text now uses those values. Schema update is outside
   this worker's edit set.
2. `policies/schemas/release-result.json` does not list `POLICY_DRIFT` or
   `GUARD_REMOVED`, although the release-engineer contract names them, and its
   single `head`/`capability_id` model predates a multi-lane verdict set. The
   contract binds each lane head to its own PASS and records the reconciled
   integration head, but the schema needs an owner-approved expansion.
3. `policies/branch-protection.json` sets `required_linear_history: true` while
   `ci.json.merge_method` is now `merge` and PR #50 was a merge commit. Either
   the protection record is stale or the repository setting must be reconciled
   by the owner.
4. `ci.json.promotion_branch_prefix: "task/"` remains for non-lane work. The
   lane path ignores it; it is not a lane-branch prefix.
5. `files/sop/*` still describes the single task-branch flow and the
   `merge_pr` pilot. It was not in this worker's ownership.
6. `lane/c` and `lane/d` still exist in the worktree list. They are dormant but
   remain outside the declared active set, so P-WT must keep treating them as
   out of scope rather than as expected worktrees.
