# R05-07 — release-path reconciliation (wrappers, permissions, result schema)

Date: 2026-11-07
Requester: CARBON (FDE), under the owner's factory-hardening directive
Status: APPLIED (residual item flagged, not resolved)

## Problem

The distributed topology was encoded in the role contracts, but the wrapper and
schema layer still contradicted it in four places found by the release-engineer
SOP pass:

1. `files/release-engineer.md:7` said "deny overrides allow, regardless of
   order", while the harness contract (`files/auditor.md:14-16`) and every
   role's deny-then-allow table use "ordered list; the last matching rule wins".
   Under a literal deny-overrides reading, the five wrapper allows are dead.
2. `scripts/merge_pr.ps1:67` projected `.mergeCommit` (a JSON object) instead of
   `.mergeCommit.oid`, so the follow-up `git rev-parse "<object>^{tree}"` could
   not produce a merged tree.
3. `scripts/open_pr.ps1` hard-coded `-Base feat/add-frontend` and never read
   `policies/ci.json`; Q-BASE in the role contract requires the policy value.
   Its fallback also printed the base branch name in a field named `baseOid`.
4. `policies/schemas/release-result.json` had `additionalProperties: false` and
   did not define `guard_ref`, `policy_digest`, or `control_set_sha`, which the
   role contract requires, and its `refusal_code` enum lacked `POLICY_DRIFT` and
   `GUARD_REMOVED`. The check object also rejected the `runner` field the role
   emits.

## Change

- `files/release-engineer.md` + installed twin: M1 now states the ordered
  last-match-wins rule.
- `scripts/merge_pr.ps1`: `--jq '.mergeCommit.oid'`; a merged SHA that is not
  40/64 hex is reported as "none reported" and is not rev-parsed.
- `scripts/open_pr.ps1`: `-Base`/`-Head` default to `ci.json.promotion_branch`
  and `ci.json.base_branch`; an explicit flag still wins; the script refuses if
  the policy file is missing or either value is empty; the pre-view `baseOid`
  fallback is empty rather than the branch name.
- `policies/schemas/release-result.json`: required + properties for `guard_ref`,
  `policy_digest`, `control_set_sha`; `refusal_code` adds `POLICY_DRIFT` and
  `GUARD_REMOVED`; `check.runner` is required and enum `release-engineer|ci`.

## Evidence

```
powershell -NoProfile -File scripts\open_pr.ps1 -WhatIf
EXIT 0 | create PR: base=feat/add-frontend head=spec-comp
         head_sha=12c96d1117c1a581eafe4a5c780a12f45808e30c

powershell -NoProfile -File scripts\open_pr.ps1 -Base feat/add-frontend -Head spec-comp -WhatIf
EXIT 0 | same create line (explicit values win)

parse: merge_pr/open_pr/reconcile_lanes/push_ref/watch_checks
EXIT 0 | PARSE_OK

python scripts\check_harness_config.py
EXIT 0 | RESULT: PASS (47 checks)

python files\tools\gate_control.py --verify 0005-...
EXIT 0 | result=PASS problems=[]
policy_digest unchanged c847118644fa18d704773ba3f9a8892b13b756f9c67afb322607d6f927f631a8
```

The schema edits do not move `policy_digest` (only tiers/severity/
negative-controls/check-runners/layers are covered), so `0005` remains valid.

## Residual (not resolved here)

- `merged_tree == audited spec-comp tree` is not guaranteed when
  `origin/feat/add-frontend` contains commits that `spec-comp` lacks. Current
  state: `origin/feat/add-frontend` `e77e9ca` is 3 commits not in `spec-comp`,
  `spec-comp` is 46 ahead. A GitHub `--merge` promotion will produce a tree that
  includes the base-only commits, so P-MERGE cannot hold without either
  (a) reconciling the base into `spec-comp` before audit, or (b) auditing the
  merge result. Do not claim tree equality until this is decided.
- `policies/branch-protection.json` has `required_linear_history: true` while
  `ci.json.merge_method` is `merge` (PR #50 is a merge commit). One must change.
