# Changelog — Phase 1 + Phase 2 + Phase 3 (2026-11-07)

> `RE-SEAL: SKIPPED per owner — manifest drift expected, document-only.` No manifest
> re-seal run; `files/policies/policy-manifest.json` intentionally left stale. This file
> documents intent; it does not change behavior. No secrets included.

- **Phase 1:** Landed (per owner brief; 7 skill/guard items below).
- **Phase 2:** All 8 items `LANDED` — single-source generation in-sync term, validator wired.
  Final counts: gate 24, ci 8+16=24, tiers required_checks 14/23/24 monotonic to max==all
  checks with max_cycles 3/3/4, THREAD_RACE NOT_APPLICABLE, generator `--check` PASS
  (no drift), validator wired (5 new completeness asserts). RE-SEAL: SKIPPED.
- **Phase 3:** All 5 items `LANDED` — negative-controls hash+tombstones, models
  triangle+enum+alias, mutation informative-only + semgrep single-source,
  redaction expand + fuzz per-cycle random + shuffle, DOC backend/docs + covered_by
  proof. Validator wired (exempt-aware independence + 8 enum asserts,
  acceptance_derived with refund-cluster grandfather). RE-SEAL: SKIPPED.

## Phase 1 — landed

| Item | Files touched (expected) | Before → After | Why not a generic MCP/feature | Re-seal |
|---|---|---|---|---|
| dispatch fix | `files/skills/dispatch/SKILL.md`, `files/policies/dispatch-rules.json` | implicit routing → explicit dispatch rules | Workflow routing, not a new server/tool | Skipped |
| pwsh fix | `files/skills/*/SKILL.md` (pwsh snippets) | bash-isms → pwsh-native commands | Shell dialect correction, not a capability | Skipped |
| merge/open-pr exit0 docs | `files/skills/merge-pr/SKILL.md`, `files/skills/open-pr/SKILL.md` | exit code ambiguous → exit 0 = documented no-op success | Docs only; no new endpoint | Skipped |
| push-branch decommission | `files/skills/push-ref/SKILL.md` (successor); push-branch skill removed | `push-branch` active → decommissioned | Retires obsolete path; not a feature add | Skipped |
| reconcile label | `files/skills/reconcile-lanes/SKILL.md` | unlabeled reconcile → labeled lane reconcile | Labeling/clarity; no new integration | Skipped |
| sync-worktrees mirror | `files/skills/sync-worktrees/SKILL.md` | divergent copies → mirror parity | Consistency fix, not a new tool | Skipped |
| guards +3 (107→110) | `files/policies/checks.json`, `files/tools/guard_delta.py`, checker | 107 guards → 110 guards (+3) | Policy invariants, not an MCP feature | Skipped |

## Phase 2 — landed (single-source generation in-sync, validator wired)

| Item | Status | Files touched (expected) | Before → After | Why not a generic MCP/feature | Re-seal |
|---|---|---|---|---|---|
| shadow off | LANDED | `files/policies/check-runners.json`, `checks.json`, `ci.json` | `shadow:true` (some) → `shadow:false` (CI) | Enforcement mode flag, not a feature | Skipped |
| ci runners | LANDED | `files/policies/check-runners.json`, `ci.json`, `gate.json` | implicit/manual → declared runner matrix | CI topology config, not a server | Skipped |
| AUTHZ in CI | LANDED | `files/policies/ci.json`, `checks.json`, `files/tools/authz_matrix.py` | ad-hoc/local → required CI check | Gate tightening, not new capability | Skipped |
| THREAD_RACE expand + NOT_APPLICABLE | LANDED | `files/policies/checks.json`, `check-runners.json` | narrow predicate, no N/A → expanded predicate + explicit `NOT_APPLICABLE` | Verdict vocabulary extension | Skipped |
| auto-generate = yes | LANDED | `.agt/policy.json`, generation config in `files/policies/*.json` | `auto-generate:no` → `auto-generate:yes` | Default flag flip, not a feature | Skipped |
| backfill AGT | LANDED | `.agt/policy.json`, `files/tools/agt_audit.py`, `agt_parity.py` | missing/stale → backfilled AGT parity | Backfill of existing policy, not new MCP | Skipped |
| max_cycles 4 | LANDED | `files/policies/task-limits.json`, `escalation.json` | unbounded/other → `max_cycles=4` | Cycle bound, not a feature | Skipped |
| builder closure | LANDED | `files/builder.md`, `.opencode/agents/builder.md`, `files/sop/builder.md` | open-ended build → explicit closure criteria | Process closure rule, not a tool | Skipped |

Final generation counts (derived from canonical `files/policies/checks.json` via
`scripts/generate_policies.py`):

- `min_tier` landed in `checks.json` for all 24 checks (none=14, high=9, max=1;
  DAST_BASELINE=max, AGT_PARITY/AGT_AUDIT=high; JSON valid).
- `gate.json gate_checks` = 24 (all checks, canonical order).
- `ci.json` partition 8+16=24 (required: SUITE, CHANGELOG, SECRETS, CONVENTION,
  POLICY_DIGEST, AUTHZ_MATRIX, BOOTTEST, ZIZMOR; not_run=16).
- `tiers.json required_checks` monotonic 14 (none) <= 23 (high) <= 24 (max==all);
  `max_cycles` 3/3/4 (none/high/max).
- THREAD_RACE expanded predicate with explicit `NOT_APPLICABLE` (tiers
  `check_conditions.THREAD_RACE`: sqlite_outcome/else_outcome NOT_APPLICABLE).
- Generator `--check` in-sync: before (all 24 lack min_tier, exit 2) → after
  min_tier (5-item drift, exit 1) → after write PASS no drift (exit 0). No manual
  intent clobbered (generator rewrites derived fields only; shadow/runners untouched,
  AUTHZ `required_in_ci` true preserved, ci_self_audit corrected 7→8).
- Validator wired: `scripts/check_harness_config.py` +5 completeness asserts
  (gate==checks, ci partition, check-runners mirror, ci_self_audit==ci required,
  tiers monotonic to max==all), stdlib json only, no new deps.

Notes:
- Phase 2 flags (`shadow`, `max_cycles`, `auto-generate`) and new verdicts take effect
  as landed above; `files/policies/policy-manifest.json` intentionally left stale
  (RE-SEAL: SKIPPED — manifest drift expected, document-only).
- All items above are harness-internal policy/skill/documentation changes. None adds a
  generic MCP server, external integration, or user-facing feature, so none is
  documented as such.
- Phase 2 status: LANDED (per assessor — generator `--check` PASS, no drift);
  RE-SEAL: SKIPPED until all phases complete (do not re-seal until owner approves).

## Phase 3 — landed (5 fix agents, finalizer wiring)

| Item | Status | Files touched (expected) | Before → After | Why not a generic MCP/feature | Re-seal |
|---|---|---|---|---|---|
| negative-controls hash+tombstones | LANDED | `files/policies/negative-controls.json`, `files/tools/gate_control.py` | ambiguous counts, thresholds unhashed, silent delete undercounts → `controls_declared`/`known_bad_total` split (53/28) + thresholds hash in `control_set_sha` + `retired_controls` tombstones | Policy counting invariant, not a feature | Skipped |
| models triangle + enum + alias | LANDED | `files/policies/models.json`, `scripts/check_harness_config.py`, `files/tools/validatedrain.py` | orchestrator==builder and auditor==release-engineer false FAILs, free-text family → triangle builder<->auditor<->hacker enforced, `exempt_edges` + `enforced:false`, `acceptance_author_role_enum` canonical hacker-high, legacy `hacker` alias → hacker-high, derived family minimax (refund-cluster grandfather: deepseek+note with re-derivation) | Model-independence policy, not a new model/server | Skipped |
| mutation informative-only + semgrep single-source | LANDED | `files/policies/mutation.json`, `files/policies/semgrep.yml`, `files/tools/semgrep_runner.py` | ratio could pass with survivors, money models shadowed/divergent → kill_ratio informative-only with 0-survivor bar, `min_mutants_per_hunk: 1`, semgrep single-source canonical list in `semgrep_runner.py`, un-shadow money patterns | Gate semantics tightening, not a feature | Skipped |
| redaction expand + fuzz per-cycle random + shuffle | LANDED | `files/policies/redaction.json`, `files/policies/schema-fuzz.json` | narrow patterns, fixed seed `20261106`, fixed order → expanded secret/PII patterns + high-entropy fallback (policy-only), per-cycle random CSPRNG seed evidence-only, Fisher-Yates shuffle of cases + key order | Evidence-redaction policy, not a feature | Skipped |
| task-kinds DOC + covered_by | LANDED | `files/policies/task-kinds.json`, `files/policies/test-removal-reasons.json` | DOC paths loose, removals without proof → DOC backend/docs exception (docs in `backend/docs/`, not repo root) + reject .py even under backend/docs, EVERY reason_code requires non-empty covered_by proof (`TEST_REMOVAL_UNCOVERED`) | Task-kind policy, not a feature | Skipped |

Finalizer wiring (this change; no new deps, stdlib only):

- `scripts/check_harness_config.py`: independence loop is exempt-aware (skip
  `exempt_edges`; skip role when `enforced:false` — orchestrator skipped) and
  adds 8 enum asserts: independence covers 6 roles, orchestrator lists builder,
  RE expanded vs builder+auditor+hacker-high+max, hacker mutual forbid,
  triangle scope, acceptance canonical in enum, legacy hacker alias, derived
  family equals roles family. Result: family FAILs gone; `RESULT: FAIL (1/123)`
  with the sole FAIL `policy manifest verifies` (intentional drift).
- `files/tools/validatedrain.py`: `acceptance_derived` block after the capability
  `policy_digest` check derives the expected family from the canonical role
  (`human` → `human`, otherwise `roles[canonical].family`, legacy `hacker` →
  hacker-high). The refund-cluster is grandfathered (deepseek + note with
  re-derivation, auditor re-derivation mandatory). Report: existing
  policy_digest / gate-control drift only; no new acceptance problem.
- `scripts/check_harness_config.py` + `files/tools/validatedrain.py` compile
  clean (`python -m py_compile` exit 0). `policy_manifest --verify` READ-ONLY
  FAIL as expected (2 added + 20 changed, digest drift intentional; see Footer).

Notes:

- Phase 3 follows the same document-only rule as Phases 1-2: all items above are
  harness-internal policy/tool/documentation changes. None adds a generic MCP
  server, external integration, or user-facing feature, so none is documented as such.
- Phase 3 status: LANDED (per fix agents + finalizer wiring above); RE-SEAL: SKIPPED
  until all phases complete (do not re-seal until owner approves).

## Footer

- Total checks: 123 (`scripts/check_harness_config.py`; 8 new Phase-3 enum asserts
  PASS, orchestrator independence edge skipped via `enforced:false`, RE auditor
  edge skipped via `exempt_edges`; 122 PASS, 1 FAIL — `policy manifest verifies`
  only, intentional drift).
- Pending seal batch: manifest drift = 2 added + 20 changed (0 removed), intentional,
  digest drift intentional, to be sealed after final phase (RE-SEAL: SKIPPED until
  all phases complete). `--verify` READ-ONLY FAIL expected; no `--write`/seal run.
- Generator in-sync: `scripts/generate_policies.py --check` PASS, no drift.
- `max_cycles` 3/3/4 (none/high/max); tiers required_checks 14<=23<=24.
- THREAD_RACE NOT_APPLICABLE warning: `gate_run` prefilter is still a documented
  follow-up with patch text, not applied (verdict vocabulary landed, runner
  prefilter pending).
- Follow-ups NOT applied (patch text/policy only; owners own their files):
  (1) gate_run mutation-cap patch text (`mutants_truncated` + missing
  score/threshold/0-mutant BLOCK — `files/policies/mutation.json`
  `cap_enforcement.gate_run_patch_pending`); (2) redaction runner patch
  (steps 1-5: compile patterns, replace, residue entropy scan, throw on
  unredactable, throw on fail-variant — policy-only, `on_match` stays replace);
  (3) DOC gate_run function (policy authoritative, SCOPE enforces — `task-kinds.json`
  DOC `enforcement_layer`); (4) read-perm deny rule for fuzz seed evidence
  (seed lives in evidence artifact only, no usable seed in the policy file);
  (5) TS NOT_APPLICABLE fail-closed (python-only; 0 mutants BLOCK, never PASS).
- RE-SEAL SKIPPED until all phases complete.

## Deferred follow-ups — now completed (still no seal)

| # | Follow-up | Status | Files | Test evidence |
|---|---|---|---|---|
| 1 | Redaction runner patch (steps 1–5: compile patterns, replace, residue entropy scan, throw on unredactable, throw on fail-variant) | LANDED | `files/tools/redaction_runner.py` (463 lines) | 31 selftests PASS |
| 2 | Read-perm deny rule for fuzz seed evidence (seed lives in evidence artifact only) | LANDED | `.agt/policy.json` (`no-fuzz-seed-evidence`) | deny rule landed |
| 3 | Gate-run mutation cap (`check_mutation`: MUTATION_TRUNCATED, missing score/threshold, 0-mutant BLOCK) | LANDED | `files/tools/gate_run.py` | control PASS |
| 4 | DOC gate_run wiring (`check_doc_scope` registered) | LANDED | `files/tools/gate_run.py`, `files/tools/gate_run_doc_patch.py` | DOC 18 cases PASS, `--check DOC` clean PASS / bad FAIL |

- Pending seal batch: still intentional; manifest drift expected. RE-SEAL SKIPPED until all phases complete.
