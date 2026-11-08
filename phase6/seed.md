# Phase 6 seed (from spec: Phase 6 - Typed-tool lockdown)

## Findings seed (F-01..F-13 + F-71..F-77)

| ID | Finding |
| --- | --- |
| F-01 | Wildcard shell globs (gate_run.py, manage.py test, python hacker-scratch/*) match any command containing the substring, in every role |
| F-02 | Auditor can run makemigrations (a write) and git show rev:.env, bypassing read denies |
| F-03 | Auditor A1 says no access to quality/**, yet grants read on quality/ledger/** |
| F-04 | Auditor promises ledger verdict writes, but edit and write are blanket denied |
| F-05 | Builder can edit any test file except tests_gate\* and conftest.py; write is not denied on pytest.ini, tox.ini, .coveragerc, .github, .gitleaks.toml |
| F-06 | Builder can read attack-catalog and tiers and tune code to known probes |
| F-07 | Builder git commit\* allows --no-verify (bypasses B6 hook); git add\* allows -f |
| F-08 | Orchestrator has edit quality/\*\* with no deny for verdict, finding, release, risk-acceptance records |
| F-09 | Orchestrator cannot create capability.json and lacks subagent allows for hacker-high, hacker-max, design-research |
| F-10 | Hacker has no k1_exec or probe grant, though the K1 contract expects runtime attacks |
| F-11 | Hacker writes audit-scratch/\*\*, where the auditor stores its re-derived acceptance test |
| F-12 | crouton-alpha: no orchestrator subagent allow; lacks the grep and glob denies for policy-manifest.json |
| F-13 | K1 plan says IMPLEMENTED and smoke-tested; FACTORY-POLICY-MAP says not ready (no pinned image, Postgres on 0.0.0.0); digest pin is a placeholder; /work tmpfs is exec |
| F-71 | Check-set drift: ci.json (9), branch-protection.json (8, no AUTHZ_MATRIX), release-engineer.md (7) |
| F-72 | severity.json lacks BARE_EXCEPT, AGT_PARITY_MISMATCH, AGT_AUDIT_GAP; TEST_SET and ERROR_HANDLING are never emitted |
| F-73 | test-removal-reasons covered_by is a substring match; require exact id |
| F-74 | assert-rules: tautology regexes miss trailing messages and comments, unittest forms, and all TS/JS |
| F-75 | redaction.json: phone_nanp and ipv4 mangle evidence; entropy fallback trips on session and CSRF tokens; runner patch not implemented |
| F-76 | Auditor acceptance re-derivation (audit-scratch) has no write path; drain R3 has no owner able to write the test |
| F-77 | The MCP server and probe client are not in gate_impl_digest |

## Required tool surface

| Tool | Roles | Runs in | Notes |
| --- | --- | --- | --- |
| git.state | all except compliance | host-pure | head, tree, branch, clean, merge-base, is-ancestor, ls-tree, worktree list; replaces every rev-parse |
| git.status / log / diff / read_file | per matrix | host-pure | validated shas, path deny globs, no ext-diff or textconv |
| git.commit | builder | host-pure | validates STAGED diff against scope and test-infra denies; HEAD equals capability.head; branch equals task_branch; never --no-verify |
| git.push_ref | auditor (SHIP), release-engineer | host-pure | refs/heads/<branch> only, fast-forward only |
| worktrees.list / sync / reconcile | release-engineer (list also orchestrator) | host-pure | native, no .ps1 layer |
| check.run(check_id) | roles named in checks.json runners | sandbox at git object id | one dispatcher: suite, ruff (pinned config, added lines), gitleaks (--redact, pinned config and baseline, base..head), semgrep, arch, guard, authz, smell, oracle, mutate, boottest, zizmor, schema fuzz, thread race, dast, agt parity and audit, policy digest |
| gate.control | auditor; orchestrator verify only | sandbox | target enum |
| k1.up / down / exec / status | auditor | containers | TTL lease reaper; exec actions enum (django test, migrate, makemigrations check, boot test) |
| hacker.probe | hacker | K1 network | actor enum, run bound to capability, batch plus barrier race mode, per-probe record |
| repro.run | auditor, hacker, builder | sandbox | runs parameter; ledger-copy specs only |
| static.scan | hacker | host-pure, read-only | PROMPT-INJECTION static_match findings |
| scratch.write | hacker, auditor | host-pure | namespace per role and capability; size and extension caps; returns sha |
| ledger.append | orchestrator (dispatch, capability); auditor (verdict, finding, attack-log, gate-control); release-engineer (release) | host-pure | typed, schema-validated, expected_prev_hash, per-role record types |
| acceptance.materialize | auditor (drain R3) | host-pure | deterministic repro-spec to test file, content-hashed |
| drain.validate | auditor, orchestrator, release-engineer | host-pure | read-only |
| evidence.hash | builder, auditor | host-pure | replaces Get-FileHash |
| harness.verify | orchestrator | host-pure | check_harness_config plus policy manifest verify, read-only |
| pr.open / watch / merge | release-engineer | host-pure | one watch per (pr, head) enforced server-side |
| docker.ensure | builder, auditor | host-pure |  |

Dispatch (subagent targets) stays harness-level, but its allow list must match what the orchestrator routes to.
