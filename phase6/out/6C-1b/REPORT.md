# 6C-1b Prose for builder, auditor, hacker — REPORT

WP: 6C-1b | Prose for builder, auditor, hacker (typed-tool rewrite)
Commit: phase6c: 6C-1b prose1
Branch: master (local phase6c commit; no push)

Owned paths (6 files, twins byte-identical):
- files/builder.md | sha256 0CDC34B3041CA01DD6550627BF1FC1FB5770BDAB89FA9290A08CB96A818F7A80
- files/auditor.md | sha256 F91A0AF69685E4C22050A74635AF4AADA0C5D86A76F0056A633160BB4ACE35CE
- files/hacker.md  | sha256 3147C190E45413BE37D62D3F61F50A5143EB00441907E186B9496E391CCB33A9
- .opencode/agents/builder.md | same as files/builder.md
- .opencode/agents/auditor.md | same as files/auditor.md
- .opencode/agents/hacker.md  | same as files/hacker.md

## What changed

Permission blocks in all three files were replaced with the frozen
gen_perms output for the role (registry ∩ matrix): blanket deny, typed-tool
allows sorted, broad read/grep/glob allows, wall denies (manifest,
.opencode tree, secrets, hacker-scratch for non-hackers, attack-catalog for
builder). Every prior shell/skill/question/subagent/edit/write line was
removed from these three blocks. The new blocks contain zero lines with
action shell, edit, or write, and zero skill/subagent lines.

Procedure prose was kept behaviorally identical (role paragraphs, operating
rules, check definitions, verdict function, schemas) except that every
command invocation now names a typed tool:

- Builder: all git-state queries → git.state { fields:[head,tree] };
  all code writes → code.write; commit → git.commit { message, tree, paths };
  every check → check.run { check_id, tree, engine };
  precheck → check.run per required id; engine ensure → docker.ensure;
  content hash → evidence.hash.
- Auditor: SHIP push via git.push_ref { ref, expected_head }; K1 lifecycle
  via k1.up / k1.status / k1.exec (enum: django test, migrate,
  makemigrations check, boot test) / k1.down; all checks via check.run;
  GATE_CONTROLS / POLICY_DIGEST via gate.control + check.run; findings via
  repro.run on the ledger copy; state via git.state/status/log/diff.
- Hacker: runtime attacks via hacker.probe { item_id, actor, capability_id,
  endpoint, tenant_pair, batch, barrier }; drafts via scratch.write
  { namespace:"hacker" }; replay via repro.run; static match via static.scan;
  state via git.state; DAST baseline via check.run DAST_BASELINE.

## Findings fixed

- F-03 (auditor quality/ledger contradiction): A1 now scopes the sandbox
  denial to the working tree (no quality/** filesystem access, ledger
  arrives only as sealed evidence refs through typed tools), and the
  permission block no longer carries direct quality/ledger read/write rules;
  reads of quality/** verdict paths through git.read_file are server-refused
  and the prose says so (A-STATE).
- F-04 (verdict write impossible): A3 and Output now persist verdict,
  finding, attack-log, and gate-control records exclusively through
  ledger.append { record_type, record, expected_prev_hash }. No direct
  quality/** write is described or granted.
- F-10 (hacker has no k1 grant): K1 and Tool slice now state the inverse —
  k1.up/down/status/exec are auditor-only and are not granted to hacker;
  hacker's runtime capability is hacker.probe only. No k1.* tool is called
  by hacker in any procedure step.
- F-11 (hacker audit-scratch overwrite): hacker's scratch capability is
  scratch.write namespaced to "hacker" only, capability-bound; Tool slice
  explicitly excludes the auditor namespace, audit-scratch material, and
  acceptance.materialize. Probes cannot overwrite or read the auditor's
  audit-scratch area.
- F-76 (audit re-derivation had no write path / test-cheat): BASE_FAIL_HEAD_PASS
  now drafts via scratch.write { namespace:"auditor", path under
  audit-scratch } and materializes deterministically via
  acceptance.materialize { spec, path } (content-hashed, never inside
  quality/** — the server refuses ledger targets), then runs via repro.run.
  The same re-derived test is therefore both writable (by its owner) and
  un-cheatable by the other role.

## Exit test (fresh grep, this worktree)

```
python files/tools/mcp/gen_perms.py --check
  → gen_perms: idempotent OK (7 roles, 60 tool grants), exit 0

Select-String files/builder.md,files/auditor.md,files/hacker.md '\.ps1' → 0
Select-String same 'python' (case-insensitive) → 0
Select-String same 'shell' (case-insensitive) → 0
Select-String same 'action: shell' → 0
Select-String same 'action: (edit|write)' → 0
Select-String same '\bgit (rev-parse|show|cat-file|add|commit|push|diff|log|status|merge-base|ls-tree|branch|worktree)' → 0
  (the only hacker-scratch text left is the required generator wall)
```

Permission blocks equal gen_perms output for each role; twin sync verified
(byte-identical sha256 per pair); typed-tool mentions in the three files:
145.

## Diff summary

6 files changed, 962 insertions(+), 930 deletions(-) — builder 119+/153-,
auditor 251+/220-, hacker 111+/92- per file (identical in both trees).
Behavioral prose (operating rules, check predicates, verdict function,
output schemas, lane protocol) preserved; only the invocation surface and
the permission blocks changed.

## Legacy note

No file was moved to files/legacy and no legacy copy was created; the
directory does not exist in this worktree. Per the 6C seal criterion, old
agent files stay outside the manifest until the seal (6C-4/6C-5/6C-6) and
are moved only after phase6-sealed. This WP records the point and does not
act on it.

## Deviations / open questions

Deviations: none beyond the WP owned paths plus this REPORT.
Open questions: none for 6C-1b; harness-checker invariants (INV-1..7) and
seal remain for 6C-3/6C-4.
