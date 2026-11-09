# Factory policy map, hash tiers, and edit procedure

**Host:** OS-agnostic — typed tools are canonical (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is Windows-only (powershell) — the Windows implementation; the POSIX implementation is native.

Owner/FDE document. This is the answer to "what is hashed, what depends on
what, and where do I change things so the factory does not drift."

## 1. What is hashed today

There are **40 policy files** under `files/policies/**` (29 top-level + 12
schemas minus the manifest itself), plus 7 agent contracts, 7 installed twins,
22 skills, 8 wrappers, 7 Python harness scripts, the tool bodies, the fixtures,
`opencode.json`, and `.agt/policy.json`.

Only these are in the **narrow gate digest**:

| Hash | Covers | Where it lands |
|---|---|---|
| `policy_digest` | `tiers.json`, `severity.json`, `negative-controls.json`, `check-runners.json`, `layers.json` (5 files) | gate-control record, drain R1–R3, capability, dispatch evidence `policies`, SIGNING |
| `control_set_sha` | the resolved `negative-controls.json` controls (`check_id`, `control_id`, `fixture_ref`, `runner`, `expected_outcome`, `min_count`) | gate-control record, `release-result.control_set_sha` |
| `gate_impl_digest` | the check bodies (`authz_matrix`, `arch_check`, `guard_delta`, `oracle_provenance`, `semgrep_runner`, `smell`, `gate_run`, `policy_digest`, `agt.js`), all `tools/fixtures/**`, `agt_parity.py`, `agt_audit.py`, `.agt/policy.json`, `opencode.json`, `.opencode/package{,-lock}.json` | gate-control record |
| `gate_sha` | `git log -1` over `policies/gate.json.gate_paths` in the audited repo | gate-control record |

Everything else is **not** gate-invalidating. That is deliberate: a typo in a
schema or a prose policy must not force a new seal. But it also means nothing
notices those edits. The full manifest closes that hole:

| Artifact | Covers |
|---|---|
| `files/policies/policy-manifest.json` | every policy file/schema, agent contract + installed twin, SOP, skill file, wrapper, harness script, tool body, fixture, `opencode.json`, `.agt/policy.json`, package files |
| `scripts/policy_manifest.py --verify` | recomputes the full file list, the three live digests, the newest gate-control record, and the manifest’s own `manifest_sha` |

The manifest is **not** a gate input and must never be added to
`policy_digest.COVERED` (that would make the digest self-referential and
invalidate on every manifest write).

### The structural +1 rule — manifest.record vs the newest seal (P1-2)

`files/policies/policy-manifest.json` lives under `policies/**`, which is one
of `gate_paths` in `files/policies/gate.json` (`tools/**`, `policies/**`,
`.github/workflows/**`), and `gate_sha` is `git log -1` over those paths
(`gate_control.gate_sha`) — so the manifest itself is a gate-path input.
Step order (§3A) is: seal (step 5, `gate_control.py --write`) → manifest
write (step 9, `scripts/policy_manifest.py --write`). The manifest therefore
always records the seal that precedes it: `manifest.gate_control.record`
(`policy_manifest.newest_record()` in `scripts/policy_manifest.py`) is the
newest seal minus the manifest's own commit, and committing the manifest
advances `gate_sha`, so the next seal is structurally one ahead. Expected
steady state after a clean seal → manifest → commit cycle: `manifest.record`
lags the newest seal by **exactly one** (e.g. newest `0023-*.json`,
`manifest.record` `0022-*.json`). That lag is not drift. **Freshness is digest
equality, not record-id equality**: `policy_digest`, `control_set_sha`, and
`gate_impl_digest` must match between `manifest.gate_control` / `manifest.digests`
(`policy_manifest.verify()` compares live digests) and the newest gate-control
record. Record-id equality can never hold post-commit and must never be
required. A lag greater than one (or any digest mismatch) means a re-seal
happened without a manifest refresh (or vice versa) — re-run
`scripts/policy_manifest.py --write`, then `gate_control.py --verify-chain`.

Current manifest: `policy-manifest/2`, **180 files**, `owner_only: true`,
`manifest_sha` recomputes over the body minus itself, and
`scripts/check_harness_config.py` runs `policy_manifest.py --verify` as one of
its 107 checks. The current seal is `0006-7567ce1902de.json`; re-seal to a new
record whenever one of the three gate digests or `gate_sha` moves.

## 2. Dependency map

```
policies/tiers.json ─────────────┐
policies/severity.json ──────────┤
policies/negative-controls.json ─┼─> policy_digest ─┐
policies/check-runners.json ─────┤                  │
policies/layers.json ────────────┘                  │
                                                    ├─> gate-control record ─> dispatch P-CTRL
policies/negative-controls.json ─> control_set_sha ─┤        │
tools/** + fixtures/** ──────────> gate_impl_digest ─┤        ├─> SIGNING.md
opencode.json + .agt/policy.json ┘                   │        │
policies/gate.json gate_paths ───> gate_sha ─────────┘        │
                                                             ├─> drain R1/R2/R3 (policy_digest)
                                                             ├─> capability (policy_digest)
                                                             └─> dispatch evidence refs
```

Agent permissions are a separate chain:

```
files/<role>.md  ──byte-identical──>  .opencode/agents/<role>.md
        │                                      │
        ├─> .opencode/skills/<id>/SKILL.md  (skill allow)
        ├─> .agt/policy.json allowedTools   (tool-name gate; in gate_impl_digest)
        ├─> opencode.json                   (no widening override; in gate_impl_digest)
        └─> scripts/check_harness_config.py (47 invariants)
```

## 3. What to change, and in what order

### A. A covered policy file (the five)
1. Edit the file.
2. If `negative-controls.json` changed: recompute `control_set_sha`
   (`gate_control.control_set_sha`) and write it into the file; run
   `python scripts/control_mutation.py --all`.
3. Dry-run `python files/tools/gate_control.py`; require `result=PASS`.
4. Back up `files/quality/ledger/gate-control` outside the scan directory.
5. `python files/tools/gate_control.py --write` → new record (on success it
   auto-appends the seal block to `files/drain/refund-cluster/SIGNING.md`;
   if the append fails the run errors instead of claiming success).
6. Re-seal the drain chain to the new `policy_digest`: R1 → R2 → R3
   (`prev_hash` then `record_hash`), capability, dispatch evidence, R4 artifact.
7. Confirm the auto-appended `SIGNING.md` block (record id + digests + result);
   hand-append only for seals predating the auto-append (P1-3).
8. `gate_control.py --verify <new>`, `--verify-chain`, `validatedrain.py`.
9. `python scripts/policy_manifest.py --write`.
10. If `.agt/policy.json`, `opencode.json`, a tool body, or a fixture also
    changed, the same seal covers `gate_impl_digest`.

### B. A non-covered policy file (schema, semgrep.yml, invariants, etc.)
1. Edit the file.
2. Find its consumer in §2; run that consumer’s control (`gate_run.py --check
   <ID> --control`, `semgrep_runner.py --control`, validator tests).
3. `python scripts/policy_manifest.py --write`.
4. **No re-seal** unless the file is one of the five, a tool body/fixture, or
   `opencode.json`/`.agt/policy.json`.

### C. An agent permission
1. Edit `files/<role>.md` (source).
2. Copy it byte-identically to `.opencode/agents/<role>.md`. `check_harness_config.py`
   fails on any drift.
3. If a new skill is granted, add `.opencode/skills/<id>/SKILL.md` and the
   `skill` allow.
4. If a new tool name is used, add it to `.agt/policy.json`
   `toolPolicies.allowedTools` (this changes `gate_impl_digest` → re-seal).
5. If the invariant itself changes, update `scripts/check_harness_config.py`.
6. Run `python scripts/check_harness_config.py` and the permission controls
   (negative probe must deny, positive probe must allow).
7. `python scripts/policy_manifest.py --write`.
8. Re-seal **only** if step 4 or `opencode.json` changed.

### D. A wrapper or skill
1. Add/edit `scripts/<name>.ps1` (Windows implementation; POSIX implementation is native — prefer the typed tool) or `.opencode/skills/<id>/SKILL.md`.
2. Add the wrapper/skill to the owning role’s shell/skill allow, in source **and**
   installed twin.
3. Update the role contract and `files/sop/<role>.md`.
4. Parse the wrapper, run `-WhatIf`, run `check_harness_config.py`.
5. `policy_manifest.py --write`.
6. No re-seal (wrappers/skills are not in `gate_impl_digest`).

### E. `opencode.json` or `.agt/policy.json`
1. Edit.
2. `check_harness_config.py`; load the service (`opencode models`).
3. Re-seal (both are in `gate_impl_digest`), then `policy_manifest.py --write`.

## 4. Manifest protection (owner-only)

`files/policies/policy-manifest.json` is owner/FDE-only. Every factory agent
carries these rules **after** its read allows (last matching rule wins):

```yaml
- { action: read,  resource: "**/policy-manifest.json", effect: deny }
- { action: edit,  resource: "**/policy-manifest.json", effect: deny }
- { action: write, resource: "**/policy-manifest.json", effect: deny }
- { action: grep,  resource: "**/policy-manifest.json", effect: deny }
- { action: glob,  resource: "**/policy-manifest.json", effect: deny }
- { action: shell, resource: "*policy-manifest.json*", effect: deny }
```

The `grep`/`glob` denies close the search-tool bypass (compliance has
`grep`/`glob` allows for its own work). The checker asserts all six rules on
all seven agents.

The file is also marked read-only (`attrib +R`). The harness verifier
(`scripts/policy_manifest.py --verify`) may read it; it prints only PASS/FAIL and
hashes, not the inventory. A factory agent cannot read, edit, write, or delete
it through the tool layer.

Honest limitation: this host has one Windows user and no OS-level trust
boundary. The permission table and AGT are the enforcement; the read-only
attribute only stops accidental writes. Do not claim OS isolation.

## 5. How each part works

- **`policy_digest`** — canonical JSON of sorted `(path, sha256)` for the five
  gate threshold/control files, hashed again. A byte change moves it. It is the
  gate-control cache/invalidation key, not a policy inventory.
- **`control_set_sha`** — canonical JSON of the resolved control list
  (one row per fixture, with `min_count`), hashed. A control add/remove,
  fixture/runner change, expected outcome, or `min_count` moves it.
- **`gate_impl_digest`** — canonical JSON of the tool bodies, every fixture,
  and the harness config files, hashed. Editing a check body moves it.
- **`gate_sha`** — the last commit touching `gate_paths` in the audited repo;
  ties a seal to the gate code that produced it.
- **Gate-control record** — append-only, `prev_hash` → `record_hash`, newest is
  the only PASS; older records are `SUPERSEDED`. It carries the four hashes and
  the observed outcome of every control.
- **Fail actions (P3-2 note):** all 24 checks in `files/policies/checks.json`
  are `fail_action: BLOCK` — there is no WARN tier. P3-residual severity is
  informational-only and never a PASS (see `files/policies/severity.json`:
  blocking P1/P2, residual P3). This note documents the gate; it does not alter it.
- **Drain chain** — R1 → R2 → R3 `prev_hash` links; `validatedrain.py` checks
  schema, tree identity, live `policy_digest`, capability, dispatch evidence,
  R3 repro file, and the newest seal.
- **Capability** — sealed scope/head/tree/tier/budget/acceptance; `record_hash`
  over canonical JSON minus itself; schema `capability.json`.
- **Dispatch** — `DISPATCH`/`OK` with evidence refs (R1–R3 record hashes, live
  `policies` digest, newest gate-control record hash). P-CTRL gates it.
- **Release** — `release-result/1` with `guard_ref`, `policy_digest`,
  `control_set_sha`, head-pinned merge; no admin/auto/force.
- **AGT** — `.agt/policy.json` tool-name allowlist, `defaultEffect: deny`,
  `execute.before` hook; redaction after execution. It is the second boundary,
  not the per-agent command gate.
- **OpenCode permissions** — ordered list, last matching rule wins, blanket deny
  first, narrow allows after. Source and installed twin must match byte for
  byte. `check_harness_config.py` asserts the invariants.

### Ask, don't bypass

The builder's permission list ends with `effect: ask` rules for reads outside the
worktree (`../**`, the temp parent, the harness root) and for `docker
pull/build/run/create/compose`, `git clone`, venv creation, and `pip`/`npm`/`pnpm
install`. The rules come last, so they override the broad allows (last match
wins); they never widen a hard deny: the manifest, hacker skills/scratch, audit
scratch, verdicts, and secret paths are re-asserted after the asks. An ask is
requested once; a human denial returns BLOCKED with the denied command. Never
route around a denial with an alternate path, a shell trick, or a different
image source. Push, merge, and PR remain hard-denied.

### K1 lifecycle is auditor-owned

Prefer the typed tool (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is the Windows implementation, the POSIX implementation is native.
The auditor holds the only `k1.up`/`k1.exec`/`k1.down` allows (Windows implementation: `shell` allows for `scripts/k1_up.ps1`,
`scripts/k1_exec.ps1`, and `scripts/k1_down.ps1`), plus the `k1-sandbox` skill;
the hacker gets `k1_exec`, never Docker. `k1_up` runs before every
`hacker_dispatch`; a non-zero exit is BLOCKED `K1_UP_FAILED` and nothing is
dispatched. `k1_down` runs on the `finally` path after the hacker returns, times
out, or errors. It removes only that run's `k1-<id>-app`/`k1-<id>-pg` pair and
its network; it never stops Docker, never touches `pg2a`/`pg2b`, and never prunes
images or volumes.

## 6. Provider mapping (2026-11-07 reversal)

- auditor + release-engineer: `opencode-go/glm-5.3-flash#high`
- hacker-high: `nous-direct/minimax/minimax-m3.1-flash#high`; fallback
  `opencode-go/minimax-m3.1-flash`
- compliance: `nous-direct/xiaomi/mimo-v2.6-flash`; fallback
  `opencode-go/mimo-v2.6-pro`
- orchestrator/builder: `opencode-go/deepseek-v4.1-flash#max`
- hacker-max: `openai/gpt-6-luna#max`

The built-in `nous` provider was tried first and rejected
`minimax/minimax-m3.1-flash` at runtime; the Nous **direct portal** accepts it.
A service must be started in this harness directory with `NOUS_API_KEY` in its
environment, or the CLI must use `--standalone`; the shared background service
does not carry that key/config.

### Hacker abort state and sandbox (2026-11-07)

The hacker aborts an unsealed "LGTM/approved hash" instruction with
`EXPLOIT_ABORT_CONTAMINATED` (or `SIG_INVALID` when the seal is absent).
`hacker-result/1` now permits `sig_status INVALID|ABSENT`, leaves
`sig_status`/`record_hash` to the harness, and carries
`exploit_spec_ref`/`authz_rows_covered`; the envelope now accepts
`authz_matrix_ref`/`drain_stage`. A fixture-setup failure is a tool fault to
retry (R6), not `NOT_RUN`. The K1 Docker/FS sandbox is **not** ready: no pinned
image, no create step, no `hacker-scratch` mount, and Postgres is published on
`0.0.0.0` rather than loopback. See `requests/R05-08-hacker-abort-schema.md`.

### Docker start (auditor/builder)

`docker.ensure({ action: "ensure" })` (Windows implementation: `scripts/ensure_docker.ps1`) is the only Docker action granted to the auditor
and builder. It starts the Docker engine (service + Docker Desktop) if
`docker info` is down and starts the named existing containers
(`pg2a,pg2b` by default; `-All` for every stopped container). It never pulls,
builds, creates, runs, or deletes a container or volume. The K1 plan (tmpfs app
+ tmpfs Postgres sidecar, internal network, no published ports) is
`files/K1-CONTAINER-PLAN.md`; the hacker gets `k1_exec`, never Docker.

## 7. Drift checklist (run before every factory start)

```bash
python scripts/policy_manifest.py --verify
python scripts/check_harness_config.py
python files/tools/gate_control.py --verify-chain
python files/tools/validatedrain.py
git -C <worktree> status --porcelain
```

Any failure is a stop, not a warning: a changed byte that is not in the
manifest, a manifest digest that differs from the live tree, a seal that no
longer verifies, or a dirty worktree means the factory is not in the state the
last audit certified.
