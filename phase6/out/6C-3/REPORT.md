# 6C-3 Harness checker — REPORT

WP: 6C-3 (phase6c). Owns `scripts/check_harness_config.py`.
Status: DONE (checker + fixtures verified; live INV-1..4,5,7 green modulo 6C-1c/crouton YAML; INV-6 pending 6C-4).

## What changed

`scripts/check_harness_config.py` now enforces INV-1..7 as pure functions
shared by live mode and `--fixtures` mode:

| INV | Rule | Live now |
| --- | ---- | -------- |
| INV-1 | No `action: shell` in any installed agent | PASS* (see crouton) |
| INV-2 | No `edit/write allow` on `quality/**` outside `ledger.append` | PASS* |
| INV-3 | Only hacker reaches `hacker-scratch` writes, only via `tool: scratch.write` | PASS* |
| INV-4 | Every role denies `read/grep/glob` on `**/policy-manifest.json` | PASS* |
| INV-5 | Per-role tool list (registry) equals matrix `TOOL:` dispositions | PASS |
| INV-6 | Registry/server (+controls, probe client) hash in `gate_impl_digest` covers + manifest files | FAIL (6C-4 pending) |
| INV-7 | Every subagent target the orchestrator routes to is allowed | PASS |

`*` = all 6 parseable roles pass; the sole blocker is `.opencode/agents/crouton-alpha.md`
(6C-1c owns it): its frontmatter `description` contains an unquoted `wired:`
colon, so `yaml.safe_load` raises "mapping values are not allowed here" and
INV-1..4 report FAIL for crouton-alpha alone. The checker reports the parse
error as a check failure instead of crashing; 6C-1c must quote that one
description line (no other fix needed — crouton's permissions already match
gen_perms output for `crouton`: `code.write` + `git.state`).

Scoping decisions (see checker header):

- **INV-5** compares registry projection vs matrix (6B gate definition), not
  agent-file tool allows. Agent tool allows are emitted by `gen_perms.py`
  (which enforces the same equality) and are now correct on all 6 cut-over
  roles (orchestrator 9, builder 10, auditor 19, hacker 6, compliance 1,
  release-engineer 13).
- **INV-6** checks covers membership + manifest `files[]` hash presence/match
  for `files/tools/mcp/registry.json`, `files/tools/mcp/core/server.py`,
  `files/tools/mcp/controls.json`, `files/docker/k1/probe_client.py`.
  It does not recompute the digest value (that is P-CTRL/`gate_control.py`;
  `gate_control.gate_impl_digest()` currently crashes on missing
  `opencode.json`). Once 6C-4 extends `gate_control.py` covers + regenerates
  the manifest, INV-6 goes green with no checker change.
- **INV-7** routes = `dispatch-rules.json` (`dispatch_first` +
  `require_before`) ∪ orchestrator `"target": "..."` enum, with
  `hacker-high/max` normalized to `hacker`. Orchestrator now allows
  `builder, auditor, hacker, hacker-high, hacker-max, design-research,
  release-engineer, compliance, crouton-alpha` (6C-1c fixed F-09/F-12),
  so routed ⊆ allowed passes.

## Known-bad fixtures

`phase6/out/6C-3/fixtures/` (each embeds real registry/matrix/dispatch data;
all other INVs pass, certifying isolation):

- `clean.json` — all 7 pass.
- `inv1-shell-bad.json` — builder `shell *docker run* allow` → INV-1 only.
- `inv2-quality-bad.json` — orchestrator `edit quality/** allow` → INV-2 only.
- `inv3-scratch-bad.json` — builder `write hacker-scratch/** allow` → INV-3 only.
- `inv4-manifest-bad.json` — hacker missing `grep` manifest deny → INV-4 only.
- `inv5-matrix-bad.json` — registry `evil.tool` for builder, no matrix entry → INV-5 only.
- `inv6-digest-bad.json` — `registry.json` dropped from covers → INV-6 only.
- `inv7-subagent-bad.json` — `design-research` allowed-claim removed → INV-7 only.

Exit test (run from harness root):

```
python scripts/check_harness_config.py --fixtures          # 8 fixtures, 56 evals
python scripts/check_harness_config.py                      # 109 live checks
```

- Fixtures: `FIXTURES RESULT: PASS (8 fixtures, 56 INV-evals)` — clean passes
  all 7; each bad fails exactly its INV (isolation asserted in
  `_run_fixtures`; any extra failure exits 1).
- Live: `RESULT: FAIL (15/109)` — failures are all outside 6C-3 ownership or
  pending sibling WPs, not INV logic:
  `default_agent` (2, `opencode.json` gitignored since 71d0137 — pre-existing),
  `installed copy matches files/` (2, orchestrator/release-engineer sync;
  6C-1b/1c in flight), `crouton-alpha denies` (3, the YAML error above),
  `policy manifest verifies` (1, `opencode.json` missing), `SKILL.md …` (2,
  6C-2 pending), `INV-1..4` (4, crouton parse error only), `INV-6` (1, 6C-4
  pending). INV-5 + INV-7 pass live. Excluding crouton-alpha, the six
  cut-over roles prove INV-1..4 pass (0 shell / 0 quality / 0 direct
  hacker-scratch / manifest denies present on every role).

## Deviations (cutover-compat, legacy checks)

Old shell-dependent checks were made cutover-compatible so the checker can be
green both pre- and post-cutover (INV-1..7 are the guards):

- Builder `asks` skip when builder has zero shell rules (INV-1 vacuous).
- Auditor K1 lifecycle accepts shell K1 **or** `tool k1.up/down/exec/status`.
- Auditor `denies edit globally` accepts explicit `edit * deny` **or**
  blanket deny + zero edit/write allows.
- V2 `edit policy is explicit` accepts an edit allow **or** the cutover form
  (blanket deny + zero edit allows).
- Manifest owner check relaxed to `read/grep/glob` (gen_perms emits no
  edit/write/shell lines; INV-1/INV-2 cover those actions).
- Resilience: missing `opencode.json` no longer crashes (treated as `{}`,
  `default_agent` checks report FAIL); broken frontmatter returns a
  `__parse_error__` marker instead of raising, so one bad file cannot abort
  the whole run.

## Open questions

- None blocking 6C-3. At seal, expect INV-1..7 green after 6C-1c quotes the
  crouton `description` (one line) and 6C-4 binds the MCP/registry/controls/
  probe-client hashes. `default_agent` / `policy manifest verifies` remain
  red until `opencode.json` is restored (or the checks are retired as
  purged-config relics) — flag for 6C-4/lead.
