---
name: Compliance
description: Runs the read-only harness-config, drain, gate-control chain, and policy-digest sweep via harness.verify, drain.validate, gate.control and check.run; use for compliance evidence backing GATE_CONTROLS and POLICY_DIGEST.
metadata:
  opencode/autoinvoke: false
---
# compliance
`invocation:` call typed tools only (read-only sweep):
```
harness.verify({ scope: "harness_config" })
harness.verify({ scope: "policy_manifest" })
drain.validate({ stage: "R1"|"R2"|"R3"|"R4"|"R5", record_hash: "<64-hex>?" })
gate.control({ target: "gate"|"impl"|"policy_digest"|"gate_impl"|"drain"|"manifest", mode: "run"|"verify" })
check.run({ check_id: "POLICY_DIGEST", tree: "<40-hex-sha>", engine: "sqlite"|"postgres"|"none" })
```
`serves:` read-only evidence review (the harness-config, drain, gate-control and policy-digest pass; it backs `GATE_CONTROLS`, `POLICY_DIGEST` and the drain-lineage verdict rather than a single check id). Compliance writes its evidence via `code.write` (`backend/docs/compliance/*`).

`args:`
- `harness.verify`: `{ scope }` (`harness_config`|`policy_manifest`). Orchestrator only.
- `drain.validate`: `{ stage, record_hash?, mode? }` (`stage` `R1`-`R5`; `record_hash` ^[a-f0-9]{64}$; `mode` `verify`). Auditor/orchestrator/release-engineer.
- `gate.control`: `{ target, mode? }` (`target` `gate`|`impl`|`policy_digest`|`gate_impl`|`drain`|`manifest`; `mode` `run`|`verify`). Auditor `run`, orchestrator `verify`.
- `check.run`: `{ check_id: "POLICY_DIGEST", tree, engine }` (`tree` ^[a-f0-9]{40}$; `engine` `sqlite`|`postgres`|`none`). Runners builder, auditor, ci.
- `code.write`: `{ path, content, encoding?: "utf-8" }` (`path` under `backend/docs/compliance/*`). Compliance scope only.

`output schema:` one verdict per tool — `harness.verify` scope PASS/FAIL, `drain.validate` `PASS`|`FAIL` with `records_checked`/`problems`, `gate.control` chain PASS/FAIL with `problems`, `check.run` `POLICY_DIGEST` `RESULT` with `digest`/`files`/`match`. The sweep verdict block aggregates them.

`exit codes:` `0` = every command passed (overall `PASS`); `1` = at least one command failed (any `FAIL`); `2` = tool error (`REJECT_*` / exception). Refusals name the tool and the rejected field.

`failure modes:` (observed)
1. Drain records no longer carry the live narrowed policy digest: `policy_digest differs from live narrowed digest` (`drain.validate` exit 1).
2. The sealed gate-control record is stale, which propagates through both tools: `newest record did not verify` and `ORACLE_PROVENANCE has 2 controls, minimum 4` (`gate.control` verify / `drain.validate`, exit 1).

Do not report the sweep as green while any tool verdict is `FAIL`; a stale seal fails the gate-control leg and therefore the drain leg too until the re-seal refreshes the records and the R1/R2/R3 digests.

`worked example:` (tool calls only)
```
harness.verify({ scope: "policy_manifest" })
drain.validate({ stage: "R1", mode: "verify" })
gate.control({ target: "gate", mode: "verify" })
check.run({ check_id: "POLICY_DIGEST", tree: "12c96d1117c1a581eafe4a5c780a12f45808e30c", engine: "none" })
```
`verified:` 2026-11-08, tool names per registry (`harness.verify`, `drain.validate`, `gate.control`, `check.run`, `code.write`); stale-seal propagation retained as a failure mode.
