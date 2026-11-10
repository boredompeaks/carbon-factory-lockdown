---
name: Dispatch
description: Starts or continues a child session through the subagent tool and records it via ledger.append; use for orchestrator dispatch (one builder per permanent lane in parallel) and the section-boundary release-engineer invocation only.
metadata:
  opencode/autoinvoke: false
---
# dispatch
`skill-level name:` dispatch

`invocation:` call the `subagent` tool directly (not shell), then record the dispatch via `ledger.append`:
```
subagent({ agent: "compliance", description: "dispatch probe",
           prompt: "Reply with the single word OK and stop. Do not use any tool." })
ledger.append({ record_type: "dispatch"|"capability", record: { /* typed dispatch record */ }, expected_prev_hash: "<64-hex-sha>" })
```
`serves:` orchestrator dispatch (builder, auditor, hacker, release-engineer, compliance). On the lane path, dispatch one builder per permanent lane in parallel (lane/a, lane/b) and dispatch release-engineer exactly once at the section boundary. This skill is for the orchestrator only. The auditor does not use this skill: its only hacker path is `hacker_dispatch(capability_id)`, which accepts a `capability_id` and nothing else — never a free-form prompt or model override.

`capability mint:` required before every lane spawn, because a builder writes only under a live capability. Order is fixed: mint, then spawn; never spawn first and mint on return.
1. Read the lane's live head and tree and the plan's allowance. Do not reuse values from an earlier message.
2. `ledger.append` exactly one `capability` record with role `orchestrator` and `expected_prev_hash` = the capability tip. `task_branch` is the lane id as keyed in `policies/worktree-map.json`. `scope` is `backend/**` or `backend/docs/**` as the lane plan declares. Set `role` = `builder`, `native_tools` = `["edit","write","patch"]`, `expires_at` = mint time + 6h, and `budget` = the plan allowance plus `tasks` = 6.
3. Spawn the child with a prompt whose FIRST step is `opencode_session_move` targeting that lane's directory from `policies/worktree-map.json`; the child then works only there. Pass `capability_id` in the prompt; the child never mints.

Payload shape (the ledger seal adds `record_hash`; `prev_hash` is the chain envelope). Budget values are examples; substitute the plan's integers and the live shas:
```json
{
  "schema": "capability/1",
  "capability_id": "cap_<8-64 of [A-Za-z0-9_-]>",
  "parent_capability_id": null,
  "lineage_id": "<lineage_id>",
  "base": "<base sha, 40 or 64 hex>",
  "head": "<lane head sha, 40 or 64 hex>",
  "tree": "<lane tree sha, 40 or 64 hex>",
  "scope": ["backend/**"],
  "tier": "high",
  "hacker_variant": "high",
  "budget": { "wall_clock_s": 21600, "tool_calls": 400, "tokens": 250000, "tasks": 6 },
  "acceptance_test_refs": ["<ref from the task input>"],
  "acceptance_author_family": "<provider family from policies/models.json>",
  "characterization_tests": [],
  "architecture_allow": [],
  "guard_delta": [],
  "allowed_test_removals": [],
  "task_kind": "FEATURE",
  "task_branch": "lane/a",
  "output_schema_ref": "policies/schemas/builder-result.json",
  "policy_digest": "<64 hex>",
  "sig_status": "unsigned_local",
  "role": "builder",
  "native_tools": ["edit", "write", "patch"],
  "expires_at": "<mint time + 6h, ISO-8601 UTC>"
}
```
`budget.tool_calls` is the plan's allowance. The orchestrator enforces `budget.tasks`; the proxy enforces `budget.tool_calls` and `expires_at`. Re-mint at every train/section boundary: every 6 hours or every 6 tasks, whichever comes first, with `parent_capability_id` = the previous `capability_id` and fresh head, tree, and `expires_at`. If no capability exists or it has expired, the proxy denies writes: do not retry blindly and do not widen scope; re-read state and re-mint.

`startup sequence:` run before the first dispatch, in order, and stop at the first blocker:
1. `harness.verify({ scope: "factory" })` — factory doctor; read `ok`, `blockers`, `facts` and clear the blockers before continuing.
2. `worktrees.list()` then `git.state({ lane: "<lane>", fields: ["head", "tree", "branch", "clean"] })` — resolve the lane and its live HEADs; never reuse shas from an earlier message.
3. `k1.up({ lane: "<lane>", run_id: "<id>", base: "<40-hex>", head: "<40-hex>" })` — lane-aware; the run mounts that lane's tree.
4. `check.run({ lane: "<lane>", check_id: "BOOTTEST", tree: "<40-hex>", engine: "postgres" })`, then the same call with `check_id: "SUITE"` — per-lane evidence, never a factory-wide run.
5. `docker.ensure({ action: "health" })` — re-confirm the engine before handing the lane to a builder.
6. Root bootstrap: when the session starts at the workspace root, `execute` → `tools.opencode.session_move({ directory: "<lane path>" })` to enter `lane/a`, `lane/b`, or `spec-comp`; every write after the move needs a live capability (see `capability mint` above).
7. Always pass `lane` explicitly to `git.*`, `check.run`, and `k1.up`; there is no implicit factory fallback in a workspace session.

`args:`
- `subagent.agent` (required) — target agent id. Only `mode: subagent` or `mode: all` agents resolve; the orchestrator's permission list allows `builder`, `auditor`, `hacker`, `release-engineer`, `compliance` and denies `*`.
- `subagent.description` (required) — short label shown in the parent session.
- `subagent.prompt` (required) — the complete child task; the child starts with fresh context and cannot see your transcript.
- `subagent.background` (optional, default false) — `true` returns immediately and notifies the parent when the child finishes.
- `subagent.sessionID` (optional) — continue an existing child instead of starting a new one.
- `subagent.model` (optional, provider/model or provider/model#variant) — dispatch-time override; the high tier uses `nous-direct/minimax/minimax-m3.1-flash#high` (primary); the fallback provider is `opencode-go` (see `policies/models.json` `fallback_provider`). `openai/gpt-6-luna#max` is not configured in `opencode.json` (unresolvable) and must not be passed.
- `ledger.append`: `{ record_type, record, expected_prev_hash }` (`record_type` `dispatch`|`capability`|`verdict`|`finding`|`attack-log`|`gate-control`|`release`; `expected_prev_hash` ^[a-f0-9]{64}$; per-role record types enforced server-side — orchestrator: `dispatch`, `capability`).

`output schema:` `{ sessionID: string, state: "completed" | "error", message/final text: string }`. Foreground calls return the child's final text; background calls return the sessionID and notify later. `ledger.append` returns the new record hash.

`exit codes:` no process exit — the tool returns a result or throws. Denied target means a permission error naming the agent id; nesting beyond the configured depth means a refusal; child failure means `state: "error"` with the child's text, never a fabricated OK.

`failure modes:`
1. `Permission denied: subagent builder` — the target id is not in the caller's `subagent` allow list; the last matching rule wins, so a trailing `* deny` silently erases per-id allows.
2. Nesting refusal — a subagent child attempting to spawn another child is blocked at the default depth of one; parallelize inside the child with its own tools instead.

`worked example:` (tool call only)
```
subagent({ agent: "compliance", description: "dispatch probe", prompt: "Reply with the single word OK and stop." })
# => { sessionID: "<id>", state: "completed", ... final text: OK }
```
`verified:` 2026-11-08, tool names per registry (`subagent`, `ledger.append`); permission action `subagent`, resource = target agent id.

`contract note:` `subagent` is a harness-namespace action, not an MCP registry tool. The dispatch contract is pinned to the gate SHA (newest gate-control record) and the registry SHA (`files/tools/mcp/registry.json`).
