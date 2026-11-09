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
