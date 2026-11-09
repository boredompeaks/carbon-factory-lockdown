# R05-04 — Serialize AGT evaluations to stop the fail-closed audit race

- **Date:** 2026-11-06
- **Requested by:** CARBON (FDE) after the Gate 6a boot proofs
- **Affects:** `.opencode/plugins/agt-compat.js` (hashed into `gate_impl_digest`)
- **Status:** APPROVED — applied and re-probed

## Finding

Live boot proof produced, verbatim:

```
AGT tool evaluation failed closed: ENOENT ... rename '...audit-log.json.tmp-35516' -> '...audit-log.json'
```

with audit entry `tool.policy_error deny`. Two evaluations from the same
process raced on one temp filename in the AGT package's audit writer; the loser
renamed a file that no longer existed, the adapter treated the evaluation error
as a policy error, and fail-closed **denied a read that policy allowed**.
`denyOnPolicyError: true` is correct; the false policy error is not.

## Change

Add a per-process promise-chain in `agt-compat.js` and route the three
evaluation calls (`evaluateOpenCodeTool`, `evaluateOpenCodeToolOutput` in the
before/after hooks, and the per-part output evaluation in `redactResult`)
through it. Audit writes from this process are then serialized; the package's
per-pid temp name can no longer collide with itself. No policy, threshold, or
decision logic changes — only the ordering of calls to the same evaluator.

## FDE evaluation

- Fail-closed stays: a real policy error still denies. The change removes only
  the self-inflicted error class (concurrent rename).
- Cross-process writes keep distinct pids; the package remains the writer of
  record. This is a serialization, not a second audit sink.
- The adapter body is in `CHECK_BODY_FILES`, so `gate_impl_digest` moves again;
  the Gate-6 re-seal (`0005`) must follow this change, once.
- Re-probe: 36+ rapid tool evaluations in one session with no
  `tool.policy_error` entry, and `agt_policy_status` still returns.

**Decision: APPROVED.**

## Related (not a policy change)

`agt_policy_status` / `agt_policy_check_text` / `skill` were absent from role
toolsets because the V2 permission layer hides tools with no explicit
`action: tool` allow. The five role files now allow `agt_policy_status`,
`agt_policy_check_text`, and `skill`; the orchestrator additionally allows
`subagent` (the Gate-7 dispatch prerequisite). Deny rules are unchanged.
