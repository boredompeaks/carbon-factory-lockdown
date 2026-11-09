# R05-01 — Restore model independence on live, cheap ids

- **Date:** 2026-11-06
- **Requested by:** owner directive (Gate 1, R05 program)
- **Prepared by:** CARBON (FDE)
- **Status:** APPROVED — applied

## Defect

`files/policies/models.json` and the five role frontmatters pin `opencode/*-free`
models. The free quota is exhausted (`Free usage limit reached`), so every role
now fails closed at load or silently falls back across families (the free-model
fallback chains in `opencode.json` name each other's families). The auditor and
builder therefore both effectively run deepseek, which voids audit independence.
`opencode.json` also still carries the dead `nous-portal` provider whose key is
revoked.

## Change

Provider `opencode-go` (paid, ultra-cheap flash tier). Three families stay
distinct; each role resolves to a live id:

| role | model | family |
|---|---|---|
| orchestrator, builder | `opencode-go/deepseek-v4.1-flash` | deepseek |
| auditor, release-engineer | `opencode-go/glm-5.3-flash` | glm |
| hacker-high, hacker-max | `opencode-go/minimax-m3.1-flash` | minimax |
| compliance (installed only) | `opencode-go/mimo-v2.6-flash` | mimo |

Files: `files/policies/models.json`; `files/{orchestrator,builder,auditor,hacker,release-engineer}.md`
frontmatter; installed copies under `.opencode/agents/` (including
`compliance.md`); `opencode.json` — delete `provider.opencode` (retired free
ids + cross-family fallbacks) and `provider.nous-portal` (revoked key).

No fallback chain may cross a family: the paid ids are used directly, and a
failure writes a load error instead of substituting another family.

## FDE evaluation

- Independence rule in `models.json` is unchanged: auditor ∉ {builder, hacker},
  builder ∉ {auditor, hacker}, hacker ∉ {builder, auditor}, release-engineer ∉
  {builder}. The new ids satisfy every rule under the checker's family token
  (`glm`, `deepseek`, `minimax`).
- The checker compares `f"{provider}/{model}"` against the installed
  frontmatter; both trees must be updated in the same pass.
- Removing the `opencode` provider block removes the cross-family fallback
  surface that made the split advisory. `ollama-cloud` is unrelated and stays.
- Cost: all four ids sit on the cheapest paid flash tier (deepseek 0.15/0.6,
  glm flash and minimax flash comparable), so this does not change the budget
  class.

**Decision: APPROVED.** Verification: `python scripts/check_harness_config.py`
→ PASS; a live `opencode run --agent auditor` session whose recorded model is
`opencode-go/glm-5.3-flash` (family `glm` ≠ builder `deepseek`).
