---
description: >-
  DISABLED. Superseded by the ui-orchestrator / ui-builder / ui-auditor
  pipeline. Its design direction ("no animation for its own sake") contradicted
  the settled UI-UX-SPEC §0/§3 direction and was filed as ledger finding 3A-.
  Kept for reference only; will not load. Frontend work must go through the
  ui-* agents instead.
mode: primary
disable: true
tools:
  read: true
  write: false
  edit: false
  bash: false
  webfetch: false
permission:
  edit: deny
  bash: deny
---

# Role

This agent is disabled. Do not dispatch it. Route all frontend work through
`ui-orchestrator` (which delegates to `ui-builder` / `ui-auditor`).

The original file was recovered from a markdown-escaped write (literal `\---`
delimiters and `&#x20;` entities), which is why the body was not preserved
verbatim. Its superseded design direction is retained in the UI-UX-SPEC §0
"Design direction - settled" and in the `.opencode/ui-ref/` taste doctrine.
