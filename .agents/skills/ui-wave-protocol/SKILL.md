---
name: ui-wave-protocol
description: Use when the ui-orchestrator dispatches a wave, syncs lane worktrees, or routes an audit. Encodes the 3-parallel-builder flow (isolated worktrees ui/tN -> sync -> 1 auditor on ui-wt -> push origin/spec-ui), the strict sync standard because the backend is in active development, and the RE train every 9 tasks. Read before dispatching or syncing anything.
---

# UI wave protocol — parallel builders, serial audit, strict sync

The frontend-ops phase (user-directed 2026-10-15) runs **N parallel builders →
sync → 1 auditor → push**. This skill is the flow and the sync standard. It is
the storefront counterpart of the backend's two-phase
BUILD_PHASE/GATE_PHASE machine, but the unit is a **wave**, not a section.

## The wave, end to end

```
1. ui-orchestrator splits the next slice into ≤3 tasks, each:
   - ≤5 files, ≤1 new shared component (split BEFORE dispatch, not mid-flight)
   - names its UI-UX-SPEC section range + the motion contract it must carry
2. Dispatch each task to an ISOLATED worktree:
     worktree  C:\Users\Admin\AppData\Local\Temp\opencode\ui-wt-<id>
     branch    ui/<id>            (e.g. ui/t1, ui/t2, ui/t3)
   Builders commit LOCALLY on their branch. NO push. NO merge. NO touching
   spec-ui directly.
3. When all builders in the wave have returned (or checkpointed):
   SYNC on ui-wt (branch spec-ui):
     - merge each ui/<id> into spec-ui in task order
      - if a merge conflicts, resolve BACKEND-FIRST (the backend is authoritative;
        see "strict sync" below) — or, if the conflict is a genuine contract
        ambiguity, stop and escalate to the user.
4. AUDIT — exactly ONE ui-auditor runs on ui-wt against the merged tree.
   It re-runs the full gate itself (ui-audit-protocol Rule 3) and, when the work
   is visual, does Playwright visual inspection (ui-visual-qa).
5. Verdict:
   - SHIP  -> ui-auditor pushes origin spec-ui. Wave done. Update RE-train count.
   - FIX   -> ui-orchestrator dispatches a fix cycle to the owning worktree
              (max 3 cycles per task, then ESCALATE — ui-audit-protocol Rule 1).
6. RE train: every 9 shipped tasks, hand to release-engineer for the promotion
   pass (same cadence as the backend run).
```

## Isolated worktree rules (builders)

- Work **only** in your assigned worktree and on your assigned branch. Never
  `git checkout`/`switch`/`merge`/`rebase` across worktrees, never touch
  `spec-ui` directly (this is why the builder agent's permissions deny
  `checkout`/`switch`/`merge`/`rebase`/`worktree`).
- Commit **locally**, one commit per task, linear history. **Never push.**
- The auditor verifies and pushes (durability backup + origin update). The
  release-engineer promotes. `master` and `feat/add-frontend` are never targets.
- Read the shared ledger (`ui-ledger.md`) at the **start** of the task and write
  your report row at the **end** — you do **not** edit the ledger yourself
  (ui-spec-ledger editing rules).

## Strict sync standard — the backend is in active development

This is the rule that makes parallel UI work safe against a moving backend.

1. **A lane worktree may not go stale across a wave boundary.** Before any
   sync, re-merge the current `spec-ui` tip (and, if a backend change has
   landed, the backend lane) into each `ui/<id>` you are about to merge. A
   builder working against a tree more than one wave old is building against a
   fiction — re-sync it or re-dispatch.
2. **Resolve conflicts backend-first.** The backend is authoritative for
   contract shape (`A-12.D API BINDING`). If a UI change and a backend change
   disagree on a field, endpoint, or response shape, the backend wins and the
   UI adapts — unless the spec says otherwise, in which case escalate.
3. **A conflict that is a genuine contract ambiguity is escalated to the user,
   not a silent resolution.** Do not guess at a contract boundary. Stop, surface
   the question, and hold the merge.
4. **Never let a builder push, and never let two builders share a worktree.**
   The whole point of isolation is that no builder can observe or corrupt
   another's in-flight tree; the sync is the only place they meet.
5. **Scope-slip rule.** If a builder touched a file outside its ≤5-file scope
   (the wave-1 record: a builder appended a row to `backend/docs/changes.md`),
   **drop that hunk before audit** and record it in the ledger. Backend writes
   from a UI task are always out of scope.

## Scope discipline (enforced at dispatch, re-checked at audit)

- **≤5 files and ≤1 new shared component per task.** Split before dispatch. A
  task that needs more is two tasks.
- **Template architecture first, then features/policies, then per-page
  redesign** (the user's stated order). Do not start a per-page redesign before
  the template + theme + page-registry wave is audited SHIP.
- **a11y = keep shipped tokens, no new gates** (user-confirmed). Do not invent
  new accessibility gates; implement what A-7 already specifies.
- **guest-token = sessionStorage** (standing recommendation, reversible — user
  has not vetoed). Note it in the ledger; it is not a permanent decision.

## Ledger rows the orchestrator writes for a wave

```
| U-W<n>-T<m> | <wave> | <STATUS> | <attempts> | <evidence: sha + what was proven> |
```

Evidence cites the commit sha and what was actually measured (build exit,
route count, test counts, stylesheet bytes) — never a bare "done". A number in
the evidence cell is a claim audited like code (`ui-cycle-cost`).
