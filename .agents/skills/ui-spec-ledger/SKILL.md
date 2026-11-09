---
name: ui-spec-ledger
description: Use when you need to find the authoritative UI requirement, design decision, status, floor, or ownership rule for a task on the spec-ui storefront. Maps the frontend doc set (UI-UX-SPEC.md A-0b..A-14, ui-ledger.md, MOTION-3D-ANALYSIS.md, STITCH-PROMPTS.md) and says which file answers which question, who may write which file, and which one you must never edit. Read before any UI task; the backend counterpart is spec-ledger.
---

# UI doc set map — the storefront on `spec-ui`

The frontend has **its own** ledger and design docs under `frontend/docs/`.
Read `run-topology` first to confirm you are on the right tree — a number is
valid only for the branch it was measured on.

```powershell
git branch --show-current    # expect: spec-ui (or ui/tN on a lane worktree)
```

## The doc set

| File | Size | What it is |
|---|---|---|
| `frontend/docs/design/UI-UX-SPEC.md` | ~3,000 lines, **the single source of truth** | Sections A-0b..A-14 (below). Every task cites a section. |
| `frontend/docs/run/ui-ledger.md` | ~160 lines | The **run ledger** — phase status, bug findings, process rules, session notes, the wave tracker. Written by the **ui-orchestrator only**. |
| `frontend/docs/design/STITCH-PROMPTS.md` | per-page | One Google Stitch prompt per page + a design-system prompt. Human-in-the-loop (user runs Stitch; designs are **not** committed). |
| `frontend/docs/design/MOTION-3D-ANALYSIS.md` | — | 3D/cube feasibility study behind the A-11/A-13 motion decisions. |
| `frontend/docs/design/*.md` scanned by Tailwind? | — | **No — and that is a bug.** BUG-10: Tailwind v4 auto source-detection was scanning these `.md` files and injecting dead CSS. Fix is an explicit `@source` allowlist. Keep prose out of the CSS source graph. |
| `media/res/` (gitignored) | — | The 17 selected Stitch reference images. **Uncommitted by design** — the spec must remain executable from words alone. |
| `BACKEND_REQUESTS.md` (repo root) | — | Cross-repo gaps the UI logs for the backend. Appended, never rewritten. |

## Which section of UI-UX-SPEC answers which question

| Question | Section |
|---|---|
| What is the design direction and what must not regress? | **A-0** (direction settled; KEEP/CHANGE/DROP tables; CSS-first ladder) |
| What binds from the Stitch refs, and what is placeholder? | **A-0b** (the refs are a SYSTEM, not CONTENT; provenance rules) |
| What are the design principles (and their falsifiers)? | **A-1** P1–P5 (whitespace, one accent, motion-as-sentence, single-image, say-the-real-number) |
| What are the colour / type / spacing / motion tokens? | **A-2** (2.1 colour, 2.2 type, 2.3 spacing/radii/z, 2.4 motion tokens) |
| How does motion work, and what is rejected? | **A-3** (scroll-driven, route transitions, reduced-motion policy, rejected techniques) |
| What is the responsive strategy? | **A-4** |
| What does each page look like? | **A-5** (5.1–5.12 per-page layout + out-of-scope list) |
| What components exist / are required? | **A-6** (component inventory) |
| What a11y must not regress, and how is it tested? | **A-7** (7.1–7.8, incl. the a11y test surface) |
| What is the SEO plan? | **A-8** (metadata, sitemap, scroll-driven vs crawling) |
| What is the testing plan (vitest + playwright + what gets no test)? | **A-9** (9.1–9.3) |
| What is the performance budget (LCP, per-route JS, images, fonts, CSP)? | **A-10** |
| What is the dependency budget (and what was rejected)? | **A-11** (incl. the 3D feasibility corrections A-11.5) |
| What backend gaps exist / what must come from the API? | **A-12** (12.A open questions, 12.B genuine gaps, **12.D API BINDING**) |
| What assumptions were made, and how verified? | **A-13** (13.1 verified, 13.2 assumptions, 13.3 the selected-refs limits) |
| **The reconciliation checklist (BACKEND orchestrator runs this)** | **A-14** — **the UI side never edits this section** |

## Sizes — the context-cost rule

`UI-UX-SPEC.md` is ~100KB+. **Read only the cited section range**, never the
whole file. Use `Select-String` for structure and targeted reads for the range
your task names. The ledger (`ui-ledger.md`) is small — read it whole at the top
of a cycle; it is the state of the run.

```powershell
Select-String -Path frontend\docs\design\UI-UX-SPEC.md -Pattern "^#{2,3} "   # structure only
# then Read with offset/limit for your section
```

## Editing rules — who owns what

| File | Owner | You may edit? |
|---|---|---|
| `UI-UX-SPEC.md` (A-0..A-13) | ui-orchestrator / design-research | Only if your task explicitly says so; a builder **implements** it, does not rewrite it. |
| `UI-UX-SPEC.md` **§A-14** | **backend orchestrator** | **NEVER.** Byte-identical contract. Verified with `cmd` byte-exact compare, never `Out-File`. |
| `ui-ledger.md` | **ui-orchestrator only** | **No** if you are a builder or auditor. Editing the ledger is fraud, same as a stub. The auditor returns a report; the orchestrator writes the row. |
| `STITCH-PROMPTS.md`, `MOTION-3D-ANALYSIS.md` | design-research | Only if your task names them. |
| `BACKEND_REQUESTS.md` | every UI agent, append-only | **Yes** — append a gap entry. Never rewrite existing entries. |
| `frontend/src/**` | ui-builder | **Yes**, within the task scope (≤5 files, ≤1 new shared component). |
| `backend/**` | backend agents | **Read-only** for every UI agent. Log a gap in `BACKEND_REQUESTS.md` instead of editing. |

`ui-builder.md` states this as a hard failure: *"NO ledger tampering … Editing
the ui-ledger is fraud, same as a stub."*

## Status vocabulary (same as the backend run)

```
PENDING → IN-COMPLIANCE → BUILDING → IN-AUDIT → BUGS-FOUND → SHIPPED → PR-OPENED
                                                                        | ESCALATED
                                                                        | NOT-APPLICABLE
```

**Max 3 builder↔auditor fix cycles per task**, then ESCALATE (see
`ui-audit-protocol` Rule 1). Classify each cycle with `ui-cycle-cost`.

## The current wave tracker (in `ui-ledger.md`)

The ledger's "Frontend-ops phase" section holds the live wave table (task id,
wave, status, attempts, evidence). **Trust the ledger about the task in front of
you; re-derive anything else you depend on** — `git log` and the actual files,
not a status cell (the backend run's `dc04100` is the cautionary row: 15/18
deferred rows went stale and had to be re-checked from code).

## Current verified numbers — measure, don't inherit

The batch A/B audit-A2 floor (for calibration only; **re-measure on your tree**):
build exit 0, 23 routes, 61 tests / 8 files, stylesheet 44,564 B production.
The §A-14.6 backend floor of **1757** does **not** match the ledger's latest
figure (1515→1617) — finding **A-9** says this **must be reconciled before A-14
runs**, and A-14 is deliberately not edited by the UI side.

Quote only what you re-measured, on the tree you measured it on. See
`ui-audit-protocol` Rule 3 for the floor format.
