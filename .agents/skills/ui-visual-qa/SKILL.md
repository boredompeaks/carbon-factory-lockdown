---
name: ui-visual-qa
description: Use when the ui-auditor (or a ui-builder verifying its own visual work) must inspect a page, component, animation, or layout change with a real browser. Encodes the Playwright inspection procedure (dev server background-only, screenshot at 1280 and 390, click every control, keyboard focus pass, reduced-motion, both themes), the contrast/target-size/reduced-motion checks the gates cannot see, and how to close BUG-4 (e2e unproven) by running playwright with the backend up. Read before any visual verdict.
---

# UI visual QA — look at it, don't assume it

The gates pass while a screen is still visibly broken: a checkbox that will not
toggle, a control that changes nothing on click, a panel with a grey band through
it. This skill is the procedure for actually looking. It is the storefront's
form of the `design-critic` pattern from the reference kit
(`.opencode/ui-ref/xias/`) — review the **artifact**, never the argument.

## When this applies

- The task is **visual**: layout, typography, colour, spacing, motion, a new
  component, a per-page redesign, or anything the batch audit would call "the
  batch repaints every route".
- The ui-auditor is issuing a **SHIP verdict** on visual work.
- A ui-builder wants to self-verify before returning a visual task.

Non-visual work (a token-existence guard, a doc figure, a sitemap change) needs
the `ui-cycle-cost` gate, not a browser.

## Setup — dev server is background-only

- Start the dev server **in the background** (`npm run dev` in `frontend/`, on
  its default port 3000). Never block the session on it. Record the port.
- The **backend must be up** for anything that renders real data (the Django
  server on :8000). If the backend is down, the page may render empty/loading
  states — say so; do not mistake an offline backend for a rendering bug.
- Playwright is the tool (`npx playwright test`, or the MCP `playwright_*`
  tools for interactive inspection). Screenshots are evidence; save them under
  the task's evidence path, not loose.

## The inspection procedure (visual work)

1. **Screenshot at both viewports:** 1280 (desktop) and 390 (phone). The phone
   viewport is the base (`mobile-first` is a house rule) — check 390 first.
2. **Both themes** if the page is themed (light/dark). One palette, two modes,
   no per-page palette — a page that looks different between themes bypassed
   the theme.
3. **Click every control.** Confirm each one changes something visible. A control
   that declares a state contract and changes nothing on click is a defect (the
   `verify_interactive` gate's whole reason for existing).
4. **Keyboard focus pass.** Tab through the page. Every interactive element is
   reachable, has a visible `:focus-visible` ring (`--focus #9c6a2e` + halo, not
   the retired `#8a5a24`), and the focus order is logical. Focus traps work
   (menu overlay: initial focus, Tab cycle, Shift-Tab wrap, Escape, focus
   restore, body scroll lock — the KEEP example at `MenuOverlay.tsx:26-64`).
5. **Reduced-motion.** Emulate `prefers-reduced-motion: reduce`. Scroll-driven
   work must be **removed entirely** (not shortened); entrances land at final
   position with no opacity flash; nothing is lost that is not also present as
   text.
6. **Empty / loading / error states.** If the page has them, look at each. A
   skeleton must mirror the real grid's exact columns; an empty state must own
   its viewport and offer a way forward; an error must use `--color-danger`, not
   the bronze accent.
7. **Screen economy on the phone.** At 390×844 the primary heading + at least
   one primary action are visible without scrolling. No image wider than its
   container. No single box swallows the viewport.

## What the browser cannot see — check these from source/literals

- **Contrast ratios** — recompute from the hex literals (the ledger's process
  rule: a number in a comment is a claim). Use the token values, not a
  screenshot's perceived colour. `line` (1.23:1) is decorative-only and must
  never become a control boundary; `line-strong` (4.62:1) is the non-text floor.
- **Target sizes** (WCAG 2.5.8, ≥24×24) — measure the element box.
- **`prefers-reduced-motion` coverage** — grep which files handle it; a policy
  that exists only in `globals.css` and not in components is the recorded gap.
- **Hardcoded values / emoji** — grep the source, not the render.

## BUG-4 — closing "e2e unproven" the honest way

BUG-4 is open because e2e could not reach the servers (`ECONNREFUSED ::1:8000`,
`localhost:3000`) — **environmental, so UNPROVEN, never "passing."** Zero
assertion failures is not evidence when the servers were down.

To close it (this is the only valid way):
1. Start the backend (`:8000`) **and** the frontend dev server (`:3000`).
2. Run `npx playwright test` in `frontend/`.
3. Report the real counts: passed / failed / did-not-run. If any test did not
   run or the servers were unreachable, it is **still UNPROVEN** — say so.

Do not waive BUG-4 to get a SHIP verdict. The ledger records it as a **must-run
with the backend up before A-14**. If a wave repaints routes and e2e is the only
gate that would catch a visual regression, an unproven e2e is a blocking gap,
not a note.

## Reporting a visual verdict

The ui-auditor returns, and the ui-orchestrator records into the ledger:

```
visual: <page/component> @ <1280|390> <light|dark> — <what was checked>
  controls: <N> clicked, <k> changed nothing        [defects listed if any]
  focus:    <reachable / ring / order / trap>       [defects listed if any]
  reduced-motion: <removed / instant / opacity>     [defects listed if any]
  states:   <empty / loading / error>               [defects listed if any]
  contrast (recomputed from literals): <pass/fail per pair>
verdict: SHIP | FIX (findings by P1/P2/P3)
evidence: <screenshot paths>
```

A SHIP on visual work is only credible with the screenshots attached and the
control-click pass reported. "It looked fine" is not a verdict.
