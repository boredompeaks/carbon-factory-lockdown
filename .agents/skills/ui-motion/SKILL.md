---
name: ui-motion
description: Use when adding, reviewing, or changing ANY animation, transition, scroll effect, or route transition on the spec-ui frontend, and when weighing SPA-vs-SSR routing or worrying about LCP. Loads the CSS-first ladder, the 10 motion tokens by intent class, the LCP guard, and the reduced-motion policy. Read before touching motion; also read before any Next.js App Router / loading.tsx / client-component decision that trades SSR for interactivity.
---

# UI motion — a little animation, done well, without costing LCP

The client wants animation-heavy **and** heavily optimised. That tension is the
whole point of this skill: resolve it, don't ignore either half. Full grammar in
`.opencode/ui-ref/xias/taste/motion-choreography.md`; the binding, project-
specific version is here. Tokens live in §2.4, the narrative rules in §3, the
performance budget in §10 of `UI-UX-SPEC.md`.

## The one-line contract

**Motion that exists for its own sake is a defect.** An animation ships only if
it answers, out loud (§3 P3):
1. **What state is this in?** (toast confirms an add; cart badge morphs to show
   *where* the item went; checkout hairline shows which step), OR
2. **What should I read next, in what order?** (PDP story image drifting as notes
   are read; tracking timeline revealing oldest-first).

"It looks nice", "feels premium", "adds polish" are all the same answer: **cut**.
Hover micro-motion is retained *only* as a state answer at the smallest scale
(≤240ms, ≤1.03) — beyond that it's decoration and is cut (§3 P3 *wrong when*).

## Two sub-rules that make it checkable

- **No animation may gate or delay an interaction.** If a click depends on an
  animation finishing, the animation is wrong. Nothing above the fold animates
  in (§10); the checkout submit button never animates.
- **No animation may carry information that is not also present as text.** A
  customer with reduced motion, a crawler, or a screen reader loses nothing.

## The CSS-first ladder (§0 — an engineering position, not a preference)

Reach for the platform before a dependency, in this order:

1. **CSS-only, compositor-friendly.** `transform` and `opacity` only. **Never**
   animate `width`, `height`, `top`, `left`, `margin`, or `box-shadow` in a way
   that triggers layout or paint per frame.
2. **CSS-native modern features.** `@starting-style`, view transitions,
   `animation-timeline: view()`/`scroll()`, `content-visibility`.
3. **A JS library only when orchestration is genuinely required** — layout
   animation, gestures, shared-element transitions. Name it, state the KB, and
   it must be **route-scoped, never global** (lazy `import()` inside the route,
   dynamic `ssr:false` only where the component is pure decoration).
4. **GSAP + ScrollTrigger** only for scrubbed timeline sequences CSS cannot
   express. Same rule: route-scoped, KB stated.

Rule 4 from the reference grammar that this project treats as non-negotiable:
**animate `transform` + `opacity` only** (GPU-composited, 60fps). `box-shadow`
transitions on 12 grid cards is exactly §0 forbids — the `.card-lift` fix
(§0 CHANGE-6) swaps it for a `border-color` change.

## The 10 motion tokens — by intent class, never a raw ms value (§2.4)

Defined in `@theme` in `globals.css`. A component **never** writes a duration in
milliseconds; it picks the intent class.

| Intent | Token | Duration | Reduced-motion |
|---|---|---|---|
| `state` | `--motion-state-dur` | 200ms | instant (colour/border need no motion → 0ms) |
| `enter` | `--motion-enter-dur` | 200ms | instant at final position, **no opacity flash** |
| `exit` | `--motion-exit-dur` | 160ms | instant |
| `hover` | `--motion-hover-dur` | 250ms | instant |
| `narrative` | `--motion-narrative-dur` | 600ms | instant — ONE accent moment per page |
| `progress` | `--motion-progress-dur` | 200ms | instant |
| `track` | `--motion-track-dur` | 500ms | instant, transition declaration **removed** |
| `scrub` | (timeline) | n/a | animation **removed entirely**, not shortened |
| `loading` | `--motion-loading-dur` | 1200ms | static flat `--color-hairline` block |
| `toast` | `--motion-toast-dur` | 200ms | opacity only |

One easing literal, one spelling — the spaced form is canonical:
`--motion-ease: cubic-bezier(0.16, 1, 0.3, 1)`, `--motion-ease-exit:
cubic-bezier(0.4, 0, 1, 1)`, `--motion-ease-track: cubic-bezier(0.25, 1, 0.5, 1)`
(carousel only, §2.4.1). The consolidated table (§2.4.2) maps every off-token
ref duration (150/300/500/700/1000) onto an intent class — **no duration ships
that a token cannot name**.

## Reduced-motion is a token-layer policy, not a per-component decision (§0 CHANGE-5)

The blanket `animation-duration: .01ms !important` in `globals.css:117` stays as
a **backstop**, but it is **insufficient on its own** for scroll-driven work: on
a progress-based timeline the duration *is* the mapper, so forcing `.01ms` lands
the element on whatever `animation-fill-mode` selects — *probably* visible, but
"probably" is not an accessibility guarantee. The deterministic fix: **every
scroll-driven animation is also wrapped in `@media (prefers-reduced-motion:
no-preference)`**. The blanket rule stays as the belt-and-braces layer.

## Hybrid SPA + SSR, and keeping LCP fast

This is a Next.js App Router storefront deployed on OpenNext/Cloudflare. The
goal is a **fast LCP with SPA-grade transitions** — not a client-rendered SPA
wearing an SSR shell. The rules that keep both true:

- **Static HTML reaches crawlers and the first paint.** Nothing above the fold
  animates in before LCP (§0, §10). The LCP element (hero image / heading) is
  server-rendered and never waits on a client-only animation to become visible.
- **Server Components by default.** Reach for `"use client"` only where the
  component genuinely needs state/effects/handlers. A client island you add for
  a hover transition drags its whole subtree into the bundle — prefer a CSS
  `:hover`/`transition` on a Server Component, which costs **0 B**.
- **Route transitions (§3 "Route transitions"):** use the platform (view
  transitions / `@starting-style`) before a library. If a JS transition layer is
  added it is **route-scoped** and lazy — never imported into the root layout.
- **`loading.tsx` + skeletons** (`GridSkeleton` mirrors real columns, §0 KEEP)
  give SPA-like perceived speed while staying server-rendered. A skeleton that
  isn't the same shape as the content causes the CLS it was meant to prevent.
- **Data:** server-fetch where it benefits perf (§13, e.g. `GET
  /api/orders/{id}/` instead of the full list + `.find()`). Don't hold LCP behind
  a client `useEffect` fetch that a Server Component could do.
- **The §10 budget is the enforcement layer.** Per-route JS budget, image format
  + sizing strategy, font preload (`preload: false` unless it is the LCP font —
  the two preloads = 77,348 B are justified off the *total* font bytes, §10.4).
  The CSP is also a performance control (§10.5) — Razorpay loads at the payment
  step, never globally.

**The reconciliation, stated:** animation-heavy means *the accent moments are
executed well*, not *everything moves*. Heavily optimised means *nothing above
the fold animates before LCP, static HTML is server-rendered, and every JS
library is route-scoped and lazy*. Both are satisfied by the CSS-first ladder +
the LCP guard + the token-layer reduced-motion policy.

## Patterns and anti-patterns (condensed from the reference grammar)

**Do:** entrance reveal = translate ≤8–16px + fade (`enter`, ease-out); stagger
grouped items 40–80ms capped <400ms total; hover lift `translateY(-2px)` at
`hover` (no hover dependency on touch — resting state must be complete); press
`scale(0.97)` snap-back; overlay enter `scale(0.96→1)`+fade with focus
trap/restore; skeleton pulse/shimmer at `loading`.

**Don't:** everything animates on load; durations >500ms on routine UI; bounce
on every element; animating `box-shadow`/`filter`/`width`; motion with no
reduced-motion fallback; scroll-jacking that fights the user's scroll.

## Before you ship motion

1. Pick the intent token — never a raw ms value.
2. Confirm it answers P3 question 1 or 2, out loud. If neither, cut it.
3. Wrap scroll-driven work in `@media (prefers-reduced-motion: no-preference)`.
4. Transform + opacity only; no layout/paint properties per frame.
5. Nothing above the fold animates before LCP; LCP element is server-rendered.
6. Any JS library is route-scoped, lazy, KB-stated, inside the §11 budget.
7. Screenshot at rest and (if interactive) mid-state; confirm the resting state
   is complete without the motion.
