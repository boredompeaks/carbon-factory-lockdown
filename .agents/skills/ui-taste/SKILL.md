---
name: ui-taste
description: Use when building or reviewing ANY UI on the spec-ui frontend — components, pages, layouts, copy, or visual polish. Loads the project's anti-slop doctrine (restrained-luxury perfume, P1-P5, tokens-only, screen economy) plus the borrowed GitHub taste rules, gated so they load only for visual work. Read before writing a single JSX/TSX/CSS line; re-read before any visual SHIP verdict.
---

# UI taste — anti-slop doctrine, tailored to this storefront

Taste makes a design *expensive*; tokens and a11y only make it *correct*. This
is the judgment layer. It is derived from the settled direction in
`frontend/docs/design/UI-UX-SPEC.md` §0/§1 and from the distilled GitHub
doctrines in `.opencode/ui-ref/xias/taste/` (read that folder for the full
138-design-system library and archetypes — this skill is the short, binding
version). When a system rule and a taste preference conflict, **the system rule
wins** (this is the same priority order the spec records: a11y > correctness >
taste).

## The two sentences this project actually is

- **Restrained-luxury base, theatrical motion as accent** (§0). Whitespace,
  hierarchy and one confident type pairing *are* the luxury. Noise reads cheap.
- **One accent moment per page; everything else is still** (§2 P2). A page that
  is 2% animated is noisier than one that is 0% animated.

## Decide before you generate (mandatory)

Slop comes from generating before deciding. For every page/screen/component,
state this block in your reply *before any markup*:

```
Domain:          luxury fragrance e-commerce (perfume storefront)
Audience & tone: premium buyer, calm + considered, NOT utilitarian-busy
Mood:            expensive, editorial, still — the one adjective it must earn
Motion depth:    subtle feedback (240ms hover) + at most ONE narrative accent
Layout family:   the section sequence, named, varied per section (see Variance)
Reference anchor: the 17 selected Stitch refs in the spec §0b (the SYSTEM, not content)
```

If you cannot name the mood and the layout family, you will regress to the mean
no matter how many gates pass.

## Break these deliberately (they are defects, not starting points)

| The slop default | Why it looks cheap here | The taste move |
|---|---|---|
| Three/four identical equal-weight cards | No focal point; reads generated | One leads on weight + content, rest go quieter. Density, not size. |
| Everything centered, or the same left-text/right-row repeated | Templated rhythm | Vary composition per section (Variance Mandate, below) |
| A heading that is just bold body text | Timid | Display type ≥2.5× body, short, on an 18–24ch measure |
| `#000` on `#fff` | Harsh, amateur | Use the KEEP palette: ink `#1c1917` on paper `#faf8f3` / surface `#fff` (spec §2.1). Off-black / warm-white is the luxury register. |
| A drop shadow on every box | Muddy, dated | Hairline `line`/`line-strong` + surface separation. Most surfaces are flat. |
| More than one accent colour | No discipline | **One accent moment per page.** Bronze is the accent; `bronze-light` is its on-ink form. Neutrals carry the weight. |
| Emoji anywhere in the UI | Loudest generated-UI tell; renders differently per platform | A real icon set as inline SVG with `currentColor`. Never emoji — including in JS that swaps a label. |
| "SECTION 01" / "FEATURE" / lorem / "Your headline here" | Fake structure | Real, specific microcopy or none. |
| Em-dashes in UI copy, "elevate / seamless / unlock / empower", triads ("powerful, intuitive, beautiful") | The top AI writing tells | Say the concrete benefit, shorter, specific. Read it aloud; if it sounds like a press release, rewrite. |
| A colored border on ONE side of a card/toast/callout | Generated-UI cliche in every direction | Full hairline border, or surface/elevation separation. Carry status with icon **+** text, never colour alone. |
| Cramped vertical rhythm | Dense, anxious | Section seam gap `--space-32` (128px desktop) / `--space-16` (64px phone); inside a section never > `--space-8`. The 4:1 ratio is the layout signature (§2 P1). |
| Native `<select>` | Draws its own chevron, cannot match the system | Button trigger + ARIA listbox/combobox, keyboard parity, `aria-expanded` that changes something visible. |

## Screen economy — every part of the screen earns its space (house rule, outranks archetypes)

Two senses, both binding:

- **Space.** First screen shows real content and a way to act. No single box or
  image swallows the viewport. No image wider than its container, ever. At
  390×844 the primary heading + at least one primary action are visible without
  scrolling.
- **Energy.** Large bright areas, heavy images and endless animation cost
  battery (OLED). Keep them small and rare. **Nothing animates forever**; no
  autoplaying background video unless it carries an explicit opt-out comment.

Full thresholds live in `.opencode/ui-ref/xias/taste/design-taste.md`
("Screen economy"). The spec's own hard caps: product-image media ≤60vh, total
image bytes under the §10 budget, skeleton shimmer ≤12 instances per page.

## Variance Mandate — never generate the same layout twice in a row

Before a multi-section page, pick a *layout sequence* that varies. Do not
repeat one section-archetype back-to-back:

- **Full-bleed hero** (bounded — see screen economy, ≤60vh media) · **Asymmetric
  split** (7/5 or 8/4, not 50/50) · **Bento grid** (mixed tile sizes, no empty
  dead cells) · **Editorial stack** (narrow prose measure, wide media) ·
  **Offset/overlap** (elements break the grid edge for depth) · **Full-width
  band** (resets rhythm) · **Index/list** (dense, typographic, for specs).

Rule of thumb: if two adjacent sections share column structure and alignment,
change one. But **vary composition, not vocabulary** — the materials (colour,
type, depth, motion tokens) stay constant across the whole page (Block
Coherence).

## Typography taste (tokens in §2.2)

- Display type is short and wide: tight line-height (1.05–1.15), never wraps to
  5+ lines. Extreme scale contrast (6xl/7xl over base) — timid contrast reads
  as a template.
- Body measure 60–75ch (`max-width: 65ch`). Long full-width lines are a
  readability and taste failure.
- One sans (Jakarta family) for all UI; the serif (Playfair) **only** for
  headings and money-adjacent display. Tabular figures for data; generous
  tracking + small size for overline/eyebrow labels.
- Nine-step named scale only (§2.2). Ad-hoc `text-8xl` / `[0.25em]` tracking is
  drift, banned (§0 CHANGE-10).

## Colour & depth taste

- Off-black, warm-white from the KEEP palette; `line` (1.23:1) is **decorative
  only** and must never become a control boundary; `line-strong` (4.62:1) is the
  non-text control floor (§2.1).
- Calibrated, not saturated: dial chroma down on large surfaces, reserve high
  saturation for small intentional highlights.
- Depth through layering + hairlines, not a shadow on most boxes. Radius
  language is **square (0px)** everywhere except the cart-count counter (the
  single strongest luxury signal — §2.3). Mixing radii looks accidental.

## Micro-interaction taste (see `ui-motion` for the full grammar)

- Every interactive element has hover + focus-visible + press states; presence
  of these states *is* the taste. Focus ring is `--focus #9c6a2e` + halo
  (§2.1 CHANGE-1) — never the retired `#8a5a24`.
- Motion has purpose; `ease-out` in, `ease-in` out. Always honour
  `prefers-reduced-motion`.

## Pre-flight aesthetic check (run before any visual SHIP)

1. No heading wraps past ~3 lines; display type wide + short, ≥2.5× body.
2. Adjacent sections do NOT share the same layout archetype.
3. Body text constrained to 60–75ch.
4. One accent moment per page; bronze is the accent; neutrals carry the rest.
5. Ink on paper/surface — no pure `#000`/`#fff`.
6. Section whitespace generous; spacing hierarchy outer > inner (4:1 seam ratio).
7. Depth from hairlines/surfaces, not a shadow on every box.
8. Grid has no empty dead cells; alignment exact.
9. All interactive elements have hover + focus + press.
10. **Zero emoji anywhere**; no filler labels; no invisible button text.
11. Reduced-motion fallback present (token-layer, not per-component).
12. Every value traces to a token — nothing hardcoded.

> Passing the objective gates (`ui-visual-qa`) is never evidence of taste. After
> the gates, screenshot it and argue against your own work: what would a critic
> reject first? The full critic rubric is in `.opencode/ui-ref/xias/` (the
> forked-`design-critic` pattern — review the *artifact*, never the argument).

## Where the borrowed GitHub material lives

`.opencode/ui-ref/` holds the distilled references this skill draws on:
- `xias/taste/design-taste.md` — full anti-slop + screen-economy doctrine
- `xias/taste/motion-choreography.md` — motion grammar (see `ui-motion`)
- `xias/taste/aesthetic-systems.md` — 138 named systems + archetypes
- `uupm/src/ui-ux-pro-max/data/` — search catalogs (styles, colours, fonts, motion)

Read those **only** when you need a specific archetype or a named reference —
they are reference material, not a checklist to load wholesale on every task.
