# Orbis Brand Guide

Working identity for the Orbis security visibility and remediation platform.
The rule of the whole system: **one accent, semantic severity colors for data only, no gradients, no glows.**

## Positioning

Professional infrastructure tooling. Orbis should read like it belongs next to the tools it orchestrates (nmap, trivy, semgrep), not like a consumer app. Calm surfaces, strong typography, mono for anything a machine said.

The name is a working codename pending trademark and package clearance.

## Logo

Geometric orbit mark: a center circle (the environment), a tilted orbital ring (visibility over everything in it), and a solid dot on the ring (the asset under watch).

- Stroke-based, 2px at 32px viewBox, round joins
- Ring uses ink, center circle and satellite dot use the accent
- Wordmark: system sans, weight 650-680, tracking -0.015em, always "Orbis" with a capital O
- Clear space: half the mark's width on all sides. Minimum size 20px
- Files: `assets/logo.svg` (theme-aware, uses CSS variables), `assets/favicon.svg` (fixed dark tile)

## Color

### Light mode (default)

| Token | Hex | Use |
|---|---|---|
| Background | `#F7F8F7` | Page |
| Surface | `#FFFFFF` | Cards, tiles |
| Surface 2 | `#EEF1EF` | Inset areas |
| Band | `#EDF2EF` | Closing CTA band |
| Ink | `#16201E` | Headings |
| Ink 2 | `#43504B` | Body text |
| Ink 3 | `#6B7773` | Captions, metadata |
| Line | `#DFE5E2` | Hairlines, borders |
| Accent | `#0B6B57` | Primary actions, links |
| Accent hover | `#095A49` | Pressed/hover state |
| Accent soft | `#E3EFEA` | Icon chips, selection |
| On accent | `#FFFFFF` | Text on accent |

### Dark mode (`prefers-color-scheme: dark`)

| Token | Hex | Use |
|---|---|---|
| Background | `#0D1110` | Page |
| Surface | `#131917` | Cards, tiles |
| Band | `#101715` | Closing CTA band |
| Ink | `#E8EEEB` | Headings |
| Ink 2 | `#A9B6B1` | Body text |
| Ink 3 | `#7E8C87` | Captions, metadata |
| Line | `#26302C` | Hairlines, borders |
| Accent | `#3EC99B` | Primary actions, links |
| Accent hover | `#55D6AC` | Hover state |
| Accent soft | `#14261F` | Icon chips, selection |
| On accent | `#06231A` | Text on accent (dark text on bright emerald) |

### Accent rationale

Signal emerald. Green is the color of "verified, secure, passing" in every ops tool engineers already live in (CI checks, status pages, TLS padslocks). It ties the brand to the Verify step of the loop. Desaturated and deep enough to sit calmly next to ink, never neon.

### Semantic severity (data only)

These colors appear **only** on real findings data: terminal output, risk verdicts, diff lines, status badges. They are never decorative.

| Severity | Light | Dark / terminal |
|---|---|---|
| Critical | `#BC3A22` | `#ED6A4D` |
| High | `#B35B12` | `#E1913C` |
| Medium | `#8F750F` | `#CBB35A` |
| OK / resolved | `#0B6B57` | `#5BC493` |

Diff convention: removed lines `#ED6A4D` tint, added lines `#57C79A` tint, both at 12% opacity backgrounds.

### Terminal palette (fixed, always dark)

Terminals and code panels are always dark regardless of theme: that is what a terminal looks like, and it keeps severity hues stable.

| Token | Hex |
|---|---|
| Terminal bg | `#0E1312` |
| Terminal surface | `#121917` |
| Terminal line | `#232D29` |
| Terminal text | `#DCE5E2` |
| Terminal dim | `#7C8A85` |
| Prompt / accent | `#52CFA2` |

## Typography

System stacks, zero webfont dependencies. Self-hosting a variable sans (Geist, Satoshi, or Söhne) is a valid upgrade later; if you do, keep the mono stack.

- Sans: `"Segoe UI Variable Text", "Segoe UI", -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif`
- Mono: `ui-monospace, "Cascadia Code", Consolas, "JetBrains Mono", "SF Mono", Menlo, monospace`

| Role | Size | Weight | Tracking |
|---|---|---|---|
| H1 | clamp(2.5rem, 5vw, 3.85rem) | 680 | -0.032em |
| H2 | clamp(1.75rem, 3.2vw, 2.4rem) | 650 | -0.022em |
| H3 / card title | 1.01rem | 650 | -0.01em |
| Body | 1.06rem | 400 | normal |
| Metadata / kicker | 0.78rem mono | 600-700 | +0.10-0.14em, uppercase |

Mono is for anything a machine produced: commands, findings, config, IDs, formulas.

## Shape

One radius system, no mixing:

- Controls (buttons, inputs, small icon chips): 8px
- Cards, tiles, path nodes: 12px
- Large panels (terminal, diff, risk cards): 16px
- Command chips and status pills: fully rounded

## Iconography

- Library: Phosphor (`@phosphor-icons/web`), regular weight for inline glyphs, bold for directional arrows
- One family only, no mixing with other sets
- Sizes: 20-22px inline, 36-44px in circles
- Icon chips sit on `accent-soft` with `accent-ink` glyphs, or hairline-bordered circles over white

## Motion

- One-time, purposeful: terminal lines cascade in once on load (it simulates a scan), sections fade up 14px as they enter view
- Hover and active states only elsewhere; buttons press down 2% on `:active`
- Everything collapses to static under `prefers-reduced-motion: reduce`
- No infinite loops, no parallax, no scroll hijacking

## Do not

- No gradients anywhere, especially purple-to-blue. Surfaces are flat with hairlines.
- No glows, outer shadows on text, or neon accents
- No severity colors on non-data UI (never a red button, never an amber decorative dot)
- No pure `#000000` or `#FFFFFF`; use the ink and surface tokens
- No mixing warm and cool grays; every neutral here carries a slight green undertone to match the accent
