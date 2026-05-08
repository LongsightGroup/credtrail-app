# CredTrail Design Style Guide

This guide defines the visual system for CredTrail product surfaces (admin, public badges, auth, and LTI pages). Use it to keep the interface coherent as we add features.

## 1) Audience and UX Priorities

Primary audience: institution admins and LMS operators

- Need trust immediately (security, correctness, auditability).
- Need fast task completion (issue badge, verify state, fix errors).
- Need dense data with low cognitive load.

Secondary audience: learners and external verifiers

- Need clear credential legitimacy and easy sharing.
- Need confidence that links, JSON, and wallet actions are official.

Tertiary audience: institutional leadership/procurement

- Need confidence that the platform is modern, stable, and enterprise-ready.

Design consequence:

- Visual tone is "scholarly + operational": credible serif headlines, clean geometric sans UI, restrained but distinct Great Lakes palette.

## 2) Brand Language

- Voice: calm, precise, transparent.
- Shape language: rounded rectangles with medium radii; avoid harsh corners.
- Contrast: always prioritize readability over decorative color.
- Motion: subtle entrance and hover movement only where it improves comprehension.

## 3) Token Architecture

Use two layers of variables:

1. Raw palette tokens (`--ct-brand-*`) for fixed colors.
2. Semantic tokens (`--ct-theme-*`) for meaning and usage context.

Do not style components with raw palette tokens directly except in token definitions.

### 3.1 Raw Palette Tokens

- `--ct-brand-midnight-*`: trust, structure, heading weight.
- `--ct-brand-lake-*`: interactive/action family.
- `--ct-brand-sun-400`: limited accent highlight.
- `--ct-brand-mint-600`, `--ct-brand-amber-600`, `--ct-brand-rose-600`: success/warning/danger anchors.

### 3.2 Semantic Tokens

Text:

- `--ct-theme-text-title`
- `--ct-theme-text-body`
- `--ct-theme-text-muted`
- `--ct-theme-text-subtle`
- `--ct-theme-text-inverse`
- `--ct-theme-text-on-brand`

Surfaces:

- `--ct-theme-surface-canvas`
- `--ct-theme-surface-shell`
- `--ct-theme-surface-soft`
- `--ct-theme-surface-card`
- `--ct-theme-surface-card-strong`
- `--ct-theme-surface-info`
- `--ct-theme-surface-success`
- `--ct-theme-surface-warning`
- `--ct-theme-surface-danger`

Borders:

- `--ct-theme-border-soft`
- `--ct-theme-border-default`
- `--ct-theme-border-strong`
- `--ct-theme-border-focus`

Interaction and emphasis:

- `--ct-theme-link`
- `--ct-theme-link-hover`
- `--ct-theme-gradient-hero`
- `--ct-theme-gradient-action`
- `--ct-theme-gradient-action-hover`
- `--ct-theme-gradient-canvas`

State:

- `--ct-theme-state-success`
- `--ct-theme-state-warning`
- `--ct-theme-state-danger`

Elevation and motion:

- `--ct-theme-shadow-soft`
- `--ct-theme-shadow-card`
- `--ct-theme-shadow-shell`
- `--ct-theme-shadow-focus`
- `--ct-duration-fast`
- `--ct-duration-standard`
- `--ct-ease-standard`

## 4) Typography System

- Display/headings: `--ct-font-display` (`Newsreader`), used for page titles and major section headers.
- Body/UI text: `--ct-font-sans` (`Space Grotesk`), used everywhere else.
- Monospace: `--ct-font-mono` for JSON, IDs, and technical output.

Rules:

- Headings use display font with tight tracking (-0.02em).
- Dense operational tables/forms use sans for legibility.
- Admin page headers use restrained sizes: h1 at `clamp(1.25rem, 2.5vw, 1.6rem)`.
- Avoid mixing additional font families.
- Newsreader replaces the previous Fraunces pairing for stronger editorial authority without decorative softness.

## 5) Layout, Spacing, and Radius

- Spacing scale: `--ct-space-1` through `--ct-space-6`.
- Radius scale:
  - `--ct-radius-sm` for chips and compact controls
  - `--ct-radius-md` for inputs/buttons
  - `--ct-radius-lg` for cards/panels
  - `--ct-radius-xl` for shells/major containers
- Max content width: `--ct-max-content-width`.

Prefer shared primitives from `foundationCss`:

- `.ct-container`
- `.ct-stack`
- `.ct-cluster`
- `.ct-grid`
- `.ct-grid--sidebar`
- `.ct-card`

## 6) Accessibility and Interaction

- Minimum contrast:
  - body text >= WCAG AA on all surfaces
  - status text and badges must remain readable in color-blind scenarios
- Always show a focus indicator with `--ct-theme-shadow-focus`.
- Do not rely on color alone for status; include text labels (`Verified`, `Error`, etc.).
- Respect `prefers-reduced-motion`.

## 7) Implementation Rules

- Keep page-level CSS in `apps/api-worker/src/ui/page-assets/content/*`.
- Keep route handlers free from inline styles/scripts.
- Use semantic tokens first; keep legacy aliases (`--ct-color-*`, `--ct-surface-*`) only for migration.
- New CSS should avoid hard-coded hex values unless:
  - it is a one-off brand asset treatment, and
  - no semantic token fits.
- When introducing a new visual pattern, add/update tokens before duplicating raw values.

## 8) Migration Policy

Current codebase contains older hard-coded values in some page assets.

Migration sequence for each page:

1. Replace hard-coded colors with semantic tokens.
2. Replace custom spacing/radius values with scale tokens where possible.
3. Ensure shared theme variables still map correctly.
4. Capture before/after screenshots for visual regression review.

This keeps shipping velocity while converging on a cohesive design language.
