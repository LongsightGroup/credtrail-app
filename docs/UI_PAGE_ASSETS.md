# UI Page Assets

CredTrail server-rendered pages should keep route handlers focused on orchestration and move presentation assets (CSS/JS) into typed page asset modules.

Design baseline and token policy live in `docs/DESIGN_STYLE_GUIDE.md`.

## Goals

- Keep route files focused on auth, validation, and data loading.
- Keep page renderer modules focused on HTML structure + view model mapping.
- Serve CSS/JS from stable asset URLs with long-lived caching.

## Asset Registry

Page assets are registered in `apps/api-worker/src/ui/page-assets/build-registry.ts` and exposed through `apps/api-worker/src/ui/page-assets/index.tsx`.

- Every asset has:
  - `kind` (`style` or `script`)
  - `stem` (human-readable name)
- Style assets declare `sources`: an ordered list of `.css` file paths under `ui/page-assets/content/`, plus optional media groups that wrap nested source paths in `@media` blocks.
- Script assets declare `body`: the authored JavaScript source string.
- Public paths are content-hashed under `/assets/ui/*`.
- Asset responses are served with:
  - `Cache-Control: public, max-age=31536000, immutable`
  - explicit `Content-Type`
  - `X-Content-Type-Options: nosniff`

## Authoring CSS Sources

- Write page CSS as plain `.css` files in `apps/api-worker/src/ui/page-assets/content/`.
- Keep individual source files under 1000 lines; split large surfaces into focused files and list them in `build-registry.ts`.
- Use `assemble-style-asset.ts` as the single assembly implementation for both `pnpm build:page-assets` and test helpers.
- Resolve authored source paths through `page-asset-content.ts` (`PAGE_ASSET_CONTENT_DIR`, `readPageAssetContentFile`).
- Run `pnpm build:page-assets` after CSS edits so hashed public assets and `page-assets-manifest.ts` stay in sync.

## Usage

In page renderer modules, import and include asset tags in `renderPageShell(..., headContent)`:

- `renderPageAssetTags([...])`
- `pageStylesheetTag(...)`
- `pageScriptTag(...)`

Example pages using this pattern:

- Magic link login page
- Institution admin dashboard page
- LTI launch/deep-link/issuer pages

Shared foundation asset:

- `foundationCss` loads generated design tokens and layout utility classes:
  - `.ct-stack`
  - `.ct-cluster`
  - `.ct-grid`
  - `.ct-grid--sidebar`
  - `.ct-card`

Design-token source:

- Edit `design/tokens/credtrail.tokens.json` when a shared color, type, spacing, radius, motion, or elevation value changes.
- Run `pnpm build:design-tokens` after token edits. This regenerates:
  - `apps/api-worker/src/ui/page-assets/content/generated/design-tokens.css`
- Admin visual patterns are covered by the source-controlled page assets and component tests.
  It documents JSX page components, the Style Dictionary pipeline, token usage, admin action patterns, and table controls.

## Testing CSS Sources

- Use `readStyleAssetSource(assetKey)` from `page-asset-test-utils.ts` when a test needs the composed CSS for a registered style asset.
- Use `readStyleSourceFile("actions.css")` when a test targets one authored source file directly.
- Use `readGeneratedAsset(assetKey)` from `page-assets.test.ts` helpers when a test should assert against the built, hashed public asset output.

## Inline CSS/JS Policy

Avoid large inline `<style>` and `<script>` blocks.

Allowed inline content:

- Tiny, page-specific critical snippets (prefer < 10 lines)
- JSON context blobs for external scripts (e.g. `<script type="application/json">`)

Not allowed inline content:

- Full page stylesheets
- Large behavior scripts
- Reused styles/scripts duplicated across routes

Token/layout guidance:

- Prefer semantic page classes for page personality.
- Use semantic `--ct-theme-*` tokens for color, surface, border, state, and shadow roles.
- Prefer foundation tokens/utilities for spacing, radius, elevation, and layout primitives.
- Avoid introducing Tailwind-like utility sprawl; keep utilities few and predictable.

## Ownership

- Route handlers own request orchestration and security checks.
- Page renderers own HTML structure.
- `ui/page-assets` owns CSS/JS delivery and cache strategy.
