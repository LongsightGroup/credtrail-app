# AGENTS.md

This file defines execution standards for humans and coding agents working in this repository.

## 1) Product and Stack Guardrails

- Language: TypeScript everywhere.
- Runtime: Cloudflare Workers.
- Framework: Hono.
- Data: Postgres.
- Object storage: Cloudflare R2.
- Async jobs: DB-backed job messages in Postgres.
- UI: server-rendered Hono JSX (`.tsx`) with htmx-compatible markup and minimal
  feature-local JavaScript.
- React is out of scope for v1.
- Standards scope: Open Badges 3.0 only.
- Architecture policy: single-path implementation in v1. No dual runtimes, no parallel frameworks, no "either/or" code paths for the same capability.

If a proposed change conflicts with these guardrails, open an ADR before implementation.

## 1.1) `apps/api-worker/src` Ownership Boundaries

Keep file ownership explicit so `app.ts` does not grow into a monolith again.

- `app.ts` is the composition root only:
- wire dependencies/factories
- register routes
- export the worker
- avoid embedding feature/business logic here
- `routes/`: HTTP endpoint handlers and request/response shaping.
- `auth/`: tenant/session/permission guard helpers.
- `badges/`: badge issuance, public badge page/view models, revocation metadata, recipient identifier logic.
- `credentials/`: credential verification checks and proof verification logic.
- `signing/`: signing key material, signing registries, DID/JWKS docs, credential signing helpers.
- `ob3/`: Open Badges 3.0 OAuth/discovery/auth helpers and error response shaping.
- `http/`: generic transport concerns shared across routes (middleware, shared request helpers).
- `queue/`: queue payload parsing, processing orchestration, and schedule-trigger utilities.
- `lti/`, `learner/`, `presentation/`, `notifications/`: domain-focused helpers per capability.

Refactor rule of thumb:
- if new behavior needs more than a small helper in `app.ts`, create/extend a feature module and inject it from `app.ts` rather than implementing inline.

## 1.2) Server-rendered UI Rules

- Author server-rendered app pages in Hono JSX using `hono/jsx` and the renderer
  in `apps/api-worker/src/ui/render-page.tsx`.
- Page modules return `AppPage` via `appPage`; route handlers render with
  `renderAppPage(c, page, status?)`.
- Use JSX asset components and page asset keys for CSS and feature-local
  JavaScript. CSS and client script source strings are asset payloads, not server
  page templates.
- Do not introduce React, Kiwa, Tailwind, client components, hydration,
  `hono/html`, `raw()`, `dangerouslySetInnerHTML`, or interpolated
  full-document HTML strings.
- Let JSX own text and attribute escaping for page markup. Keep `escapeHtml` out
  of page modules.
- Preserve route paths, form field names, element IDs, `data-*` attributes,
  asset URLs, cache headers, and visible copy unless a deliberate product change
  requires otherwise.

## 2) TypeScript Quality Bar (Non-Negotiable)

Use a strict TypeScript config and keep it green at all times.

Required compiler behavior:
- `strict: true`
- `noImplicitAny: true`
- `exactOptionalPropertyTypes: true`
- `noUncheckedIndexedAccess: true`
- `noImplicitOverride: true`
- `useUnknownInCatchVariables: true`
- `noFallthroughCasesInSwitch: true`

Rules:
- Do not use `any` in application code.
- Use `unknown` at boundaries and narrow explicitly.
- Keep domain types explicit and reusable.
- All exported functions must have explicit parameter and return types.
- Model untrusted input with runtime schemas and inferred TS types.

## 3) Validation Rules

- Validate all external input using Zod:
- HTTP bodies
- query/path params
- queue messages
- webhooks
- migration/import payloads
- Treat schema as the source of truth for boundary types.

## 4) Linting, Formatting, and Spacing

- ESLint must run with type-aware rules (`typescript-eslint` strict type-checked presets).
- Prettier is the single formatter.
- Lint rule severity target: zero warnings and zero errors in CI.

Style defaults:
- 2-space indentation.
- Semicolons enabled.
- Trailing commas where valid.
- Single quotes in TypeScript unless escaping hurts readability.
- Keep lines readable (target 100 chars, split long chains/objects).
- No unused imports or variables.
- No floating promises.

## 5) Testing and CI Gates

Every change must pass:
- `pnpm lint`
- `pnpm typecheck`
- `pnpm test`

Type safety is a release gate:
- `tsc --noEmit` must pass.

## 5.1) Local Dev and Browser QA

Preferred local app runtime for manual QA is Wrangler local with local Postgres
and local Wrangler R2 emulation.

Local-only files:
- `wrangler.local.jsonc` is intentionally gitignored. It should define the local
  Worker entrypoint, `BADGE_OBJECTS` R2 binding, `APP_ENV=development`,
  `PLATFORM_DOMAIN=localhost`, `JOB_PROCESSOR_TOKEN`, `BOOTSTRAP_ADMIN_TOKEN`,
  and a `HYPERDRIVE` binding with `localConnectionString` pointing at local
  Postgres. Start from `wrangler.local.jsonc.example`, and keep the Hyperdrive
  `id` as a local placeholder unless testing a deployed Hyperdrive config.
- `.dev.vars.local` is intentionally gitignored. It should contain local secrets
  for scripts and fallback DB access, such as:
  `DATABASE_URL=postgres://credtrail:credtrail@127.0.0.1:5432/credtrail`

Local database setup:
- Ensure Postgres is listening on `127.0.0.1:5432`.
- For a fresh local machine, create the local role/database if needed:
  `CREATE ROLE credtrail LOGIN PASSWORD 'credtrail';`
  `CREATE DATABASE credtrail OWNER credtrail;`
- Run migrations with:
  `DATABASE_URL=postgres://credtrail:credtrail@127.0.0.1:5432/credtrail pnpm db:migrate:postgres`

Run the app locally:
- Start Wrangler with:
  `pnpm exec wrangler dev --config wrangler.local.jsonc --env-file .dev.vars.local --port 8787`
- If port `8787` is occupied by an old `workerd`, either stop that process or use
  a different port and set `CREDTRAIL_DEV_BASE_URL` accordingly.

Seed local demo data:
- Run `pnpm dev:seed` after migrations.
- The seed creates a local institution tenant, owner user, membership, org unit,
  and badge templates for manual admin QA.
- Default seeded login identity:
  `admin@credtrail.local`
- Default seeded tenant:
  `tenant_123`

Local development login:
- Do not add production auth bypasses.
- In `APP_ENV=development`, `/v1/auth/magic-link/request` returns a
  `magicLinkUrl` in the JSON response. This is the intended local-dev shortcut.
- Do not define an `EMAIL` binding in local Wrangler config while debugging
  magic-link login. Development magic-link requests capture the URL and skip
  email delivery.
- With Wrangler running, use `pnpm dev:login-link` to print a browser-ready
  local login URL for the seeded admin user.
- Open the printed URL in a browser to establish the Better Auth session, then
  continue manual QA at `/tenants/tenant_123/admin`.

Browser/e2e notes:
- Playwright defaults to `E2E_BASE_URL=http://127.0.0.1:8787`.
- Real LMS tests use `E2E_BOOTSTRAP_ADMIN_TOKEN` and bootstrap admin APIs; they
  do not establish a reusable browser login state by default.
- For local manual QA, prefer the seeded magic-link workflow above over adding
  ad hoc cookies or direct session table writes.

## 6) Simplicity Rules (K.I.S.S.)

- Prefer server-rendered Hono JSX pages and HTML forms over client-heavy
  abstractions.
- Prefer plain HTML forms, htmx-compatible markup, and small feature-local
  scripts over SPA complexity.
- Keep client JavaScript minimal and local to the feature.
- Choose straightforward code over clever code.
- Implement one clear way to do each thing in v1; defer alternatives.

## 7) Tenancy and Data Safety

- All tenants use shared Postgres with strict tenant isolation in v1.
- Do not bypass tenant scoping in queries.
- Use idempotency keys for issuance and revocation operations.

## 8) Commit and Review Checklist

Before submitting:
- Confirm architecture guardrails are unchanged.
- Confirm no `any` was introduced.
- Confirm lint, typecheck, and tests pass.
- Confirm formatting is clean and consistent.
- Confirm no dead code, TODO noise, or debug logs remain.

## 9) Source of Truth

- Architecture decisions: `docs/adr/`
- This file: implementation discipline and quality standards
