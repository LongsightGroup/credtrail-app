# AGENTS.md

This file defines execution standards for humans and coding agents working in this repository.

## 1) Product and Stack Guardrails

- Language: TypeScript everywhere.
- Runtime: Cloudflare Workers.
- Framework: Hono.
- Data: Postgres.
- Object storage: Cloudflare R2.
- Async jobs: DB-backed job messages in Postgres.
- UI: server-rendered HTML + htmx + Shoelace.
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

## 6) Simplicity Rules (K.I.S.S.)

- Prefer server-rendered pages and HTML forms over client-heavy abstractions.
- Use htmx for partial updates instead of introducing SPA complexity.
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
