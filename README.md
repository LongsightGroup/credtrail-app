# CredTrail App

Open-source Open Badges 3.0 platform built on Cloudflare Workers + Hono.

## App layout

- `apps/api-worker`: Primary Worker serving API + server-rendered UI.
- `packages/core-domain`: Shared domain models and helpers.
- `packages/db`: D1 query helpers, tenant scoping utilities, and DB-backed job queue storage.
- `packages/validation`: Zod schemas for HTTP and queue boundaries.
- `packages/lti`: LTI 1.3 parsing/validation primitives.
- `packages/ui-components`: Server-rendered HTML helper components.
- `docs`: Implementation docs.

## Async jobs

- Queue messages are stored in D1 table `job_queue_messages`.
- Use `POST /v1/jobs/process` to lease and process pending jobs.
- Hosted deployment can run the same processor via Cloudflare Cron scheduled events.

## Commands

Run from the workspace root:

- `pnpm check:public-docs`
- `pnpm lint`
- `pnpm typecheck`
- `pnpm test`

## Observability

- Structured logs are emitted as JSON and can be exported through Logpush configuration.
- Optional Sentry capture is enabled with `SENTRY_DSN`.
- See `docs/OBSERVABILITY.md`.
