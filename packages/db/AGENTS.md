# packages/db

New database code belongs in a focused domain slice under `src/`, not inline in
`src/index.ts`.

Keep `src/index.ts` as the public barrel for `@credtrail/db`: re-export domain
modules from there so existing callers can continue importing from the package
root.

## Postgres integration tests

Some `src/*.test.ts` suites exercise real SQL against Postgres. They use
`describeDbIntegration` from `src/postgres-test-support.ts`, which **skips** when
`TEST_DATABASE_URL` is unset so `pnpm test` still passes locally without a database.

When running integration tests locally:

1. Start Postgres (see root `AGENTS.md` §5.1).
2. Migrate: `DATABASE_URL=postgres://credtrail:credtrail@127.0.0.1:5432/credtrail pnpm db:migrate:postgres`
3. Export `TEST_DATABASE_URL` (same URL as `DATABASE_URL` is fine).

Shared fixtures, seed helpers, and cleanup live in `postgres-test-support.ts`.
Integration tests share one Postgres pool for the Vitest worker; it is closed in
`afterAll` when `TEST_DATABASE_URL` is set.

Use `cleanupTestResources` in `finally` blocks to delete tenants, CredTrail
users, and Better Auth rows created during a test. Do not add per-fixture
`cleanup()` helpers.

Unit-only suites (migration file assertions, in-memory reporting rollups) use plain
`describe` and do not require Postgres.
