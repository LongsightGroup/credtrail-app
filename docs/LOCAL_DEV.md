# Local Development

CredTrail local development uses Wrangler, local Postgres, Wrangler R2
emulation, a deterministic demo seed, and Playwright for browser QA.

## First Run

From `credtrail-app`:

```bash
pnpm dev:up
```

This command:

1. Copies `wrangler.local.jsonc.example` to `wrangler.local.jsonc` if missing.
2. Copies `.dev.vars.local.example` to `.dev.vars.local` if missing.
3. Starts the Postgres-only `docker-compose.dev.yml` service.
4. Runs Postgres migrations.
5. Runs the full local demo seed.
6. Starts Wrangler on `http://127.0.0.1:8787`.

The command prints a JSON ready block with `baseUrl`, `tenantId`,
`adminLoginUrl`, and named demo routes.

## Daily Commands

```bash
pnpm dev:status
pnpm dev
pnpm dev:login-as
pnpm dev:seed
pnpm dev:reset
pnpm dev:demo
pnpm test:e2e
pnpm dev:down
```

- `dev:status` checks local Postgres and Wrangler, then prints the ready block.
- `dev` starts Wrangler watch mode after local files, migrations, and seed data
  already exist.
- `dev:login-as` prints the development-only Better Auth login URL for the
  seeded admin.
- `dev:seed` creates or refreshes the deterministic demo tenant.
- `dev:reset` deletes the seeded tenant data and reseeds it.
- `dev:demo` runs a headed Playwright browser workflow that creates a badge
  template and issues a badge through normal admin routes.
- `test:e2e` runs the same browser surface headlessly for regression coverage.
- `dev:down` stops the Postgres compose service.

## Seeded Demo Contract

Defaults:

| Item | Value |
| --- | --- |
| Tenant | `tenant_123` |
| Admin | `admin@credtrail.local` |
| Learner | `learner@example.edu` |
| Admin URL | `/tenants/tenant_123/admin` |
| Templates URL | `/tenants/tenant_123/admin/rules/templates` |
| Rules URL | `/tenants/tenant_123/admin/rules` |
| Manual issue URL | `/tenants/tenant_123/admin/operations/issue` |

The seed creates:

- The demo tenant, owner user, membership, and institution org unit.
- Four badge templates:
  - `Applied Analytics TrustEd Credential`, with complete TrustEd metadata.
  - `Workforce Readiness Credential`, with intentionally incomplete TrustEd
    metadata.
  - `Foundations Badge`, without TrustEd metadata.
  - `Capstone Badge`, without TrustEd metadata.
- One active seeded badge rule:
  `Local Demo: Applied Analytics Completion`.
- A learner profile for `learner@example.edu`.
- A DB row and local Wrangler R2 credential object for
  `/badges/trusted-demo-credential`.

The R2 object is written with `wrangler r2 object put --local --persist-to
.wrangler/state`, which is the same local persistence directory used by the
Wrangler dev runtime. Set `CREDTRAIL_DEV_SEED_R2=false` only when you want to
seed database rows without touching local R2.

## Browser QA

All local browser automation uses:

```text
/v1/dev/auth/login-as
```

That route is gated to `APP_ENV=development` and creates a real Better Auth
session cookie for seeded tenant members.

Playwright files live in:

```text
playwright.config.mjs
tests/e2e/
```

Artifacts go under `output/`, which is gitignored.
