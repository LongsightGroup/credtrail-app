# CredTrail App

Open-source Open Badges 3.0 platform with Cloudflare SaaS and Docker self-host runtime profiles.

**Standards-compliant verifiable credential issuance and verification for educational achievements.**

## What Can CredTrail Do?

### ✅ Core Badge Management
- **Badge template creation** - Define reusable badge designs with achievement criteria, images, and metadata
- **Manual badge issuance** - Issue badges to individual learners with signed verifiable credentials
- **Cryptographic signing** - Ed25519-based credential signing with `did:web` issuer identities
- **Immutable storage** - Store signed credentials as `.jsonld` files in object storage (R2/S3)
- **Badge revocation** - Revoke credentials with BitstringStatusList status tracking
- **Email notifications** - Automatic learner notifications on badge issuance

### ✅ Learner Experience
- **Learner dashboard** - View all earned badges in one place
- **Public badge pages** - Shareable URLs for each credential with verification indicators
- **Badge sharing** - Copy URL, download VC JSON, add to LinkedIn profile directly
- **Account linking** - Link institutional identities with email fallback for post-graduation access
- **Identity recovery** - Maintain badge access after institutional email loss
- **Multiple identities** - Support for learner identity aliases across institutions
- **Learner DID settings** - Optional `did:key`, `did:web`, or `did:ion` subject IDs for privacy-preserving issuance

### ✅ Verification & Standards Compliance
- **Public verification API** - `/credentials/v1/{id}` endpoint for third-party verification
- **Open Badges 3.0** - Full OB3 spec compliance with W3C Verifiable Credentials Data Model 2.0
- **IMS Global validator** - Deep-links to official IMS validator on badge pages
- **Proof formats** - Support for both VC-JWT and JSON-LD embedded proofs (EdDSA)
- **Verifiable Presentations** - VP create/verify APIs for holder-bound credential sharing
- **DID documents** - Serve `did:web` documents for issuer public key discovery
- **Canonical URLs** - OB3 JSON discovery links on public pages
- **Achievement metadata** - Rich achievement descriptions with evidence links

### ✅ Authentication & Access Control
- **Hosted authentication** - Better Auth-backed passwordless email login through CredTrail wrapper routes
- **Institutional SSO integration** - Better Auth-backed institutional sign-in with learner identity linking
- **Multi-tenant RBAC** - Tenant-scoped roles: owner, admin, issuer
- **Session management** - Better Auth sessions with tenant-scoped authorization and secure cookie handling
- **Guided onboarding** - New tenant setup flow with first badge template and issuance walkthrough

### ✅ Open Badges 3.0 API Compliance
- **OAuth 2.0 flows** - Authorization Code Grant with Dynamic Client Registration
- **PKCE enforcement** - S256 code challenge method required
- **Service discovery** - `/.well-known/openid-credential-issuer` endpoint with OpenAPI documentation
- **Secure REST endpoints** - `/ims/ob/v3p0/credentials` and `/ims/ob/v3p0/profile` with scoped authorization
- **Token management** - Refresh token rotation and revocation endpoints
- **Content negotiation** - Accept both VC-JWT and JSON-LD formats
- **Credential upsert** - Update existing credentials while maintaining immutability

### ✅ Governance & Compliance
- **Audit logging** - Immutable logs for issuance, revocation, and role changes
- **Tenant isolation** - Strict data separation between organizations
- **Type safety** - Full TypeScript with strict mode enabled
- **Input validation** - Zod schemas at all HTTP and queue boundaries

### ✅ Infrastructure & Operations
- **Database-backed queues** - Simple Postgres table for async jobs (issue_badge, revoke_badge)
- **Monorepo structure** - Turborepo-based workspace with shared packages
- **CI/CD pipeline** - Automated linting, type checking, and testing
- **Observability** - Structured JSON logging with Logpush export
- **Runtime profiles** - Cloudflare Workers (SaaS) and Node + Docker (self-host)

## App layout

- `apps/api-worker`: Primary Worker serving API + server-rendered Hono JSX UI.
- `packages/core-domain`: Shared domain models, VC signing, and cryptographic helpers.
- `packages/db`: Postgres query helpers, tenant scoping utilities, and DB-backed job queue storage.
- `packages/validation`: Zod schemas for HTTP and queue boundaries.
- `packages/lti`: LTI 1.3 parsing/validation primitives.
- `packages/ui-components`: Shared Hono JSX page layout components.
- `docs`: Implementation docs and ADRs (including `docs/LEARNER_DID_SETUP.md`, `docs/LEARNER_WALLET_IMPORT.md`, `docs/DCC_LCW_COMPATIBILITY.md`, `docs/VERIFIABLE_PRESENTATIONS.md`, and `docs/LMS_INDEPENDENCE_MIGRATION_RUNBOOK.md`).

### API worker module layout (`apps/api-worker/src`)

- `app.ts`: Composition root only (dependency wiring + route registration).
- `routes/`: Route handlers by feature area.
- `auth/`: Tenant/session permission helpers.
- `badges/`: Issuance flow, public badge rendering/view models, revocation helpers.
- `credentials/`: Verification checks and proof verification helpers.
- `signing/`: Signing key/registry resolution, DID/JWKS docs, credential signer helpers.
- `ob3/`: Open Badges 3.0 OAuth/discovery/access-token helpers.
- `http/`: Common middleware and shared HTTP utility helpers.
- `queue/`: Queue job payload/building/processing/scheduled trigger helpers.

### Server-rendered UI

- Server-rendered app pages are authored in Hono JSX (`.tsx`) and rendered through
  `appPage` / `renderAppPage` from `apps/api-worker/src/ui/render-page.tsx`.
- Page modules return `AppPage`; route handlers render them with
  `renderAppPage(c, page, status?)`.
- Use page asset keys and `PageAssets` for CSS and feature-local JavaScript. CSS
  and client script source strings live under `apps/api-worker/src/ui/page-assets/content`.
- Do not add React, Kiwa, Tailwind, client components, hydration, `hono/html`,
  `raw()`, `dangerouslySetInnerHTML`, or interpolated full-document HTML strings.
- JSX owns text and attribute escaping for page markup. Validate boundary input
  with Zod and keep manual HTML escaping out of page modules.

## Async jobs

- Queue messages are stored in Postgres table `job_queue_messages`.
- Use `POST /v1/jobs/process` to lease and process pending jobs.
- Hosted deployment can run the same processor via Cloudflare Cron scheduled events.
- Self-host deployment can run the queue polling worker process in Docker.
- Jobs: `issue_badge`, `revoke_badge`, `rebuild_verification_cache`, `import_migration_batch`

## Commands

Run from the workspace root:

- `pnpm export:ob3-openapi`
- `pnpm check:ob3-openapi`
- `pnpm build:design-tokens`
- `pnpm check:design-tokens`
- `pnpm lint`
- `pnpm lint:fix`
- `pnpm format`
- `pnpm format:check`
- `pnpm typecheck`
- `pnpm test`
- `pnpm check`

OB3 OpenAPI snapshot file: `docs/openapi/ims-ob-v3p0.openapi.json`

## Self-host Docker

- Build image: `docker build -t credtrail-app:local .`
- Run reference stack: `docker compose -f docker-compose.selfhost.yml up --build`
- Runbook: `docs/SELF_HOST_DOCKER_RUNBOOK.md`

## Observability

- Structured logs are emitted as JSON and can be exported through Logpush configuration.
