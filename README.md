# CredTrail App

Open-source Open Badges 3.0 platform built on Cloudflare Workers + Hono.

**Standards-compliant verifiable credential issuance and verification for educational achievements.**

## What Can CredTrail Do?

### ✅ Core Badge Management
- **Badge template creation** - Define reusable badge designs with achievement criteria, images, and metadata
- **Manual badge issuance** - Issue badges to individual learners with signed verifiable credentials
- **Cryptographic signing** - Ed25519-based credential signing with `did:web` issuer identities
- **Immutable storage** - Store signed credentials as `.jsonld` files in R2 object storage
- **Badge revocation** - Revoke credentials with BitstringStatusList status tracking
- **Email notifications** - Automatic learner notifications on badge issuance

### ✅ Learner Experience
- **Learner dashboard** - View all earned badges in one place
- **Public badge pages** - Shareable URLs for each credential with verification indicators
- **Badge sharing** - Copy URL, download VC JSON, add to LinkedIn profile directly
- **Account linking** - Link institutional identities with email fallback for post-graduation access
- **Identity recovery** - Maintain badge access after institutional email loss
- **Multiple identities** - Support for learner identity aliases across institutions

### ✅ Verification & Standards Compliance
- **Public verification API** - `/credentials/v1/{id}` endpoint for third-party verification
- **Open Badges 3.0** - Full OB3 spec compliance with W3C Verifiable Credentials Data Model 2.0
- **IMS Global validator** - Deep-links to official IMS validator on badge pages
- **Proof formats** - Support for both VC-JWT and JSON-LD embedded proofs (EdDSA)
- **DID documents** - Serve `did:web` documents for issuer public key discovery
- **Canonical URLs** - OB3 JSON discovery links on public pages
- **Achievement metadata** - Rich achievement descriptions with evidence links

### ✅ Authentication & Access Control
- **Magic link authentication** - Passwordless email-based login
- **SAML SSO integration** - SAML-first learner identity linking for institutional deployments
- **Multi-tenant RBAC** - Tenant-scoped roles: owner, admin, issuer
- **Session management** - Server-side sessions with secure cookie handling
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
- **Observability** - Structured JSON logging with Sentry error tracking and Logpush export
- **Worker architecture** - Cloudflare Workers runtime with edge deployment

## App layout

- `apps/api-worker`: Primary Worker serving API + server-rendered UI.
- `packages/core-domain`: Shared domain models, VC signing, and cryptographic helpers.
- `packages/db`: Postgres query helpers, tenant scoping utilities, and DB-backed job queue storage.
- `packages/validation`: Zod schemas for HTTP and queue boundaries.
- `packages/lti`: LTI 1.3 parsing/validation primitives.
- `packages/ui-components`: Server-rendered HTML helper components.
- `docs`: Implementation docs and ADRs.

## Async jobs

- Queue messages are stored in Postgres table `job_queue_messages`.
- Use `POST /v1/jobs/process` to lease and process pending jobs.
- Hosted deployment can run the same processor via Cloudflare Cron scheduled events.
- Jobs: `issue_badge`, `revoke_badge`, `rebuild_verification_cache`, `import_migration_batch`

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
