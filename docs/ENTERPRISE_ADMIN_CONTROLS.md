# Enterprise Admin Controls

This document covers the enterprise and programmatic controls added for `badging-wc8`:

- API key management for programmatic queue ingress
- Enterprise OIDC auth policy and provider management

## 1) Tenant API Keys (Programmatic Access)

Tenant admins (`owner`, `admin`) can create, list, and revoke API keys.

Endpoints:

- `GET /v1/tenants/:tenantId/api-keys`
- `POST /v1/tenants/:tenantId/api-keys`
- `POST /v1/tenants/:tenantId/api-keys/:apiKeyId/revoke`

Programmatic queue ingress endpoints require `x-api-key`:

- `POST /v1/programmatic/issue` (requires scope `queue.issue`)
- `POST /v1/programmatic/revoke` (requires scope `queue.revoke`)

Write-request contract:

- `idempotencyKey` is required on all programmatic write requests.
- Actor attribution is derived from the API key owner, not caller-supplied user IDs.

Key behavior:

- Plaintext key is returned only on create.
- Only key prefix and hash-derived metadata are stored.
- Last-used timestamp is updated on successful authenticated requests.
- Revoked/expired keys are rejected.

## 2) Enterprise OIDC Auth

Enterprise tenants configure hosted OIDC providers and auth policy through admin UI and API routes.

Endpoints:

- `GET /v1/tenants/:tenantId/auth-policy`
- `PUT /v1/tenants/:tenantId/auth-policy`
- `GET /v1/tenants/:tenantId/auth-providers`
- `POST /v1/tenants/:tenantId/auth-providers`
- `PUT /v1/tenants/:tenantId/auth-providers/:providerId`
- `DELETE /v1/tenants/:tenantId/auth-providers/:providerId`

Guardrails:

- Access requires tenant `owner` or `admin` role.
- Tenant plan must be `enterprise`.
- Hosted enterprise sign-in supports OIDC providers only.
