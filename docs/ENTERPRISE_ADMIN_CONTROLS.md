# Enterprise Admin Controls

This document covers the enterprise and programmatic controls added for `badging-wc8`:

- API key management for programmatic queue ingress
- Enterprise SAML SSO configuration storage
- Dedicated database provisioning request workflow

## 1) Tenant API Keys (Programmatic Access)

Tenant admins (`owner`, `admin`) can create, list, and revoke API keys.

Endpoints:

- `GET /v1/tenants/:tenantId/api-keys`
- `POST /v1/tenants/:tenantId/api-keys`
- `POST /v1/tenants/:tenantId/api-keys/:apiKeyId/revoke`

Programmatic queue ingress endpoints require `x-api-key`:

- `POST /v1/programmatic/issue` (requires scope `queue.issue`)
- `POST /v1/programmatic/revoke` (requires scope `queue.revoke`)

Key behavior:

- Plaintext key is returned only on create.
- Only key prefix and hash-derived metadata are stored.
- Last-used timestamp is updated on successful authenticated requests.
- Revoked/expired keys are rejected.

## 2) Enterprise SAML SSO Configuration

Tenant admins can read, write, and delete SAML IdP config for enterprise tenants.

Endpoints:

- `GET /v1/tenants/:tenantId/sso/saml`
- `PUT /v1/tenants/:tenantId/sso/saml`
- `DELETE /v1/tenants/:tenantId/sso/saml`

Guardrails:

- Access requires tenant `owner` or `admin` role.
- Tenant plan must be `enterprise`.

Stored fields include IdP entity ID, login URL, certificate PEM, optional metadata URL,
SP entity ID, ACS URL, NameID format, and enforcement flag.

## 3) Dedicated DB Provisioning Workflow

Bootstrap admin endpoints track dedicated DB provisioning workflows for enterprise tenants.

Endpoints:

- `GET /v1/admin/tenants/:tenantId/dedicated-db/provisioning-requests`
- `POST /v1/admin/tenants/:tenantId/dedicated-db/provisioning-requests`
- `POST /v1/admin/tenants/:tenantId/dedicated-db/provisioning-requests/:requestId/resolve`

Workflow:

- Create request with target region and optional notes.
- Resolve with status (`provisioned`, `failed`, `canceled`) and optional DB URL.
- Requests are auditable through `audit_logs` actions.
