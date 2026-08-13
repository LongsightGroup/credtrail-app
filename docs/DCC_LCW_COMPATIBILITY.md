# DCC Learner Credential Wallet Compatibility Report

Last updated: 2026-02-25

## Scope

Compatibility validation for Digital Credentials Consortium (DCC) Learner Credential Wallet import and share flows against CredTrail public badge credentials.

## Flows Covered

### 1. OpenID4VCI offer generation

- Endpoint: `GET /credentials/v1/offers/:badgeIdentifier`
- Result: Compatible offer payload generated with pre-authorized code flow.
- Evidence:
  - `apps/api-worker/src/public-badge-page.test.ts`
  - test: `returns OpenID4VCI credential offer payload for canonical public badge identifier`

### 2. OpenID4VCI HTTP contract coverage

- Result: Automated tests cover issuer discovery, credential offers, pre-authorized token exchange,
  and credential retrieval through CredTrail's HTTP routes.
- Evidence: `apps/api-worker/src/public-badge-page.test.ts`
- Limitation: Wallet-SDK-specific compatibility requires manual validation and is not claimed by the
  automated suite.

### 3. DCC deep-link invitation payload

- Endpoint: `GET /credentials/v1/dcc/request/:badgeIdentifier`
- Result: Returns DCC-compatible invitation object with:
  - `credentialRequestOrigin`
  - `protocols.vcapi`
  - `https://lcw.app/request?request=...` deep link
  - `dccrequest://...` deep link alias
- Evidence:
  - `apps/api-worker/src/public-badge-page.test.ts`
  - test: `returns DCC wallet request payload with vcapi exchange URL and deep-link aliases`

### 4. DCC VC-API exchange offer

- Endpoint: `POST /credentials/v1/dcc/exchanges/:badgeIdentifier`
- Result: Returns VC-API offer payload with:
  - `verifiablePresentation`
  - `verifiableCredential` array containing issued credential
- Evidence:
  - `apps/api-worker/src/public-badge-page.test.ts`
  - test: `returns DCC VC-API exchange offer payload that wraps badge credential as a VP offer`

### 5. Verifiable Presentation creation and verification

- Endpoints:
  - `POST /v1/presentations/create`
  - `POST /v1/presentations/verify`
- Result: CredTrail supports VP generation/verification for wallet sharing workflows.
- Evidence:
  - `apps/api-worker/src/verifiable-presentation.test.ts`

## Compatibility Matrix

| Capability | Status | Notes |
|---|---|---|
| DCC invitation deep-link generation | Pass | `lcw.app` and `dccrequest://` aliases produced. |
| DCC VC-API exchange response | Pass | Returns VP offer with issued credential. |
| OpenID4VCI offer endpoint | Pass | Standards payload generated; QR/deep-link available on badge page. |
| OpenID4VCI token + credential exchange | Pass | Pre-authorized code flow covered by tests. |
| VP share/verify on CredTrail | Pass | Endpoints and tests in place. |

## Known Issues and Workarounds

- DCC import ecosystems vary by app version and enabled protocols.
- Recommended fallback order for learners:
  1. DCC-specific button (`Open in DCC Learner Wallet`) on the badge page.
  2. Generic OpenID4VCI wallet deep-link / QR flow.
  3. Direct `.jsonld` credential download/import.

## Operator Checklist

1. Confirm badge page renders both wallet buttons:
   - `Open in Wallet App`
   - `Open in DCC Learner Wallet`
2. Open `GET /credentials/v1/dcc/request/:badgeIdentifier` and verify `protocols.vcapi`.
3. Post `{}` to `POST /credentials/v1/dcc/exchanges/:badgeIdentifier` and verify returned `verifiablePresentation`.
4. Verify credential status via `GET /credentials/v1/:credentialId`.
