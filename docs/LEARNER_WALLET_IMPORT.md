# Learner Wallet Import and Sharing

CredTrail public badge pages now expose wallet-friendly import options for already issued Open Badges 3.0 credentials.

Public docs mirror: `https://credtrail.org/docs/wallet-import/`

## Import Options

From a public badge page (`/badges/:badgeIdentifier`), learners can:

- Scan an **OpenID4VCI credential-offer QR code**
- Open a wallet app through an **`openid-credential-offer://` deep link**
- Open **DCC Learner Credential Wallet** through a `https://lcw.app/request` deep link
- Open the raw **OpenID4VCI offer JSON** endpoint
- Download the credential as **`.jsonld`** for manual wallet import
- Trigger **browser wallet import (CHAPI-style)** from the page when supported

## Endpoints

- Public badge page: `/badges/:badgeIdentifier`
- OpenID4VCI issuer metadata: `/.well-known/openid-credential-issuer`
- Offer creation endpoint: `POST /credentials/offer`
- OpenID4VCI offer endpoint: `/credentials/v1/offers/:badgeIdentifier`
- OpenID4VCI token endpoint: `POST /credentials/v1/token` (alias: `POST /token`)
- OpenID4VCI credential endpoint: `POST /credentials/v1/credentials` (alias: `POST /credentials`)
- DCC wallet invitation endpoint: `GET /credentials/v1/dcc/request/:badgeIdentifier`
- DCC VC-API exchange endpoint: `POST /credentials/v1/dcc/exchanges/:badgeIdentifier` (alias: `GET` for inspection)
- Credential JSON-LD: `/credentials/v1/:credentialId/jsonld`
- Credential attachment download (`.jsonld` filename): `/credentials/v1/:credentialId/download`

The offer endpoint includes:

- `credential_issuer`
- `credential_configuration_ids`
- `grants` (`pre-authorized_code`)
- `credentials` metadata (`ldp_vc`, `OpenBadgeCredential`)
- `x_credtrail` URLs for direct JSON-LD/download/verification/public badge access
- `x_credtrail.offer_expires_at` for offer timeout visibility

Offer security behavior:

- Pre-authorized codes are **single-use**
- Pre-authorized codes expire after **10 minutes**
- OID4VCI access tokens expire after **10 minutes**

## DCC Learner Credential Wallet compatibility

CredTrail supports DCC wallet ingestion with a VC-API invitation flow in addition to OpenID4VCI:

1. Badge page generates a DCC deep link (`https://lcw.app/request?request=...`) containing a `protocols.vcapi` exchange URL.
2. DCC wallet calls `POST /credentials/v1/dcc/exchanges/:badgeIdentifier`.
3. CredTrail responds with a VC-API offer payload containing a `verifiablePresentation` wrapper with the issued credential.
4. DCC wallet extracts and stores the credential.

Automated compatibility evidence is covered in:

- `apps/api-worker/src/public-badge-page.test.ts`
  - `returns DCC wallet request payload with vcapi exchange URL and deep-link aliases`
  - `returns DCC VC-API exchange offer payload that wraps badge credential as a VP offer`

## Sharing with Verifiable Presentations

After import, learners can share credentials from their wallet directly to verifiers. CredTrail also exposes VP APIs:

- `POST /v1/presentations/create`
- `POST /v1/presentations/verify`

See `docs/VERIFIABLE_PRESENTATIONS.md` for request/response details.

## Wallet Validation Checklist

Use this checklist for manual interoperability validation with major wallets:

1. Open badge page and scan wallet QR code.
2. Confirm wallet receives `credential_offer_uri` and resolves the offer endpoint.
3. Confirm wallet can import using `.jsonld` fallback if offer flow is not fully supported.
4. Confirm imported credential can be shared as a VP.
5. Confirm verifier receives VP and verification passes.

Target wallets for manual validation:

- Learning Wallet
- Velocity Network-compatible wallet

## Interoperability Validation Evidence

Date: 2026-02-25

Automated coverage validates CredTrail's OpenID4VCI discovery, offer, token, and credential
HTTP contracts. Wallet-specific compatibility remains a manual validation step against the target
wallets listed above.

Validation test: `apps/api-worker/src/public-badge-page.test.ts`

What is asserted:

1. Wallet deep link format: `openid-credential-offer://?credential_offer_uri=...`
2. Offer endpoint resolution over HTTP
3. Credential offer fields required by the CredTrail contract:
   - `credential_issuer`
   - `credential_configuration_ids` includes `OpenBadgeCredential`
   - `grants` pre-authorized code payload
   - `credentials` includes `ldp_vc`
