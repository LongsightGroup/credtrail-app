# OB3 Verification Notes

This document describes how `GET /credentials/v1/:credentialId` verifies Open Badges 3.0 credentials in the API worker.

## Proof Formats

The verifier accepts:

- `Ed25519Signature2020`
- `DataIntegrityProof` with `cryptosuite`:
  - `eddsa-rdfc-2022`
  - `ecdsa-sd-2023`

Proof format and cryptosuite results are returned in `verification.proof`.

## Key Resolution

Proof verification keys are resolved from issuer `did:web` signing configuration:

1. Active signing key (DB-backed registration or `TENANT_SIGNING_REGISTRY_JSON`)
2. Historical signing keys (`TENANT_SIGNING_KEY_HISTORY_JSON`) for rotation continuity

The verifier requires:

- `proof.verificationMethod` DID matches credential `issuer`
- Key fragment matches an active or historical key id

## Selective Disclosure Expectations

For `OpenBadgeCredential`, disclosed payloads must still include required display fields. The verifier enforces:

- `credentialSubject.id` or `credentialSubject.identifier`
- `credentialSubject.achievement` object
- `credentialSubject.achievement.type` includes `Achievement`

If required fields are missing from a disclosed credential, `verification.checks.credentialSubject` is marked `invalid`.

## Related Tests

- `apps/api-worker/src/index.test.ts`
  - `verifies DataIntegrityProof ecdsa-sd-2023 proofs when issuer signing keys are resolvable`
  - `verifies DataIntegrityProof eddsa-rdfc-2022 proofs when issuer signing keys are resolvable`
  - `verifies DataIntegrityProof credentials with both EdDSA and ECDSA cryptosuites through the same endpoint`
  - `marks credentialSubject as invalid when OpenBadgeCredential omits achievement details`
