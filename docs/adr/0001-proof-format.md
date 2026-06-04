# ADR-0001: Proof Format for Open Badges 3.0 Credentials

- Status: Accepted, amended 2026-06-04
- Date: 2026-02-10
- Decision owner: Foundation (Days 1-15)
- Related issue: `credtrail-vxf`
- Supersedes: none

## Context

The v1 platform issues Open Badges 3.0 credentials as JSON-LD Verifiable Credentials and must keep a single proof format.

Constraints from product and architecture:

- Open Badges 3.0 only for v1.
- `did:web` issuer identity with per-tenant Ed25519 keys.
- Server-rendered product with Cloudflare Workers, Postgres, R2, and queue processing.
- Single-path implementation policy for v1.
- Current 1EdTech Open Badges 3.0 Linked Data Proof certification expectations.
- No existing CredTrail customers, integrations, or issued credentials require legacy proof compatibility.

Options considered:

1. JSON-LD VC with `DataIntegrityProof` and `eddsa-rdfc-2022`.
2. JSON-LD VC with legacy `Ed25519Signature2020`.
3. JWT-VC (`vc+ld+jwt`) using a JWS envelope.
4. Multiple proof formats in parallel.

## Decision

For v1, CredTrail issues and verifies JSON-LD Verifiable Credentials using `DataIntegrityProof` with `cryptosuite: "eddsa-rdfc-2022"`.

CredTrail does not issue JWT-VCs, `Ed25519Signature2020`, or `ecdsa-sd-2023` credentials in v1.

Verification support follows the same single-path policy: the public verifier validates `DataIntegrityProof` credentials with `eddsa-rdfc-2022` and reports other proof formats as unsupported.

## Rationale

- Matches the current Open Badges 3.0 Linked Data Proof direction.
- Keeps one standards path for signing, storage, revocation, verification, and presentation workflows.
- Avoids carrying legacy proof formats before CredTrail has any legacy customers or credentials.
- Fits the `did:web` + Ed25519 issuer key model without adding a second key family.
- Avoids JWT-specific parsing, validation, and verifier behavior in the first release.
- Reduces dependency and maintenance pressure by keeping the canonicalization and proof model narrowly scoped.

## Cost

- Short-term implementation cost: medium, because signing and verification must use JSON-LD canonicalization for Data Integrity proofs.
- Additional v1 operating cost: one proof model and one key family.
- Avoided cost: no JWT issuance, no legacy proof verification path, and no parallel ECDSA credential path.

## Complexity

- Net complexity is lower than supporting several formats.
- JSON-LD canonicalization remains the main complexity, but it is confined to one implementation and one conformance surface.
- Pinned JSON-LD contexts are required so Workers do not fetch remote context documents during signing or verification.

## Migration Impact

- No customer migration is required because this decision was amended before production customers or production-issued credentials.
- Any future import of externally issued badges must be handled as an import/interoperability feature, not as CredTrail issuance policy.
- If CredTrail later accepts additional proof formats, support must be additive, explicitly scoped, and covered by verifier compatibility tests.

## Rollback Plan

If `DataIntegrityProof` with `eddsa-rdfc-2022` proves non-viable during implementation or certification:

1. Open a new ADR proposing the replacement proof format.
2. Keep any already issued credentials verifiable where feasible.
3. Add verifier support before changing issuance.
4. Gate any format transition by issuance date or tenant only after compatibility tests pass.
5. Freeze new proof-format changes until verification stability is confirmed.

## Consequences

- Signing, verification, status-list credentials, and verifiable presentations target `DataIntegrityProof` with `eddsa-rdfc-2022`.
- R2 credential storage remains JSON-LD with embedded linked-data proof objects.
- `Ed25519Signature2020`, JWT-VC, and `ecdsa-sd-2023` are out of v1 issuance scope unless a follow-up ADR is accepted.
