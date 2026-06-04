# Verifiable Presentations (VP)

CredTrail supports W3C VC 2.0 Verifiable Presentation workflows for learner-controlled sharing.

## Endpoints

- `POST /v1/presentations/create`: Create a signed VP for the authenticated learner from selected credential IDs.
- `POST /v1/presentations/verify`: Verify holder proof and embedded credential proofs/checks.

## Create flow

Request body:

```json
{
  "holderDid": "did:key:z6Mk...",
  "holderPrivateJwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "...",
    "d": "..."
  },
  "credentialIds": ["tenant_123:assertion_456"]
}
```

Notes:

- Current VP creation path supports `did:key` holder DIDs.
- `credentialIds` must be tenant-scoped assertion IDs owned by the authenticated learner.
- Each selected credential must have `credentialSubject.id` equal to `holderDid`.

## Verify flow

Request body:

```json
{
  "presentation": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiablePresentation"],
    "holder": "did:key:z6Mk...",
    "verifiableCredential": [{ "...": "..." }],
    "proof": { "...": "..." }
  }
}
```

Response includes:

- Overall VP `status` (`valid` or `invalid`)
- Holder proof verification summary
- Per-credential binding status (`credentialSubject.id` vs holder DID)
- Per-credential proof verification summary
- Per-credential lifecycle/check summaries (dates, schema, status list checks)

## University verifier guidance

1. Require VP `status = valid`.
2. Require holder proof status `valid`.
3. For each credential, require `status = valid`, binding status `valid`, and lifecycle state `active`.
4. Reject VPs with mismatched holder binding or invalid credential proofs.

## Sample university verifier test

```bash
curl -sS \
  -X POST "https://api.example.edu/v1/presentations/verify" \
  -H "Content-Type: application/json" \
  -d @presentation-request.json
```

Expected result:

- HTTP 200
- Top-level response `status` is `valid`
- `holder.proof.status` is `valid`
- Every entry in `credentials` has `status = valid`

## Cryptosuite support

Holder and embedded credential proofs inside VP verification support:

- `DataIntegrityProof` with `cryptosuite: "eddsa-rdfc-2022"`

Other proof formats, including `Ed25519Signature2020`, JWT-VC, and `ecdsa-sd-2023`, are outside v1 support.
