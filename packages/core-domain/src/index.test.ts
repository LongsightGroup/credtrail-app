import { describe, expect, it } from "vitest";

import {
  type JsonObject,
  createDidDocument,
  createDidWeb,
  decodeJwkPublicKeyMultibase,
  didWebDocumentPath,
  encodeJwkPublicKeyMultibase,
  generateTenantDidSigningMaterial,
  signCredentialWithDataIntegrityProof,
  verifyCredentialProofWithDataIntegrity,
} from "./index";

describe("did:web helpers", () => {
  it("builds did:web identifiers for host and tenant path", () => {
    expect(createDidWeb({ host: "issuers.credtrail.org" })).toBe("did:web:issuers.credtrail.org");
    expect(createDidWeb({ host: "issuers.credtrail.org", pathSegments: ["tenant-a"] })).toBe(
      "did:web:issuers.credtrail.org:tenant-a",
    );
  });

  it("maps did:web identifiers to document path", () => {
    expect(didWebDocumentPath("did:web:issuers.credtrail.org")).toBe("/.well-known/did.json");
    expect(didWebDocumentPath("did:web:issuers.credtrail.org:tenant-a")).toBe("/tenant-a/did.json");
  });
});

describe("credential signing", () => {
  const sampleCredential = (did: string, id: string): JsonObject => {
    return {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
      ],
      id,
      type: ["VerifiableCredential", "OpenBadgeCredential"],
      issuer: did,
      credentialSubject: {
        id: "mailto:learner@example.edu",
        type: ["AchievementSubject"],
        achievement: {
          id: "urn:uuid:badge-123",
          type: ["Achievement"],
          name: "TypeScript Fundamentals",
        },
      },
    };
  };

  it("generates keys, signs credentials, and verifies proof", async () => {
    const did = createDidWeb({
      host: "issuers.credtrail.org",
      pathSegments: ["tenant-a"],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
      keyId: "key-1",
    });
    const didDocument = createDidDocument({
      did,
      keyId: signingMaterial.keyId,
      publicJwk: signingMaterial.publicJwk,
    });
    const signedCredential = await signCredentialWithDataIntegrityProof({
      credential: sampleCredential(did, "urn:uuid:vc-123"),
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${did}#${signingMaterial.keyId}`,
    });

    expect(didDocument.id).toBe(did);
    expect(didDocument.verificationMethod[0].type).toBe("Ed25519VerificationKey2020");
    expect(didDocument.verificationMethod[0].publicKeyMultibase).toContain("z");
    expect(signedCredential.proof.type).toBe("DataIntegrityProof");
    expect(signedCredential.proof.cryptosuite).toBe("eddsa-rdfc-2022");
    expect(signedCredential.proof.verificationMethod).toBe(`${did}#${signingMaterial.keyId}`);
    const encodedMultibase = encodeJwkPublicKeyMultibase(signingMaterial.publicJwk);
    expect(didDocument.verificationMethod[0].publicKeyMultibase).toBe(encodedMultibase);
    expect(decodeJwkPublicKeyMultibase(encodedMultibase)).toBe(signingMaterial.publicJwk.x);

    const isValid = await verifyCredentialProofWithDataIntegrity({
      credential: signedCredential,
      publicJwk: signingMaterial.publicJwk,
    });

    expect(isValid).toBe(true);
  });

  it("fails verification when credential payload is modified", async () => {
    const did = createDidWeb({
      host: "issuers.credtrail.org",
      pathSegments: ["tenant-b"],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
    });
    const signedCredential = await signCredentialWithDataIntegrityProof({
      credential: sampleCredential(did, "urn:uuid:vc-456"),
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${did}#${signingMaterial.keyId}`,
    });

    const tamperedCredential = {
      ...signedCredential,
      issuer: "did:web:tampered.credtrail.org:tenant-b",
    };

    const isValid = await verifyCredentialProofWithDataIntegrity({
      credential: tamperedCredential,
      publicJwk: signingMaterial.publicJwk,
    });

    expect(isValid).toBe(false);
  });

  it("rejects multibase values that do not include the Ed25519 multicodec prefix", () => {
    expect(() => decodeJwkPublicKeyMultibase("z3vQB7B6MrGQZaxCuFg4oh")).toThrow(
      "Expected multicodec value with Ed25519 0xed01 prefix",
    );
  });

  it("uses multibase-derived key IDs by default for generated signing material", async () => {
    const did = createDidWeb({
      host: "issuers.credtrail.org",
      pathSegments: ["tenant-c"],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
    });
    const expectedKeyId = encodeJwkPublicKeyMultibase(signingMaterial.publicJwk);
    const didDocument = createDidDocument({
      did,
      keyId: signingMaterial.keyId,
      publicJwk: signingMaterial.publicJwk,
    });

    expect(signingMaterial.keyId).toBe(expectedKeyId);
    expect(signingMaterial.publicJwk.kid).toBe(expectedKeyId);
    expect(signingMaterial.privateJwk.kid).toBe(expectedKeyId);
    expect(didDocument.verificationMethod[0].id).toBe(`${did}#${expectedKeyId}`);
  });

  it("signs and verifies DataIntegrityProof with eddsa-rdfc-2022", async () => {
    const did = createDidWeb({
      host: "issuers.credtrail.org",
      pathSegments: ["tenant-d"],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
    });
    const signedCredential = await signCredentialWithDataIntegrityProof({
      credential: sampleCredential(did, "urn:uuid:vc-789"),
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${did}#${signingMaterial.keyId}`,
      cryptosuite: "eddsa-rdfc-2022",
    });

    expect(signedCredential.proof.type).toBe("DataIntegrityProof");
    expect(signedCredential.proof.cryptosuite).toBe("eddsa-rdfc-2022");

    const isValid = await verifyCredentialProofWithDataIntegrity({
      credential: signedCredential,
      publicJwk: signingMaterial.publicJwk,
    });

    expect(isValid).toBe(true);
  });

  it("signs and verifies credentials with VC v2 validUntil and credentialSchema terms", async () => {
    const did = createDidWeb({
      host: "issuers.credtrail.org",
      pathSegments: ["tenant-schema"],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
    });
    const signedCredential = await signCredentialWithDataIntegrityProof({
      credential: {
        ...sampleCredential(did, "urn:uuid:vc-schema"),
        validFrom: "2026-02-10T22:00:00.000Z",
        validUntil: "2027-02-10T22:00:00.000Z",
        credentialSchema: [
          {
            id: "https://credtrail.example/schemas/open-badge-credential.json",
            type: "1EdTechJsonSchemaValidator2019",
          },
        ],
      },
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${did}#${signingMaterial.keyId}`,
      cryptosuite: "eddsa-rdfc-2022",
    });

    const isValid = await verifyCredentialProofWithDataIntegrity({
      credential: signedCredential,
      publicJwk: signingMaterial.publicJwk,
    });

    expect(isValid).toBe(true);
  });

  it("fails DataIntegrityProof verification with mismatched key material", async () => {
    const did = createDidWeb({
      host: "issuers.credtrail.org",
      pathSegments: ["tenant-f"],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
    });
    const signedCredential = await signCredentialWithDataIntegrityProof({
      credential: sampleCredential(did, "urn:uuid:vc-791"),
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${did}#${signingMaterial.keyId}`,
      cryptosuite: "eddsa-rdfc-2022",
    });
    const wrongSigningMaterial = await generateTenantDidSigningMaterial({
      did,
      keyId: "wrong-key",
    });

    const isValid = await verifyCredentialProofWithDataIntegrity({
      credential: signedCredential,
      publicJwk: wrongSigningMaterial.publicJwk,
    });

    expect(isValid).toBe(false);
  });

  it("does not fetch remote JSON-LD contexts during signing or verification", async () => {
    const did = createDidWeb({
      host: "issuers.credtrail.org",
      pathSegments: ["tenant-g"],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
    });
    const originalFetch = globalThis.fetch;
    let fetchCalled = false;

    globalThis.fetch = ((request: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      fetchCalled = true;
      return originalFetch(request, init);
    }) as typeof fetch;

    try {
      const signedCredential = await signCredentialWithDataIntegrityProof({
        credential: sampleCredential(did, "urn:uuid:vc-792"),
        privateJwk: signingMaterial.privateJwk,
        verificationMethod: `${did}#${signingMaterial.keyId}`,
      });
      const isValid = await verifyCredentialProofWithDataIntegrity({
        credential: signedCredential,
        publicJwk: signingMaterial.publicJwk,
      });

      expect(isValid).toBe(true);
      expect(fetchCalled).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("rejects unsupported JSON-LD contexts without fetching them", async () => {
    const did = createDidWeb({
      host: "issuers.credtrail.org",
      pathSegments: ["tenant-h"],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
    });
    const originalFetch = globalThis.fetch;
    let fetchCalled = false;

    globalThis.fetch = ((request: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      fetchCalled = true;
      return originalFetch(request, init);
    }) as typeof fetch;

    try {
      await expect(
        signCredentialWithDataIntegrityProof({
          credential: {
            ...sampleCredential(did, "urn:uuid:vc-793"),
            "@context": ["https://attacker.example/context.json"],
          },
          privateJwk: signingMaterial.privateJwk,
          verificationMethod: `${did}#${signingMaterial.keyId}`,
        }),
      ).rejects.toThrow("Dereferencing a URL did not result in a valid JSON-LD object");
      expect(fetchCalled).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
