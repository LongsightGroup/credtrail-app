import { describe, expect, it } from "vitest";

import { isValidationParseError } from "./json.js";
import { parseSignCredentialRequest, parseTenantSigningRegistry } from "./signing.js";

describe("parseSignCredentialRequest", () => {
  it("accepts a valid did:web signing request", () => {
    const payload = parseSignCredentialRequest({
      did: "did:web:issuers.credtrail.org:tenant-a",
      credential: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential"],
      },
    });

    expect(payload.did).toBe("did:web:issuers.credtrail.org:tenant-a");
  });

  it("accepts DataIntegrity signing requests with the eddsa-rdfc-2022 cryptosuite", () => {
    const payload = parseSignCredentialRequest({
      did: "did:web:issuers.credtrail.org:tenant-a",
      credential: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential"],
      },
      proofType: "DataIntegrityProof",
      cryptosuite: "eddsa-rdfc-2022",
    });

    expect(payload.proofType).toBe("DataIntegrityProof");
    expect(payload.cryptosuite).toBe("eddsa-rdfc-2022");
  });

  it("rejects non did:web identifiers", () => {
    let thrownError: unknown = null;

    try {
      parseSignCredentialRequest({
        did: "did:key:z6Mk...",
        credential: {
          id: "urn:vc:1",
        },
      });
    } catch (error) {
      thrownError = error;
    }

    expect(isValidationParseError(thrownError)).toBe(true);
  });

  it("accepts DataIntegrity signing requests without an explicit cryptosuite", () => {
    const payload = parseSignCredentialRequest({
      did: "did:web:issuers.credtrail.org:tenant-a",
      credential: {
        id: "urn:vc:1",
      },
      proofType: "DataIntegrityProof",
    });

    expect(payload.proofType).toBe("DataIntegrityProof");
    expect(payload.cryptosuite).toBeUndefined();
  });

  it("rejects legacy proof types", () => {
    expect(() => {
      parseSignCredentialRequest({
        did: "did:web:issuers.credtrail.org:tenant-a",
        credential: {
          id: "urn:vc:1",
        },
        proofType: "Ed25519Signature2020",
      });
    }).toThrow(/./);
  });

  it("rejects cryptosuite when proofType is not DataIntegrityProof", () => {
    expect(() => {
      parseSignCredentialRequest({
        did: "did:web:issuers.credtrail.org:tenant-a",
        credential: {
          id: "urn:vc:1",
        },
        cryptosuite: "eddsa-rdfc-2022",
      });
    }).toThrow(/./);
  });
});

describe("parseTenantSigningRegistry", () => {
  it("accepts tenant registry entries", () => {
    const registry = parseTenantSigningRegistry({
      "did:web:issuers.credtrail.org:tenant-a": {
        tenantId: "tenant_a",
        keyId: "key-1",
        publicJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: "11qYAYLef1f99sL4fY49fN7kP8Yw6s9w8lY9Yd6n8oE",
        },
        privateJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: "11qYAYLef1f99sL4fY49fN7kP8Yw6s9w8lY9Yd6n8oE",
          d: "nWGxne_9WmZ8QfQwJdK2fNn_Ef3FQk7xU4mS1sM3x2U",
        },
      },
    });

    expect(Object.keys(registry)).toHaveLength(1);
  });

  it("accepts P-256 tenant registry entries", () => {
    const registry = parseTenantSigningRegistry({
      "did:web:issuers.credtrail.org:tenant-b": {
        tenantId: "tenant_b",
        keyId: "key-p256",
        publicJwk: {
          kty: "EC",
          crv: "P-256",
          x: "X".repeat(43),
          y: "Y".repeat(43),
        },
        privateJwk: {
          kty: "EC",
          crv: "P-256",
          x: "X".repeat(43),
          y: "Y".repeat(43),
          d: "D".repeat(43),
        },
      },
    });

    expect(Object.keys(registry)).toHaveLength(1);
  });

  it("rejects tenant registry entries with mismatched key types", () => {
    expect(() => {
      parseTenantSigningRegistry({
        "did:web:issuers.credtrail.org:tenant-c": {
          tenantId: "tenant_c",
          keyId: "key-mismatch",
          publicJwk: {
            kty: "OKP",
            crv: "Ed25519",
            x: "11qYAYLef1f99sL4fY49fN7kP8Yw6s9w8lY9Yd6n8oE",
          },
          privateJwk: {
            kty: "EC",
            crv: "P-256",
            x: "X".repeat(43),
            y: "Y".repeat(43),
            d: "D".repeat(43),
          },
        },
      });
    }).toThrow(/./);
  });
});
