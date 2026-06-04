import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findTenantSigningRegistrationByDid: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  type JsonObject,
  generateTenantDidSigningMaterial,
  signCredentialWithDataIntegrityProof,
} from "@credtrail/core-domain";
import {
  findTenantSigningRegistrationByDid,
  type SqlDatabase,
  type TenantSigningRegistrationRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";
import { generateP256SigningMaterial } from "./test-support/p256-signing-material";

interface ErrorResponse {
  error: string;
}

const mockedFindTenantSigningRegistrationByDid = vi.mocked(findTenantSigningRegistrationByDid);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
});

const asJsonObject = (value: unknown): JsonObject | null => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }

  return value as JsonObject;
};

const asString = (value: unknown): string | null => {
  return typeof value === "string" ? value : null;
};

const jsonObjectFromRequestInitBody = (init: RequestInit | undefined): JsonObject => {
  if (typeof init?.body !== "string") {
    return {};
  }

  try {
    const parsed = JSON.parse(init.body) as unknown;
    return asJsonObject(parsed) ?? {};
  } catch {
    return {};
  }
};

const sampleTenantSigningRegistration = (
  overrides?: Partial<TenantSigningRegistrationRecord>,
): TenantSigningRegistrationRecord => {
  return {
    tenantId: "sakai",
    did: "did:web:credtrail.test:sakai",
    keyId: "key-1",
    publicJwkJson: JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "A".repeat(32),
    }),
    privateJwkJson: JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "A".repeat(32),
      d: "B".repeat(32),
    }),
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

describe("POST /v1/signing/credentials", () => {
  beforeEach(() => {
    mockedFindTenantSigningRegistrationByDid.mockReset();
  });

  it("signs credentials using DB-backed signing registrations", async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:sakai",
      keyId: "key-db-sign",
    });

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: "sakai",
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      "/v1/signing/credentials",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          did: signingMaterial.did,
          credential: {
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            type: ["VerifiableCredential"],
            issuer: signingMaterial.did,
            credentialSubject: {
              id: "urn:credtrail:subject:test",
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<JsonObject>();
    const signedCredential = asJsonObject(body.credential);

    expect(response.status).toBe(201);
    expect(asString(body.did)).toBe(signingMaterial.did);
    expect(asJsonObject(signedCredential?.proof)).not.toBeNull();
    expect(mockedFindTenantSigningRegistrationByDid).toHaveBeenCalledWith(
      fakeDb,
      signingMaterial.did,
    );
  });

  it("signs credentials through configured remote signers when DID private keys are externalized", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:sakai",
      keyId: "key-remote",
    });
    const env = {
      ...createEnv(),
      TENANT_REMOTE_SIGNER_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:sakai": {
          url: "https://kms.credtrail.test/sign",
        },
      }),
    };
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      const request = jsonObjectFromRequestInitBody(init);
      const unsignedCredential = asJsonObject(request.credential);
      const verificationMethod = asString(request.verificationMethod);

      if (unsignedCredential === null || verificationMethod === null) {
        return new Response(
          JSON.stringify({
            error: "invalid signer request",
          }),
          {
            status: 400,
            headers: {
              "content-type": "application/json",
            },
          },
        );
      }

      const signedCredential = await signCredentialWithDataIntegrityProof({
        credential: unsignedCredential,
        privateJwk: signingMaterial.privateJwk,
        verificationMethod,
      });

      return new Response(
        JSON.stringify({
          credential: signedCredential,
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
          },
        },
      );
    });

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: "sakai",
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: null,
      }),
    );

    const response = await app.request(
      "/v1/signing/credentials",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          did: signingMaterial.did,
          credential: {
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            type: ["VerifiableCredential"],
            issuer: signingMaterial.did,
            credentialSubject: {
              id: "urn:credtrail:subject:test",
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<JsonObject>();

    expect(response.status).toBe(201);
    expect(asString(body.did)).toBe(signingMaterial.did);
    expect(asJsonObject(asJsonObject(body.credential)?.proof)).not.toBeNull();
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0]?.[0]).toBe("https://kms.credtrail.test/sign");

    fetchSpy.mockRestore();
  });

  it("rejects ecdsa-sd-2023 signing requests", async () => {
    const env = createEnv();
    const did = "did:web:credtrail.test:sakai";

    const response = await app.request(
      "/v1/signing/credentials",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          did,
          proofType: "DataIntegrityProof",
          cryptosuite: "ecdsa-sd-2023",
          credential: {
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            type: ["VerifiableCredential"],
            issuer: did,
            credentialSubject: {
              id: "urn:credtrail:subject:test",
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toContain("Invalid");
  });

  it("signs DataIntegrity credentials with eddsa-rdfc-2022 when DID has Ed25519 key material", async () => {
    const env = createEnv();
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:sakai",
      keyId: "key-db-sign",
    });

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: "sakai",
        did: signingMaterial.did,
        keyId: signingMaterial.keyId,
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      "/v1/signing/credentials",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          did: signingMaterial.did,
          proofType: "DataIntegrityProof",
          cryptosuite: "eddsa-rdfc-2022",
          credential: {
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            type: ["VerifiableCredential"],
            issuer: signingMaterial.did,
            credentialSubject: {
              id: "urn:credtrail:subject:test",
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<JsonObject>();
    const signedCredential = asJsonObject(body.credential);
    const proof = asJsonObject(signedCredential?.proof);

    expect(response.status).toBe(201);
    expect(asString(proof?.type)).toBe("DataIntegrityProof");
    expect(asString(proof?.cryptosuite)).toBe("eddsa-rdfc-2022");
  });

  it("returns 422 when signing key is not Ed25519", async () => {
    const env = createEnv();
    const signingMaterial = await generateP256SigningMaterial("key-p256");
    const did = "did:web:credtrail.test:sakai";

    mockedFindTenantSigningRegistrationByDid.mockResolvedValue(
      sampleTenantSigningRegistration({
        tenantId: "sakai",
        did,
        keyId: "key-p256",
        publicJwkJson: JSON.stringify(signingMaterial.publicJwk),
        privateJwkJson: JSON.stringify(signingMaterial.privateJwk),
      }),
    );

    const response = await app.request(
      "/v1/signing/credentials",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          did,
          credential: {
            "@context": [
              "https://www.w3.org/ns/credentials/v2",
              "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            type: ["VerifiableCredential"],
            issuer: did,
            credentialSubject: {
              id: "urn:credtrail:subject:test",
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(422);
    expect(body.error).toBe(
      "DataIntegrity eddsa-rdfc-2022 signing requires an Ed25519 private key",
    );
  });
});
