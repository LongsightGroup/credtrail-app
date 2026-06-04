import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
  mockedFindActiveSessionByHash,
  mockedTouchSession,
} = vi.hoisted(() => {
  return {
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
    mockedFindActiveSessionByHash: vi.fn(),
    mockedTouchSession: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findActiveSessionByHash: mockedFindActiveSessionByHash,
    findAssertionById: vi.fn(),
    findTenantSigningRegistrationByDid: vi.fn(),
    findUserById: vi.fn(),
    listLearnerBadgeSummaries: vi.fn(),
    touchSession: mockedTouchSession,
  };
});

vi.mock("@credtrail/core-domain", async () => {
  const actual =
    await vi.importActual<typeof import("@credtrail/core-domain")>("@credtrail/core-domain");

  return {
    ...actual,
    getImmutableCredentialObject: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

vi.mock("./auth/better-auth-adapter", async () => {
  const actual = await vi.importActual<typeof import("./auth/better-auth-adapter")>(
    "./auth/better-auth-adapter",
  );

  return {
    ...actual,
    createBetterAuthProvider: vi.fn(() => ({
      requestMagicLink: vi.fn(),
      createMagicLinkSession: vi.fn(),
      createLtiSession: vi.fn(),
      resolveAuthenticatedPrincipal: mockedResolveBetterAuthPrincipal,
      resolveRequestedTenantContext: mockedResolveBetterAuthRequestedTenant,
      revokeCurrentSession: vi.fn(async () => {}),
    })),
  };
});

import {
  type JsonObject,
  encodeJwkPublicKeyMultibase,
  generateTenantDidSigningMaterial,
  getImmutableCredentialObject,
  signCredentialWithDataIntegrityProof,
} from "@credtrail/core-domain";
import {
  findAssertionById,
  findTenantSigningRegistrationByDid,
  findUserById,
  listLearnerBadgeSummaries,
  type AssertionRecord,
  type LearnerBadgeSummaryRecord,
  type SessionRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

interface ErrorResponse {
  error: string;
}

const mockedFindAssertionById = vi.mocked(findAssertionById);
const mockedFindTenantSigningRegistrationByDid = vi.mocked(findTenantSigningRegistrationByDid);
const mockedFindUserById = vi.mocked(findUserById);
const mockedGetImmutableCredentialObject = vi.mocked(getImmutableCredentialObject);
const mockedListLearnerBadgeSummaries = vi.mocked(listLearnerBadgeSummaries);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;
const originalFetch = globalThis.fetch;
const VC_V2_CONTEXT_URL = "https://www.w3.org/ns/credentials/v2";
const VC_V2_CONTEXT_DOCUMENT = {
  "@context": {
    "@protected": true,
    id: "@id",
    type: "@type",
    VerifiableCredential: "https://www.w3.org/2018/credentials#VerifiableCredential",
    VerifiablePresentation: "https://www.w3.org/2018/credentials#VerifiablePresentation",
    OpenBadgeCredential: "https://purl.imsglobal.org/spec/ob/v3p0#OpenBadgeCredential",
    Achievement: "https://purl.imsglobal.org/spec/ob/v3p0#Achievement",
    credentialSubject: "https://www.w3.org/2018/credentials#credentialSubject",
    issuer: {
      "@id": "https://www.w3.org/2018/credentials#issuer",
      "@type": "@id",
    },
    validFrom: {
      "@id": "https://www.w3.org/2018/credentials#validFrom",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
    },
    holder: {
      "@id": "https://www.w3.org/2018/credentials#holder",
      "@type": "@id",
    },
    verifiableCredential: {
      "@id": "https://www.w3.org/2018/credentials#verifiableCredential",
      "@container": "@set",
    },
    proof: "https://w3id.org/security#proof",
    proofPurpose: {
      "@id": "https://w3id.org/security#proofPurpose",
      "@type": "@vocab",
    },
    assertionMethod: "https://w3id.org/security#assertionMethod",
    verificationMethod: {
      "@id": "https://w3id.org/security#verificationMethod",
      "@type": "@id",
    },
    created: {
      "@id": "http://purl.org/dc/terms/created",
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
    },
    proofValue: "https://w3id.org/security#proofValue",
    cryptosuite: "https://w3id.org/security#cryptosuite",
    DataIntegrityProof: "https://w3id.org/security#DataIntegrityProof",
    name: "http://schema.org/name",
    achievement: "https://purl.imsglobal.org/spec/ob/v3p0#achievement",
  },
};

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  TENANT_SIGNING_KEY_HISTORY_JSON?: string;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string;
  JOB_PROCESSOR_TOKEN?: string;
  LTI_ISSUER_REGISTRY_JSON?: string;
  LTI_STATE_SIGNING_SECRET?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

beforeEach(() => {
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

    if (url === VC_V2_CONTEXT_URL) {
      return new Response(JSON.stringify(VC_V2_CONTEXT_DOCUMENT), {
        status: 200,
        headers: {
          "content-type": "application/ld+json",
        },
      });
    }

    if (originalFetch === undefined) {
      throw new Error(`Unexpected fetch in presentation test: ${url}`);
    }

    return originalFetch(input, init);
  });
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthPrincipal.mockImplementation(
    async (context: { req: { header(name: string): string | undefined } }) => {
      const cookieHeader = context.req.header("cookie") ?? "";

      if (!cookieHeader.includes("better-auth.session_token=")) {
        return null;
      }

      return {
        userId: "usr_123",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth" as const,
        expiresAt: "2026-02-11T22:00:00.000Z",
      };
    },
  );
  mockedResolveBetterAuthRequestedTenant.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockImplementation(
    async (context: { req: { header(name: string): string | undefined } }) => {
      const cookieHeader = context.req.header("cookie") ?? "";

      if (!cookieHeader.includes("better-auth.session_token=")) {
        return null;
      }

      return {
        tenantId: "tenant_123",
        source: "legacy_session" as const,
        authoritative: true,
      };
    },
  );
  mockedFindUserById.mockReset();
  mockedFindUserById.mockResolvedValue({
    id: "usr_123",
    email: "learner@example.edu",
  });
  mockedFindTenantSigningRegistrationByDid.mockReset();
  mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
  mockedFindActiveSessionByHash.mockReset();
  mockedTouchSession.mockReset();
  mockedListLearnerBadgeSummaries.mockReset();
  mockedFindAssertionById.mockReset();
  mockedGetImmutableCredentialObject.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const sampleAssertion = (overrides?: {
  revokedAt?: string | null;
  statusListIndex?: number | null;
}): AssertionRecord => {
  return {
    id: "tenant_123:assertion_456",
    tenantId: "tenant_123",
    publicId: "40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    learnerProfileId: "lpr_123",
    badgeTemplateId: "badge_template_001",
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    vcR2Key: "tenants/tenant_123/assertions/tenant_123%3Aassertion_456.jsonld",
    statusListIndex: overrides?.statusListIndex === undefined ? 0 : overrides.statusListIndex,
    idempotencyKey: "idem_abc",
    issuedAt: "2026-02-10T22:00:00.000Z",
    issuedByUserId: "usr_123",
    revokedAt: overrides?.revokedAt ?? null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
  };
};

const asJsonObject = (value: unknown): JsonObject | null => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }

  return value as JsonObject;
};

const asString = (value: unknown): string | null => {
  return typeof value === "string" ? value : null;
};

const sampleSession = (overrides?: { tenantId?: string; userId?: string }): SessionRecord => {
  return {
    id: "ses_123",
    tenantId: overrides?.tenantId ?? "tenant_123",
    userId: overrides?.userId ?? "usr_123",
    sessionTokenHash: "session-hash",
    expiresAt: "2026-02-11T22:00:00.000Z",
    lastSeenAt: "2026-02-10T22:00:00.000Z",
    revokedAt: null,
    createdAt: "2026-02-10T22:00:00.000Z",
  };
};

const sampleLearnerBadge = (
  overrides?: Partial<LearnerBadgeSummaryRecord>,
): LearnerBadgeSummaryRecord => {
  return {
    assertionId: "tenant_123:assertion_456",
    assertionPublicId: "40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    tenantId: "tenant_123",
    badgeTemplateId: "badge_template_001",
    badgeTitle: "TypeScript Foundations",
    badgeDescription: "Awarded for completing TS basics.",
    issuedAt: "2026-02-10T22:00:00.000Z",
    revokedAt: null,
    ...overrides,
  };
};

const createDidKeyHolderMaterial = async (): Promise<{
  did: string;
  verificationMethod: string;
  privateJwk: {
    kty: "OKP";
    crv: "Ed25519";
    x: string;
    d: string;
    kid?: string;
  };
}> => {
  const signingMaterial = await generateTenantDidSigningMaterial({
    did: "did:web:credtrail.test:holder",
  });
  const multibase = encodeJwkPublicKeyMultibase(signingMaterial.publicJwk);
  const did = `did:key:${multibase}`;

  return {
    did,
    verificationMethod: `${did}#${multibase}`,
    privateJwk: signingMaterial.privateJwk,
  };
};

describe("Verifiable Presentation endpoints", () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedListLearnerBadgeSummaries.mockReset();
    mockedFindAssertionById.mockReset();
    mockedGetImmutableCredentialObject.mockReset();
  });

  it("creates a signed VP for authenticated learner-selected credentials", async () => {
    const env = createEnv();
    const holder = await createDidKeyHolderMaterial();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedListLearnerBadgeSummaries.mockResolvedValue([sampleLearnerBadge()]);
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedGetImmutableCredentialObject.mockResolvedValue({
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
      ],
      type: ["VerifiableCredential", "OpenBadgeCredential"],
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      issuer: "did:web:credtrail.test:tenant_123",
      validFrom: "2026-02-10T22:00:00.000Z",
      credentialSubject: {
        id: holder.did,
        type: ["AchievementSubject"],
        achievement: {
          type: ["Achievement"],
          name: "TypeScript Foundations",
        },
      },
    });

    const response = await app.request(
      "/v1/presentations/create",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          holderDid: holder.did,
          holderPrivateJwk: holder.privateJwk,
          credentialIds: ["tenant_123:assertion_456"],
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();
    const presentation = asJsonObject(body.presentation);

    expect(response.status).toBe(200);
    expect(body.credentialCount).toBe(1);
    expect(body.holderDid).toBe(holder.did);
    expect(asString(presentation?.holder)).toBe(holder.did);
    expect(asJsonObject(presentation?.proof)).not.toBeNull();
  });

  it("rejects VP creation when credential is not owned by authenticated learner", async () => {
    const env = createEnv();
    const holder = await createDidKeyHolderMaterial();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedListLearnerBadgeSummaries.mockResolvedValue([]);

    const response = await app.request(
      "/v1/presentations/create",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          holderDid: holder.did,
          holderPrivateJwk: holder.privateJwk,
          credentialIds: ["tenant_123:assertion_456"],
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toContain("not accessible");
    expect(mockedFindAssertionById).not.toHaveBeenCalled();
  });

  it("verifies VP holder proof and multiple EdDSA credential proofs", async () => {
    const holder = await createDidKeyHolderMaterial();
    const firstIssuer = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
    });
    const secondIssuer = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123:second",
    });

    const firstCredential = await signCredentialWithDataIntegrityProof({
      credential: {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type: ["VerifiableCredential", "OpenBadgeCredential"],
        id: "urn:credtrail:credential:first",
        issuer: firstIssuer.did,
        validFrom: "2026-02-10T22:00:00.000Z",
        credentialSubject: {
          id: holder.did,
          type: ["AchievementSubject"],
          achievement: {
            type: ["Achievement"],
            name: "First Badge",
          },
        },
      },
      privateJwk: firstIssuer.privateJwk,
      verificationMethod: firstIssuer.did + "#" + firstIssuer.keyId,
    });

    const secondCredential = await signCredentialWithDataIntegrityProof({
      credential: {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type: ["VerifiableCredential", "OpenBadgeCredential"],
        id: "urn:credtrail:credential:second",
        issuer: secondIssuer.did,
        validFrom: "2026-02-10T22:00:00.000Z",
        credentialSubject: {
          id: holder.did,
          type: ["AchievementSubject"],
          achievement: {
            type: ["Achievement"],
            name: "Second Badge",
          },
        },
      },
      privateJwk: secondIssuer.privateJwk,
      verificationMethod: secondIssuer.did + "#" + secondIssuer.keyId,
    });

    const presentation = await signCredentialWithDataIntegrityProof({
      credential: {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type: ["VerifiablePresentation"],
        holder: holder.did,
        verifiableCredential: [firstCredential, secondCredential],
      },
      privateJwk: holder.privateJwk,
      verificationMethod: holder.verificationMethod,
    });

    const env = {
      ...createEnv(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        [firstIssuer.did]: {
          tenantId: "tenant_123",
          keyId: firstIssuer.keyId,
          publicJwk: firstIssuer.publicJwk,
        },
        [secondIssuer.did]: {
          tenantId: "tenant_123",
          keyId: secondIssuer.keyId,
          publicJwk: secondIssuer.publicJwk,
        },
      }),
    };

    const response = await app.request(
      "/v1/presentations/verify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          presentation,
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();
    const credentials = Array.isArray(body.credentials)
      ? body.credentials.map((entry) => asJsonObject(entry))
      : [];
    const proofFormats = credentials
      .map((entry) => asJsonObject(entry?.proof))
      .map((proof) => asString(proof?.format))
      .filter((format): format is string => format !== null);

    expect(response.status).toBe(200);
    expect(body.status).toBe("valid");
    expect(body.credentialCount).toBe(2);
    expect(asString(asJsonObject(asJsonObject(body.holder)?.proof)?.status)).toBe("valid");
    expect(proofFormats).toEqual(
      expect.arrayContaining(["DataIntegrityProof", "DataIntegrityProof"]),
    );
    expect(credentials.every((entry) => asString(entry?.status) === "valid")).toBe(true);
  });

  it("returns invalid when VP credential subject does not match holder DID", async () => {
    const holder = await createDidKeyHolderMaterial();
    const issuer = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
    });

    const credential = await signCredentialWithDataIntegrityProof({
      credential: {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type: ["VerifiableCredential", "OpenBadgeCredential"],
        id: "urn:credtrail:credential:mismatch",
        issuer: issuer.did,
        validFrom: "2026-02-10T22:00:00.000Z",
        credentialSubject: {
          id: "did:key:z6MkpresentationMismatchHolder",
          type: ["AchievementSubject"],
          achievement: {
            type: ["Achievement"],
            name: "Mismatch Badge",
          },
        },
      },
      privateJwk: issuer.privateJwk,
      verificationMethod: issuer.did + "#" + issuer.keyId,
    });

    const presentation = await signCredentialWithDataIntegrityProof({
      credential: {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type: ["VerifiablePresentation"],
        holder: holder.did,
        verifiableCredential: [credential],
      },
      privateJwk: holder.privateJwk,
      verificationMethod: holder.verificationMethod,
    });

    const env = {
      ...createEnv(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        [issuer.did]: {
          tenantId: "tenant_123",
          keyId: issuer.keyId,
          publicJwk: issuer.publicJwk,
        },
      }),
    };

    const response = await app.request(
      "/v1/presentations/verify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          presentation,
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();
    const credentials = Array.isArray(body.credentials)
      ? body.credentials.map((entry) => asJsonObject(entry))
      : [];
    const firstBindingStatus = asString(asJsonObject(credentials[0]?.binding)?.status);

    expect(response.status).toBe(200);
    expect(body.status).toBe("invalid");
    expect(firstBindingStatus).toBe("invalid");
  });
});
