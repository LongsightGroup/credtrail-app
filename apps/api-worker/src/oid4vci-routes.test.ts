import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findActiveOid4vciAccessTokenByHash: vi.fn(),
    findAssertionById: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    recordAssertionEngagementEvent: vi.fn(),
    resolveAssertionLifecycleState: vi.fn(),
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

import { type JsonObject, getImmutableCredentialObject } from "@credtrail/core-domain";
import {
  findActiveOid4vciAccessTokenByHash,
  findAssertionById,
  findBadgeTemplateById,
  recordAssertionEngagementEvent,
  resolveAssertionLifecycleState,
  type AssertionEngagementEventRecord,
  type AssertionRecord,
  type Oid4vciAccessTokenRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

interface ErrorResponse {
  error: string;
  error_description?: string;
}

const mockedFindActiveOid4vciAccessTokenByHash = vi.mocked(findActiveOid4vciAccessTokenByHash);
const mockedFindAssertionById = vi.mocked(findAssertionById);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedRecordAssertionEngagementEvent = vi.mocked(recordAssertionEngagementEvent);
const mockedResolveAssertionLifecycleState = vi.mocked(resolveAssertionLifecycleState);
const mockedGetImmutableCredentialObject = vi.mocked(getImmutableCredentialObject);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  PUBLIC_APP_ORIGIN: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

const sampleAssertion = (): AssertionRecord => {
  return {
    id: "tenant_123:assertion_456",
    tenantId: "tenant_123",
    publicId: "40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    learnerProfileId: "lpr_123",
    badgeTemplateId: "badge_template_001",
    achievementSnapshot: {
      badgeTemplateId: "badge_template_001",
      title: "TypeScript Foundations",
      description: "Awarded for completing TypeScript fundamentals.",
      criteriaUri: "https://example.edu/criteria/typescript",
      imageUri: "https://example.edu/badges/typescript.png",
      trustedCredentialMetadataJson: null,
    },
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    vcR2Key: "tenants/tenant_123/assertions/tenant_123%3Aassertion_456.jsonld",
    statusListIndex: 0,
    idempotencyKey: "idem_abc",
    issuedAt: "2026-02-10T22:00:00.000Z",
    issuedByUserId: "usr_123",
    revokedAt: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
  };
};

const sampleAccessToken = (
  overrides?: Partial<Oid4vciAccessTokenRecord>,
): Oid4vciAccessTokenRecord => {
  return {
    id: "ova_123",
    accessTokenHash: "oid4vci-access-hash",
    tenantId: "tenant_123",
    assertionId: "tenant_123:assertion_456",
    expiresAt: "2026-02-10T22:10:00.000Z",
    revokedAt: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleAssertionEngagementEvent = (
  overrides?: Partial<AssertionEngagementEventRecord>,
): AssertionEngagementEventRecord => {
  return {
    id: "aee_wallet_123",
    tenantId: "tenant_123",
    assertionId: "tenant_123:assertion_456",
    eventType: "wallet_accept",
    actorType: "wallet",
    channel: "oid4vci",
    occurredAt: "2026-02-10T22:00:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindActiveOid4vciAccessTokenByHash.mockReset();
  mockedFindActiveOid4vciAccessTokenByHash.mockResolvedValue(sampleAccessToken());
  mockedFindAssertionById.mockReset();
  mockedFindAssertionById.mockResolvedValue(sampleAssertion());
  mockedFindBadgeTemplateById.mockReset();
  mockedFindBadgeTemplateById.mockResolvedValue(null);
  mockedRecordAssertionEngagementEvent.mockReset();
  mockedRecordAssertionEngagementEvent.mockResolvedValue({
    status: "recorded",
    event: sampleAssertionEngagementEvent(),
  });
  mockedResolveAssertionLifecycleState.mockReset();
  mockedResolveAssertionLifecycleState.mockResolvedValue({
    state: "active",
    source: "default_active",
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    revokedAt: null,
  });
  mockedGetImmutableCredentialObject.mockReset();
});

describe("GET /.well-known/openid-credential-issuer", () => {
  it("publishes only the configured application origin", async () => {
    const response = await app.request(
      "https://unexpected.example/.well-known/openid-credential-issuer",
      undefined,
      createEnv(),
    );
    const body = await response.json<{
      credential_issuer: string;
      token_endpoint: string;
      credential_endpoint: string;
    }>();

    expect(response.status).toBe(200);
    expect(body).toMatchObject({
      credential_issuer: "https://credtrail.test",
      token_endpoint: "https://credtrail.test/credentials/v1/token",
      credential_endpoint: "https://credtrail.test/credentials/v1/credentials",
    });
  });
});

describe("POST /credentials/v1/credentials", () => {
  it("records wallet acceptance when a credential is retrieved through OID4VCI", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      type: ["VerifiableCredential", "OpenBadgeCredential"],
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedGetImmutableCredentialObject.mockResolvedValue(credential);

    const response = await app.request(
      "/credentials/v1/credentials",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer oid4vci_at_example",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          format: "ldp_vc",
          credential_identifier: "tenant_123:assertion_456",
        }),
      },
      env,
    );
    const body = await response.json<{
      credential_identifier: string;
    }>();

    expect(response.status).toBe(200);
    expect(body.credential_identifier).toBe("tenant_123:assertion_456");
    expect(mockedRecordAssertionEngagementEvent).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        assertionId: "tenant_123:assertion_456",
        eventType: "wallet_accept",
        actorType: "wallet",
        channel: "oid4vci",
        occurredAt: expect.stringMatching(/^20/),
      }),
    );
  });

  it("keeps wallet retrieval successful when acceptance was already recorded", async () => {
    const env = createEnv();
    const credential: JsonObject = {
      id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
      credentialSubject: {
        achievement: {
          name: "TypeScript Foundations",
        },
      },
    };

    mockedGetImmutableCredentialObject.mockResolvedValue(credential);
    mockedRecordAssertionEngagementEvent
      .mockResolvedValueOnce({
        status: "recorded",
        event: sampleAssertionEngagementEvent(),
      })
      .mockResolvedValueOnce({
        status: "already_recorded",
        event: sampleAssertionEngagementEvent(),
      });

    const firstResponse = await app.request(
      "/credentials/v1/credentials",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer oid4vci_at_example",
        },
      },
      env,
    );
    const secondResponse = await app.request(
      "/credentials/v1/credentials",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer oid4vci_at_example",
        },
      },
      env,
    );

    expect(firstResponse.status).toBe(200);
    expect(secondResponse.status).toBe(200);
    expect(mockedRecordAssertionEngagementEvent).toHaveBeenCalledTimes(2);
  });

  it("does not record wallet acceptance when the access token is invalid", async () => {
    const env = createEnv();

    mockedFindActiveOid4vciAccessTokenByHash.mockResolvedValueOnce(null);

    const response = await app.request(
      "/credentials/v1/credentials",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer oid4vci_at_invalid",
        },
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(401);
    expect(body.error).toBe("invalid_token");
    expect(mockedRecordAssertionEngagementEvent).not.toHaveBeenCalled();
  });
});
