import { completeTrustEdCredentialMetadataInput } from "@credtrail/validation/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
  mockedFindActiveSessionByHash,
  mockedTouchSession,
  mockedSendIssuanceEmailNotification,
} = vi.hoisted(() => {
  return {
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
    mockedFindActiveSessionByHash: vi.fn(),
    mockedTouchSession: vi.fn(),
    mockedSendIssuanceEmailNotification: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    createAssertion: vi.fn(),
    createAuditLog: vi.fn(),
    findActiveDelegatedIssuingAuthorityGrantForAction: vi.fn(),
    findActiveSessionByHash: mockedFindActiveSessionByHash,
    findAssertionByIdempotencyKey: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findTenantMembership: vi.fn(),
    findTenantSigningRegistrationByDid: vi.fn(),
    findUserById: vi.fn(),
    hasTenantMembershipOrgUnitAccess: vi.fn(),
    hasTenantMembershipOrgUnitScopeAssignments: vi.fn(),
    listLearnerIdentitiesByProfile: vi.fn(),
    nextAssertionStatusListIndex: vi.fn(),
    resolveAssertionLifecycleState: vi.fn(),
    resolveLearnerProfileForIdentity: vi.fn(),
    touchSession: mockedTouchSession,
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

vi.mock("./notifications/send-issuance-email", () => {
  return {
    sendIssuanceEmailNotification: mockedSendIssuanceEmailNotification,
  };
});

import {
  type JsonObject,
  generateTenantDidSigningMaterial,
  signCredentialWithDataIntegrityProof,
} from "@credtrail/core-domain";
import {
  createAssertion,
  createAuditLog,
  findActiveDelegatedIssuingAuthorityGrantForAction,
  findAssertionByIdempotencyKey,
  findBadgeTemplateById,
  findTenantMembership,
  findTenantSigningRegistrationByDid,
  findUserById,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  listLearnerIdentitiesByProfile,
  nextAssertionStatusListIndex,
  resolveAssertionLifecycleState,
  resolveLearnerProfileForIdentity,
  type AssertionRecord,
  type AuditLogRecord,
  type BadgeTemplateRecord,
  type DelegatedIssuingAuthorityGrantRecord,
  type LearnerProfileRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
  type ResolveAssertionLifecycleStateResult,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

interface ConsoleLogSpy {
  mockRestore: () => void;
  mock: {
    calls: unknown[][];
  };
}

interface ErrorResponse {
  error: string;
}

interface ManualIssueResponse {
  status: "issued" | "already_issued";
  assertionId: string;
  tenantId: string;
  credential: JsonObject;
}

const mockedFindAssertionByIdempotencyKey = vi.mocked(findAssertionByIdempotencyKey);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedFindActiveDelegatedIssuingAuthorityGrantForAction = vi.mocked(
  findActiveDelegatedIssuingAuthorityGrantForAction,
);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedFindTenantSigningRegistrationByDid = vi.mocked(findTenantSigningRegistrationByDid);
const mockedFindUserById = vi.mocked(findUserById);
const mockedHasTenantMembershipOrgUnitAccess = vi.mocked(hasTenantMembershipOrgUnitAccess);
const mockedHasTenantMembershipOrgUnitScopeAssignments = vi.mocked(
  hasTenantMembershipOrgUnitScopeAssignments,
);
const mockedResolveLearnerProfileForIdentity = vi.mocked(resolveLearnerProfileForIdentity);
const mockedCreateAssertion = vi.mocked(createAssertion);
const mockedNextAssertionStatusListIndex = vi.mocked(nextAssertionStatusListIndex);
const mockedResolveAssertionLifecycleState = vi.mocked(resolveAssertionLifecycleState);
const mockedListLearnerIdentitiesByProfile = vi.mocked(listLearnerIdentitiesByProfile);
const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;
let consoleLogSpy: ConsoleLogSpy | null = null;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  TENANT_SIGNING_KEY_HISTORY_JSON?: string;
  TENANT_REMOTE_SIGNER_REGISTRY_JSON?: string;
  ISSUANCE_EMAIL_NOTIFICATIONS_ENABLED?: string;
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
  consoleLogSpy?.mockRestore();
  consoleLogSpy = null;
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
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue(null);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
  mockedFindTenantSigningRegistrationByDid.mockReset();
  mockedFindTenantSigningRegistrationByDid.mockResolvedValue(null);
  mockedFindUserById.mockReset();
  mockedFindUserById.mockResolvedValue({
    id: "usr_123",
    email: "learner@example.edu",
  });
  mockedHasTenantMembershipOrgUnitAccess.mockReset();
  mockedHasTenantMembershipOrgUnitAccess.mockResolvedValue(false);
  mockedHasTenantMembershipOrgUnitScopeAssignments.mockReset();
  mockedHasTenantMembershipOrgUnitScopeAssignments.mockResolvedValue(false);
  mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockReset();
  mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(null);
  mockedListLearnerIdentitiesByProfile.mockReset();
  mockedListLearnerIdentitiesByProfile.mockResolvedValue([]);
  mockedFindActiveSessionByHash.mockReset();
  mockedTouchSession.mockReset();
  mockedFindBadgeTemplateById.mockReset();
  mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
  mockedFindAssertionByIdempotencyKey.mockReset();
  mockedResolveLearnerProfileForIdentity.mockReset();
  mockedResolveAssertionLifecycleState.mockReset();
  mockedResolveAssertionLifecycleState.mockResolvedValue(sampleLifecycle());
  mockedNextAssertionStatusListIndex.mockReset();
  mockedCreateAssertion.mockReset();
  mockedCreateAuditLog.mockReset();
  mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
  mockedSendIssuanceEmailNotification.mockReset();
  mockedSendIssuanceEmailNotification.mockResolvedValue(undefined);
});

afterEach(() => {
  consoleLogSpy?.mockRestore();
  consoleLogSpy = null;
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

const sampleLifecycle = (
  overrides?: Partial<ResolveAssertionLifecycleStateResult>,
): ResolveAssertionLifecycleStateResult => {
  return {
    state: "active",
    source: "default_active",
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    revokedAt: null,
    ...overrides,
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

const sampleBadgeTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => {
  return {
    id: "badge_template_001",
    tenantId: "tenant_123",
    slug: "typescript-foundations",
    title: "TypeScript Foundations",
    description: "Awarded for completing TS basics.",
    criteriaUri: null,
    imageUri: null,
    createdByUserId: "usr_issuer",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: '{"stability":"institution_registry"}',
    isArchived: false,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleDelegatedIssuingAuthorityGrant = (
  overrides?: Partial<DelegatedIssuingAuthorityGrantRecord>,
): DelegatedIssuingAuthorityGrantRecord => {
  return {
    id: "dag_123",
    tenantId: "tenant_123",
    delegateUserId: "usr_delegate",
    delegatedByUserId: "usr_admin",
    orgUnitId: "tenant_123:org:department-math",
    allowedActions: ["issue_badge"],
    badgeTemplateIds: ["badge_template_001"],
    startsAt: "2026-02-13T00:00:00.000Z",
    endsAt: "2026-03-13T00:00:00.000Z",
    revokedAt: null,
    revokedByUserId: null,
    revokedReason: null,
    status: "active",
    createdAt: "2026-02-13T00:00:00.000Z",
    updatedAt: "2026-02-13T00:00:00.000Z",
    ...overrides,
  };
};

const sampleTenantMembership = (
  overrides?: Partial<TenantMembershipRecord>,
): TenantMembershipRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_123",
    role: "issuer",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    id: "aud_123",
    tenantId: "tenant_123",
    actorUserId: "usr_123",
    action: "assertion.issued",
    targetType: "assertion",
    targetId: "tenant_123:assertion_456",
    metadataJson: null,
    occurredAt: "2026-02-10T22:00:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleLearnerProfile = (overrides?: Partial<LearnerProfileRecord>): LearnerProfileRecord => {
  return {
    id: "lpr_123",
    tenantId: "tenant_123",
    subjectId: "urn:credtrail:learner:tenant_123:lpr_123",
    displayName: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const createInMemoryBadgeObjects = (): R2Bucket => {
  const objects = new Map<string, string>();

  return {
    head: vi.fn((key: string) => {
      if (!objects.has(key)) {
        return Promise.resolve(null);
      }

      return Promise.resolve({ key });
    }),
    get: vi.fn((key: string) => {
      const value = objects.get(key);

      if (value === undefined) {
        return Promise.resolve(null);
      }

      return Promise.resolve({
        text: () => Promise.resolve(value),
      });
    }),
    put: vi.fn((key: string, value: unknown) => {
      if (typeof value !== "string") {
        throw new Error("Expected string value for R2 put in test bucket");
      }

      objects.set(key, value);
      return Promise.resolve({
        key,
        etag: "etag-test",
        version: "version-test",
        size: value.length,
        uploaded: new Date(),
      });
    }),
  } as unknown as R2Bucket;
};

describe("POST /v1/tenants/:tenantId/assertions/manual-issue", () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedFindTenantMembership.mockReset();
    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
    mockedTouchSession.mockReset();
    mockedFindBadgeTemplateById.mockReset();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindAssertionByIdempotencyKey.mockReset();
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedResolveAssertionLifecycleState.mockReset();
    mockedResolveAssertionLifecycleState.mockResolvedValue(sampleLifecycle());
    mockedNextAssertionStatusListIndex.mockReset();
    mockedCreateAssertion.mockReset();
    mockedCreateAuditLog.mockReset();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
  });

  it("returns already_issued when idempotency key matches an active assertion", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
    });
    const badgeObjects = createInMemoryBadgeObjects();
    const existingAssertion = sampleAssertion();
    await badgeObjects.put(
      existingAssertion.vcR2Key,
      JSON.stringify({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential", "OpenBadgeCredential"],
        id: "urn:credtrail:assertion:tenant_123%3Aassertion_456",
        credentialSubject: {
          id: "urn:credtrail:learner:tenant_123:lpr_123",
        },
      }),
    );
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: badgeObjects,
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:tenant_123": {
          tenantId: "tenant_123",
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        },
      }),
    };

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(existingAssertion);
    mockedResolveAssertionLifecycleState.mockResolvedValue(sampleLifecycle());

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "student@umich.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem_abc",
        }),
      },
      env,
    );
    const body = await response.json<ManualIssueResponse>();

    expect(response.status).toBe(200);
    expect(body.status).toBe("already_issued");
    expect(mockedResolveAssertionLifecycleState).toHaveBeenCalledWith(
      fakeDb,
      "tenant_123",
      existingAssertion.id,
    );
    expect(mockedCreateAssertion).not.toHaveBeenCalled();
  });

  it("returns 409 when idempotency key resolves to a suspended assertion", async () => {
    const existingAssertion = sampleAssertion();
    const env = createEnv();
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(existingAssertion);
    mockedResolveAssertionLifecycleState.mockResolvedValue(
      sampleLifecycle({
        state: "suspended",
        source: "lifecycle_event",
        reasonCode: "appeal_pending",
        reason: "Credential is suspended pending review.",
        transitionedAt: "2026-02-18T00:00:00.000Z",
      }),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "student@umich.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem_abc",
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(409);
    expect(body.error).toContain("Issuance blocked by lifecycle policy");
    expect(body.error).toContain("suspended");
    expect(mockedCreateAssertion).not.toHaveBeenCalled();
  });

  it("uses stable learner subject identifiers across old and new recipient emails", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
    });
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:tenant_123": {
          tenantId: "tenant_123",
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        },
      }),
    };

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedNextAssertionStatusListIndex.mockResolvedValueOnce(0).mockResolvedValueOnce(1);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const firstIssueResponse = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "student@umich.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem-1",
        }),
      },
      env,
    );
    const firstBody = await firstIssueResponse.json<ManualIssueResponse>();

    const secondIssueResponse = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "student@gmail.com",
          recipientIdentityType: "email",
          idempotencyKey: "idem-2",
        }),
      },
      env,
    );
    const secondBody = await secondIssueResponse.json<ManualIssueResponse>();

    const firstSubjectId = asString(asJsonObject(firstBody.credential.credentialSubject)?.id);
    const secondSubjectId = asString(asJsonObject(secondBody.credential.credentialSubject)?.id);
    const firstIdentifierEntries = asJsonObject(firstBody.credential.credentialSubject)?.identifier;
    const firstCredentialContexts = firstBody.credential["@context"];
    const firstIssuer = asJsonObject(firstBody.credential.issuer);
    const firstCredentialSubjectType = asJsonObject(firstBody.credential.credentialSubject)?.type;

    expect(firstIssueResponse.status).toBe(201);
    expect(secondIssueResponse.status).toBe(201);
    expect(firstSubjectId).toBe("urn:credtrail:learner:tenant_123:lpr_123");
    expect(secondSubjectId).toBe("urn:credtrail:learner:tenant_123:lpr_123");
    expect(Array.isArray(firstCredentialContexts)).toBe(true);
    expect(firstCredentialContexts).toEqual(
      expect.arrayContaining([
        "https://www.w3.org/ns/credentials/v2",
        "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        "https://www.w3.org/ns/credentials/status/v1",
      ]),
    );
    expect(firstIssuer).toEqual(
      expect.objectContaining({
        id: "did:web:credtrail.test:tenant_123",
        type: "Profile",
      }),
    );
    expect(Array.isArray(firstCredentialSubjectType)).toBe(true);
    expect(firstCredentialSubjectType).toEqual(expect.arrayContaining(["AchievementSubject"]));
    expect(Array.isArray(firstIdentifierEntries)).toBe(true);
    expect(firstIdentifierEntries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "IdentityObject",
          identityType: "ext:studentId",
          identityHash: "lpr_123",
          hashed: false,
        }),
        expect.objectContaining({
          type: "IdentityObject",
          identityType: "emailAddress",
          identityHash: "student@umich.edu",
          hashed: false,
        }),
      ]),
    );
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenNthCalledWith(1, fakeDb, {
      tenantId: "tenant_123",
      identityType: "email",
      identityValue: "student@umich.edu",
    });
    expect(mockedResolveLearnerProfileForIdentity).toHaveBeenNthCalledWith(2, fakeDb, {
      tenantId: "tenant_123",
      identityType: "email",
      identityValue: "student@gmail.com",
    });
    expect(mockedCreateAssertion).toHaveBeenNthCalledWith(
      1,
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        learnerProfileId: "lpr_123",
        recipientIdentity: "student@umich.edu",
      }),
    );
    const firstCreateAssertionCall = mockedCreateAssertion.mock.calls.at(0);

    if (firstCreateAssertionCall === undefined) {
      throw new Error("Expected first createAssertion call");
    }

    const firstCreateAssertionInput = firstCreateAssertionCall[1] as {
      recipientIdentifiers?: unknown;
    };

    expect(Array.isArray(firstCreateAssertionInput.recipientIdentifiers)).toBe(true);
    expect(firstCreateAssertionInput.recipientIdentifiers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          identifierType: "studentId",
          identifierValue: "lpr_123",
        }),
        expect.objectContaining({
          identifierType: "emailAddress",
          identifierValue: "student@umich.edu",
        }),
      ]),
    );
    expect(mockedCreateAssertion).toHaveBeenNthCalledWith(
      2,
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        learnerProfileId: "lpr_123",
        recipientIdentity: "student@gmail.com",
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        action: "assertion.issued",
        targetType: "assertion",
      }),
    );
    expect(mockedSendIssuanceEmailNotification).not.toHaveBeenCalled();
  });

  it("only sends issuance emails when the delivery feature flag is explicitly enabled", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
    });
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      ISSUANCE_EMAIL_NOTIFICATIONS_ENABLED: "true",
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:tenant_123": {
          tenantId: "tenant_123",
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        },
      }),
    };

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedNextAssertionStatusListIndex.mockResolvedValue(0);
    const issuedAssertion = sampleAssertion({
      statusListIndex: null,
    });
    mockedCreateAssertion.mockResolvedValue(issuedAssertion);

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "Student@UMich.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem-email-delivery-enabled",
        }),
      },
      env,
    );

    expect(response.status).toBe(201);
    expect(mockedSendIssuanceEmailNotification).toHaveBeenCalledTimes(1);
    expect(mockedSendIssuanceEmailNotification).toHaveBeenCalledWith(
      expect.objectContaining({
        recipientEmail: "student@umich.edu",
        tenantId: "tenant_123",
      }),
    );
  });

  it("includes TrustEd credential metadata in issued OB3 credentials", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
    });
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:tenant_123": {
          tenantId: "tenant_123",
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        },
      }),
    };
    const trustedCredentialMetadataJson = JSON.stringify(completeTrustEdCredentialMetadataInput);

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindBadgeTemplateById.mockResolvedValue(
      sampleBadgeTemplate({ trustedCredentialMetadataJson }),
    );
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedNextAssertionStatusListIndex.mockResolvedValue(0);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "student@umich.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem-trusted",
        }),
      },
      env,
    );
    const body = await response.json<ManualIssueResponse>();
    const contextEntries = Array.isArray(body.credential["@context"])
      ? body.credential["@context"]
      : [];
    const credentialSubject = asJsonObject(body.credential.credentialSubject);
    const achievement = asJsonObject(credentialSubject?.achievement);
    const proof = asJsonObject(body.credential.proof);

    expect(response.status).toBe(201);
    expect(contextEntries).toContain("https://credtrail.org/ns/trusted-credential/v1");
    expect(asString(proof?.type)).toBe("DataIntegrityProof");
    expect(asString(proof?.cryptosuite)).toBe("eddsa-rdfc-2022");
    expect(achievement).toEqual(
      expect.objectContaining({
        achievementType: "Project",
        criteria: expect.objectContaining({
          id: "https://credentials.example.edu/badges/applied-analytics/criteria",
          narrative: "Complete the applied analytics project and faculty review.",
        }),
      }),
    );
    expect(achievement?.alignment).toEqual([
      expect.objectContaining({
        targetName: "Analyze civic datasets",
        targetUrl: "https://case.example.edu/frameworks/data-analysis/items/analyze-civic-data",
        targetFramework: "Example CASE Framework",
      }),
    ]);
    expect(credentialSubject?.evidence).toEqual([
      expect.objectContaining({
        id: "https://evidence.example.edu/learners/123/capstone",
        name: "Capstone analysis portfolio",
      }),
    ]);
    expect(credentialSubject?.result).toEqual([
      expect.objectContaining({
        value: "Pass",
        resultDate: "2026-05-18",
      }),
    ]);
    expect(achievement?.skill).toEqual([
      expect.objectContaining({
        id: "https://skills.example.edu/skills/applied-data-analysis",
        name: "Applied data analysis",
        source: "Example Skills Framework",
      }),
    ]);
    expect(achievement?.issuerAuthority).toEqual(
      expect.objectContaining({
        id: "https://www.msche.org/institution/0000/",
        name: "Middle States Commission on Higher Education",
        authorityType: "accreditor",
      }),
    );
    expect(achievement?.assessment).toEqual([
      expect.objectContaining({
        description: "Faculty-scored applied analytics capstone.",
        assessmentDate: "2026-05-18",
      }),
    ]);
    expect(achievement?.rubric).toEqual([
      expect.objectContaining({
        id: "https://credentials.example.edu/rubrics/applied-analytics",
        name: "Applied analytics rubric",
      }),
    ]);
    expect(achievement?.duration).toEqual(
      expect.objectContaining({
        value: "6 weeks",
      }),
    );
    expect(achievement?.creditValue).toEqual(
      expect.objectContaining({
        available: "3 credits",
        earned: "3 credits",
      }),
    );
    expect(achievement?.endorsement).toEqual([
      expect.objectContaining({
        id: "https://workforce.example.edu/endorsements/applied-analytics",
        name: "Regional Workforce Council",
      }),
    ]);
  });

  it("keeps template criteria URL when TrustEd metadata only provides criteria narrative", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
    });
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:tenant_123": {
          tenantId: "tenant_123",
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        },
      }),
    };
    const trustedCredentialMetadataJson = JSON.stringify({
      ...completeTrustEdCredentialMetadataInput,
      criteria: {
        text: "API-authored criteria narrative.",
        uri: null,
      },
    });

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindBadgeTemplateById.mockResolvedValue(
      sampleBadgeTemplate({
        criteriaUri: "https://example.edu/template-criteria",
        trustedCredentialMetadataJson,
      }),
    );
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedNextAssertionStatusListIndex.mockResolvedValue(0);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "student@umich.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem-trusted-criteria",
        }),
      },
      env,
    );
    const body = await response.json<ManualIssueResponse>();
    const credentialSubject = asJsonObject(body.credential.credentialSubject);
    const achievement = asJsonObject(credentialSubject?.achievement);

    expect(response.status).toBe(201);
    expect(achievement?.criteria).toEqual(
      expect.objectContaining({
        id: "https://example.edu/template-criteria",
        narrative: "API-authored criteria narrative.",
      }),
    );
  });

  it("warns and issues without TrustEd fields when stored metadata is invalid", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
    });
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:tenant_123": {
          tenantId: "tenant_123",
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        },
      }),
    };
    consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindBadgeTemplateById.mockResolvedValue(
      sampleBadgeTemplate({ trustedCredentialMetadataJson: "{not-json" }),
    );
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedNextAssertionStatusListIndex.mockResolvedValue(0);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "student@umich.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem-trusted-invalid",
        }),
      },
      env,
    );
    const body = await response.json<ManualIssueResponse>();
    const credentialSubject = asJsonObject(body.credential.credentialSubject);
    const achievement = asJsonObject(credentialSubject?.achievement);
    const warningPayloads = (consoleLogSpy.mock.calls as unknown[][])
      .map((call) => (typeof call[0] === "string" ? (JSON.parse(call[0]) as unknown) : null))
      .filter((entry): entry is Record<string, unknown> => {
        return entry !== null && typeof entry === "object" && !Array.isArray(entry);
      });

    expect(response.status).toBe(201);
    expect(achievement?.skill).toBeUndefined();
    expect(achievement?.issuerAuthority).toBeUndefined();
    expect(credentialSubject?.evidence).toBeUndefined();
    expect(
      warningPayloads.some((payload) => {
        return (
          payload.level === "warn" &&
          payload.message === "trusted_credential_metadata_invalid" &&
          payload.badgeTemplateId === "badge_template_001"
        );
      }),
    ).toBe(true);
  });

  it("uses learner DID alias as credentialSubject.id when configured", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
    });
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:tenant_123": {
          tenantId: "tenant_123",
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        },
      }),
    };

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedListLearnerIdentitiesByProfile.mockResolvedValue([
      {
        id: "lid_did_subject_123",
        tenantId: "tenant_123",
        learnerProfileId: "lpr_123",
        identityType: "did",
        identityValue: "did:key:z6MkhLearnerSubjectDid",
        isPrimary: false,
        isVerified: true,
        createdAt: "2026-02-10T22:00:00.000Z",
        updatedAt: "2026-02-10T22:00:00.000Z",
      },
    ]);
    mockedNextAssertionStatusListIndex.mockResolvedValue(0);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "student@umich.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem-did-subject",
        }),
      },
      env,
    );
    const body = await response.json<ManualIssueResponse>();
    const subjectId = asString(asJsonObject(body.credential.credentialSubject)?.id);

    expect(response.status).toBe(201);
    expect(subjectId).toBe("did:key:z6MkhLearnerSubjectDid");
  });

  it("issues badges with remote signer custody when tenant private keys are not present in runtime", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
      keyId: "key-remote",
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      const request = jsonObjectFromRequestInitBody(init);
      const unsignedCredential = asJsonObject(request.credential);
      const verificationMethod = asString(request.verificationMethod);
      const createdAt = asString(request.createdAt);

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
        cryptosuite: "eddsa-rdfc-2022",
        ...(createdAt === null ? {} : { createdAt }),
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
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:tenant_123": {
          tenantId: "tenant_123",
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
        },
      }),
      TENANT_REMOTE_SIGNER_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:tenant_123": {
          url: "https://kms.credtrail.test/sign",
        },
      }),
    };

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedNextAssertionStatusListIndex.mockResolvedValue(0);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "student@umich.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem-remote-signer",
        }),
      },
      env,
    );
    const body = await response.json<ManualIssueResponse>();

    expect(response.status).toBe(201);
    expect(asJsonObject(body.credential.proof)).not.toBeNull();
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0]?.[0]).toBe("https://kms.credtrail.test/sign");

    fetchSpy.mockRestore();
  });

  it("allows viewer role manual issuance when delegated authority grant is active", async () => {
    const signingMaterial = await generateTenantDidSigningMaterial({
      did: "did:web:credtrail.test:tenant_123",
    });
    const env = {
      ...createEnv(),
      BADGE_OBJECTS: createInMemoryBadgeObjects(),
      TENANT_SIGNING_REGISTRY_JSON: JSON.stringify({
        "did:web:credtrail.test:tenant_123": {
          tenantId: "tenant_123",
          keyId: signingMaterial.keyId,
          publicJwk: signingMaterial.publicJwk,
          privateJwk: signingMaterial.privateJwk,
        },
      }),
    };

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedFindTenantMembership.mockResolvedValue(
      sampleTenantMembership({
        role: "viewer",
      }),
    );
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(
      sampleDelegatedIssuingAuthorityGrant({
        delegateUserId: "usr_123",
        allowedActions: ["issue_badge"],
        badgeTemplateIds: ["badge_template_001"],
      }),
    );
    mockedFindAssertionByIdempotencyKey.mockResolvedValue(null);
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedNextAssertionStatusListIndex.mockResolvedValue(0);
    mockedCreateAssertion.mockResolvedValue(sampleAssertion());

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "student@umich.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem-viewer-grant",
        }),
      },
      env,
    );

    expect(response.status).toBe(201);
    expect(mockedFindActiveDelegatedIssuingAuthorityGrantForAction).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        userId: "usr_123",
        requiredAction: "issue_badge",
        badgeTemplateId: "badge_template_001",
      }),
    );
    expect(mockedCreateAssertion).toHaveBeenCalledTimes(1);
  });

  it("returns 403 when role is viewer for manual issuance", async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedFindTenantMembership.mockResolvedValue(
      sampleTenantMembership({
        role: "viewer",
      }),
    );
    mockedTouchSession.mockResolvedValue(undefined);

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/manual-issue",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_001",
          recipientIdentity: "student@umich.edu",
          recipientIdentityType: "email",
          idempotencyKey: "idem-viewer",
        }),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toBe("Insufficient role for requested action");
    expect(mockedCreateAssertion).not.toHaveBeenCalled();
  });
});
