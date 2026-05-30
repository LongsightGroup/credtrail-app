import { beforeEach, describe, expect, it, vi } from "vitest";

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
    createAuditLog: vi.fn(),
    findActiveDelegatedIssuingAuthorityGrantForAction: vi.fn(),
    findActiveSessionByHash: mockedFindActiveSessionByHash,
    findAssertionById: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findTenantMembership: vi.fn(),
    findUserById: vi.fn(),
    hasTenantMembershipOrgUnitAccess: vi.fn(),
    hasTenantMembershipOrgUnitScopeAssignments: vi.fn(),
    listTenantAssertions: vi.fn(),
    listTenantAssertionLedgerExportRows: vi.fn(),
    listAssertionLifecycleEvents: vi.fn(),
    recordAssertionLifecycleTransition: vi.fn(),
    resolveAssertionLifecycleState: vi.fn(),
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
      revokeCurrentSession: vi.fn().mockResolvedValue(undefined),
    })),
  };
});

import {
  createAuditLog,
  findActiveDelegatedIssuingAuthorityGrantForAction,
  findAssertionById,
  findBadgeTemplateById,
  findTenantMembership,
  hasTenantMembershipOrgUnitAccess,
  hasTenantMembershipOrgUnitScopeAssignments,
  listTenantAssertions,
  listTenantAssertionLedgerExportRows,
  listAssertionLifecycleEvents,
  recordAssertionLifecycleTransition,
  resolveAssertionLifecycleState,
  type AssertionRecord,
  type AuditLogRecord,
  type BadgeTemplateRecord,
  type DelegatedIssuingAuthorityGrantRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantAssertionSummaryRecord,
  type TenantAssertionLedgerExportRowRecord,
  type TenantMembershipRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";

const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedFindActiveDelegatedIssuingAuthorityGrantForAction = vi.mocked(
  findActiveDelegatedIssuingAuthorityGrantForAction,
);
const mockedFindAssertionById = vi.mocked(findAssertionById);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedHasTenantMembershipOrgUnitAccess = vi.mocked(hasTenantMembershipOrgUnitAccess);
const mockedHasTenantMembershipOrgUnitScopeAssignments = vi.mocked(
  hasTenantMembershipOrgUnitScopeAssignments,
);
const mockedListTenantAssertions = vi.mocked(listTenantAssertions);
const mockedListTenantAssertionLedgerExportRows = vi.mocked(listTenantAssertionLedgerExportRows);
const mockedListAssertionLifecycleEvents = vi.mocked(listAssertionLifecycleEvents);
const mockedRecordAssertionLifecycleTransition = vi.mocked(recordAssertionLifecycleTransition);
const mockedResolveAssertionLifecycleState = vi.mocked(resolveAssertionLifecycleState);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

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

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    ...overrides,
    id: "aud_123",
    tenantId: "tenant_123",
    actorUserId: "usr_123",
    action: "assertion.issued",
    targetType: "assertion",
    targetId: "tenant_123:assertion_456",
    metadataJson: null,
    occurredAt: "2026-02-10T22:00:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
  };
};

const sampleLedgerExportRow = (
  overrides?: Partial<TenantAssertionLedgerExportRowRecord>,
): TenantAssertionLedgerExportRowRecord => {
  return {
    assertionId: "tenant_123:assertion_456",
    tenantId: "tenant_123",
    publicId: "public_456",
    badgeTemplateId: "badge_template_001",
    badgeTitle: "TypeScript Foundations",
    recipientIdentity: "=cmd|' /C calc'!A0",
    recipientIdentityType: "email",
    issuedAt: "2026-02-10T22:00:00.000Z",
    issuedByUserId: "usr_issuer",
    revokedAt: null,
    state: "active",
    source: "default_active",
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    orgUnitId: "tenant_123:org:institution",
    orgUnitDisplayName: "Tenant 123 Institution",
    attributionSource: "issuance_snapshot",
    currentInstitutionName: "Tenant 123 Institution",
    currentCollegeName: null,
    currentDepartmentName: null,
    currentProgramName: null,
    ...overrides,
  };
};

const sampleTenantAssertionSummary = (
  overrides?: Partial<TenantAssertionSummaryRecord>,
): TenantAssertionSummaryRecord => {
  return {
    assertionId: "tenant_123:assertion_456",
    tenantId: "tenant_123",
    publicId: "40a6dc92-85ec-4cb0-8a50-afb2ae700e22",
    badgeTemplateId: "badge_template_001",
    badgeTitle: "TypeScript Foundations",
    badgeImageUri: "https://example.edu/badges/typescript.png",
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    issuedAt: "2026-02-10T22:00:00.000Z",
    issuedByUserId: "usr_issuer",
    revokedAt: null,
    state: "active",
    source: "default_active",
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthPrincipal.mockImplementation(
    (context: { req: { header(name: string): string | undefined } }) => {
      const cookieHeader = context.req.header("cookie") ?? "";

      if (!cookieHeader.includes("better-auth.session_token=")) {
        return Promise.resolve(null);
      }

      return Promise.resolve({
        userId: "usr_123",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth" as const,
        expiresAt: "2026-02-11T22:00:00.000Z",
      });
    },
  );
  mockedResolveBetterAuthRequestedTenant.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue(null);
});

describe("assertion lifecycle endpoints", () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedFindAssertionById.mockReset();
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedFindBadgeTemplateById.mockReset();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindTenantMembership.mockReset();
    mockedFindTenantMembership.mockResolvedValue(sampleTenantMembership());
    mockedHasTenantMembershipOrgUnitScopeAssignments.mockReset();
    mockedHasTenantMembershipOrgUnitScopeAssignments.mockResolvedValue(false);
    mockedHasTenantMembershipOrgUnitAccess.mockReset();
    mockedHasTenantMembershipOrgUnitAccess.mockResolvedValue(false);
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockReset();
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(null);
    mockedListTenantAssertionLedgerExportRows.mockReset();
    mockedListTenantAssertionLedgerExportRows.mockResolvedValue({
      status: "ok",
      rowLimit: 5000,
      rows: [sampleLedgerExportRow()],
    });
    mockedResolveAssertionLifecycleState.mockReset();
    mockedListTenantAssertions.mockReset();
    mockedListTenantAssertions.mockResolvedValue([]);
    mockedListAssertionLifecycleEvents.mockReset();
    mockedRecordAssertionLifecycleTransition.mockReset();
    mockedCreateAuditLog.mockClear();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
  });

  it("lists tenant assertions for issuer roles", async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedListTenantAssertions.mockResolvedValue([sampleTenantAssertionSummary()]);

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions?badgeTemplateId=badge_template_001&state=active&limit=25",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body.count).toBe(1);
    expect(Array.isArray(body.assertions)).toBe(true);
    expect(mockedListTenantAssertions).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
      state: "active",
      limit: 25,
    });
  });

  it("returns 400 for invalid assertion list query filters", async () => {
    const env = createEnv();
    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions?state=paused",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(400);
    expect(body.error).toBe("Invalid assertion list query parameters");
    expect(mockedListTenantAssertions).not.toHaveBeenCalled();
  });

  it("returns assertion lifecycle state and history for issuer roles", async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedResolveAssertionLifecycleState.mockResolvedValue({
      state: "suspended",
      source: "lifecycle_event",
      reasonCode: "administrative_hold",
      reason: "Pending registrar review",
      transitionedAt: "2026-02-12T23:10:00.000Z",
      revokedAt: null,
    });
    mockedListAssertionLifecycleEvents.mockResolvedValue([
      {
        id: "ale_123",
        tenantId: "tenant_123",
        assertionId: "tenant_123:assertion_456",
        fromState: "active",
        toState: "suspended",
        reasonCode: "administrative_hold",
        reason: "Pending registrar review",
        transitionSource: "manual",
        actorUserId: "usr_123",
        transitionedAt: "2026-02-12T23:10:00.000Z",
        createdAt: "2026-02-12T23:10:00.000Z",
      },
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/tenant_123%3Aassertion_456/lifecycle",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body.state).toBe("suspended");
    expect(body.reasonCode).toBe("administrative_hold");
    expect(Array.isArray(body.events)).toBe(true);
    expect(mockedResolveAssertionLifecycleState).toHaveBeenCalledWith(
      fakeDb,
      "tenant_123",
      "tenant_123:assertion_456",
    );
  });

  it("applies manual lifecycle transition and writes audit log", async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedRecordAssertionLifecycleTransition.mockResolvedValue({
      status: "transitioned",
      fromState: "active",
      toState: "suspended",
      currentState: "suspended",
      message: null,
      event: {
        id: "ale_456",
        tenantId: "tenant_123",
        assertionId: "tenant_123:assertion_456",
        fromState: "active",
        toState: "suspended",
        reasonCode: "administrative_hold",
        reason: "Registrar hold",
        transitionSource: "manual",
        actorUserId: "usr_123",
        transitionedAt: "2026-02-12T23:15:00.000Z",
        createdAt: "2026-02-12T23:15:00.000Z",
      },
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/tenant_123%3Aassertion_456/lifecycle/transition",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          toState: "suspended",
          reasonCode: "administrative_hold",
          reason: "Registrar hold",
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body.status).toBe("transitioned");
    expect(mockedRecordAssertionLifecycleTransition).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        assertionId: "tenant_123:assertion_456",
        toState: "suspended",
        reasonCode: "administrative_hold",
        transitionSource: "manual",
        actorUserId: "usr_123",
      }),
    );
    expect(mockedCreateAuditLog).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        action: "assertion.lifecycle_transitioned",
        targetType: "assertion",
        targetId: "tenant_123:assertion_456",
      }),
    );
  });

  it("allows viewer lifecycle revocation when delegated authority grant is active", async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedFindTenantMembership.mockResolvedValue(
      sampleTenantMembership({
        role: "viewer",
      }),
    );
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindAssertionById.mockResolvedValue(sampleAssertion());
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(
      sampleDelegatedIssuingAuthorityGrant({
        delegateUserId: "usr_123",
        allowedActions: ["revoke_badge"],
        badgeTemplateIds: ["badge_template_001"],
      }),
    );
    mockedRecordAssertionLifecycleTransition.mockResolvedValue({
      status: "transitioned",
      fromState: "active",
      toState: "revoked",
      currentState: "revoked",
      message: null,
      event: {
        id: "ale_rev_123",
        tenantId: "tenant_123",
        assertionId: "tenant_123:assertion_456",
        fromState: "active",
        toState: "revoked",
        reasonCode: "policy_violation",
        reason: "Integrity failure",
        transitionSource: "manual",
        actorUserId: "usr_123",
        transitionedAt: "2026-02-12T23:15:00.000Z",
        createdAt: "2026-02-12T23:15:00.000Z",
      },
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/tenant_123%3Aassertion_456/lifecycle/transition",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          toState: "revoked",
          reasonCode: "policy_violation",
          reason: "Integrity failure",
        }),
      },
      env,
    );

    expect(response.status).toBe(200);
    expect(mockedFindActiveDelegatedIssuingAuthorityGrantForAction).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        userId: "usr_123",
        badgeTemplateId: "badge_template_001",
        requiredAction: "revoke_badge",
      }),
    );
    expect(mockedRecordAssertionLifecycleTransition).toHaveBeenCalledTimes(1);
  });

  it("returns 422 when caller attempts automation transition source", async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/tenant_123%3Aassertion_456/lifecycle/transition",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          toState: "expired",
          reasonCode: "credential_expired",
          transitionSource: "automation",
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(422);
    expect(body.error).toBe(
      "Automation lifecycle transitions are only allowed via trusted internal jobs",
    );
    expect(mockedRecordAssertionLifecycleTransition).not.toHaveBeenCalled();
    expect(mockedCreateAuditLog).not.toHaveBeenCalled();
  });

  it("returns 409 when lifecycle transition is not allowed", async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedRecordAssertionLifecycleTransition.mockResolvedValue({
      status: "invalid_transition",
      fromState: "revoked",
      toState: "active",
      currentState: "revoked",
      event: null,
      message: "transition from revoked to active is not allowed",
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/tenant_123%3Aassertion_456/lifecycle/transition",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/json",
          Cookie: "better-auth.session_token=session-token",
        },
        body: JSON.stringify({
          toState: "active",
          reasonCode: "appeal_resolved",
        }),
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(409);
    expect(body.error).toBe("Lifecycle transition not allowed");
    expect(mockedCreateAuditLog).not.toHaveBeenCalled();
  });
});

describe("GET /v1/tenants/:tenantId/assertions/ledger-export.csv", () => {
  beforeEach(() => {
    mockedFindActiveSessionByHash.mockReset();
    mockedTouchSession.mockReset();
    mockedFindTenantMembership.mockReset();
    mockedListTenantAssertionLedgerExportRows.mockReset();
    mockedListTenantAssertionLedgerExportRows.mockResolvedValue({
      status: "ok",
      rowLimit: 5000,
      rows: [sampleLedgerExportRow()],
    });
  });

  it("allows owner and admin users to download the issued-badge ledger CSV", async () => {
    const env = createEnv();

    for (const role of ["owner", "admin"] as const) {
      mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
      mockedTouchSession.mockResolvedValue(undefined);
      mockedFindTenantMembership.mockResolvedValue(
        sampleTenantMembership({
          role,
        }),
      );

      const response = await app.request(
        "/v1/tenants/tenant_123/assertions/ledger-export.csv?issuedFrom=2026-02-01&issuedTo=2026-02-29&recipientQuery=learner",
        {
          method: "GET",
          headers: {
            Cookie: "better-auth.session_token=session-token",
          },
        },
        env,
      );
      const body = await response.text();

      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("content-type")).toBe("text/csv; charset=utf-8");
      expect(response.headers.get("content-disposition")).toContain(
        'attachment; filename="issued-badge-ledger-',
      );
      expect(body.startsWith("Assertion ID,")).toBe(true);
      expect(body).toContain("'=cmd|' /C calc'!A0");
    }

    expect(mockedListTenantAssertionLedgerExportRows).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      issuedFrom: "2026-02-01",
      issuedTo: "2026-02-29",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      recipientQuery: "learner",
      state: undefined,
    });
  });

  it("denies issuer-role users access to the recipient-level ledger export", async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindTenantMembership.mockResolvedValue(
      sampleTenantMembership({
        role: "issuer",
      }),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/ledger-export.csv",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(403);
    expect(mockedListTenantAssertionLedgerExportRows).not.toHaveBeenCalled();
  });

  it("returns a clear over-cap error when more than 5000 ledger rows match", async () => {
    const env = createEnv();

    mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
    mockedTouchSession.mockResolvedValue(undefined);
    mockedFindTenantMembership.mockResolvedValue(
      sampleTenantMembership({
        role: "admin",
      }),
    );
    mockedListTenantAssertionLedgerExportRows.mockResolvedValue({
      status: "too_large",
      rowLimit: 5000,
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/assertions/ledger-export.csv",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<Record<string, unknown>>();

    expect(response.status).toBe(413);
    expect(body).toEqual({
      error: "export_too_large",
      rowLimit: 5000,
      message: "Synchronous export is limited to 5000 rows. Narrow your filters and try again.",
    });
  });
});
