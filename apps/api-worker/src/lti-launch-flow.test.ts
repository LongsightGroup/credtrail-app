import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setCookie } from "hono/cookie";
import { LTI13JwtPayloadSchema, serializeLtiSession } from "@longsightgroup/lti-tool";
import {
  buildBadgeRuleVersionRecord,
  type BadgeRuleVersionRecordOverrides,
} from "./test-support/badge-rule-version";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    addLearnerIdentityAlias: vi.fn(),
    attachLtiLaunchSessionPrincipal: vi.fn(),
    createAuthIdentityLink: vi.fn(),
    createAuditLog: vi.fn(),
    createLtiCourseBadgeRule: vi.fn(),
    ensureExternalCourseOrgUnit: vi.fn(),
    ensureTenantMembership: vi.fn(),
    findActiveBadgeIssuanceRuleVersion: vi.fn(),
    findActiveDelegatedIssuingAuthorityGrantForAction: vi.fn(),
    findDelegatedIssuingAuthorityGrantFromActiveGrants: vi.fn(),
    listActiveDelegatedIssuingAuthorityGrantsForUser: vi.fn(),
    findAuthIdentityLinkByAuthUserId: vi.fn(),
    findAuthIdentityLinkByCredtrailUserId: vi.fn(),
    findBadgeIssuanceRuleById: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findLtiResourceLinkPlacement: vi.fn(),
    findLtiLaunchSessionById: vi.fn(),
    findActiveLtiLaunchSessionByOpaqueId: vi.fn(),
    findClaimableLearnerBadgeSummary: vi.fn(),
    findLearnerProfileByIdentity: vi.fn(),
    findUserById: vi.fn(),
    listAssertionEngagementEvents: vi.fn(),
    listAssertionsByBadgeTemplatesAndRecipientEmails: vi.fn(),
    listAssertionLifecycleStatesByAssertionIds: vi.fn(),
    listAssertionsByIdempotencyKeys: vi.fn(),
    listBadgeTemplates: vi.fn(),
    listBadgeTemplatesByIds: vi.fn(),
    listLearnerBadgeSummaries: vi.fn(),
    listAllLtiIssuerRegistrations: vi.fn(),
    listLtiResourceLinkPlacementsForContext: vi.fn(),
    listLtiResourceLinkPlacementRuleStates: vi.fn(),
    listTenantLmsConnections: vi.fn(),
    moveLearnerIdentityAliasToProfile: vi.fn(),
    resolveLearnerProfileFromSaml: vi.fn(),
    recordAssertionEngagementEvent: vi.fn(),
    upsertLtiDeployment: vi.fn(),
    upsertLtiLaunchSession: vi.fn(),
    resolveLearnerProfileForIdentity: vi.fn(),
    upsertLtiResourceLinkPlacement: vi.fn(),
    upsertTenantMembershipRole: vi.fn(),
    upsertUserByEmail: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

vi.mock("./rules/badge-rule-facts-loader", () => ({
  loadRuleFacts: vi.fn(),
}));

import {
  addLearnerIdentityAlias,
  attachLtiLaunchSessionPrincipal,
  createAuthIdentityLink,
  createAuditLog,
  createLtiCourseBadgeRule,
  ensureExternalCourseOrgUnit,
  ensureTenantMembership,
  findActiveBadgeIssuanceRuleVersion,
  findActiveDelegatedIssuingAuthorityGrantForAction,
  findDelegatedIssuingAuthorityGrantFromActiveGrants,
  findAuthIdentityLinkByAuthUserId,
  findAuthIdentityLinkByCredtrailUserId,
  findBadgeIssuanceRuleById,
  findBadgeTemplateById,
  findLtiResourceLinkPlacement,
  findLtiLaunchSessionById,
  findActiveLtiLaunchSessionByOpaqueId,
  findClaimableLearnerBadgeSummary,
  findLearnerProfileByIdentity,
  findUserById,
  listAssertionEngagementEvents,
  listAssertionsByBadgeTemplatesAndRecipientEmails,
  listAssertionLifecycleStatesByAssertionIds,
  listAssertionsByIdempotencyKeys,
  listActiveDelegatedIssuingAuthorityGrantsForUser,
  listBadgeTemplates,
  listBadgeTemplatesByIds,
  listLearnerBadgeSummaries,
  listAllLtiIssuerRegistrations,
  listLtiResourceLinkPlacementsForContext,
  listLtiResourceLinkPlacementRuleStates,
  listTenantLmsConnections,
  moveLearnerIdentityAliasToProfile,
  resolveLearnerProfileFromSaml,
  recordAssertionEngagementEvent,
  resolveLearnerProfileForIdentity,
  type AssertionRecord,
  type AuditLogRecord,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type DelegatedIssuingAuthorityGrantRecord,
  type LearnerBadgeSummaryRecord,
  upsertLtiResourceLinkPlacement,
  upsertLtiLaunchSession,
  upsertTenantMembershipRole,
  upsertUserByEmail,
  type LearnerProfileRecord,
  type LtiIssuerRegistrationRecord,
  type LtiLaunchSessionRecord,
  type LtiResourceLinkPlacementRecord,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
  type TenantMembershipRecord,
} from "@credtrail/db";
import type { LTISession } from "@longsightgroup/lti-tool";
import {
  mockLtiToolCreateAdvantageForSession,
  mockLtiToolWithDeepLinking,
} from "./lti/test-support/lti-tool-mocks";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";
import { loadRuleFacts } from "./rules/badge-rule-facts-loader";
import { readScriptAssetSource } from "./page-asset-test-utils";
import { createLtiCourseBadgeSetupToken } from "./lti/course-badge-setup-token";

interface ErrorResponse {
  error: string;
}

const LTI_POST_MESSAGE_STORAGE_JS = readScriptAssetSource("ltiPostMessageStorageJs");

const mockedAddLearnerIdentityAlias = vi.mocked(addLearnerIdentityAlias);
const mockedAttachLtiLaunchSessionPrincipal = vi.mocked(attachLtiLaunchSessionPrincipal);
const mockedCreateAuthIdentityLink = vi.mocked(createAuthIdentityLink);
const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedEnsureExternalCourseOrgUnit = vi.mocked(ensureExternalCourseOrgUnit);
const mockedEnsureTenantMembership = vi.mocked(ensureTenantMembership);
const mockedFindActiveBadgeIssuanceRuleVersion = vi.mocked(findActiveBadgeIssuanceRuleVersion);
const mockedFindActiveDelegatedIssuingAuthorityGrantForAction = vi.mocked(
  findActiveDelegatedIssuingAuthorityGrantForAction,
);
const mockedFindDelegatedIssuingAuthorityGrantFromActiveGrants = vi.mocked(
  findDelegatedIssuingAuthorityGrantFromActiveGrants,
);
const mockedListActiveDelegatedIssuingAuthorityGrantsForUser = vi.mocked(
  listActiveDelegatedIssuingAuthorityGrantsForUser,
);
const mockedFindAuthIdentityLinkByAuthUserId = vi.mocked(findAuthIdentityLinkByAuthUserId);
const mockedFindAuthIdentityLinkByCredtrailUserId = vi.mocked(
  findAuthIdentityLinkByCredtrailUserId,
);
const mockedFindBadgeIssuanceRuleById = vi.mocked(findBadgeIssuanceRuleById);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedFindLtiResourceLinkPlacement = vi.mocked(findLtiResourceLinkPlacement);
const mockedFindLtiLaunchSessionById = vi.mocked(findLtiLaunchSessionById);
const mockedFindActiveLtiLaunchSessionByOpaqueId = vi.mocked(findActiveLtiLaunchSessionByOpaqueId);
const mockedFindClaimableLearnerBadgeSummary = vi.mocked(findClaimableLearnerBadgeSummary);
const mockedFindLearnerProfileByIdentity = vi.mocked(findLearnerProfileByIdentity);
const mockedFindUserById = vi.mocked(findUserById);
const mockedListAssertionEngagementEvents = vi.mocked(listAssertionEngagementEvents);
const mockedListAssertionsByBadgeTemplatesAndRecipientEmails = vi.mocked(
  listAssertionsByBadgeTemplatesAndRecipientEmails,
);
const mockedListAssertionLifecycleStatesByAssertionIds = vi.mocked(
  listAssertionLifecycleStatesByAssertionIds,
);
const mockedListAssertionsByIdempotencyKeys = vi.mocked(listAssertionsByIdempotencyKeys);
const mockedListBadgeTemplates = vi.mocked(listBadgeTemplates);
const mockedListBadgeTemplatesByIds = vi.mocked(listBadgeTemplatesByIds);
const mockedListLearnerBadgeSummaries = vi.mocked(listLearnerBadgeSummaries);
const mockedListLtiIssuerRegistrations = vi.mocked(listAllLtiIssuerRegistrations);
const mockedListLtiResourceLinkPlacementsForContext = vi.mocked(
  listLtiResourceLinkPlacementsForContext,
);
const mockedListLtiResourceLinkPlacementRuleStates = vi.mocked(
  listLtiResourceLinkPlacementRuleStates,
);
const mockedListTenantLmsConnections = vi.mocked(listTenantLmsConnections);
const mockedMoveLearnerIdentityAliasToProfile = vi.mocked(moveLearnerIdentityAliasToProfile);
const mockedResolveLearnerProfileFromSaml = vi.mocked(resolveLearnerProfileFromSaml);
const mockedRecordAssertionEngagementEvent = vi.mocked(recordAssertionEngagementEvent);
const mockedResolveLearnerProfileForIdentity = vi.mocked(resolveLearnerProfileForIdentity);
const mockedCreateLtiCourseBadgeRule = vi.mocked(createLtiCourseBadgeRule);
const mockedUpsertLtiResourceLinkPlacement = vi.mocked(upsertLtiResourceLinkPlacement);
const mockedUpsertLtiLaunchSession = vi.mocked(upsertLtiLaunchSession);
const mockedUpsertTenantMembershipRole = vi.mocked(upsertTenantMembershipRole);
const mockedUpsertUserByEmail = vi.mocked(upsertUserByEmail);
const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const mockedLoadRuleFacts = vi.mocked(loadRuleFacts);

interface AuthUserRow {
  id: string;
  email: string | null;
  email_verified: boolean;
}

interface AuthSessionRow {
  id: string;
  token: string;
  user_id: string;
  expires_at: string;
  ip_address: string | null;
  user_agent: string | null;
}

interface AuthIdentityLinkRow {
  id: string;
  authSystem: string;
  authUserId: string;
  authAccountId: string | null;
  credtrailUserId: string;
  emailSnapshot: string | null;
  createdAt: string;
  updatedAt: string;
}

const authUsers: AuthUserRow[] = [];
const authSessions: AuthSessionRow[] = [];
const authIdentityLinks: AuthIdentityLinkRow[] = [];

const coerceBoundText = (value: unknown): string => {
  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "number" || typeof value === "bigint" || typeof value === "boolean") {
    return String(value);
  }

  return "";
};

const fakeDbPrepare = vi.fn((sql: string) => {
  const normalizedSql = sql.replace(/\s+/g, " ").trim();
  let params: unknown[] = [];

  return {
    bind(...boundParams: unknown[]) {
      params = boundParams;
      return this;
    },
    first: async <T>() => {
      if (
        normalizedSql.includes("FROM auth.user") &&
        normalizedSql.includes("LOWER(email) = LOWER(?)")
      ) {
        const email = coerceBoundText(params[0]).toLowerCase();
        const row =
          authUsers.find((candidate) => (candidate.email ?? "").toLowerCase() === email) ?? null;

        return row === null
          ? null
          : ({
              id: row.id,
              email: row.email,
              emailVerified: row.email_verified,
            } as T);
      }

      if (
        normalizedSql.includes("FROM auth.session AS session") &&
        normalizedSql.includes("WHERE session.token = ?")
      ) {
        const token = coerceBoundText(params[0]);
        const session = authSessions.find((candidate) => candidate.token === token) ?? null;
        const user =
          session === null
            ? null
            : (authUsers.find((candidate) => candidate.id === session.user_id) ?? null);

        return session === null
          ? null
          : ({
              sessionId: session.id,
              sessionToken: session.token,
              userId: session.user_id,
              expiresAt: session.expires_at,
              userEmail: user?.email ?? null,
              userEmailVerified: user?.email_verified ?? false,
            } as T);
      }

      if (
        normalizedSql.includes("FROM memberships") &&
        normalizedSql.includes("WHERE tenant_id = ?") &&
        normalizedSql.includes("AND user_id = ?")
      ) {
        return {
          tenantId: coerceBoundText(params[0]),
          userId: coerceBoundText(params[1]),
          role: "viewer",
          createdAt: "2026-02-10T22:00:00.000Z",
          updatedAt: "2026-02-10T22:00:00.000Z",
        } as T;
      }

      if (
        normalizedSql.includes("FROM tenant_lms_connections") &&
        normalizedSql.includes("lti_issuer = ?") &&
        normalizedSql.includes("lti_client_id = ?") &&
        normalizedSql.includes("lti_deployment_id = ?")
      ) {
        return null;
      }

      throw new Error(`Unhandled fakeDb first() SQL: ${normalizedSql}`);
    },
    all: async <T>() => {
      return {
        success: true,
        meta: {},
        results: [] as T[],
      };
    },
    run: async () => {
      if (normalizedSql === "BEGIN" || normalizedSql === "COMMIT" || normalizedSql === "ROLLBACK") {
        return {
          success: true,
          meta: {},
        };
      }

      if (normalizedSql.includes("INSERT INTO auth.user")) {
        authUsers.push({
          id: coerceBoundText(params[0]),
          email: (params[1] as string | null | undefined) ?? null,
          email_verified: Boolean(params[2]),
        });
        return {
          success: true,
          meta: {},
        };
      }

      if (normalizedSql.includes("INSERT INTO auth.session")) {
        authSessions.push({
          id: coerceBoundText(params[0]),
          token: coerceBoundText(params[1]),
          user_id: coerceBoundText(params[2]),
          expires_at: coerceBoundText(params[3]),
          ip_address: (params[4] as string | null | undefined) ?? null,
          user_agent: (params[5] as string | null | undefined) ?? null,
        });
        return {
          success: true,
          meta: {},
        };
      }

      throw new Error(`Unhandled fakeDb run() SQL: ${normalizedSql}`);
    },
  };
});

const fakeDb = {
  prepare: fakeDbPrepare,
} as unknown as SqlDatabase;

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  PUBLIC_APP_ORIGIN: string;
  LTI_ISSUER_REGISTRY_JSON?: string;
  LTI_STATE_SIGNING_SECRET?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

const sampleUserRecord = (overrides?: {
  id?: string;
  email?: string;
}): { id: string; email: string } => {
  return {
    id: overrides?.id ?? "usr_123",
    email: overrides?.email ?? "learner@example.edu",
  };
};

const sampleLtiIssuerRegistration = (
  overrides?: Partial<LtiIssuerRegistrationRecord>,
): LtiIssuerRegistrationRecord => {
  return {
    issuer: "https://canvas.example.edu",
    tenantId: "tenant_123",
    authorizationEndpoint: "https://canvas.example.edu/api/lti/authorize_redirect",
    clientId: "canvas-client-123",
    platformJwksEndpoint: null,
    tokenEndpoint: null,
    clientSecret: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
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

interface MockedInternalAuthProvider {
  requestMagicLink: ReturnType<typeof vi.fn>;
  createMagicLinkSession: ReturnType<typeof vi.fn>;
  createLtiSession: ReturnType<typeof vi.fn>;
  resolveAuthenticatedPrincipal: ReturnType<typeof vi.fn>;
  resolveRequestedTenantContext: ReturnType<typeof vi.fn>;
  revokeCurrentSession: ReturnType<typeof vi.fn>;
}

const loadAppWithMockedAuthProviders = async (
  beforeImport?: () => void,
): Promise<{
  app: typeof app;
  betterAuthProvider: MockedInternalAuthProvider;
}> => {
  vi.resetModules();
  const betterAuthProvider: MockedInternalAuthProvider = {
    requestMagicLink: vi.fn(),
    createMagicLinkSession: vi.fn(),
    createLtiSession: vi.fn(
      (context: Parameters<typeof setCookie>[0], input: { tenantId: string; userId: string }) => {
        if (!authUsers.some((user) => user.id === input.userId)) {
          authUsers.push({
            id: input.userId,
            email: "learner@example.edu",
            email_verified: true,
          });
        }
        authSessions.push({
          id: "ba_ses_adapter",
          token: "better-lti-session",
          user_id: input.userId,
          expires_at: "2026-02-11T22:00:00.000Z",
          ip_address: null,
          user_agent: null,
        });
        setCookie(context, "better-auth.session_token", "better-lti-session", {
          httpOnly: true,
          sameSite: "None",
          secure: true,
          path: "/",
        });
        return Promise.resolve({
          userId: input.userId,
          authSessionId: "ba_ses_adapter",
          authMethod: "better_auth" as const,
          expiresAt: "2026-02-11T22:00:00.000Z",
          browserSessionToken: "better-lti-session",
        });
      },
    ),
    resolveAuthenticatedPrincipal: vi.fn(() => Promise.resolve(null)),
    resolveRequestedTenantContext: vi.fn(() => Promise.resolve(null)),
    revokeCurrentSession: vi.fn(() => Promise.resolve()),
  };

  vi.doMock("./auth/better-auth-adapter", async () => {
    const actual = await vi.importActual<typeof import("./auth/better-auth-adapter")>(
      "./auth/better-auth-adapter",
    );

    return {
      ...actual,
      createBetterAuthProvider: vi.fn(() => betterAuthProvider),
    };
  });

  beforeImport?.();

  const { app: isolatedApp } = await import("./index");

  return {
    app: isolatedApp,
    betterAuthProvider,
  };
};

const sampleBadgeTemplate = (overrides?: {
  id?: string;
  title?: string;
  description?: string | null;
  imageUri?: string | null;
  governanceMetadataJson?: string | null;
}): {
  id: string;
  tenantId: string;
  slug: string;
  title: string;
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
  createdByUserId: string | null;
  ownerOrgUnitId: string;
  governanceMetadataJson: string | null;
  isArchived: boolean;
  createdAt: string;
  updatedAt: string;
} => {
  return {
    id: overrides?.id ?? "badge_template_001",
    tenantId: "tenant_123",
    slug: "typescript-foundations",
    title: overrides?.title ?? "TypeScript Foundations",
    description:
      overrides?.description === undefined
        ? "Awarded for completing TypeScript fundamentals."
        : overrides.description,
    criteriaUri: "https://example.edu/criteria",
    imageUri:
      overrides?.imageUri === undefined ? "https://example.edu/image.png" : overrides.imageUri,
    createdByUserId: "usr_123",
    ownerOrgUnitId: "tenant_123:org:department-cs",
    governanceMetadataJson:
      overrides?.governanceMetadataJson ??
      JSON.stringify({ ltiInstructorPlacement: { enabled: true } }),
    isArchived: false,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
  };
};

const sampleDelegatedIssuingAuthorityGrant = (
  overrides?: Partial<DelegatedIssuingAuthorityGrantRecord>,
): DelegatedIssuingAuthorityGrantRecord => {
  return {
    id: "diag_lti_course_setup_123",
    tenantId: "tenant_123",
    delegateUserId: "usr_lti_123",
    delegatedByUserId: "usr_admin_123",
    orgUnitId: "tenant_123:org:department-cs",
    allowedActions: ["issue_badge", "revoke_badge", "manage_lifecycle", "configure_course_rule"],
    badgeTemplateIds: ["badge_template_001"],
    startsAt: "2026-02-01T00:00:00.000Z",
    endsAt: "2026-06-01T00:00:00.000Z",
    revokedAt: null,
    revokedByUserId: null,
    revokedReason: null,
    status: "active",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleAuditLog = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    id: "aud_lti_123",
    tenantId: "tenant_123",
    actorUserId: "usr_lti_123",
    action: "lti.course_badge_setup_submitted",
    targetType: "badge_issuance_rule",
    targetId: "brl_lti_rule_123",
    metadataJson: null,
    occurredAt: "2026-02-10T22:00:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleTenantLmsConnection = (
  overrides?: Partial<TenantLmsConnectionRecord>,
): TenantLmsConnectionRecord => {
  return {
    id: "lms_sakai_001",
    tenantId: "tenant_123",
    displayName: "Sakai LTI connection",
    providerKind: "sakai",
    apiBaseUrl: "https://canvas.example.edu",
    authorizationEndpoint: null,
    tokenEndpoint: null,
    clientId: null,
    clientSecret: null,
    scope: null,
    accessToken: null,
    refreshToken: null,
    accessTokenExpiresAt: null,
    refreshTokenExpiresAt: null,
    connectedAt: "2026-02-10T22:00:00.000Z",
    ltiIssuer: "https://canvas.example.edu",
    ltiClientId: "canvas-client-123",
    ltiDeploymentId: "deployment-123",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleBadgeIssuanceRule = (
  overrides?: Partial<BadgeIssuanceRuleRecord>,
): BadgeIssuanceRuleRecord => {
  return {
    id: "brl_lti_rule_123",
    tenantId: "tenant_123",
    name: "Sakai course rule: Introduction to TypeScript · TypeScript Foundations",
    description: "Created from LTI Deep Linking for Introduction to TypeScript.",
    badgeTemplateId: "badge_template_001",
    orgUnitId: "tenant_123:org:course-typescript-101",
    ownerOrgUnitId: "tenant_123:org:institution",
    lmsProviderKind: "sakai",
    lmsConnectionId: "lms_sakai_001",
    activeVersionId: null,
    createdByUserId: "usr_lti_123",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleBadgeIssuanceRuleVersion = (
  overrides: BadgeRuleVersionRecordOverrides = {},
): BadgeIssuanceRuleVersionRecord => {
  const { snapshot, ...versionOverrides } = overrides;

  return buildBadgeRuleVersionRecord({
    id: "brlv_lti_rule_123_v1",
    ruleId: "brl_lti_rule_123",
    ruleJson: JSON.stringify({
      conditions: {
        type: "grade_threshold",
        courseId: "course-123",
        scoreField: "final_score",
        minScore: 85,
      },
      options: {
        issuanceTiming: "manual",
        reviewOnMissingFacts: true,
      },
    }),
    changeSummary: "Created from LTI Deep Linking course badge setup.",
    createdByUserId: "usr_lti_123",
    submittedByUserId: null,
    submittedAt: null,
    approvedByUserId: null,
    approvedAt: null,
    activatedByUserId: null,
    activatedAt: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...versionOverrides,
    snapshot: {
      name: "LTI course badge rule",
      badgeTemplateId: "badge_template_001",
      badgeTemplateTitle: "Course badge",
      orgUnitId: "tenant_123:org:course-typescript-101",
      lmsProviderKind: "sakai",
      lmsConnectionId: "lms_sakai_001",
      ...snapshot,
    },
  });
};

const sampleAssertionRecord = (overrides?: Partial<AssertionRecord>): AssertionRecord => {
  return {
    id: "tenant_123:assertion_existing",
    tenantId: "tenant_123",
    publicId: null,
    learnerProfileId: "lpr_123",
    badgeTemplateId: "badge_template_001",
    achievementSnapshotStatus: "captured",
    achievementSnapshot: {
      badgeTemplateId: "badge_template_001",
      title: "TypeScript Foundations",
      description: "Awarded for completing TypeScript fundamentals.",
      criteriaUri: "https://example.edu/criteria/typescript",
      imageUri: null,
      trustedCredentialMetadataJson: null,
    },
    recipientIdentity: "learner-one@example.edu",
    recipientIdentityType: "email",
    vcR2Key: "tenants/tenant_123/assertions/tenant_123%3Aassertion_existing.jsonld",
    statusListIndex: 1,
    idempotencyKey: "lti:existing",
    issuedAt: "2026-05-18T18:00:00.000Z",
    issuedByUserId: "usr_lti_123",
    revokedAt: null,
    createdAt: "2026-05-18T18:00:00.000Z",
    updatedAt: "2026-05-18T18:00:00.000Z",
    ...overrides,
  };
};

const sampleLearnerBadgeSummary = (
  overrides?: Partial<LearnerBadgeSummaryRecord>,
): LearnerBadgeSummaryRecord => {
  return {
    assertionId: "tenant_123:assertion_existing",
    assertionPublicId: "public_badge_001",
    tenantId: "tenant_123",
    badgeTemplateId: "badge_template_001",
    badgeTitle: "TypeScript Foundations",
    badgeDescription: "Awarded for completing TypeScript fundamentals.",
    issuedAt: "2026-02-11T14:00:00.000Z",
    revokedAt: null,
    ...overrides,
  };
};

const sampleLtiResourceLinkPlacement = (
  overrides?: Partial<Extract<LtiResourceLinkPlacementRecord, { status: "active" }>>,
): Extract<LtiResourceLinkPlacementRecord, { status: "active" }> => {
  return {
    id: "lti_place_123",
    tenantId: "tenant_123",
    issuer: "https://canvas.example.edu",
    clientId: "canvas-client-123",
    deploymentId: "deployment-123",
    contextId: "course-123",
    resourceLinkId: "resource-link-placed-badge",
    badgeTemplateId: "badge_template_001",
    ruleId: "brl_lti_rule_123",
    createdByUserId: "usr_lti_123",
    status: "active",
    lastSeenAt: "2026-02-10T22:00:00.000Z",
    retiredAt: null,
    retiredByUserId: null,
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const sampleLtiLaunchSessionRecord = (
  overrides?: Partial<LtiLaunchSessionRecord>,
): LtiLaunchSessionRecord => {
  return {
    id: "lti-session-123",
    issuer: "https://canvas.example.edu",
    clientId: "canvas-client-123",
    deploymentId: "deployment-123",
    tenantId: "tenant_123",
    userId: "usr_lti_123",
    dataJson: "{}",
    expiresAt: "2026-02-10T23:00:00.000Z",
    createdAt: "2026-02-10T22:00:00.000Z",
    updatedAt: "2026-02-10T22:00:00.000Z",
    ...overrides,
  };
};

const bytesToBase64UrlForTest = (bytes: Uint8Array): string => {
  let raw = "";

  for (const byte of bytes) {
    raw += String.fromCharCode(byte);
  }

  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const compactJwsForTest = (input: {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}): string => {
  const headerSegment = bytesToBase64UrlForTest(
    new TextEncoder().encode(JSON.stringify(input.header)),
  );
  const payloadSegment = bytesToBase64UrlForTest(
    new TextEncoder().encode(JSON.stringify(input.payload)),
  );
  return `${headerSegment}.${payloadSegment}.signature`;
};

const ltiClaim = {
  context: "https://purl.imsglobal.org/spec/lti/claim/context",
  custom: "https://purl.imsglobal.org/spec/lti/claim/custom",
  deepLinkingSettings: "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings",
  deploymentId: "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
  lis: "https://purl.imsglobal.org/spec/lti/claim/lis",
  messageType: "https://purl.imsglobal.org/spec/lti/claim/message_type",
  namesRoleService: "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice",
  resourceLink: "https://purl.imsglobal.org/spec/lti/claim/resource_link",
  roles: "https://purl.imsglobal.org/spec/lti/claim/roles",
  targetLinkUri: "https://purl.imsglobal.org/spec/lti/claim/target_link_uri",
  version: "https://purl.imsglobal.org/spec/lti/claim/version",
} as const;

const parseBase64UrlJsonSegmentForTest = (segment: string): Record<string, unknown> => {
  const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = `${normalized}${"=".repeat((4 - (normalized.length % 4)) % 4)}`;
  const decoded = atob(padded);

  return JSON.parse(decoded) as Record<string, unknown>;
};

const parseCompactJwtPayloadForTest = (compactJwt: string): Record<string, unknown> => {
  const [, payloadSegment] = compactJwt.split(".");

  if (payloadSegment === undefined) {
    throw new Error("Test JWT is missing payload segment");
  }

  return parseBase64UrlJsonSegmentForTest(payloadSegment);
};

const stringClaimForTest = (value: unknown, fallback: string): string => {
  return typeof value === "string" ? value : fallback;
};

afterEach(() => {
  vi.doUnmock("./auth/better-auth-adapter");
  vi.doUnmock("./badges/direct-issue");
  vi.doUnmock("./lti/credtrail-lti-tool");
});

describe("LTI 1.3 core launch flow", () => {
  const issuer = "https://canvas.example.edu";
  const authorizationEndpoint = "https://canvas.example.edu/api/lti/authorize_redirect";
  const platformJwksEndpoint = "https://canvas.example.edu/api/lti/security/jwks";
  const tokenEndpoint = "https://canvas.example.edu/login/oauth2/token";
  const clientId = "canvas-client-123";
  const tenantId = "tenant_123";
  const targetLinkUri = "https://tool.example.edu/v1/lti/launch";
  const deploymentId = "deployment-123";
  const linkedUserId = "usr_lti_123";

  beforeEach(() => {
    authUsers.length = 0;
    authSessions.length = 0;
    authIdentityLinks.length = 0;
    fakeDbPrepare.mockClear();
    mockedCreatePostgresDatabase.mockReset();
    mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
    mockedCreateAuthIdentityLink.mockReset();
    mockedCreateAuthIdentityLink.mockImplementation(
      async (_db, input): Promise<(typeof authIdentityLinks)[number]> => {
        const link = {
          id: "ail_123",
          authSystem: input.authSystem,
          authUserId: input.authUserId,
          authAccountId: input.authAccountId ?? null,
          credtrailUserId: input.credtrailUserId,
          emailSnapshot: input.emailSnapshot ?? null,
          createdAt: "2026-02-10T22:00:00.000Z",
          updatedAt: "2026-02-10T22:00:00.000Z",
        };
        authIdentityLinks.push(link);
        return link;
      },
    );
    mockedListLtiIssuerRegistrations.mockReset();
    mockedListLtiIssuerRegistrations.mockResolvedValue([]);
    mockedFindAuthIdentityLinkByAuthUserId.mockReset();
    mockedFindAuthIdentityLinkByAuthUserId.mockImplementation(
      async (_db, authSystem, authUserId) => {
        return (
          authIdentityLinks.find(
            (candidate) =>
              candidate.authSystem === authSystem && candidate.authUserId === authUserId,
          ) ?? null
        );
      },
    );
    mockedFindAuthIdentityLinkByCredtrailUserId.mockReset();
    mockedFindAuthIdentityLinkByCredtrailUserId.mockImplementation(
      async (_db, authSystem, credtrailUserId) => {
        return (
          authIdentityLinks.find(
            (candidate) =>
              candidate.authSystem === authSystem && candidate.credtrailUserId === credtrailUserId,
          ) ?? null
        );
      },
    );
    mockedListBadgeTemplates.mockReset();
    mockedListBadgeTemplates.mockResolvedValue([sampleBadgeTemplate()]);
    mockedListBadgeTemplatesByIds.mockReset();
    mockedListBadgeTemplatesByIds.mockResolvedValue([sampleBadgeTemplate()]);
    mockedListLearnerBadgeSummaries.mockReset();
    mockedListLearnerBadgeSummaries.mockResolvedValue([]);
    mockedListAssertionEngagementEvents.mockReset();
    mockedListAssertionEngagementEvents.mockResolvedValue([]);
    mockedListAssertionsByBadgeTemplatesAndRecipientEmails.mockReset();
    mockedListAssertionsByBadgeTemplatesAndRecipientEmails.mockResolvedValue([]);
    mockedListAssertionsByIdempotencyKeys.mockReset();
    mockedListAssertionsByIdempotencyKeys.mockResolvedValue([]);
    mockedListAssertionLifecycleStatesByAssertionIds.mockReset();
    mockedListAssertionLifecycleStatesByAssertionIds.mockResolvedValue([]);
    mockedListLtiResourceLinkPlacementsForContext.mockReset();
    mockedListLtiResourceLinkPlacementsForContext.mockResolvedValue([]);
    mockedListLtiResourceLinkPlacementRuleStates.mockReset();
    mockedListLtiResourceLinkPlacementRuleStates.mockImplementation(async (_db, input) =>
      input.ruleIds.map((ruleId) => ({ ruleId, isActive: true })),
    );
    mockedListTenantLmsConnections.mockReset();
    mockedListTenantLmsConnections.mockResolvedValue([sampleTenantLmsConnection()]);
    mockedEnsureExternalCourseOrgUnit.mockReset();
    mockedEnsureExternalCourseOrgUnit.mockResolvedValue({
      status: "ok",
      orgUnit: {
        id: "tenant_123:org:course-typescript-101",
        tenantId: "tenant_123",
        unitType: "course",
        slug: "course-typescript-101",
        displayName: "TypeScript 101",
        parentOrgUnitId: "tenant_123:org:department-cs",
        createdByUserId: linkedUserId,
        isActive: true,
        createdAt: "2026-02-10T22:00:00.000Z",
        updatedAt: "2026-02-10T22:00:00.000Z",
      },
    });
    mockedFindBadgeIssuanceRuleById.mockReset();
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(
      sampleBadgeIssuanceRule({
        activeVersionId: "brlv_lti_rule_123_v1",
      }),
    );
    mockedFindActiveBadgeIssuanceRuleVersion.mockReset();
    mockedFindActiveBadgeIssuanceRuleVersion.mockResolvedValue(
      sampleBadgeIssuanceRuleVersion({
        status: "active",
      }),
    );
    mockedFindLtiResourceLinkPlacement.mockReset();
    mockedFindLtiResourceLinkPlacement.mockResolvedValue({
      id: "lti_place_123",
      tenantId,
      issuer,
      clientId,
      deploymentId,
      contextId: "course-42",
      resourceLinkId: "resource-link-123",
      badgeTemplateId: "badge_template_001",
      ruleId: "brl_lti_rule_123",
      createdByUserId: linkedUserId,
      status: "active",
      lastSeenAt: "2026-02-10T22:00:00.000Z",
      retiredAt: null,
      retiredByUserId: null,
      createdAt: "2026-02-10T22:00:00.000Z",
      updatedAt: "2026-02-10T22:00:00.000Z",
    });
    mockedLoadRuleFacts.mockReset();
    mockedLoadRuleFacts.mockImplementation(async (_input) => ({
      learnerId: "learner-001",
      nowIso: "2026-02-10T22:00:00.000Z",
      grades: [
        {
          courseId: "course-123",
          learnerId: "learner-001",
          currentScore: 92,
          finalScore: 92,
        },
      ],
      completions: [],
      submissions: [],
      surveyCompletions: [],
      customFields: [],
      earnedBadgeTemplateIds: [],
    }));
    mockedCreateLtiCourseBadgeRule.mockReset();
    mockedCreateLtiCourseBadgeRule.mockResolvedValue({
      status: "completed",
      writeStatus: "created",
      rule: sampleBadgeIssuanceRule(),
      version: sampleBadgeIssuanceRuleVersion({ status: "pending_approval" }),
      placement: {
        id: "lti_place_123",
        tenantId,
        issuer,
        clientId,
        deploymentId,
        contextId: "course-123",
        resourceLinkId: "resource-link-selected-badge",
        badgeTemplateId: "badge_template_001",
        ruleId: "brl_lti_rule_123",
        createdByUserId: linkedUserId,
        status: "active",
        lastSeenAt: "2026-02-10T22:00:00.000Z",
        retiredAt: null,
        retiredByUserId: null,
        createdAt: "2026-02-10T22:00:00.000Z",
        updatedAt: "2026-02-10T22:00:00.000Z",
      },
    });
    mockedCreateAuditLog.mockReset();
    mockedCreateAuditLog.mockResolvedValue(sampleAuditLog());
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockReset();
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(
      sampleDelegatedIssuingAuthorityGrant(),
    );
    mockedListActiveDelegatedIssuingAuthorityGrantsForUser.mockReset();
    mockedListActiveDelegatedIssuingAuthorityGrantsForUser.mockResolvedValue([
      sampleDelegatedIssuingAuthorityGrant(),
    ]);
    mockedFindDelegatedIssuingAuthorityGrantFromActiveGrants.mockReset();
    mockedFindDelegatedIssuingAuthorityGrantFromActiveGrants.mockImplementation(
      async (_db, grants, input) => {
        for (const grant of grants) {
          if (
            grant.allowedActions.includes(input.requiredAction) &&
            (grant.badgeTemplateIds.length === 0 ||
              grant.badgeTemplateIds.includes(input.badgeTemplateId)) &&
            grant.orgUnitId === input.orgUnitId
          ) {
            return grant;
          }
        }

        return null;
      },
    );
    mockedFindLtiLaunchSessionById.mockReset();
    mockedFindLtiLaunchSessionById.mockResolvedValue(sampleLtiLaunchSessionRecord());
    mockedFindActiveLtiLaunchSessionByOpaqueId.mockReset();
    mockedFindActiveLtiLaunchSessionByOpaqueId.mockResolvedValue(sampleLtiLaunchSessionRecord());
    mockedAttachLtiLaunchSessionPrincipal.mockReset();
    mockedAttachLtiLaunchSessionPrincipal.mockImplementation(async (_db, input) =>
      sampleLtiLaunchSessionRecord({
        id: input.id,
        tenantId: input.tenantId,
        userId: input.userId,
      }),
    );
    mockedUpsertLtiLaunchSession.mockReset();
    mockedUpsertLtiLaunchSession.mockImplementation(async (_db, input) =>
      sampleLtiLaunchSessionRecord({
        id: input.id,
        issuer: input.issuer,
        clientId: input.clientId,
        deploymentId: input.deploymentId,
        tenantId: input.tenantId ?? null,
        userId: input.userId ?? null,
        dataJson: input.dataJson,
        expiresAt: input.expiresAt,
      }),
    );
    mockedFindBadgeTemplateById.mockReset();
    mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
    mockedMoveLearnerIdentityAliasToProfile.mockReset();
    mockedMoveLearnerIdentityAliasToProfile.mockImplementation(async (_db, input) => ({
      id: "lid_moved_123",
      tenantId: input.tenantId,
      learnerProfileId: input.learnerProfileId,
      identityType: input.identityType,
      identityValue: input.identityValue,
      isPrimary: input.isPrimary ?? false,
      isVerified: input.isVerified ?? true,
      createdAt: "2026-02-10T22:00:00.000Z",
      updatedAt: "2026-02-10T22:00:00.000Z",
    }));
    mockedFindClaimableLearnerBadgeSummary.mockReset();
    mockedFindClaimableLearnerBadgeSummary.mockResolvedValue(
      sampleLearnerBadgeSummary({
        assertionId: "tenant_123:assertion_existing",
      }),
    );
    mockedRecordAssertionEngagementEvent.mockReset();
    mockedRecordAssertionEngagementEvent.mockResolvedValue({
      status: "recorded",
      event: {
        id: "aee_claim_123",
        tenantId,
        assertionId: "tenant_123:assertion_existing",
        eventType: "learner_claim",
        actorType: "learner",
        channel: "learner_dashboard",
        occurredAt: "2026-02-11T14:00:00.000Z",
        createdAt: "2026-02-11T14:00:00.000Z",
      },
    });
    mockedUpsertLtiResourceLinkPlacement.mockReset();
    mockedUpsertLtiResourceLinkPlacement.mockResolvedValue({
      id: "lti_place_123",
      tenantId,
      issuer,
      clientId,
      deploymentId,
      contextId: "course-123",
      resourceLinkId: "resource-link-123",
      badgeTemplateId: "badge_template_001",
      ruleId: null,
      createdByUserId: linkedUserId,
      status: "active",
      lastSeenAt: "2026-02-10T22:00:00.000Z",
      retiredAt: null,
      retiredByUserId: null,
      createdAt: "2026-02-10T22:00:00.000Z",
      updatedAt: "2026-02-10T22:00:00.000Z",
    });
    mockedResolveLearnerProfileFromSaml.mockReset();
    mockedResolveLearnerProfileFromSaml.mockResolvedValue({
      profile: sampleLearnerProfile(),
      strategy: "created",
    });
    mockedResolveLearnerProfileForIdentity.mockReset();
    mockedResolveLearnerProfileForIdentity.mockResolvedValue(sampleLearnerProfile());
    mockedFindLearnerProfileByIdentity.mockReset();
    mockedFindLearnerProfileByIdentity.mockResolvedValue(null);
    mockedFindUserById.mockReset();
    mockedFindUserById.mockResolvedValue(
      sampleUserRecord({
        id: linkedUserId,
      }),
    );
    mockedAddLearnerIdentityAlias.mockReset();
    mockedUpsertUserByEmail.mockReset();
    mockedUpsertUserByEmail.mockResolvedValue(
      sampleUserRecord({
        id: linkedUserId,
      }),
    );
    mockedEnsureTenantMembership.mockReset();
    mockedEnsureTenantMembership.mockResolvedValue({
      membership: sampleTenantMembership({
        tenantId,
        userId: linkedUserId,
        role: "viewer",
      }),
      created: true,
    });
    mockedUpsertTenantMembershipRole.mockReset();
    mockedUpsertTenantMembershipRole.mockResolvedValue({
      membership: sampleTenantMembership({
        tenantId,
        userId: linkedUserId,
        role: "issuer",
      }),
      previousRole: "viewer",
      changed: true,
    });
  });

  const createLtiEnv = (): ReturnType<typeof createEnv> => {
    const env = createEnv();
    env.BADGE_OBJECTS = {
      get: () =>
        Promise.resolve({
          text: () =>
            Promise.resolve(
              JSON.stringify({
                version: 1,
                mimeType: "image/png",
                byteSize: 8,
                base64Data: "iVBORw0KGgo=",
                uploadedAt: "2026-08-12T10:00:00.000Z",
                originalFilename: "badge.png",
              }),
            ),
        }),
    } as unknown as R2Bucket;
    env.LTI_ISSUER_REGISTRY_JSON = JSON.stringify({
      [issuer]: {
        authorizationEndpoint,
        clientId,
        tenantId,
        platformJwksEndpoint,
        tokenEndpoint,
      },
    });
    env.LTI_STATE_SIGNING_SECRET = "test-lti-state-secret";
    return env;
  };

  const createUnsignedOnlyLtiEnv = (): ReturnType<typeof createEnv> => {
    const env = createEnv();
    env.LTI_ISSUER_REGISTRY_JSON = JSON.stringify({
      [issuer]: {
        authorizationEndpoint,
        clientId,
        tenantId,
      },
    });
    env.LTI_STATE_SIGNING_SECRET = "test-lti-state-secret";
    return env;
  };

  const performInstructorDeepLinkingLaunch = async (input?: {
    deepLinkReturnUrl?: string;
    deepLinkingData?: string;
    additionalDeepLinkingSettings?: Readonly<Record<string, unknown>>;
  }): Promise<{
    response: Response;
    body: string;
    loginUrl: URL;
    isolatedApp: Awaited<ReturnType<typeof loadAppWithMockedSignedLtiTool>>["app"];
    env: ReturnType<typeof createLtiEnv>;
  }> => {
    const env = createLtiEnv();
    const deepLinkReturnUrl =
      input?.deepLinkReturnUrl ?? "https://canvas.example.edu/api/lti/deep_link_return";
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginUrl = new URL(loginResponse.headers.get("location") ?? "");
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "user-999",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce: loginUrl.searchParams.get("nonce") ?? "",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
        "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings": {
          deep_link_return_url: deepLinkReturnUrl,
          accept_types: ["ltiResourceLink"],
          accept_presentation_document_targets: [],
          ...(input?.deepLinkingData === undefined ? {} : { data: input.deepLinkingData }),
          ...input?.additionalDeepLinkingSettings,
        },
      },
    });
    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state: loginUrl.searchParams.get("state") ?? "",
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    return {
      response,
      body,
      loginUrl,
      isolatedApp,
      env,
    };
  };

  const ltiSessionFromClaims = (claims: Record<string, unknown>): LTISession => {
    const context = claims[ltiClaim.context] as Record<string, unknown> | undefined;
    const roles = Array.isArray(claims[ltiClaim.roles]) ? (claims[ltiClaim.roles] as string[]) : [];
    const normalizedRoles = roles.map((role) => role.toLowerCase());
    const isInstructor = normalizedRoles.some((role) => role.includes("#instructor"));
    const isStudent = normalizedRoles.some(
      (role) => role.includes("#learner") || role.includes("#student"),
    );
    const nrpsClaim = claims[ltiClaim.namesRoleService] as Record<string, unknown> | undefined;
    const deepLinkingSettings = claims[ltiClaim.deepLinkingSettings] as
      | Record<string, unknown>
      | undefined;
    const userName = typeof claims.name === "string" ? claims.name : undefined;
    const userEmail = typeof claims.email === "string" ? claims.email : undefined;
    const contextId = typeof context?.id === "string" ? context.id : undefined;
    const contextLabel = typeof context?.label === "string" ? context.label : undefined;
    const contextTitle = typeof context?.title === "string" ? context.title : undefined;
    const resourceLink = claims[ltiClaim.resourceLink] as Record<string, unknown> | undefined;
    const resourceLinkId = typeof resourceLink?.id === "string" ? resourceLink.id : undefined;
    const resourceLinkTitle =
      typeof resourceLink?.title === "string" ? resourceLink.title : undefined;
    const deepLinkingData =
      typeof deepLinkingSettings?.data === "string" ? deepLinkingSettings.data : undefined;

    return {
      jwtPayload: LTI13JwtPayloadSchema.parse(claims),
      id: "lti-session-test",
      user: {
        id: stringClaimForTest(claims.sub, "lti-user"),
        ...(userName === undefined ? {} : { name: userName }),
        ...(userEmail === undefined ? {} : { email: userEmail }),
        roles,
      },
      context: {
        id: contextId ?? "",
        label: contextLabel ?? "",
        title: contextTitle ?? "",
      },
      platform: {
        issuer,
        clientId,
        deploymentId: stringClaimForTest(claims[ltiClaim.deploymentId], deploymentId),
        name: "Canvas",
      },
      launch: {
        target: stringClaimForTest(claims[ltiClaim.targetLinkUri], targetLinkUri),
      },
      ...(resourceLinkId === undefined
        ? {}
        : {
            resourceLink: {
              id: resourceLinkId,
              ...(resourceLinkTitle === undefined ? {} : { title: resourceLinkTitle }),
            },
          }),
      services: {
        ...(nrpsClaim === undefined
          ? {}
          : {
              nrps: {
                membershipUrl: stringClaimForTest(nrpsClaim.context_memberships_url, ""),
                versions: Array.isArray(nrpsClaim.service_versions)
                  ? (nrpsClaim.service_versions as string[])
                  : [],
              },
            }),
        ...(deepLinkingSettings === undefined
          ? {}
          : {
              deepLinking: {
                returnUrl: stringClaimForTest(deepLinkingSettings.deep_link_return_url, ""),
                acceptTypes: Array.isArray(deepLinkingSettings.accept_types)
                  ? (deepLinkingSettings.accept_types as string[])
                  : [],
                acceptPresentationDocumentTargets: [],
                acceptMultiple: false,
                autoCreate: false,
                ...(deepLinkingData === undefined ? {} : { data: deepLinkingData }),
              },
            }),
      },
      customParameters: {},
      isAdmin: false,
      isInstructor,
      isStudent,
      isAssignmentAndGradesAvailable: false,
      isDeepLinkingAvailable: deepLinkingSettings !== undefined,
      isNameAndRolesAvailable: nrpsClaim !== undefined,
    } satisfies LTISession;
  };

  const loadAppWithMockedSignedLtiTool = async (options?: {
    authorizationEndpoint?: string;
    getMembers?: ReturnType<typeof vi.fn>;
    getSession?: ReturnType<typeof vi.fn>;
    issueBadgeForTenant?: ReturnType<typeof vi.fn>;
  }): Promise<
    Awaited<ReturnType<typeof loadAppWithMockedAuthProviders>> & {
      ltiTool: {
        handleLogin: ReturnType<typeof vi.fn>;
        verifyLaunch: ReturnType<typeof vi.fn>;
        createSession: ReturnType<typeof vi.fn>;
        createSessionFromVerifiedLaunch: ReturnType<typeof vi.fn>;
        getSession: ReturnType<typeof vi.fn>;
        createAdvantage: ReturnType<typeof vi.fn>;
      };
    }
  > => {
    let latestSession: LTISession | null = null;
    const ltiTool = {
      handleLogin: vi.fn(async (input: Record<string, unknown>) => {
        const redirectUrl = new URL(options?.authorizationEndpoint ?? authorizationEndpoint);
        const launchUrl = input.launchUrl;

        if (!(launchUrl instanceof URL)) {
          throw new Error("Expected LTI login launchUrl");
        }

        redirectUrl.searchParams.set("scope", "openid");
        redirectUrl.searchParams.set("response_type", "id_token");
        redirectUrl.searchParams.set("response_mode", "form_post");
        redirectUrl.searchParams.set("prompt", "none");
        redirectUrl.searchParams.set("client_id", stringClaimForTest(input.client_id, clientId));
        redirectUrl.searchParams.set("redirect_uri", launchUrl.toString());
        redirectUrl.searchParams.set("state", "mock-lti-state");
        redirectUrl.searchParams.set("nonce", "mock-lti-nonce");
        return redirectUrl.toString();
      }),
      verifyLaunch: vi.fn(
        async (
          idToken: string,
          _state: string,
          verifyOptions?: {
            authorizeVerifiedLaunch?: (launch: Record<string, unknown>) =>
              | Promise<{
                  success: boolean;
                  data?: unknown;
                  code?: string;
                  message?: string;
                }>
              | {
                  success: boolean;
                  data?: unknown;
                  code?: string;
                  message?: string;
                };
          },
        ) => {
          const payload = parseCompactJwtPayloadForTest(idToken);
          const launch = {
            payload,
            issuer,
            clientId,
            nonce: stringClaimForTest(payload.nonce, "mock-lti-nonce"),
            targetLinkUri: stringClaimForTest(
              payload["https://purl.imsglobal.org/spec/lti/claim/target_link_uri"],
              targetLinkUri,
            ),
            deploymentId: stringClaimForTest(
              payload["https://purl.imsglobal.org/spec/lti/claim/deployment_id"],
              deploymentId,
            ),
          };

          if (verifyOptions?.authorizeVerifiedLaunch === undefined) {
            return {
              success: true,
              launch,
            };
          }

          const authorization = await verifyOptions.authorizeVerifiedLaunch(launch);

          if (!authorization.success) {
            return {
              success: false,
              error: new Error(authorization.message ?? "Verified launch authorization failed"),
            };
          }

          return {
            success: true,
            launch: {
              ...launch,
              authorization: authorization.data,
            },
          };
        },
      ),
      createSession: vi.fn(async (claims: Record<string, unknown>) => {
        latestSession = ltiSessionFromClaims(claims);
        return latestSession;
      }),
      createSessionFromVerifiedLaunch: vi.fn(
        async (launch: { payload: Record<string, unknown> }) => {
          latestSession = ltiSessionFromClaims(launch.payload);
          return latestSession;
        },
      ),
      getSession:
        options?.getSession ??
        vi.fn(async (sessionId: string) =>
          latestSession !== null && latestSession.id === sessionId ? latestSession : undefined,
        ),
      createAdvantage: mockLtiToolCreateAdvantageForSession(
        options?.getMembers === undefined ? {} : { getMembers: options.getMembers },
      ),
    };
    const result = await loadAppWithMockedAuthProviders(() => {
      if (options?.issueBadgeForTenant !== undefined) {
        vi.doMock("./badges/direct-issue", async () => {
          const actual =
            await vi.importActual<typeof import("./badges/direct-issue")>("./badges/direct-issue");

          return {
            ...actual,
            createIssueBadgeForTenant: vi.fn(() => options.issueBadgeForTenant),
          };
        });
      }

      vi.doMock("./lti/credtrail-lti-tool", () => {
        return {
          createCredTrailLtiTool: vi.fn(async () => ltiTool),
        };
      });
    });

    return {
      ...result,
      ltiTool,
    };
  };

  const launchLearnerResourceLinkForTest = async (input: {
    isolatedApp: typeof app;
    env: ReturnType<typeof createLtiEnv>;
    targetLinkUri?: string;
    resourceLinkId: string;
    role?: "learner" | "instructor";
    subjectId?: string;
    name?: string;
    email?: string;
    sourcedId?: string;
    context?: {
      id: string;
      title?: string | undefined;
      label?: string | undefined;
    };
  }): Promise<{
    response: Response;
    body: string;
  }> => {
    const effectiveTargetLinkUri = input.targetLinkUri ?? targetLinkUri;
    const loginResponse = await input.isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(
        effectiveTargetLinkUri,
      )}&lti_deployment_id=${encodeURIComponent(deploymentId)}`,
      undefined,
      input.env,
    );
    const loginUrl = new URL(loginResponse.headers.get("location") ?? "");
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const role = input.role ?? "learner";
    const payload: Record<string, unknown> = {
      iss: issuer,
      sub: input.subjectId ?? (role === "instructor" ? "instructor-001" : "learner-001"),
      aud: clientId,
      exp: nowEpochSeconds + 300,
      iat: nowEpochSeconds - 10,
      nonce: loginUrl.searchParams.get("nonce") ?? "",
      [ltiClaim.deploymentId]: deploymentId,
      [ltiClaim.messageType]: "LtiResourceLinkRequest",
      [ltiClaim.version]: "1.3.0",
      [ltiClaim.targetLinkUri]: effectiveTargetLinkUri,
      [ltiClaim.resourceLink]: {
        id: input.resourceLinkId,
      },
      [ltiClaim.roles]: [
        role === "instructor"
          ? "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"
          : "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
      ],
    };

    if (input.name !== undefined) {
      payload.name = input.name;
    }

    if (input.email !== undefined) {
      payload.email = input.email;
    }

    if (input.sourcedId !== undefined) {
      payload[ltiClaim.lis] = {
        person_sourcedid: input.sourcedId,
      };
    }

    if (input.context !== undefined) {
      payload[ltiClaim.context] = input.context;
    }

    const response = await input.isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: compactJwsForTest({
            header: {
              alg: "RS256",
              typ: "JWT",
            },
            payload,
          }),
          state: loginUrl.searchParams.get("state") ?? "",
        }).toString(),
      },
      input.env,
    );

    return {
      response,
      body: await response.text(),
    };
  };

  it("establishes a Better Auth browser session for LTI launches without legacy session writes", async () => {
    const { app: isolatedApp, betterAuthProvider } = await loadAppWithMockedSignedLtiTool();
    const env = createLtiEnv();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "user-123",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-123",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
        "https://purl.imsglobal.org/spec/lti/claim/context": {
          id: "course-123",
          label: "TS101",
          title: "TypeScript 101",
        },
        name: "Instructor Example",
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie") ?? "").toContain(
      "better-auth.session_token=better-lti-session",
    );
    expect(response.headers.get("set-cookie") ?? "").toContain("SameSite=None");
    expect(response.headers.get("set-cookie") ?? "").toContain("Secure");
    const body = await response.text();
    expect(body).toContain("CredTrail could not load badge progress");
    expect(body).toContain("Open CredTrail dashboard");
    expect(body).toContain("lti_session_handoff=");
    expect(body).not.toContain("<h1>Review badge progress for this course</h1>");
    expect(betterAuthProvider.createLtiSession).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        tenantId,
        userId: linkedUserId,
      }),
    );
  });

  it("redirects OIDC login initiation to issuer authorization endpoint with required parameters", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const response = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );

    expect(response.status).toBe(302);
    const location = response.headers.get("location");
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? "");
    expect(`${redirectUrl.origin}${redirectUrl.pathname}`).toBe(authorizationEndpoint);
    expect(redirectUrl.searchParams.get("scope")).toBe("openid");
    expect(redirectUrl.searchParams.get("response_type")).toBe("id_token");
    expect(redirectUrl.searchParams.get("response_mode")).toBe("form_post");
    expect(redirectUrl.searchParams.get("prompt")).toBe("none");
    expect(redirectUrl.searchParams.get("client_id")).toBe(clientId);
    expect(redirectUrl.searchParams.get("redirect_uri")).toBe(
      "https://credtrail.test/v1/lti/launch",
    );
    expect(redirectUrl.searchParams.get("state")).toBeTruthy();
    expect(redirectUrl.searchParams.get("nonce")).toBeTruthy();
  });

  it("uses LTI postMessage storage before OIDC redirect when the platform advertises storage support", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const response = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}&lti_storage_target=${encodeURIComponent("_parent")}`,
      undefined,
      env,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("location")).toBeNull();

    const body = await response.text();
    const scriptMatch =
      /<script[^>]*src="([^"]*\/assets\/ui\/lti-post-message-storage\.[^"]+\.js)"[^>]*><\/script>/.exec(
        body,
      );
    const scriptPath = scriptMatch?.[1] ?? null;

    expect(scriptPath).not.toBeNull();
    expect(body).toContain('data-state="mock-lti-state"');
    expect(body).toContain('data-nonce="mock-lti-nonce"');
    expect(body).toContain(`data-platform-origin="${new URL(authorizationEndpoint).origin}"`);
    expect(body).toContain('data-storage-target="_parent"');
    expect(body).toContain('role="status"');
    expect(body).toContain("Continuing LTI launch.");
    expect(body).not.toContain("<h1>Continuing LTI launch</h1>");

    expect(scriptPath).toMatch(/^\/assets\/ui\/lti-post-message-storage\.[a-f0-9]{10}\.js$/);
    const script = LTI_POST_MESSAGE_STORAGE_JS;

    expect(script).toContain("lti.put_data");
    expect(script).toContain("org.sakailms.lti.prelaunch");
    expect(script).toContain("JSON.stringify(message)");
    expect(script).toContain("JSON.parse(message)");
  });

  it("uses DB-backed issuer registrations when env registry is not configured", async () => {
    const env = createEnv();
    env.LTI_STATE_SIGNING_SECRET = "test-lti-state-secret";
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    mockedListLtiIssuerRegistrations.mockResolvedValue([
      sampleLtiIssuerRegistration({
        issuer,
        tenantId,
        clientId,
        authorizationEndpoint,
        platformJwksEndpoint,
        tokenEndpoint,
      }),
    ]);

    const response = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}`,
      undefined,
      env,
    );

    expect(response.status).toBe(302);
    const location = response.headers.get("location");
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? "");
    expect(`${redirectUrl.origin}${redirectUrl.pathname}`).toBe(authorizationEndpoint);
    expect(redirectUrl.searchParams.get("client_id")).toBe(clientId);
  });

  it("prefers DB issuer registrations over env defaults for the same issuer", async () => {
    const dbClientId = "db-client-777";
    const dbAuthorizationEndpoint = "https://canvas.example.edu/db/authorize_redirect";
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool({
      authorizationEndpoint: dbAuthorizationEndpoint,
    });
    env.LTI_ISSUER_REGISTRY_JSON = JSON.stringify({
      [issuer]: {
        authorizationEndpoint: "https://canvas.example.edu/env/authorize_redirect",
        clientId: "env-client-123",
        tenantId,
        platformJwksEndpoint,
        tokenEndpoint,
      },
    });
    mockedListLtiIssuerRegistrations.mockResolvedValue([
      sampleLtiIssuerRegistration({
        issuer,
        tenantId,
        clientId: dbClientId,
        authorizationEndpoint: dbAuthorizationEndpoint,
        platformJwksEndpoint,
        tokenEndpoint,
      }),
    ]);

    const response = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&client_id=${encodeURIComponent(dbClientId)}`,
      undefined,
      env,
    );

    expect(response.status).toBe(302);
    const location = response.headers.get("location");
    expect(location).not.toBeNull();

    const redirectUrl = new URL(location ?? "");
    expect(`${redirectUrl.origin}${redirectUrl.pathname}`).toBe(dbAuthorizationEndpoint);
    expect(redirectUrl.searchParams.get("client_id")).toBe(dbClientId);
  });

  it("accepts an instructor launch and renders launch completion page", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "user-123",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-123",
        },
        "https://purl.imsglobal.org/spec/lti/claim/context": {
          id: "course-123",
          label: "TS101",
          title: "TypeScript 101",
        },
        "https://purl.imsglobal.org/spec/lti/claim/custom": {
          badgeTemplateId: "badge_template_001",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("set-cookie")).toContain("better-auth.session_token=");
    expect(body).toContain("CredTrail could not load this LMS roster");
    expect(body).toContain(
      "Open CredTrail or ask an administrator to check the LMS roster connection.",
    );
    expect(body).toContain("viewer");
    expect(body).toContain("LtiResourceLinkRequest");
    expect(body).toContain("/tenants/tenant_123/learner/dashboard");
    expect(body).toContain("Launch troubleshooting details");
    expect(body).toContain("lti_session_handoff=");
    expect(body).toContain('target="_blank"');
    expect(body).toContain("/assets/ui/foundation.");
    expect(body).toContain("/assets/ui/lti-pages.");
    expect(body).not.toContain(".lti-launch__hero {");
    expect(mockedResolveLearnerProfileFromSaml).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      samlSubject: "https://canvas.example.edu::user-123",
    });
    expect(mockedResolveLearnerProfileForIdentity).not.toHaveBeenCalled();
    expect(mockedUpsertUserByEmail).toHaveBeenCalledWith(
      fakeDb,
      expect.stringContaining("@credtrail-lti.local"),
    );
    expect(mockedEnsureTenantMembership).toHaveBeenCalledWith(fakeDb, tenantId, linkedUserId);
    expect(mockedUpsertTenantMembershipRole).not.toHaveBeenCalled();
    expect(mockedUpsertLtiResourceLinkPlacement).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      issuer,
      clientId,
      deploymentId,
      contextId: "course-123",
      resourceLinkId: "resource-link-123",
      badgeTemplateId: "badge_template_001",
      ruleId: null,
      createdByUserId: linkedUserId,
    });
  });

  it("renders course badge summary for instructor leftnav launches", async () => {
    const env = createLtiEnv();
    mockedEnsureTenantMembership.mockResolvedValueOnce({
      membership: sampleTenantMembership({
        tenantId,
        userId: linkedUserId,
        role: "admin",
      }),
      created: false,
    });
    mockedListLtiResourceLinkPlacementsForContext.mockResolvedValue([
      sampleLtiResourceLinkPlacement({
        contextId: "course-123",
        resourceLinkId: "resource-link-placed-badge",
      }),
      sampleLtiResourceLinkPlacement({
        id: "lti_place_older",
        contextId: "course-123",
        resourceLinkId: "resource-link-older-badge",
        createdAt: "2026-02-09T22:00:00.000Z",
        updatedAt: "2026-02-09T22:00:00.000Z",
      }),
    ]);
    const placementAssertion = sampleAssertionRecord({
      id: "tenant_123:assertion_existing",
      idempotencyKey: "lti:placement-issued",
      recipientIdentity: "learner-one@example.edu",
      badgeTemplateId: "badge_template_001",
      issuedAt: "2026-02-11T14:00:00.000Z",
    });
    const matchingRecipientAssertion = sampleAssertionRecord({
      id: "tenant_123:assertion_manual",
      idempotencyKey: "manual:direct-issued",
      recipientIdentity: "learner-two@example.edu",
      badgeTemplateId: "badge_template_001",
      issuedAt: "2026-02-12T14:00:00.000Z",
    });
    const olderMatchingRecipientAssertion = sampleAssertionRecord({
      id: "tenant_123:assertion_manual_older",
      idempotencyKey: "manual:direct-issued-older",
      recipientIdentity: "learner-two@example.edu",
      badgeTemplateId: "badge_template_001",
      issuedAt: "2026-02-10T14:00:00.000Z",
    });
    mockedListAssertionsByBadgeTemplatesAndRecipientEmails.mockResolvedValue([
      placementAssertion,
      olderMatchingRecipientAssertion,
      matchingRecipientAssertion,
    ]);
    mockedListAssertionLifecycleStatesByAssertionIds.mockResolvedValue([
      {
        assertionId: "tenant_123:assertion_existing",
        state: "active",
        source: "default_active",
        reasonCode: null,
        reason: null,
        transitionedAt: null,
        revokedAt: null,
      },
      {
        assertionId: "tenant_123:assertion_manual",
        state: "active",
        source: "default_active",
        reasonCode: null,
        reason: null,
        transitionedAt: null,
        revokedAt: null,
      },
    ]);
    const getMembers = vi.fn().mockResolvedValue({
      success: true,
      data: [
        {
          userId: "learner-001",
          name: "Learner One",
          email: "learner-one@example.edu",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
          status: "Active",
        },
        {
          userId: "learner-002",
          name: "Learner Two",
          email: "learner-two@example.edu",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
          status: "Active",
        },
        {
          userId: "teacher-001",
          name: "Instructor One",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
          status: "Active",
        },
      ],
    });
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool({ getMembers });
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginUrl = new URL(loginResponse.headers.get("location") ?? "");
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "instructor-001",
        name: "Instructor One",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce: loginUrl.searchParams.get("nonce") ?? "",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-leftnav",
        },
        "https://purl.imsglobal.org/spec/lti/claim/context": {
          id: "course-123",
          title: "TypeScript 101",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
        "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice": {
          context_memberships_url: "https://canvas.example.edu/api/lti/courses/123/names_and_roles",
          service_versions: ["2.0"],
        },
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state: loginUrl.searchParams.get("state") ?? "",
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Hi, Instructor One");
    expect(body).toContain("Review badge progress for this course");
    expect(body).toContain("Course badge summary");
    expect(body).toContain("TypeScript 101");
    expect(body).toContain("Learner One");
    expect(body).toContain("learner-one@example.edu");
    expect(body).toContain("Learner Two");
    expect(body).toContain("learner-two@example.edu");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Badges in this course");
    expect(body.indexOf("Badges in this course")).toBeLessThan(
      body.indexOf("data-lti-course-summary-search"),
    );
    expect(body).toContain("Awarded for completing TypeScript fundamentals.");
    expect(body).toContain('src="https://example.edu/image.png"');
    expect(body).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001");
    expect(
      body.match(/\/showcase\/tenant_123\/criteria\?badgeTemplateId=badge_template_001/g) ?? [],
    ).toHaveLength(1);
    expect(body).toContain("Issued");
    expect(body).toContain('dateTime="2026-02-11T14:00:00.000Z"');
    expect(body).toContain("Issued Feb 11, 2026, 2:00 PM UTC");
    expect(body).toContain("Issued for this learner and badge.");
    expect(body).toContain('dateTime="2026-02-12T14:00:00.000Z"');
    expect(body).toContain("Issued Feb 12, 2026, 2:00 PM UTC");
    expect(body).not.toContain("Issued Feb 10, 2026, 2:00 PM UTC");
    expect(body).toContain("data-lti-course-summary-search");
    expect(body).toContain("/assets/ui/lti-course-summary.");
    expect(body).toContain(
      "/tenants/tenant_123/admin/operations/issued-badges?recipientQuery=learner-one%40example.edu&amp;badgeTemplateId=badge_template_001&amp;lifecycle=tenant_123%3Aassertion_existing&amp;lifecycleMode=audit&amp;source=lti-course-summary",
    );
    expect(body).toContain(
      "/tenants/tenant_123/admin/operations/issued-badges?recipientQuery=learner-two%40example.edu&amp;badgeTemplateId=badge_template_001&amp;lifecycle=tenant_123%3Aassertion_manual&amp;lifecycleMode=audit&amp;source=lti-course-summary",
    );
    expect(body).toContain(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001?ltiContextId=course-123&amp;ltiResourceLinkId=resource-link-placed-badge&amp;source=lti-course-summary&amp;ltiCourse=TypeScript+101",
    );
    expect(body).not.toContain('name="learner_user_id"');
    expect(body).not.toContain("Select learners and issue the badge placed in this LMS tool.");
    expect(mockedListLtiResourceLinkPlacementsForContext).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      issuer,
      clientId,
      deploymentId,
      contextId: "course-123",
      includeRetired: true,
    });
    expect(mockedListBadgeTemplates).not.toHaveBeenCalled();
    expect(mockedListBadgeTemplatesByIds).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      badgeTemplateIds: ["badge_template_001"],
      includeArchived: true,
    });
    expect(mockedListAssertionsByIdempotencyKeys).not.toHaveBeenCalled();
    expect(mockedListAssertionsByBadgeTemplatesAndRecipientEmails).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      badgeTemplateIds: ["badge_template_001"],
      recipientEmails: ["learner-one@example.edu", "learner-two@example.edu"],
    });
    expect(mockedListAssertionLifecycleStatesByAssertionIds).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      assertionIds: ["tenant_123:assertion_existing", "tenant_123:assertion_manual"],
    });
    expect(body).toContain("resource-link-placed-badge");
    expect(mockedUpsertLtiResourceLinkPlacement).not.toHaveBeenCalled();
  });

  it("renders course badge summary without admin links for issuer instructors", async () => {
    const env = createLtiEnv();
    mockedListLtiResourceLinkPlacementsForContext.mockResolvedValue([
      sampleLtiResourceLinkPlacement({
        contextId: "course-123",
        resourceLinkId: "resource-link-placed-badge",
      }),
    ]);
    const issuedAssertion = sampleAssertionRecord({
      id: "tenant_123:assertion_existing",
      idempotencyKey: "lti:placement-issued",
      recipientIdentity: "learner-one@example.edu",
      badgeTemplateId: "badge_template_001",
      issuedAt: "2026-02-11T14:00:00.000Z",
    });
    mockedListAssertionsByBadgeTemplatesAndRecipientEmails.mockResolvedValue([issuedAssertion]);
    mockedListAssertionLifecycleStatesByAssertionIds.mockResolvedValue([
      {
        assertionId: "tenant_123:assertion_existing",
        state: "active",
        source: "default_active",
        reasonCode: null,
        reason: null,
        transitionedAt: null,
        revokedAt: null,
      },
    ]);
    const getMembers = vi.fn().mockResolvedValue({
      success: true,
      data: [
        {
          userId: "learner-001",
          name: "Learner One",
          email: "learner-one@example.edu",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
          status: "Active",
        },
        {
          userId: "teacher-001",
          name: "Instructor One",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
          status: "Active",
        },
      ],
    });
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool({ getMembers });
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginUrl = new URL(loginResponse.headers.get("location") ?? "");
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "instructor-001",
        name: "Instructor One",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce: loginUrl.searchParams.get("nonce") ?? "",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-leftnav",
        },
        "https://purl.imsglobal.org/spec/lti/claim/context": {
          id: "course-123",
          title: "TypeScript 101",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
        "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice": {
          context_memberships_url: "https://canvas.example.edu/api/lti/courses/123/names_and_roles",
          service_versions: ["2.0"],
        },
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state: loginUrl.searchParams.get("state") ?? "",
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Course badge summary");
    expect(body).toContain("Learner One");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Badges in this course");
    expect(body).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001");
    expect(body).toContain("Issued Feb 11, 2026, 2:00 PM UTC");
    expect(body).not.toContain("/tenants/tenant_123/admin/operations/issued-badges");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/templates/badge_template_001");
    expect(mockedUpsertTenantMembershipRole).not.toHaveBeenCalled();
  });

  it("rejects resource-link placement when badge template is not tenant-owned and active", async () => {
    mockedFindBadgeTemplateById.mockResolvedValue(null);
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginUrl = new URL(loginResponse.headers.get("location") ?? "");
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "user-tenant-cross",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce: loginUrl.searchParams.get("nonce") ?? "",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-cross-tenant",
        },
        "https://purl.imsglobal.org/spec/lti/claim/custom": {
          badgeTemplateId: "badge_template_other_tenant",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state: loginUrl.searchParams.get("state") ?? "",
        }).toString(),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(400);
    expect(body.error).toContain("badge template is not available");
    expect(mockedFindBadgeTemplateById).toHaveBeenCalledWith(
      fakeDb,
      tenantId,
      "badge_template_other_tenant",
    );
    expect(mockedUpsertLtiResourceLinkPlacement).not.toHaveBeenCalled();
    expect(mockedResolveLearnerProfileForIdentity).not.toHaveBeenCalled();
  });

  it("pulls NRPS roster for instructor launch and renders bulk issuance view", async () => {
    const env = createLtiEnv();
    const rosterTargetLinkUri = `${targetLinkUri}?badgeTemplateId=badge_template_001`;
    const getMembers = vi.fn().mockResolvedValue({
      success: true,
      data: [
        {
          userId: "learner-001",
          name: "Learner One",
          email: "learner-one@example.edu",
          lisPersonSourcedId: "sourced-learner-001",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
          status: "Active",
        },
        {
          userId: "teacher-001",
          name: "Instructor One",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
          status: "Active",
        },
      ],
    });
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool({ getMembers });
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(rosterTargetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "instructor-001",
        name: "Instructor One",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": rosterTargetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-nrps-1",
        },
        "https://purl.imsglobal.org/spec/lti/claim/context": {
          id: "course-42",
          title: "Course 42",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
        "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice": {
          context_memberships_url: "https://canvas.example.edu/api/lti/courses/42/names_and_roles",
          service_versions: ["2.0"],
        },
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Hi, Instructor One");
    expect(body).toContain(
      "Review the selected badge, then choose learners from this course roster to issue it.",
    );
    expect(body).toContain("Issue badges from course roster");
    expect(body).toContain("lti-launch__selected-badge");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Awarded for completing TypeScript fundamentals.");
    expect(body).toContain('src="https://example.edu/image.png"');
    expect(body).toContain('alt="TypeScript Foundations badge artwork"');
    expect(body).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001");
    expect(body).toContain("Active");
    expect(body.indexOf("lti-launch__selected-badge")).toBeLessThan(
      body.indexOf('class="lti-launch__bulk-table"'),
    );
    expect(body).toContain("Loaded 1 learner from LMS roster.");
    expect(body).toContain("badge_template_001");
    expect(body).toContain("learner-one@example.edu");
    expect(body).toContain("Issued in this launch item");
    expect(body).toContain("0 of 1");
    expect(body).toContain('action="/v1/lti/resource-link/issue"');
    expect(body).toContain('name="issuance_action_token"');
    expect(body).toContain('name="learner_user_id"');
    expect(body).toContain("Issue selected badges");
    expect(getMembers).toHaveBeenCalledTimes(1);
  });

  it("marks already issued LMS roster learners on refreshed LTI launches", async () => {
    const env = createLtiEnv();
    const rosterTargetLinkUri = `${targetLinkUri}?badgeTemplateId=badge_template_001`;
    const existingAssertion = sampleAssertionRecord();
    mockedListAssertionsByIdempotencyKeys.mockImplementation(async (_db, input) => [
      {
        ...existingAssertion,
        idempotencyKey: input.idempotencyKeys[0] ?? "lti:test",
      },
    ]);
    mockedListAssertionLifecycleStatesByAssertionIds.mockResolvedValue([
      {
        assertionId: existingAssertion.id,
        state: "active",
        source: "default_active",
        reasonCode: null,
        reason: null,
        transitionedAt: null,
        revokedAt: null,
      },
    ]);
    const getMembers = vi.fn().mockResolvedValue({
      success: true,
      data: [
        {
          userId: "learner-001",
          name: "Learner One",
          email: "learner-one@example.edu",
          lisPersonSourcedId: "sourced-learner-001",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
          status: "Active",
        },
      ],
    });
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool({ getMembers });
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(rosterTargetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginUrl = new URL(loginResponse.headers.get("location") ?? "");
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "instructor-001",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce: loginUrl.searchParams.get("nonce") ?? "",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": rosterTargetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-nrps-1",
        },
        "https://purl.imsglobal.org/spec/lti/claim/context": {
          id: "course-42",
          title: "Course 42",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
        "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice": {
          context_memberships_url: "https://canvas.example.edu/api/lti/courses/42/names_and_roles",
          service_versions: ["2.0"],
        },
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state: loginUrl.searchParams.get("state") ?? "",
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Issued in this launch item");
    expect(body).toContain("1 of 1");
    expect(body).toContain(`Already issued: ${existingAssertion.id}`);
    expect(body).toContain("Selectable learners");
    expect(body).toMatch(/value="learner-001"[^>]*disabled/);
    expect(mockedListAssertionsByIdempotencyKeys).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId,
        idempotencyKeys: [expect.stringMatching(/^lti:[a-f0-9]{64}$/)],
      }),
    );
    expect(mockedListAssertionLifecycleStatesByAssertionIds).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      assertionIds: [existingAssertion.id],
    });
  });

  it("issues selected LMS roster learners through the LTI resource-link action", async () => {
    const env = createLtiEnv();
    const rosterTargetLinkUri = `${targetLinkUri}?badgeTemplateId=badge_template_001`;
    const getMembers = vi.fn().mockResolvedValue({
      success: true,
      data: [
        {
          userId: "learner-001",
          name: "Learner One",
          email: "learner-one@example.edu",
          lisPersonSourcedId: "sourced-learner-001",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
          status: "Active",
        },
        {
          userId: "learner-no-email",
          name: "Learner No Email",
          roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
          status: "Active",
        },
      ],
    });
    const issueBadgeForTenant = vi.fn(async () => ({
      status: "issued" as const,
      tenantId,
      assertionId: "assertion_lti_001",
      idempotencyKey: "lti:digest",
      vcR2Key: "tenant_123/assertion_lti_001.json",
      credential: {},
    }));
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool({
      getMembers,
      issueBadgeForTenant,
    });
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(rosterTargetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginUrl = new URL(loginResponse.headers.get("location") ?? "");
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "instructor-001",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce: loginUrl.searchParams.get("nonce") ?? "",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": rosterTargetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-nrps-1",
        },
        "https://purl.imsglobal.org/spec/lti/claim/context": {
          id: "course-42",
          title: "Course 42",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
        "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice": {
          context_memberships_url: "https://canvas.example.edu/api/lti/courses/42/names_and_roles",
          service_versions: ["2.0"],
        },
        email: "instructor@example.edu",
      },
    });
    const launchResponse = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state: loginUrl.searchParams.get("state") ?? "",
        }).toString(),
      },
      env,
    );
    const launchBody = await launchResponse.text();
    const actionToken = /name="issuance_action_token"[^>]*value="([^"]+)"/.exec(launchBody)?.[1];

    expect(actionToken).toBeTruthy();

    const issueResponse = await isolatedApp.request(
      "/v1/lti/resource-link/issue",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams([
          ["issuance_action_token", actionToken ?? ""],
          ["learner_user_id", "learner-001"],
          ["learner_user_id", "learner-no-email"],
          ["learner_user_id", "forged-learner"],
        ]).toString(),
      },
      env,
    );
    const issueBody = await issueResponse.text();

    expect(issueResponse.status).toBe(200);
    expect(issueBody).toContain("Badge issuance complete");
    expect(issueBody).toContain("Badge issued.");
    expect(issueBody).toContain("The LMS did not provide an email address for this learner.");
    expect(issueBody).toContain("Learner is not present in the current LMS roster.");
    expect(issueBadgeForTenant).toHaveBeenCalledTimes(1);
    expect(issueBadgeForTenant).toHaveBeenCalledWith(
      expect.anything(),
      tenantId,
      expect.objectContaining({
        recipientIdentity: "learner-one@example.edu",
        recipientIdentityType: "email",
        recipientIdentifiers: [
          {
            identifierType: "sourcedId",
            identifier: "sourced-learner-001",
          },
        ],
        idempotencyKey: expect.stringMatching(/^lti:[a-f0-9]{64}$/),
      }),
      linkedUserId,
      {
        recipientDisplayName: "Learner One",
      },
    );
    const issuanceRequest = (
      issueBadgeForTenant.mock.calls as readonly (readonly unknown[])[]
    )[0]?.[2];
    expect(issuanceRequest).not.toHaveProperty("badgeTemplateId");
    expect(issuanceRequest).not.toHaveProperty("achievementSnapshot");
    expect(getMembers).toHaveBeenCalledTimes(2);
  });

  it("rejects LTI roster issuance without a valid action token", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const response = await isolatedApp.request(
      "/v1/lti/resource-link/issue",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          issuance_action_token: "invalid-token",
          learner_user_id: "learner-001",
        }).toString(),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toContain("invalid or expired");
  });

  it("renders unavailable NRPS state when launch omits the service claim", async () => {
    const env = createLtiEnv();
    const rosterTargetLinkUri = `${targetLinkUri}?badgeTemplateId=badge_template_001`;
    mockedFindBadgeTemplateById.mockResolvedValue(
      sampleBadgeTemplate({
        title: "Governance Design",
        description: null,
        imageUri: null,
      }),
    );
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(rosterTargetLinkUri)}&lti_deployment_id=${encodeURIComponent(
        deploymentId,
      )}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
        typ: "JWT",
      },
      payload: {
        iss: issuer,
        sub: "instructor-002",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": rosterTargetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
          id: "resource-link-nrps-2",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
        ],
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("CredTrail could not load this LMS roster");
    expect(body).toContain("Issue badges from course roster");
    expect(body).toContain("lti-launch__selected-badge");
    expect(body).toContain("Governance Design");
    expect(body).toContain("GD");
    expect(body).toContain("Open criteria to review how learners qualify for this badge.");
    expect(body).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001");
    expect(body).toContain("Active");
    expect(body.indexOf("lti-launch__selected-badge")).toBeLessThan(
      body.indexOf('class="lti-launch__bulk-table"'),
    );
    expect(body).toContain(
      "This LMS launch did not include a learner roster, so CredTrail cannot issue badges from this tool yet.",
    );
    expect(body).toContain("Open CredTrail dashboard");
    expect(body).toContain("lti_session_handoff=");
  });

  it("accepts a learner launch and links local account session with email claim", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const { response, body } = await launchLearnerResourceLinkForTest({
      isolatedApp,
      env,
      resourceLinkId: "resource-link-456",
      subjectId: "user-456",
      name: "Learner One",
      email: "Learner@Example.edu",
      sourcedId: "sourced-learner-456",
    });

    expect(response.status).toBe(200);
    expect(body).toContain("CredTrail could not load badge details");
    expect(body).toContain(
      "Your LMS account is linked. Open your dashboard to review issued badges and sharing options.",
    );
    expect(body).toContain("Open CredTrail dashboard");
    expect(body).toContain("CredTrail could not identify this LMS course");
    expect(body).not.toContain("Launch troubleshooting details");
    expect(mockedResolveLearnerProfileFromSaml).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      samlSubject: "https://canvas.example.edu::user-456",
      email: "Learner@Example.edu",
      displayName: "Learner One",
    });
    expect(mockedUpsertUserByEmail).toHaveBeenCalledWith(fakeDb, "Learner@Example.edu");
    expect(mockedMoveLearnerIdentityAliasToProfile).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId,
        learnerProfileId: "lpr_123",
        identityType: "saml_subject",
        identityValue: "https://canvas.example.edu::user-456",
      }),
    );
    expect(mockedMoveLearnerIdentityAliasToProfile).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId,
        learnerProfileId: "lpr_123",
        identityType: "sourced_id",
        identityValue: "sourced-learner-456",
      }),
    );
    expect(mockedAddLearnerIdentityAlias).not.toHaveBeenCalled();
    expect(mockedUpsertTenantMembershipRole).not.toHaveBeenCalled();
  });

  it("links a learner LTI launch to an existing issued-email learner profile", async () => {
    const env = createLtiEnv();
    const existingEmailProfile = sampleLearnerProfile({
      id: "lpr_email_existing",
      subjectId: "urn:credtrail:learner:tenant_123:lpr_email_existing",
    });
    const staleLtiProfile = sampleLearnerProfile({
      id: "lpr_stale_lti",
      subjectId: "urn:credtrail:learner:tenant_123:lpr_stale_lti",
    });
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();

    mockedFindLearnerProfileByIdentity.mockImplementation(async (_db, input) => {
      if (input.identityType === "email" && input.identityValue === "learner@example.edu") {
        return existingEmailProfile;
      }

      if (
        input.identityType === "saml_subject" &&
        input.identityValue === "https://canvas.example.edu::canvas-user-claim"
      ) {
        return staleLtiProfile;
      }

      return null;
    });

    const { response, body } = await launchLearnerResourceLinkForTest({
      isolatedApp,
      env,
      resourceLinkId: "resource-link-claim",
      subjectId: "canvas-user-claim",
      name: "Learner Claim",
      email: "learner@example.edu",
    });

    expect(response.status).toBe(200);
    expect(body).not.toContain("Unable to link LTI launch to local account");
    expect(mockedResolveLearnerProfileFromSaml).not.toHaveBeenCalled();
    expect(mockedResolveLearnerProfileForIdentity).not.toHaveBeenCalled();
    expect(mockedMoveLearnerIdentityAliasToProfile).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId,
        learnerProfileId: existingEmailProfile.id,
        identityType: "saml_subject",
        identityValue: "https://canvas.example.edu::canvas-user-claim",
      }),
    );
    expect(mockedAddLearnerIdentityAlias).not.toHaveBeenCalled();
  });

  it("renders learner left-nav badge summary for all active course placements", async () => {
    const env = createLtiEnv();
    mockedListLtiResourceLinkPlacementsForContext.mockResolvedValue([
      sampleLtiResourceLinkPlacement({
        resourceLinkId: "resource-link-placed-typescript",
        badgeTemplateId: "badge_template_001",
      }),
      sampleLtiResourceLinkPlacement({
        id: "lti_place_duplicate",
        resourceLinkId: "resource-link-placed-typescript-copy",
        badgeTemplateId: "badge_template_001",
      }),
      sampleLtiResourceLinkPlacement({
        id: "lti_place_governance",
        resourceLinkId: "resource-link-placed-governance",
        badgeTemplateId: "badge_template_002",
      }),
    ]);
    mockedListBadgeTemplatesByIds.mockResolvedValue([
      sampleBadgeTemplate(),
      sampleBadgeTemplate({
        id: "badge_template_002",
        title: "Governance Design",
        description: null,
        imageUri: null,
      }),
    ]);
    mockedListLearnerBadgeSummaries.mockResolvedValue([
      sampleLearnerBadgeSummary({
        assertionId: "tenant_123:assertion_existing",
        badgeTemplateId: "badge_template_001",
        issuedAt: "2026-02-11T14:00:00.000Z",
      }),
    ]);
    mockedListAssertionLifecycleStatesByAssertionIds.mockResolvedValue([
      {
        assertionId: "tenant_123:assertion_existing",
        state: "active",
        source: "default_active",
        reasonCode: null,
        reason: null,
        transitionedAt: null,
        revokedAt: null,
      },
    ]);
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const { response, body } = await launchLearnerResourceLinkForTest({
      isolatedApp,
      env,
      resourceLinkId: "resource-link-leftnav",
      name: "Jennifer Truman",
      email: "Learner@Example.edu",
      context: {
        id: "course-123",
        title: "TypeScript 101",
      },
    });

    expect(response.status).toBe(200);
    expect(body).toContain("Hi, Jennifer Truman");
    expect(body).toContain("Open CredTrail dashboard");
    expect(body).toContain("Badges in this course");
    expect(body).toContain("Showing 2 active badges in this course.");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Governance Design");
    expect(body).toContain("Open criteria to review how learners qualify for this badge.");
    expect(body).toContain("GD");
    expect(body).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001");
    expect(body).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_002");
    expect(
      body.match(/\/showcase\/tenant_123\/criteria\?badgeTemplateId=badge_template_001/g) ?? [],
    ).toHaveLength(1);
    expect(body).toContain("Issued Feb 11, 2026, 2:00 PM UTC");
    expect(body).toContain("Claim badge and open sharing options");
    expect(body).toContain(
      "/tenants/tenant_123/learner/badges/tenant_123%3Aassertion_existing/claim",
    );
    expect(body).toContain(
      "/tenants/tenant_123/learner/badges/tenant_123%3Aassertion_existing/claim?lti_session_handoff=",
    );
    expect(body).toContain("Not issued");
    expect(body).toContain("Not issued yet.");
    expect(body).not.toContain("Launch troubleshooting details");
    expect(body).not.toContain("/tenants/tenant_123/admin/");
    expect(mockedListLtiResourceLinkPlacementsForContext).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      issuer,
      clientId,
      deploymentId,
      contextId: "course-123",
      includeRetired: true,
    });
    expect(mockedListBadgeTemplatesByIds).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      badgeTemplateIds: ["badge_template_001", "badge_template_002"],
      includeArchived: true,
    });
    expect(mockedListLearnerBadgeSummaries).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      userId: linkedUserId,
    });
    expect(mockedListAssertionLifecycleStatesByAssertionIds).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      assertionIds: ["tenant_123:assertion_existing"],
    });
    expect(mockedUpsertLtiResourceLinkPlacement).not.toHaveBeenCalled();
  });

  it("renders learner Lessons selected badge context with claim action", async () => {
    const env = createLtiEnv();
    mockedListLearnerBadgeSummaries.mockResolvedValue([
      sampleLearnerBadgeSummary({
        assertionId: "tenant_123:assertion_existing",
        badgeTemplateId: "badge_template_001",
        issuedAt: "2026-02-11T14:00:00.000Z",
      }),
    ]);
    mockedListAssertionLifecycleStatesByAssertionIds.mockResolvedValue([
      {
        assertionId: "tenant_123:assertion_existing",
        state: "active",
        source: "default_active",
        reasonCode: null,
        reason: null,
        transitionedAt: null,
        revokedAt: null,
      },
    ]);
    const selectedBadgeTargetLinkUri = `${targetLinkUri}?badgeTemplateId=badge_template_001&ruleId=brl_lti_rule_123`;
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const { response, body } = await launchLearnerResourceLinkForTest({
      isolatedApp,
      env,
      targetLinkUri: selectedBadgeTargetLinkUri,
      resourceLinkId: "resource-link-selected-badge",
      name: "Jennifer Truman",
      email: "Learner@Example.edu",
      context: {
        id: "course-123",
        title: "TypeScript 101",
      },
    });

    expect(response.status).toBe(200);
    expect(body).toContain("Hi, Jennifer Truman");
    expect(body).toContain("Selected badge");
    expect(body).not.toContain("Badges in this course");
    expect(body).toContain("Review the badge selected for this LMS lesson.");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Awarded for completing TypeScript fundamentals.");
    expect(body).toContain('src="https://example.edu/image.png"');
    expect(body).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001");
    expect(body).toContain("Issued Feb 11, 2026, 2:00 PM UTC");
    expect(body).toContain("Claim badge and open sharing options");
    expect(body).toContain(
      "/tenants/tenant_123/learner/badges/tenant_123%3Aassertion_existing/claim",
    );
    expect(body).toContain(
      "/tenants/tenant_123/learner/badges/tenant_123%3Aassertion_existing/claim?lti_session_handoff=",
    );
    expect(body).not.toContain("Launch troubleshooting details");
    expect(body).not.toContain("/tenants/tenant_123/admin/");
    const claimAction = body.match(
      /action="([^"]*\/tenants\/tenant_123\/learner\/badges\/tenant_123%3Aassertion_existing\/claim\?lti_session_handoff=[^"]+)"/,
    )?.[1];
    expect(claimAction).toBeDefined();

    const claimResponse = await isolatedApp.request(
      claimAction === undefined ? "/" : claimAction.replaceAll("&amp;", "&"),
      {
        method: "POST",
      },
      env,
    );

    expect(claimResponse.status).toBe(303);
    expect(claimResponse.headers.get("location")).toContain(
      "/badges/public_badge_001#share-this-credential",
    );
    expect(claimResponse.headers.get("set-cookie")).toContain("better-auth.session_token=");
    expect(mockedRecordAssertionEngagementEvent).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId,
        assertionId: "tenant_123:assertion_existing",
        eventType: "learner_claim",
        actorType: "learner",
        channel: "learner_dashboard",
      }),
    );
    expect(mockedUpsertLtiResourceLinkPlacement).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      issuer,
      clientId,
      deploymentId,
      contextId: "course-123",
      resourceLinkId: "resource-link-selected-badge",
      badgeTemplateId: "badge_template_001",
      ruleId: "brl_lti_rule_123",
      createdByUserId: linkedUserId,
    });
    expect(mockedListLtiResourceLinkPlacementsForContext).not.toHaveBeenCalled();
    expect(mockedListBadgeTemplatesByIds).not.toHaveBeenCalled();
  });

  it("creates the shared rule and placement when an instructor launches an LTI setup link", async () => {
    mockedFindBadgeTemplateById.mockResolvedValue(
      sampleBadgeTemplate({
        imageUri: "https://credtrail.test/badges/assets/tenant_123/badge_template_001/asset_456",
      }),
    );
    const env = createLtiEnv();
    const setupToken = await createLtiCourseBadgeSetupToken(env, {
      tenantId,
      issuer,
      clientId,
      deploymentId,
      contextId: "course-123",
      badgeTemplateId: "badge_template_001",
      setupRequest: {
        preset: "final_course_score_threshold",
        scoreThreshold: 85,
      },
      ttlSeconds: 600,
    });
    const selectedBadgeTargetLinkUri = `${targetLinkUri}?badgeTemplateId=badge_template_001&setupToken=${encodeURIComponent(setupToken)}`;
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const { response } = await launchLearnerResourceLinkForTest({
      isolatedApp,
      env,
      role: "instructor",
      targetLinkUri: selectedBadgeTargetLinkUri,
      resourceLinkId: "resource-link-selected-badge",
      name: "Instructor One",
      email: "instructor@example.edu",
      context: {
        id: "course-123",
        title: "TypeScript 101",
      },
    });

    expect(response.status).toBe(200);
    expect(mockedCreateLtiCourseBadgeRule).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      course: {
        parentOrgUnitId: "tenant_123:org:department-cs",
        externalSystemId: "lms_sakai_001",
        externalCourseId: "course-123",
        title: "TypeScript 101",
      },
      rule: expect.objectContaining({
        badgeTemplateId: "badge_template_001",
        lmsProviderKind: "sakai",
        lmsConnectionId: "lms_sakai_001",
      }),
      placement: {
        issuer,
        clientId,
        deploymentId,
        contextId: "course-123",
        resourceLinkId: "resource-link-selected-badge",
        delegatedGrantId: "diag_lti_course_setup_123",
      },
      actorUserId: linkedUserId,
      actorRole: "viewer",
    });
    const createRuleInput = mockedCreateLtiCourseBadgeRule.mock.calls[0]?.[1];
    expect(JSON.parse(createRuleInput?.rule.ruleJson ?? "{}")).toMatchObject({
      conditions: {
        type: "grade_threshold",
        courseId: "course-123",
        scoreField: "final_score",
        minScore: 85,
      },
    });
    expect(mockedFindActiveDelegatedIssuingAuthorityGrantForAction).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      userId: linkedUserId,
      orgUnitId: "tenant_123:org:department-cs",
      badgeTemplateId: "badge_template_001",
      requiredAction: "configure_course_rule",
    });
  });

  it("returns a conflict when an LTI placement already has a different badge rule", async () => {
    mockedFindBadgeTemplateById.mockResolvedValue(
      sampleBadgeTemplate({
        imageUri: "https://credtrail.test/badges/assets/tenant_123/badge_template_001/asset_456",
      }),
    );
    const env = createLtiEnv();
    const setupToken = await createLtiCourseBadgeSetupToken(env, {
      tenantId,
      issuer,
      clientId,
      deploymentId,
      contextId: "course-123",
      badgeTemplateId: "badge_template_001",
      setupRequest: {
        preset: "final_course_score_threshold",
        scoreThreshold: 85,
      },
      ttlSeconds: 600,
    });
    const selectedBadgeTargetLinkUri = `${targetLinkUri}?badgeTemplateId=badge_template_001&setupToken=${encodeURIComponent(setupToken)}`;
    mockedCreateLtiCourseBadgeRule.mockResolvedValueOnce({
      status: "placement_conflict",
    });
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const { response, body } = await launchLearnerResourceLinkForTest({
      isolatedApp,
      env,
      role: "instructor",
      targetLinkUri: selectedBadgeTargetLinkUri,
      resourceLinkId: "resource-link-selected-badge",
      name: "Instructor One",
      email: "instructor@example.edu",
      context: {
        id: "course-123",
        title: "TypeScript 101",
      },
    });

    expect(response.status).toBe(409);
    expect(JSON.parse(body)).toEqual({
      error:
        "This Sakai placement already has a different badge rule. Change that rule in CredTrail before placing it again.",
      reason: "course_rule_already_configured",
    });
  });

  it("accepts Sakai instructor deep linking extensions and renders placement forms", async () => {
    const deepLinkReturnUrl = "https://canvas.example.edu/api/lti/deep_link_return";
    const { response, body } = await performInstructorDeepLinkingLaunch({
      deepLinkReturnUrl,
      deepLinkingData: "opaque-deep-link-state",
      additionalDeepLinkingSettings: {
        "https://www.sakailms.org/spec/lti-dl/placement": "lessons",
        "https://www.sakailms.org/spec/lti-dl/accept_lineitem": true,
        "https://www.sakailms.org/spec/lti-dl/accept_available": false,
        "https://www.sakailms.org/spec/lti-dl/accept_submission": false,
      },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("set-cookie")).toContain("better-auth.session_token=");
    expect(body).toContain("Select badge template placement");
    expect(body).toContain(deepLinkReturnUrl);
    expect(body).toContain('name="lti_session_id"');
    expect(body).toContain('name="badge_template_id"');
    expect(body).toContain('name="criteria_preset"');
    expect(body).toContain("Course earning criteria");
    expect(body).toContain("manual_instructor_approval");
    expect(body).toContain("final_course_score_threshold");
    expect(body).toContain("Advanced setup in CredTrail");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("badgeTemplateId=badge_template_001");
    expect(body).toContain("source=lti-deep-link");
    expect(body).toContain("/assets/ui/foundation.");
    expect(body).toContain("/assets/ui/lti-pages.");
    expect(mockedListBadgeTemplates).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      includeArchived: false,
    });
    expect(mockedListActiveDelegatedIssuingAuthorityGrantsForUser).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      userId: linkedUserId,
    });
    expect(mockedFindActiveDelegatedIssuingAuthorityGrantForAction).not.toHaveBeenCalled();
  });

  it("filters Deep Linking templates that are not instructor-placeable", async () => {
    mockedListBadgeTemplates.mockResolvedValue([
      sampleBadgeTemplate({
        governanceMetadataJson: JSON.stringify({ ltiInstructorPlacement: { enabled: false } }),
      }),
    ]);
    const { response, body } = await performInstructorDeepLinkingLaunch();

    expect(response.status).toBe(200);
    expect(body).toContain("Select badge template placement");
    expect(body).not.toContain("TypeScript Foundations");
    expect(mockedListActiveDelegatedIssuingAuthorityGrantsForUser).not.toHaveBeenCalled();
    expect(mockedFindActiveDelegatedIssuingAuthorityGrantForAction).not.toHaveBeenCalled();
  });

  it("filters Deep Linking templates when the instructor lacks a placement grant", async () => {
    mockedListActiveDelegatedIssuingAuthorityGrantsForUser.mockResolvedValue([]);
    const { response, body } = await performInstructorDeepLinkingLaunch();

    expect(response.status).toBe(200);
    expect(body).toContain("Select badge template placement");
    expect(body).not.toContain("TypeScript Foundations");
    expect(mockedListActiveDelegatedIssuingAuthorityGrantsForUser).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      userId: linkedUserId,
    });
    expect(mockedFindActiveDelegatedIssuingAuthorityGrantForAction).not.toHaveBeenCalled();
  });

  it("returns a signed Deep Linking response for selected templates through lti-tool core", async () => {
    const env = createLtiEnv();
    const deepLinkReturnUrl = "https://canvas.example.edu/api/lti/deep_link_return";
    const ltiSession: LTISession = {
      jwtPayload: LTI13JwtPayloadSchema.parse({
        iss: issuer,
        sub: "user-999",
        aud: clientId,
        exp: 1_800_000_000,
        iat: 1_700_000_000,
        nonce: "nonce-123",
        [ltiClaim.deploymentId]: deploymentId,
        [ltiClaim.messageType]: "LtiDeepLinkingRequest",
        [ltiClaim.version]: "1.3.0",
        [ltiClaim.targetLinkUri]: targetLinkUri,
        [ltiClaim.deepLinkingSettings]: {
          deep_link_return_url: deepLinkReturnUrl,
          accept_types: ["ltiResourceLink"],
          accept_presentation_document_targets: [],
        },
      }),
      id: "lti-session-123",
      user: {
        id: "user-999",
        roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
      },
      context: {
        id: "course-123",
        label: "TS101",
        title: "TypeScript 101",
      },
      platform: {
        issuer,
        clientId,
        deploymentId,
        name: "Canvas",
      },
      launch: {
        target: targetLinkUri,
      },
      services: {
        deepLinking: {
          returnUrl: deepLinkReturnUrl,
          acceptTypes: ["ltiResourceLink"],
          acceptPresentationDocumentTargets: [],
          acceptMultiple: false,
          autoCreate: false,
          data: "opaque-deep-link-state",
        },
      },
      customParameters: {},
      isAdmin: false,
      isInstructor: true,
      isStudent: false,
      isAssignmentAndGradesAvailable: false,
      isDeepLinkingAvailable: true,
      isNameAndRolesAvailable: false,
    };
    const createDeepLinkingHtmlResponse = vi.fn().mockResolvedValue({
      success: true,
      data: new Response("<!DOCTYPE html><html><body>signed deep link</body></html>", {
        headers: {
          "cache-control": "no-store",
          "content-type": "text/html; charset=utf-8",
        },
      }),
    });
    mockedFindActiveLtiLaunchSessionByOpaqueId.mockResolvedValue(
      sampleLtiLaunchSessionRecord({
        dataJson: serializeLtiSession(ltiSession),
      }),
    );
    const { app: isolatedApp } = await loadAppWithMockedAuthProviders(() => {
      vi.doMock("./lti/credtrail-lti-tool", () => {
        const createTool = vi.fn(async () =>
          mockLtiToolWithDeepLinking({
            createDeepLinkingHtmlResponse,
          }),
        );

        return {
          createCredTrailLtiTool: createTool,
        };
      });
    });

    const response = await isolatedApp.request(
      "/v1/lti/deep-linking/select",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          lti_session_id: ltiSession.id,
          badge_template_id: "badge_template_001",
          criteria_preset: "final_course_score_threshold",
          score_threshold: "85",
        }).toString(),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("signed deep link");
    expect(mockedFindActiveLtiLaunchSessionByOpaqueId).toHaveBeenCalledWith(fakeDb, ltiSession.id);
    expect(mockedListTenantLmsConnections).not.toHaveBeenCalled();
    expect(createDeepLinkingHtmlResponse).toHaveBeenCalledWith([
      expect.objectContaining({
        type: "ltiResourceLink",
        title: "TypeScript Foundations",
        url: expect.stringMatching(
          /^https:\/\/tool\.example\.edu\/v1\/lti\/launch\?badgeTemplateId=badge_template_001&setupToken=.+/,
        ),
        custom: expect.objectContaining({
          badgeTemplateId: "badge_template_001",
          setupToken: expect.any(String),
        }),
      }),
    ]);
  });

  it("rejects Deep Linking selection when the instructor lacks course rule authority", async () => {
    mockedFindActiveDelegatedIssuingAuthorityGrantForAction.mockResolvedValue(null);
    const env = createLtiEnv();
    const deepLinkReturnUrl = "https://canvas.example.edu/api/lti/deep_link_return";
    const ltiSession: LTISession = {
      jwtPayload: LTI13JwtPayloadSchema.parse({
        iss: issuer,
        sub: "user-999",
        aud: clientId,
        exp: 1_800_000_000,
        iat: 1_700_000_000,
        nonce: "nonce-123",
        [ltiClaim.deploymentId]: deploymentId,
        [ltiClaim.messageType]: "LtiDeepLinkingRequest",
        [ltiClaim.version]: "1.3.0",
        [ltiClaim.targetLinkUri]: targetLinkUri,
        [ltiClaim.deepLinkingSettings]: {
          deep_link_return_url: deepLinkReturnUrl,
          accept_types: ["ltiResourceLink"],
          accept_presentation_document_targets: [],
        },
      }),
      id: "lti-session-123",
      user: {
        id: "user-999",
        roles: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
      },
      context: {
        id: "course-123",
        label: "TS101",
        title: "TypeScript 101",
      },
      platform: {
        issuer,
        clientId,
        deploymentId,
        name: "Canvas",
      },
      launch: {
        target: targetLinkUri,
      },
      services: {
        deepLinking: {
          returnUrl: deepLinkReturnUrl,
          acceptTypes: ["ltiResourceLink"],
          acceptPresentationDocumentTargets: [],
          acceptMultiple: false,
          autoCreate: false,
          data: "opaque-deep-link-state",
        },
      },
      customParameters: {},
      isAdmin: false,
      isInstructor: true,
      isStudent: false,
      isAssignmentAndGradesAvailable: false,
      isDeepLinkingAvailable: true,
      isNameAndRolesAvailable: false,
    };
    const createDeepLinkingHtmlResponse = vi.fn().mockResolvedValue({
      success: true,
      data: new Response("<!DOCTYPE html><html><body>signed deep link</body></html>", {
        headers: {
          "cache-control": "no-store",
          "content-type": "text/html; charset=utf-8",
        },
      }),
    });
    mockedFindActiveLtiLaunchSessionByOpaqueId.mockResolvedValue(
      sampleLtiLaunchSessionRecord({
        dataJson: serializeLtiSession(ltiSession),
      }),
    );
    const { app: isolatedApp } = await loadAppWithMockedAuthProviders(() => {
      vi.doMock("./lti/credtrail-lti-tool", () => {
        const createTool = vi.fn(async () =>
          mockLtiToolWithDeepLinking({
            createDeepLinkingHtmlResponse,
          }),
        );

        return {
          createCredTrailLtiTool: createTool,
        };
      });
    });

    const response = await isolatedApp.request(
      "/v1/lti/deep-linking/select",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          lti_session_id: ltiSession.id,
          badge_template_id: "badge_template_001",
          criteria_preset: "final_course_score_threshold",
          score_threshold: "85",
        }).toString(),
      },
      env,
    );
    const body = (await response.json()) as ErrorResponse & { reason?: string };

    expect(response.status).toBe(403);
    expect(body.reason).toBe("missing_delegated_authority");
    expect(createDeepLinkingHtmlResponse).not.toHaveBeenCalled();
    expect(mockedFindActiveDelegatedIssuingAuthorityGrantForAction).toHaveBeenCalledWith(fakeDb, {
      tenantId,
      userId: linkedUserId,
      orgUnitId: "tenant_123:org:department-cs",
      badgeTemplateId: "badge_template_001",
      requiredAction: "configure_course_rule",
    });
  });

  it("rejects deep linking launch for learner role", async () => {
    const env = createLtiEnv();
    const { app: isolatedApp } = await loadAppWithMockedSignedLtiTool();
    const loginResponse = await isolatedApp.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}`,
      undefined,
      env,
    );
    const loginLocation = loginResponse.headers.get("location");
    const loginUrl = new URL(loginLocation ?? "");
    const state = loginUrl.searchParams.get("state") ?? "";
    const nonce = loginUrl.searchParams.get("nonce") ?? "";
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    const idToken = compactJwsForTest({
      header: {
        alg: "RS256",
      },
      payload: {
        iss: issuer,
        sub: "user-learner-deep-link",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 10,
        nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deploymentId,
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": targetLinkUri,
        "https://purl.imsglobal.org/spec/lti/claim/roles": [
          "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
        ],
        "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings": {
          deep_link_return_url: "https://canvas.example.edu/api/lti/deep_link_return",
          accept_types: ["ltiResourceLink"],
          accept_presentation_document_targets: [],
        },
      },
    });

    const response = await isolatedApp.request(
      "/v1/lti/launch",
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          id_token: idToken,
          state,
        }).toString(),
      },
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(403);
    expect(body.error).toContain("requires instructor role");
    expect(mockedListBadgeTemplates).not.toHaveBeenCalled();
  });

  it("rejects OIDC login when issuer is missing signed launch configuration", async () => {
    const env = createUnsignedOnlyLtiEnv();
    const response = await app.request(
      `/v1/lti/oidc/login?iss=${encodeURIComponent(issuer)}&login_hint=${encodeURIComponent(
        "opaque-login-hint",
      )}&target_link_uri=${encodeURIComponent(targetLinkUri)}`,
      undefined,
      env,
    );
    const body = await response.json<ErrorResponse>();

    expect(response.status).toBe(501);
    expect(body.error).toContain("requires platform JWKS and token endpoint");
  });
});
