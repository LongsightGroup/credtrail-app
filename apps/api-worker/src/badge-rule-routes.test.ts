import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedIssueBadgeForTenant,
  mockedCreateGradebookProvider,
  submitBadgeIssuanceRuleVersionMock,
  decideBadgeIssuanceRuleVersionMock,
} = vi.hoisted(() => {
  return {
    mockedIssueBadgeForTenant: vi.fn(),
    mockedCreateGradebookProvider: vi.fn(),
    submitBadgeIssuanceRuleVersionMock: vi.fn(),
    decideBadgeIssuanceRuleVersionMock: vi.fn(),
  };
});

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
    createBadgeIssuanceRuleWithAction: vi.fn(),
    findBadgeIssuanceRuleAuthoringReplay: vi.fn(),
    createBadgeIssuanceRuleValueList: vi.fn(),
    updateBadgeIssuanceRuleWithAction: vi.fn(),
    submitBadgeIssuanceRuleVersionForApproval: submitBadgeIssuanceRuleVersionMock,
    decideBadgeIssuanceRuleVersion: decideBadgeIssuanceRuleVersionMock,
    activateBadgeIssuanceRuleVersion: vi.fn(),
    findBadgeIssuanceRuleEvaluationById: vi.fn(),
    findBadgeIssuanceRuleById: vi.fn(),
    findBadgeTemplateById: vi.fn(),
    findBadgeIssuanceRuleVersionById: vi.fn(),
    listBadgeIssuanceRules: vi.fn(),
    listBadgeIssuanceRuleEvaluations: vi.fn(),
    listBadgeIssuanceRuleValueLists: vi.fn(),
    listBadgeIssuanceRuleVersions: vi.fn(),
    listBadgeIssuanceRuleVersionApprovalSteps: vi.fn(),
    listBadgeIssuanceRuleVersionApprovalEvents: vi.fn(),
    saveBadgeIssuanceRuleBuilderDraft: vi.fn(),
    deleteBadgeIssuanceRuleBuilderDraftForRule: vi.fn(),
    resolveBadgeIssuanceRuleEvaluationReview: vi.fn(),
    findTenantLmsConnectionById: vi.fn(),
    findTenantLmsUserIdentity: vi.fn(),
    listTenantLmsConnections: vi.fn(),
    upsertTenantLmsConnection: vi.fn(),
    updateTenantLmsConnectionTokens: vi.fn(),
    listAuditLogs: vi.fn(),
    listIssuedBadgeTemplateIdsForRecipient: vi.fn(),
    findActiveSessionByHash: mockedFindActiveSessionByHash,
    findTenantMembership: vi.fn(),
    enqueueJobQueueMessageOnce: vi.fn(),
    touchSession: mockedTouchSession,
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

vi.mock("./badges/direct-issue", () => {
  return {
    createIssueBadgeForTenant: vi.fn(() => mockedIssueBadgeForTenant),
  };
});

vi.mock("./lms/gradebook-provider", async () => {
  const actual = await vi.importActual<typeof import("./lms/gradebook-provider")>(
    "./lms/gradebook-provider",
  );

  return {
    ...actual,
    createGradebookProvider: mockedCreateGradebookProvider,
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
  activateBadgeIssuanceRuleVersion,
  createAuditLog,
  createBadgeIssuanceRuleWithAction,
  createBadgeIssuanceRuleValueList,
  decideBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleEvaluationById,
  findBadgeIssuanceRuleById,
  findBadgeTemplateById,
  findBadgeIssuanceRuleVersionById,
  findTenantMembership,
  findBadgeIssuanceRuleAuthoringReplay,
  enqueueJobQueueMessageOnce,
  findTenantLmsConnectionById,
  findTenantLmsUserIdentity,
  listIssuedBadgeTemplateIdsForRecipient,
  listAuditLogs,
  listBadgeIssuanceRuleEvaluations,
  listBadgeIssuanceRuleValueLists,
  listBadgeIssuanceRuleVersionApprovalEvents,
  listBadgeIssuanceRuleVersionApprovalSteps,
  listBadgeIssuanceRuleVersions,
  listBadgeIssuanceRules,
  listTenantLmsConnections,
  resolveBadgeIssuanceRuleEvaluationReview,
  saveBadgeIssuanceRuleBuilderDraft,
  deleteBadgeIssuanceRuleBuilderDraftForRule,
  submitBadgeIssuanceRuleVersionForApproval,
  updateBadgeIssuanceRuleWithAction,
  upsertTenantLmsConnection,
  type AuditLogRecord,
  type BadgeIssuanceRuleEvaluationRecord,
  type BadgeIssuanceRuleApprovalEventRecord,
  type BadgeIssuanceRuleApprovalStepRecord,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleValueListRecord,
  type BadgeIssuanceRuleVersionRecord,
  type BadgeTemplateRecord,
  type SessionRecord,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
  type TenantMembershipRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { GradebookProviderError } from "./lms/gradebook-provider-error";
import type { GradebookCourseSearchInput } from "./lms/gradebook-types";
import {
  buildBadgeRuleVersionRecord,
  type BadgeRuleVersionRecordOverrides,
} from "./test-support/badge-rule-version";
import { app } from "./index";

const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
const mockedCreateAuditLog = vi.mocked(createAuditLog);
const mockedEnqueueJobQueueMessageOnce = vi.mocked(enqueueJobQueueMessageOnce);
const mockedCreateBadgeIssuanceRuleWithAction = vi.mocked(createBadgeIssuanceRuleWithAction);
const mockedFindBadgeIssuanceRuleAuthoringReplay = vi.mocked(findBadgeIssuanceRuleAuthoringReplay);
const mockedUpdateBadgeIssuanceRuleWithAction = vi.mocked(updateBadgeIssuanceRuleWithAction);
const mockedCreateBadgeIssuanceRuleValueList = vi.mocked(createBadgeIssuanceRuleValueList);
const mockedSubmitBadgeIssuanceRuleVersionForApproval = vi.mocked(
  submitBadgeIssuanceRuleVersionForApproval,
);
const mockedDecideBadgeIssuanceRuleVersion = vi.mocked(decideBadgeIssuanceRuleVersion);
const mockedActivateBadgeIssuanceRuleVersion = vi.mocked(activateBadgeIssuanceRuleVersion);
const mockedFindBadgeIssuanceRuleById = vi.mocked(findBadgeIssuanceRuleById);
const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
const mockedFindBadgeIssuanceRuleEvaluationById = vi.mocked(findBadgeIssuanceRuleEvaluationById);
const mockedFindBadgeIssuanceRuleVersionById = vi.mocked(findBadgeIssuanceRuleVersionById);
const mockedListBadgeIssuanceRules = vi.mocked(listBadgeIssuanceRules);
const mockedListBadgeIssuanceRuleEvaluations = vi.mocked(listBadgeIssuanceRuleEvaluations);
const mockedListBadgeIssuanceRuleValueLists = vi.mocked(listBadgeIssuanceRuleValueLists);
const mockedListBadgeIssuanceRuleVersions = vi.mocked(listBadgeIssuanceRuleVersions);
const mockedListTenantLmsConnections = vi.mocked(listTenantLmsConnections);
const mockedListBadgeIssuanceRuleVersionApprovalSteps = vi.mocked(
  listBadgeIssuanceRuleVersionApprovalSteps,
);
const mockedListBadgeIssuanceRuleVersionApprovalEvents = vi.mocked(
  listBadgeIssuanceRuleVersionApprovalEvents,
);
const mockedListAuditLogs = vi.mocked(listAuditLogs);
const mockedSaveBadgeIssuanceRuleBuilderDraft = vi.mocked(saveBadgeIssuanceRuleBuilderDraft);
const mockedDeleteBadgeIssuanceRuleBuilderDraft = vi.mocked(
  deleteBadgeIssuanceRuleBuilderDraftForRule,
);
const mockedResolveBadgeIssuanceRuleEvaluationReview = vi.mocked(
  resolveBadgeIssuanceRuleEvaluationReview,
);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedFindTenantLmsConnectionById = vi.mocked(findTenantLmsConnectionById);
const mockedFindTenantLmsUserIdentity = vi.mocked(findTenantLmsUserIdentity);
const mockedUpsertTenantLmsConnection = vi.mocked(upsertTenantLmsConnection);
const mockedListIssuedBadgeTemplateIdsForRecipient = vi.mocked(
  listIssuedBadgeTemplateIdsForRecipient,
);

const sampleTenantLmsConnection = (
  overrides?: Partial<TenantLmsConnectionRecord>,
): TenantLmsConnectionRecord => {
  return {
    id: "lms_123",
    tenantId: "tenant_123",
    displayName: "Canvas Test",
    providerKind: "canvas",
    apiBaseUrl: "https://canvas.example.edu",
    authorizationEndpoint: "https://canvas.example.edu/login/oauth2/auth",
    tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
    clientId: "client-id",
    clientSecret: "client-secret",
    scope: "url:GET|/api/v1/courses",
    accessToken: "canvas-token",
    refreshToken: "canvas-refresh-token",
    accessTokenExpiresAt: null,
    refreshTokenExpiresAt: null,
    connectedAt: "2026-02-17T00:00:00.000Z",
    ltiIssuer: null,
    ltiClientId: null,
    ltiDeploymentId: null,
    createdAt: "2026-02-17T00:00:00.000Z",
    updatedAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  };
};

const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;
const courseSearchInputs: GradebookCourseSearchInput[] = [];

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
    BADGE_OBJECTS: {
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
    } as unknown as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

const sampleBadgeTemplate = (): BadgeTemplateRecord => ({
  id: "badge_template_cs101",
  tenantId: "tenant_123",
  slug: "cs101",
  title: "CS101 Excellence",
  description: "Issue badge for CS101 excellence",
  criteriaUri: "https://credtrail.test/criteria/cs101",
  imageUri: "https://credtrail.test/badges/assets/tenant_123/badge_template_cs101/asset_456",
  trustedCredentialMetadataJson: null,
  createdByUserId: "usr_123",
  ownerOrgUnitId: "tenant_123:org:institution",
  governanceMetadataJson: null,
  isArchived: false,
  createdAt: "2026-02-17T00:00:00.000Z",
  updatedAt: "2026-02-17T00:00:00.000Z",
});

const sampleSession = (overrides?: Partial<SessionRecord>): SessionRecord => {
  return {
    id: "ses_123",
    tenantId: "tenant_123",
    userId: "usr_123",
    sessionTokenHash: "session-hash",
    expiresAt: "2026-02-20T00:00:00.000Z",
    lastSeenAt: "2026-02-17T00:00:00.000Z",
    revokedAt: null,
    createdAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  };
};

const sampleMembership = (overrides?: Partial<TenantMembershipRecord>): TenantMembershipRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_123",
    role: "admin",
    createdAt: "2026-02-17T00:00:00.000Z",
    updatedAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  };
};

const sampleAuditLogRecord = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    id: "audit_123",
    tenantId: "tenant_123",
    actorUserId: "usr_123",
    action: "badge_rule.test",
    targetType: "badge_rule",
    targetId: "brl_123",
    metadataJson: null,
    occurredAt: "2026-02-17T00:00:00.000Z",
    createdAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  };
};

const sampleRule = (overrides?: Partial<BadgeIssuanceRuleRecord>): BadgeIssuanceRuleRecord => {
  return {
    id: "brl_123",
    tenantId: "tenant_123",
    name: "CS101 Rule",
    description: "Issue badge for CS101 excellence",
    badgeTemplateId: "badge_template_cs101",
    orgUnitId: "tenant_123:org:institution",
    ownerOrgUnitId: "tenant_123:org:institution",
    lmsProviderKind: "canvas",
    lmsConnectionId: "lms_123",
    activeVersionId: "brv_123",
    createdByUserId: "usr_123",
    createdAt: "2026-02-17T00:00:00.000Z",
    updatedAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  };
};

const sampleVersion = (
  overrides: BadgeRuleVersionRecordOverrides = {},
): BadgeIssuanceRuleVersionRecord => {
  return buildBadgeRuleVersionRecord({
    ruleJson: JSON.stringify({
      conditions: {
        type: "grade_threshold",
        courseId: "course_101",
        minScore: 80,
      },
    }),
    changeSummary: "Initial draft",
    createdByUserId: "usr_123",
    createdAt: "2026-02-17T00:00:00.000Z",
    updatedAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  });
};

const sampleEvaluationRecord = (
  overrides?: Partial<BadgeIssuanceRuleEvaluationRecord>,
): BadgeIssuanceRuleEvaluationRecord => {
  return {
    id: "bre_123",
    tenantId: "tenant_123",
    ruleId: "brl_123",
    versionId: "brv_123",
    learnerId: "learner_123",
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    matched: true,
    issuanceStatus: "issued",
    assertionId: "tenant_123:assertion_1",
    evaluationJson: "{}",
    reviewStatus: null,
    reviewDecision: null,
    reviewComment: null,
    reviewedByUserId: null,
    reviewedAt: null,
    evaluatedAt: "2026-02-17T00:00:00.000Z",
    createdAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  };
};

const sampleValueListRecord = (
  overrides?: Partial<BadgeIssuanceRuleValueListRecord>,
): BadgeIssuanceRuleValueListRecord => {
  return {
    id: "brvl_123",
    tenantId: "tenant_123",
    label: "Core CS sequence",
    kind: "course_ids",
    values: ["course_101", "course_102", "course_103"],
    createdByUserId: "usr_123",
    archivedAt: null,
    createdAt: "2026-02-17T00:00:00.000Z",
    updatedAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  };
};

const sampleApprovalStep = (
  overrides?: Partial<
    Extract<BadgeIssuanceRuleApprovalStepRecord, { targetType: "role_threshold" }>
  >,
): BadgeIssuanceRuleApprovalStepRecord => {
  return {
    id: "bras_123",
    tenantId: "tenant_123",
    versionId: "brv_123",
    stepNumber: 1,
    targetType: "role_threshold",
    requiredRole: "admin",
    targetUserId: null,
    targetApproverGroupId: null,
    orgUnitId: null,
    label: "Registrar approval",
    status: "pending",
    decidedByUserId: null,
    decidedAt: null,
    decisionComment: null,
    createdAt: "2026-02-17T00:00:00.000Z",
    updatedAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  };
};

const sampleApprovalEvent = (
  overrides?: Partial<BadgeIssuanceRuleApprovalEventRecord>,
): BadgeIssuanceRuleApprovalEventRecord => {
  return {
    id: "brae_123",
    tenantId: "tenant_123",
    versionId: "brv_123",
    stepNumber: 1,
    action: "submitted",
    actorUserId: "usr_123",
    actorRole: "issuer",
    comment: null,
    occurredAt: "2026-02-17T00:00:00.000Z",
    createdAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
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
        expiresAt: "2026-02-20T00:00:00.000Z",
      };
    },
  );
  mockedResolveBetterAuthRequestedTenant.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue(null);

  mockedFindActiveSessionByHash.mockReset();
  mockedFindActiveSessionByHash.mockResolvedValue(sampleSession());
  mockedTouchSession.mockReset();
  mockedTouchSession.mockResolvedValue(undefined);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleMembership());

  mockedCreateAuditLog.mockReset();
  mockedCreateAuditLog.mockResolvedValue(sampleAuditLogRecord());
  mockedEnqueueJobQueueMessageOnce.mockReset();
  mockedEnqueueJobQueueMessageOnce.mockResolvedValue(true);
  mockedCreateBadgeIssuanceRuleWithAction.mockReset();
  mockedFindBadgeIssuanceRuleAuthoringReplay.mockReset();
  mockedFindBadgeIssuanceRuleAuthoringReplay.mockResolvedValue(null);
  mockedCreateBadgeIssuanceRuleValueList.mockReset();
  mockedCreateBadgeIssuanceRuleValueList.mockResolvedValue(sampleValueListRecord());
  mockedUpdateBadgeIssuanceRuleWithAction.mockReset();
  mockedSubmitBadgeIssuanceRuleVersionForApproval.mockReset();
  mockedDecideBadgeIssuanceRuleVersion.mockReset();
  mockedActivateBadgeIssuanceRuleVersion.mockReset();
  mockedFindBadgeIssuanceRuleEvaluationById.mockReset();
  mockedFindBadgeIssuanceRuleById.mockReset();
  mockedFindBadgeTemplateById.mockReset();
  mockedFindBadgeTemplateById.mockResolvedValue(sampleBadgeTemplate());
  mockedFindBadgeIssuanceRuleVersionById.mockReset();
  mockedListBadgeIssuanceRules.mockReset();
  mockedListBadgeIssuanceRules.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleEvaluations.mockReset();
  mockedListBadgeIssuanceRuleEvaluations.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleValueLists.mockReset();
  mockedListBadgeIssuanceRuleValueLists.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleVersions.mockReset();
  mockedListBadgeIssuanceRuleVersions.mockResolvedValue([]);
  mockedListTenantLmsConnections.mockReset();
  mockedListTenantLmsConnections.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleVersionApprovalSteps.mockReset();
  mockedListBadgeIssuanceRuleVersionApprovalSteps.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleVersionApprovalEvents.mockReset();
  mockedListBadgeIssuanceRuleVersionApprovalEvents.mockResolvedValue([]);
  mockedListAuditLogs.mockReset();
  mockedListAuditLogs.mockResolvedValue([]);
  mockedSaveBadgeIssuanceRuleBuilderDraft.mockReset();
  mockedDeleteBadgeIssuanceRuleBuilderDraft.mockReset();
  mockedDeleteBadgeIssuanceRuleBuilderDraft.mockResolvedValue(true);
  mockedResolveBadgeIssuanceRuleEvaluationReview.mockReset();
  mockedIssueBadgeForTenant.mockReset();
  mockedCreateGradebookProvider.mockReset();
  courseSearchInputs.length = 0;
  mockedCreateGradebookProvider.mockReturnValue({
    kind: "canvas",
    verifyCourseAccess: () => Promise.resolve({ authorizedCourses: [], unauthorizedCourseIds: [] }),
    listCourses: (input: GradebookCourseSearchInput) => {
      courseSearchInputs.push(input);
      return Promise.resolve({
        courses: [
          {
            courseId: "course_101",
            title: "CS101",
            courseCode: "CS101",
            workflowState: "available",
            startsAt: null,
            endsAt: null,
          },
        ],
        hasMore: false,
      });
    },
    listAssignments: () =>
      Promise.resolve([
        {
          assignmentId: "assignment_1",
          courseId: "course_101",
          title: "Final exam",
          workflowState: "published",
          pointsPossible: 100,
          dueAt: null,
        },
      ]),
    listEnrollments: () => Promise.resolve([]),
    listLearners: () =>
      Promise.resolve([
        {
          courseId: "course_101",
          learnerId: "learner_123",
          displayName: "Learner One",
          email: "learner@example.edu",
        },
      ]),
    listSubmissions: () => Promise.resolve([]),
    listGrades: () =>
      Promise.resolve([
        {
          courseId: "course_101",
          learnerId: "learner_123",
          currentScore: 92,
          finalScore: 92,
          currentGrade: "A",
          finalGrade: "A",
        },
      ]),
    listCompletions: () =>
      Promise.resolve([
        {
          courseId: "course_101",
          learnerId: "learner_123",
          completed: true,
          completedAt: null,
          completionPercent: 100,
          sourceState: "completed",
        },
      ]),
  });
  mockedFindTenantLmsConnectionById.mockReset();
  mockedFindTenantLmsConnectionById.mockResolvedValue(sampleTenantLmsConnection());
  mockedFindTenantLmsUserIdentity.mockReset();
  mockedFindTenantLmsUserIdentity.mockResolvedValue({
    tenantId: "tenant_123",
    connectionId: "lms_123",
    userId: "usr_123",
    providerUserId: "instructor_123",
    createdAt: "2026-02-17T00:00:00.000Z",
    updatedAt: "2026-02-17T00:00:00.000Z",
  });
  mockedUpsertTenantLmsConnection.mockReset();
  mockedUpsertTenantLmsConnection.mockResolvedValue(sampleTenantLmsConnection());
  mockedListIssuedBadgeTemplateIdsForRecipient.mockReset();
  mockedListIssuedBadgeTemplateIdsForRecipient.mockResolvedValue([]);
});

describe("badge rule routes", () => {
  it("creates badge issuance rules", async () => {
    const env = createEnv();
    mockedCreateBadgeIssuanceRuleWithAction.mockResolvedValue({
      status: "completed",
      outcome: "draft_saved",
      pendingStepNumber: null,
      writeStatus: "created",
      rule: sampleRule(),
      version: sampleVersion(),
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "CS101 Rule",
          description: "Issue badge for CS101 excellence",
          badgeTemplateId: "badge_template_cs101",
          badgeTemplateReuseAcknowledged: false,
          lmsConnectionId: "lms_123",
          action: "save_draft",
          definition: {
            conditions: {
              type: "grade_threshold",
              courseId: "course_101",
              minScore: 80,
            },
          },
        }),
      },
      env,
    );

    expect(response.status).toBe(201);
    expect(mockedCreateBadgeIssuanceRuleWithAction).toHaveBeenCalledTimes(1);
  });

  it("rejects automated rules whose matching learners cannot be found from LMS rosters", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "Prerequisite badge rule",
          badgeTemplateId: "badge_template_cs101",
          badgeTemplateReuseAcknowledged: false,
          lmsConnectionId: "lms_123",
          action: "save_draft",
          definition: {
            conditions: {
              type: "prerequisite_badge",
              badgeTemplateId: "badge_template_foundations",
            },
            options: { issuanceTiming: "end_of_term" },
          },
        }),
      },
      createEnv(),
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(422);
    expect(body.error).toContain("choose Instructor confirmation");
    expect(mockedCreateBadgeIssuanceRuleWithAction).not.toHaveBeenCalled();
  });

  it("creates and submits the returned rule version with one authoring command", async () => {
    const env = createEnv();
    mockedCreateBadgeIssuanceRuleWithAction.mockResolvedValue({
      status: "completed",
      outcome: "pending_approval",
      pendingStepNumber: 3,
      writeStatus: "created",
      rule: sampleRule(),
      version: sampleVersion({ status: "pending_approval" }),
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "CS101 Rule",
          badgeTemplateId: "badge_template_cs101",
          badgeTemplateReuseAcknowledged: false,
          lmsConnectionId: "lms_123",
          action: "submit_for_approval",
          builderDraftId: "brd_submit",
          definition: {
            conditions: {
              type: "grade_threshold",
              courseId: "course_101",
              minScore: 80,
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<{ outcome: string; version: { status: string } }>();

    expect(response.status).toBe(201);
    expect(body.outcome).toBe("pending_approval");
    expect(body.version.status).toBe("pending_approval");
    expect(mockedCreateBadgeIssuanceRuleWithAction).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "submit_for_approval",
        builderDraftId: "brd_submit",
        actorUserId: "usr_123",
      }),
    );
    expect(mockedSubmitBadgeIssuanceRuleVersionForApproval).not.toHaveBeenCalled();
  });

  it("returns an atomic authoring rejection without recording a created-rule audit", async () => {
    const env = createEnv();
    mockedCreateBadgeIssuanceRuleWithAction.mockResolvedValue({
      status: "failed",
      reason: "self_certification_required",
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "CS101 Rule",
          badgeTemplateId: "badge_template_cs101",
          badgeTemplateReuseAcknowledged: false,
          lmsConnectionId: "lms_123",
          action: "submit_for_approval",
          builderDraftId: "brd_submit",
          definition: {
            conditions: {
              type: "grade_threshold",
              courseId: "course_101",
              minScore: 80,
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(409);
    expect(body.error).toContain("self-certification");
    expect(mockedCreateAuditLog).not.toHaveBeenCalled();
  });

  it("directs stale builder replays to the saved formal rule", async () => {
    const env = createEnv();
    mockedCreateBadgeIssuanceRuleWithAction.mockResolvedValue({
      status: "failed",
      reason: "replay_conflict",
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "Stale retry",
          badgeTemplateId: "badge_template_cs101",
          badgeTemplateReuseAcknowledged: false,
          lmsConnectionId: "lms_123",
          action: "submit_for_approval",
          builderDraftId: "brd_stale",
          definition: {
            conditions: {
              type: "grade_threshold",
              courseId: "course_101",
              minScore: 80,
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(409);
    expect(body.error).toBe(
      "This unfinished rule has already been promoted. Continue from the saved rule.",
    );
    expect(mockedCreateAuditLog).not.toHaveBeenCalled();
  });

  it("does not save a course rule for a user without a linked LMS identity", async () => {
    const env = createEnv();
    mockedFindTenantLmsUserIdentity.mockResolvedValue(null);

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "CS101 Rule",
          badgeTemplateId: "badge_template_cs101",
          badgeTemplateReuseAcknowledged: false,
          lmsConnectionId: "lms_123",
          action: "save_draft",
          definition: {
            conditions: {
              type: "grade_threshold",
              courseId: "course_101",
              minScore: 80,
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(403);
    expect(body.error).toContain("Open CredTrail from Canvas once");
    expect(mockedCreateBadgeIssuanceRuleWithAction).not.toHaveBeenCalled();
  });

  it("promotes the exact unfinished builder draft into a formal rule", async () => {
    const env = createEnv();
    mockedCreateBadgeIssuanceRuleWithAction.mockResolvedValue({
      status: "completed",
      outcome: "draft_saved",
      pendingStepNumber: null,
      writeStatus: "created",
      rule: sampleRule(),
      version: sampleVersion(),
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "CS101 Rule",
          badgeTemplateId: "badge_template_cs101",
          badgeTemplateReuseAcknowledged: false,
          lmsConnectionId: "lms_123",
          builderDraftId: "brd_exact",
          action: "save_draft",
          definition: {
            conditions: {
              type: "grade_threshold",
              courseId: "course_101",
              minScore: 80,
            },
          },
        }),
      },
      env,
    );

    expect(response.status).toBe(201);
    expect(mockedCreateBadgeIssuanceRuleWithAction).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        builderDraftId: "brd_exact",
        action: "save_draft",
        actorUserId: "usr_123",
      }),
    );
    expect(mockedDeleteBadgeIssuanceRuleBuilderDraft).not.toHaveBeenCalled();
  });

  it("replays the original promoted rule after an ambiguous client retry", async () => {
    const env = createEnv();
    mockedFindBadgeIssuanceRuleAuthoringReplay.mockResolvedValue({
      status: "completed",
      outcome: "draft_saved",
      pendingStepNumber: null,
      writeStatus: "replayed",
      rule: sampleRule(),
      version: sampleVersion(),
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "Changed retry payload",
          badgeTemplateId: "badge_template_cs101",
          badgeTemplateReuseAcknowledged: false,
          lmsConnectionId: "lms_123",
          builderDraftId: "brd_exact",
          action: "save_draft",
          definition: {
            conditions: {
              type: "grade_threshold",
              courseId: "course_101",
              minScore: 90,
            },
          },
        }),
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(201);
    expect(body).toMatch(/"minScore":\s*80/);
    expect(body).not.toMatch(/"minScore":\s*90/);
    expect(mockedCreateBadgeIssuanceRuleWithAction).not.toHaveBeenCalled();
    expect(mockedCreateGradebookProvider).not.toHaveBeenCalled();
    expect(mockedCreateAuditLog).not.toHaveBeenCalled();
  });

  it("saves incomplete rule builder drafts without creating rule versions", async () => {
    const env = createEnv();
    mockedSaveBadgeIssuanceRuleBuilderDraft.mockResolvedValue({
      status: "saved",
      draft: {
        id: "brd_123",
        tenantId: "tenant_123",
        userId: "user_123",
        targetKind: "unfinished",
        ruleId: null,
        versionId: null,
        currentStep: "metadata",
        draftJson: '{"badgeTemplateId":"badge_template_123","definitionJson":""}',
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rule-builder-drafts/brd_123",
      {
        method: "PUT",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          target: { kind: "unfinished" },
          currentStep: "metadata",
          badgeTemplateId: "badge_template_123",
          definitionJson: "",
          builderState: {
            rootLogic: "all",
          },
        }),
      },
      env,
    );
    const body = await response.json<{ draft: { currentStep: string } }>();

    expect(response.status).toBe(200);
    expect(body.draft.currentStep).toBe("metadata");
    expect(mockedSaveBadgeIssuanceRuleBuilderDraft).toHaveBeenCalledWith(fakeDb, {
      id: "brd_123",
      tenantId: "tenant_123",
      userId: "usr_123",
      target: { kind: "unfinished" },
      currentStep: "metadata",
      draftJson: JSON.stringify({
        name: "",
        description: "",
        badgeTemplateId: "badge_template_123",
        lmsConnectionId: "",
        definitionJson: "",
        builderState: {
          rootLogic: "all",
        },
      }),
    });
  });

  it("does not expose the former singular builder-draft endpoint", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rule-builder-draft",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          currentStep: "metadata",
        }),
      },
      createEnv(),
    );

    expect(response.status).toBe(404);
  });

  it("lets issuer-role API clients save editable badge issuance rule changes as a new draft version", async () => {
    const env = createEnv();
    const updatedVersion = sampleVersion({
      id: "brv_124",
      versionNumber: 2,
      ruleJson: JSON.stringify({
        conditions: {
          type: "assignment_submission",
          courseId: "course_101",
          assignmentId: "assignment_1",
          minScore: 90,
        },
      }),
    });
    mockedUpdateBadgeIssuanceRuleWithAction.mockResolvedValue({
      status: "completed",
      outcome: "draft_saved",
      pendingStepNumber: null,
      writeStatus: "updated",
      rule: sampleRule({
        name: "CS101 Rule Revised",
        activeVersionId: null,
      }),
      version: updatedVersion,
    });
    mockedFindTenantMembership.mockResolvedValue(sampleMembership({ role: "issuer" }));

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/draft",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "CS101 Rule Revised",
          description: "",
          badgeTemplateId: "badge_template_cs101",
          badgeTemplateReuseAcknowledged: false,
          lmsConnectionId: "lms_123",
          action: "save_draft",
          definition: {
            conditions: {
              type: "assignment_submission",
              courseId: "course_101",
              assignmentId: "assignment_1",
              minScore: 90,
            },
          },
          changeSummary: "Retuned assignment score threshold",
        }),
      },
      env,
    );
    const body = await response.json<{
      version: {
        id: string;
        versionNumber: number;
        definition: { conditions: { minScore?: number } };
      };
    }>();

    expect(response.status).toBe(200);
    expect(mockedUpdateBadgeIssuanceRuleWithAction).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      name: "CS101 Rule Revised",
      description: undefined,
      badgeTemplateId: "badge_template_cs101",
      expectedBadgeTemplateRevision: {
        updatedAt: "2026-02-17T00:00:00.000Z",
        achievementSnapshot: {
          badgeTemplateId: "badge_template_cs101",
          title: "CS101 Excellence",
          description: "Issue badge for CS101 excellence",
          criteriaUri: "https://credtrail.test/criteria/cs101",
          imageUri:
            "https://credtrail.test/badges/assets/tenant_123/badge_template_cs101/asset_456",
          trustedCredentialMetadataJson: null,
        },
      },
      badgeTemplateReuseAcknowledged: false,
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_123",
      ruleJson: JSON.stringify({
        conditions: {
          type: "assignment_submission",
          courseId: "course_101",
          assignmentId: "assignment_1",
          minScore: 90,
        },
      }),
      changeSummary: "Retuned assignment score threshold",
      action: "save_draft",
      actorUserId: "usr_123",
      actorRole: "issuer",
    });
    expect(body.version.id).toBe("brv_124");
    expect(body.version.versionNumber).toBe(2);
    expect(body.version.definition.conditions.minScore).toBe(90);
  });

  it("returns conflict when saving a protected badge issuance rule draft", async () => {
    const env = createEnv();
    mockedUpdateBadgeIssuanceRuleWithAction.mockResolvedValue({
      status: "failed",
      reason: "not_editable",
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/draft",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "CS101 Rule Revised",
          badgeTemplateId: "badge_template_cs101",
          badgeTemplateReuseAcknowledged: false,
          lmsConnectionId: "lms_123",
          action: "save_draft",
          definition: {
            conditions: {
              type: "grade_threshold",
              courseId: "course_101",
              minScore: 80,
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(409);
    expect(body.error).toContain("latest draft or rejected version");
  });

  it("lists LMS connections without returning secrets", async () => {
    const env = createEnv();
    mockedListTenantLmsConnections.mockResolvedValue([sampleTenantLmsConnection()]);

    const response = await app.request(
      "/v1/tenants/tenant_123/lms/connections",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<{
      connections: Array<Record<string, unknown>>;
    }>();

    expect(response.status).toBe(200);
    expect(body.connections[0]?.displayName).toBe("Canvas Test");
    expect(body.connections[0]?.hasAccessToken).toBe(true);
    expect(body.connections[0]?.hasStoredCredential).toBe(true);
    expect(body.connections[0]).not.toHaveProperty("accessToken");
    expect(body.connections[0]).not.toHaveProperty("clientSecret");
  });

  it("creates tenant LMS connections", async () => {
    const env = createEnv();

    const response = await app.request(
      "/v1/tenants/tenant_123/lms/connections",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          displayName: "TrySakai",
          providerKind: "sakai",
          apiBaseUrl: "https://trysakai.example.edu",
          sakaiUsername: "sakai-admin",
          sakaiPassword: "sakai-password",
          ltiIssuer: "https://trysakai.example.edu",
          ltiClientId: "client-123",
          ltiDeploymentId: "deployment-123",
        }),
      },
      env,
    );
    const body = await response.json<{
      connection: Record<string, unknown>;
    }>();

    expect(response.status).toBe(201);
    expect(mockedUpsertTenantLmsConnection).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      displayName: "TrySakai",
      providerKind: "sakai",
      apiBaseUrl: "https://trysakai.example.edu",
      clientId: "sakai-admin",
      clientSecret: "sakai-password",
      ltiIssuer: "https://trysakai.example.edu",
      ltiClientId: "client-123",
      ltiDeploymentId: "deployment-123",
    });
    expect(body.connection).not.toHaveProperty("accessToken");
  });

  it("looks up LMS courses, learners, gradebook items, and workflow states", async () => {
    const env = createEnv();

    const coursesResponse = await app.request(
      "/v1/tenants/tenant_123/lms/connections/lms_123/courses?q=cs",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const coursesBody = await coursesResponse.json<{
      courses: Array<{ courseId: string }>;
      hasMore: boolean;
    }>();

    expect(coursesResponse.status).toBe(200);
    expect(coursesResponse.headers.get("Cache-Control")).toBe("no-store");
    expect(coursesBody.courses[0]?.courseId).toBe("course_101");
    expect(coursesBody.hasMore).toBe(false);
    expect(courseSearchInputs).toEqual([
      {
        accessScope: { kind: "provider_user", providerUserId: "instructor_123" },
        searchTerm: "cs",
        limit: 100,
      },
    ]);

    const learnersResponse = await app.request(
      "/v1/tenants/tenant_123/lms/connections/lms_123/courses/course_101/learners",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const learnersBody = await learnersResponse.json<{
      learners: Array<{ learnerId: string; displayName: string; email: string | null }>;
      hasMore: boolean;
    }>();

    expect(learnersResponse.status).toBe(200);
    expect(learnersResponse.headers.get("Cache-Control")).toBe("no-store");
    expect(learnersBody.hasMore).toBe(false);
    expect(learnersBody.learners).toEqual([
      {
        courseId: "course_101",
        learnerId: "learner_123",
        displayName: "Learner One",
        email: "learner@example.edu",
      },
    ]);

    const itemsResponse = await app.request(
      "/v1/tenants/tenant_123/lms/connections/lms_123/courses/course_101/gradebook-items?q=final",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const itemsBody = await itemsResponse.json<{
      items: Array<{ assignmentId: string }>;
    }>();

    expect(itemsResponse.status).toBe(200);
    expect(itemsBody.items[0]?.assignmentId).toBe("assignment_1");

    const statesResponse = await app.request(
      "/v1/tenants/tenant_123/lms/connections/lms_123/courses/course_101/gradebook-items/assignment_1/workflow-states",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const statesBody = await statesResponse.json<{
      states: Array<{ value: string; preselected: boolean }>;
    }>();

    expect(statesResponse.status).toBe(200);
    expect(statesBody.states).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ value: "submitted", preselected: true }),
        expect.objectContaining({ value: "graded", preselected: true }),
        expect.objectContaining({ value: "pending_review", preselected: false }),
      ]),
    );
  });

  it("does not expose generic LMS pickers to approval-only reviewers", async () => {
    const env = createEnv();
    mockedFindTenantMembership.mockResolvedValue(sampleMembership({ role: "approver" }));

    const coursesResponse = await app.request(
      "/v1/tenants/tenant_123/lms/connections/lms_123/courses?q=course_101",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const itemsResponse = await app.request(
      "/v1/tenants/tenant_123/lms/connections/lms_123/courses/course_101/gradebook-items",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const learnersResponse = await app.request(
      "/v1/tenants/tenant_123/lms/connections/lms_123/courses/course_101/learners",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(coursesResponse.status).toBe(403);
    expect(itemsResponse.status).toBe(403);
    expect(learnersResponse.status).toBe(403);
  });

  it("bounds course search results and reports when more matches are available", async () => {
    const env = createEnv();
    mockedCreateGradebookProvider.mockReturnValue({
      kind: "canvas",
      verifyCourseAccess: () =>
        Promise.resolve({ authorizedCourses: [], unauthorizedCourseIds: [] }),
      listCourses: (input: GradebookCourseSearchInput) => {
        courseSearchInputs.push(input);
        return Promise.resolve({
          courses: Array.from({ length: 100 }, (_, index) => ({
            courseId: `course_${String(index).padStart(3, "0")}`,
            title: `Course ${String(index).padStart(3, "0")}`,
            courseCode: null,
            workflowState: "available",
            startsAt: null,
            endsAt: null,
          })),
          hasMore: true,
        });
      },
      listAssignments: () => Promise.resolve([]),
      listEnrollments: () => Promise.resolve([]),
      listLearners: () => Promise.resolve([]),
      listSubmissions: () => Promise.resolve([]),
      listGrades: () => Promise.resolve([]),
      listCompletions: () => Promise.resolve([]),
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/lms/connections/lms_123/courses",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<{
      courses: Array<{ courseId: string }>;
      hasMore: boolean;
    }>();

    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(body.courses).toHaveLength(100);
    expect(body.hasMore).toBe(true);
    expect(body.courses.at(-1)?.courseId).toBe("course_099");
    expect(courseSearchInputs).toEqual([
      {
        accessScope: { kind: "provider_user", providerUserId: "instructor_123" },
        limit: 100,
      },
    ]);
  });

  it("returns actionable Sakai 403 guidance for course lookup failures", async () => {
    const env = createEnv();
    mockedFindTenantLmsUserIdentity.mockResolvedValue(null);
    mockedFindTenantLmsConnectionById.mockResolvedValue(
      sampleTenantLmsConnection({
        displayName: "TrySakai",
        providerKind: "sakai",
        apiBaseUrl: "https://trysakai.example.edu",
        accessToken: "sakai-session",
        refreshToken: null,
      }),
    );
    mockedCreateGradebookProvider.mockReturnValue({
      kind: "sakai",
      verifyCourseAccess: () =>
        Promise.resolve({ authorizedCourses: [], unauthorizedCourseIds: [] }),
      listCourses: (input: GradebookCourseSearchInput) => {
        courseSearchInputs.push(input);
        return Promise.reject(
          new GradebookProviderError({
            providerKind: "sakai",
            operation: "course_search",
            reason: "permission_denied",
            statusCode: 403,
            message: "sakai course_search request failed (403)",
          }),
        );
      },
      listAssignments: () => Promise.resolve([]),
      listEnrollments: () => Promise.resolve([]),
      listLearners: () => Promise.resolve([]),
      listSubmissions: () => Promise.resolve([]),
      listGrades: () => Promise.resolve([]),
      listCompletions: () => Promise.resolve([]),
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/lms/connections/lms_123/courses?q=cs",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(502);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(body.error).toContain("Sakai blocked CredTrail from searching courses (403).");
    expect(body.error).toContain("Save a Sakai administrator username and password");
    expect(body.error).toContain("then try again");
    expect(body.error).toContain("allow EntityBroker Sites and Gradebook access");
    expect(mockedFindTenantLmsUserIdentity).not.toHaveBeenCalled();
    expect(courseSearchInputs).toEqual([
      {
        accessScope: { kind: "connection" },
        searchTerm: "cs",
        limit: 100,
      },
    ]);
  });

  it("creates reusable badge-rule value lists", async () => {
    const env = createEnv();

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rule-value-lists",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          label: "Core CS sequence",
          kind: "course_ids",
          values: ["course_101", "course_102", "course_103"],
        }),
      },
      env,
    );
    const body = await response.json<{
      valueList: {
        id: string;
        kind: string;
      };
    }>();

    expect(response.status).toBe(201);
    expect(body.valueList.id).toBe("brvl_123");
    expect(body.valueList.kind).toBe("course_ids");
    expect(mockedCreateBadgeIssuanceRuleValueList).toHaveBeenCalledTimes(1);
  });

  it("lists reusable badge-rule value lists", async () => {
    const env = createEnv();
    mockedListBadgeIssuanceRuleValueLists.mockResolvedValue([sampleValueListRecord()]);

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rule-value-lists",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<{
      valueLists: BadgeIssuanceRuleValueListRecord[];
    }>();

    expect(response.status).toBe(200);
    expect(body.valueLists).toHaveLength(1);
    expect(body.valueLists[0]?.label).toBe("Core CS sequence");
  });

  it("submits draft rule versions for approval", async () => {
    const env = createEnv();
    mockedFindBadgeIssuanceRuleVersionById.mockResolvedValue(sampleVersion({ status: "draft" }));
    mockedSubmitBadgeIssuanceRuleVersionForApproval.mockResolvedValue({
      status: "submitted",
      version: sampleVersion({ status: "pending_approval" }),
      pendingStepNumber: 4,
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/versions/brv_123/submit-approval",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<{
      version: {
        status: string;
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.version.status).toBe("pending_approval");
    expect(mockedSubmitBadgeIssuanceRuleVersionForApproval).toHaveBeenCalledTimes(1);
    expect(mockedSubmitBadgeIssuanceRuleVersionForApproval).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        tenantId: "tenant_123",
        ruleId: "brl_123",
        versionId: "brv_123",
        actorUserId: "usr_123",
        actorRole: "admin",
      }),
    );
  });

  it("rejects approval decisions when the current step requires a higher role", async () => {
    const env = createEnv();
    mockedDecideBadgeIssuanceRuleVersion.mockResolvedValue({
      status: "forbidden",
      step: {
        targetType: "role_threshold",
        requiredRole: "owner",
      },
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/versions/brv_123/decision",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          decision: "approved",
          comment: "Looks good",
        }),
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(403);
    expect(body.error).toContain("requires role owner");
    expect(mockedDecideBadgeIssuanceRuleVersion).toHaveBeenCalledTimes(1);
    expect(mockedFindBadgeIssuanceRuleVersionById).not.toHaveBeenCalled();
    expect(mockedListBadgeIssuanceRuleVersionApprovalSteps).not.toHaveBeenCalled();
  });

  it("rejects a rejection decision without its required reviewer comment", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/versions/brv_123/decision",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({ decision: "rejected" }),
      },
      createEnv(),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "Invalid badge rule approval decision payload",
    });
    expect(mockedDecideBadgeIssuanceRuleVersion).not.toHaveBeenCalled();
  });

  it("returns the approved version from the atomic approval decision command", async () => {
    const env = createEnv();
    mockedDecideBadgeIssuanceRuleVersion.mockResolvedValue({
      status: "decided",
      version: sampleVersion({ status: "approved" }),
      decidedStepNumber: 1,
      nextStepNumber: null,
    });
    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/versions/brv_123/decision",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          decision: "approved",
          comment: "Looks good",
        }),
      },
      env,
    );
    const body = await response.json<{
      version: {
        status: string;
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.version.status).toBe("approved");
  });

  it("returns approval history for a badge rule version", async () => {
    const env = createEnv();
    mockedFindBadgeIssuanceRuleVersionById.mockResolvedValue(
      sampleVersion({ status: "pending_approval" }),
    );
    mockedListBadgeIssuanceRuleVersionApprovalSteps.mockResolvedValue([
      sampleApprovalStep({
        stepNumber: 1,
        requiredRole: "issuer",
        status: "approved",
        decidedByUserId: "usr_123",
        decidedAt: "2026-02-17T00:00:00.000Z",
      }),
      sampleApprovalStep({
        id: "bras_456",
        stepNumber: 2,
        requiredRole: "admin",
        status: "pending",
      }),
    ]);
    mockedListBadgeIssuanceRuleVersionApprovalEvents.mockResolvedValue([
      sampleApprovalEvent({
        action: "submitted",
      }),
      sampleApprovalEvent({
        id: "brae_456",
        action: "approved",
        actorRole: "issuer",
        comment: "Department sign-off complete",
      }),
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/versions/brv_123/approval-history",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<{
      approval: {
        currentStep: {
          stepNumber: number;
        } | null;
        steps: unknown[];
        events: unknown[];
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.approval.currentStep?.stepNumber).toBe(2);
    expect(body.approval.steps).toHaveLength(2);
    expect(body.approval.events).toHaveLength(2);
  });

  it("returns a structured diff between rule versions", async () => {
    const env = createEnv();
    mockedFindBadgeIssuanceRuleVersionById.mockResolvedValue(
      sampleVersion({
        id: "brv_124",
        versionNumber: 3,
        ruleJson: JSON.stringify({
          conditions: {
            type: "grade_threshold",
            courseId: "course_101",
            minScore: 85,
          },
        }),
      }),
    );
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([
      sampleVersion({
        id: "brv_124",
        versionNumber: 3,
        ruleJson: JSON.stringify({
          conditions: {
            type: "grade_threshold",
            courseId: "course_101",
            minScore: 85,
          },
        }),
      }),
      sampleVersion({
        id: "brv_123",
        versionNumber: 2,
        ruleJson: JSON.stringify({
          conditions: {
            type: "grade_threshold",
            courseId: "course_101",
            minScore: 80,
          },
        }),
      }),
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/versions/brv_124/diff",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<{
      diff: {
        changed: boolean;
        changeCount: number;
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.diff.changed).toBe(true);
    expect(body.diff.changeCount).toBeGreaterThan(0);
  });

  it("returns badge-rule scoped audit log entries", async () => {
    const env = createEnv();
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleRule());
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([
      sampleVersion({
        id: "brv_123",
      }),
    ]);
    mockedListAuditLogs.mockResolvedValue([
      sampleAuditLogRecord({
        targetType: "badge_rule",
        targetId: "brl_123",
      }),
      sampleAuditLogRecord({
        id: "audit_124",
        targetType: "badge_rule_version",
        targetId: "brv_123",
      }),
      sampleAuditLogRecord({
        id: "audit_125",
        targetType: "badge_template",
        targetId: "badge_template_cs101",
      }),
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/audit-log?limit=10",
      {
        method: "GET",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<{
      logs: AuditLogRecord[];
    }>();

    expect(response.status).toBe(200);
    expect(body.logs).toHaveLength(2);
    expect(body.logs.every((entry) => entry.targetType !== "badge_template")).toBe(true);
  });

  it("preview-evaluates unsaved rule definitions", async () => {
    const env = createEnv();

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/preview-evaluate",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          definition: {
            conditions: {
              all: [
                {
                  type: "course_completion",
                  courseId: "course_101",
                  minCompletionPercent: 100,
                },
                {
                  type: "grade_threshold",
                  courseId: "course_101",
                  minScore: 80,
                },
              ],
            },
          },
          lmsConnectionId: "lms_123",
          learnerId: "learner_123",
          facts: {
            nowIso: "2026-02-17T00:00:00.000Z",
            completions: [
              {
                courseId: "course_101",
                learnerId: "learner_123",
                completed: true,
                completionPercent: 100,
              },
            ],
            grades: [
              {
                courseId: "course_101",
                learnerId: "learner_123",
                finalScore: 92,
              },
            ],
          },
        }),
      },
      env,
    );
    const body = await response.json<{
      dryRun: boolean;
      evaluation: {
        matched: boolean;
      };
      facts: {
        grades: unknown[];
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.dryRun).toBe(true);
    expect(body.evaluation.matched).toBe(true);
    expect(body.facts.grades).toHaveLength(1);
    expect(mockedIssueBadgeForTenant).not.toHaveBeenCalled();
  });

  it("does not test a course rule for a user without a linked LMS identity", async () => {
    const env = createEnv();
    mockedFindTenantLmsUserIdentity.mockResolvedValue(null);

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/preview-evaluate",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          definition: {
            conditions: {
              type: "course_completion",
              courseId: "course_101",
              minCompletionPercent: 100,
            },
          },
          lmsConnectionId: "lms_123",
          learnerId: "learner_123",
          facts: {
            completions: [],
          },
        }),
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(403);
    expect(body.error).toContain("Open CredTrail from Canvas once");
  });

  it("preview-evaluates survey completion and custom field rules", async () => {
    const env = createEnv();

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/preview-evaluate",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          definition: {
            conditions: {
              all: [
                {
                  type: "survey_completion",
                  source: "qualtrics",
                  surveyId: "exit_survey",
                },
                {
                  type: "custom_field",
                  fieldName: "programStanding",
                  operator: "equals",
                  expectedValue: "eligible",
                },
              ],
            },
          },
          lmsConnectionId: "lms_123",
          learnerId: "learner_123",
          facts: {
            nowIso: "2026-02-17T00:00:00.000Z",
            surveyCompletions: [
              {
                surveyId: "exit_survey",
                learnerId: "learner_123",
                source: "qualtrics",
                completed: true,
              },
            ],
            customFields: [
              {
                learnerId: "learner_123",
                fieldName: "programStanding",
                value: "eligible",
              },
            ],
          },
        }),
      },
      env,
    );
    const body = await response.json<{
      dryRun: boolean;
      evaluation: {
        matched: boolean;
      };
      facts: {
        surveyCompletions: unknown[];
        customFields: unknown[];
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.dryRun).toBe(true);
    expect(body.evaluation.matched).toBe(true);
    expect(body.facts.surveyCompletions).toHaveLength(1);
    expect(body.facts.customFields).toHaveLength(1);
    expect(mockedIssueBadgeForTenant).not.toHaveBeenCalled();
  });

  it("resolves reusable value lists during preview evaluation", async () => {
    const env = createEnv();
    mockedListBadgeIssuanceRuleValueLists.mockResolvedValue([sampleValueListRecord()]);

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/preview-evaluate",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          definition: {
            conditions: {
              all: [
                {
                  type: "course_completion",
                  courseListId: "brvl_123",
                  minCompletionPercent: 100,
                },
                {
                  type: "grade_threshold",
                  courseListId: "brvl_123",
                  minScore: 80,
                },
              ],
            },
          },
          lmsConnectionId: "lms_123",
          learnerId: "learner_123",
          facts: {
            nowIso: "2026-02-17T00:00:00.000Z",
            completions: [
              {
                courseId: "course_101",
                learnerId: "learner_123",
                completed: true,
                completionPercent: 100,
              },
            ],
            grades: [
              {
                courseId: "course_101",
                learnerId: "learner_123",
                finalScore: 92,
              },
            ],
          },
        }),
      },
      env,
    );
    const body = await response.json<{
      evaluation: {
        matched: boolean;
      };
      definition: {
        conditions: {
          all: unknown[];
        };
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.evaluation.matched).toBe(true);
    expect(body.definition.conditions.all).toHaveLength(2);
    expect(mockedListBadgeIssuanceRuleValueLists).toHaveBeenCalledTimes(1);
  });

  it("uses the selected LMS connection for automated preview evaluation", async () => {
    const env = createEnv();
    mockedFindTenantLmsConnectionById.mockResolvedValue(
      sampleTenantLmsConnection({
        id: "lms_sakai",
        displayName: "TrySakai",
        providerKind: "sakai",
        apiBaseUrl: "https://sakai.example.edu",
        accessToken: "sakai-token",
        refreshToken: null,
      }),
    );
    mockedCreateGradebookProvider.mockReturnValue({
      kind: "sakai",
      verifyCourseAccess: () =>
        Promise.resolve({ authorizedCourses: [], unauthorizedCourseIds: [] }),
      listCourses: () => Promise.resolve({ courses: [], hasMore: false }),
      listAssignments: () => Promise.resolve([]),
      listEnrollments: () => Promise.resolve([]),
      listSubmissions: () => Promise.resolve([]),
      listGrades: () =>
        Promise.resolve([
          {
            courseId: "course_101",
            learnerId: "learner_123",
            currentScore: 91,
            finalScore: 91,
            currentGrade: "A-",
            finalGrade: "A-",
          },
        ]),
      listCompletions: () =>
        Promise.resolve([
          {
            courseId: "course_101",
            learnerId: "learner_123",
            completed: true,
            completedAt: null,
            completionPercent: 100,
            sourceState: "graded",
          },
        ]),
    });

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/preview-evaluate",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          definition: {
            conditions: {
              all: [
                {
                  type: "course_completion",
                  courseId: "course_101",
                  minCompletionPercent: 100,
                },
                {
                  type: "grade_threshold",
                  courseId: "course_101",
                  minScore: 80,
                },
              ],
            },
          },
          lmsProviderKind: "sakai",
          lmsConnectionId: "lms_sakai",
          learnerId: "learner_123",
        }),
      },
      env,
    );
    const body = await response.json<{
      evaluation: {
        matched: boolean;
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.evaluation.matched).toBe(true);
    expect(mockedCreateGradebookProvider).toHaveBeenCalledTimes(1);
    const providerInput: unknown = mockedCreateGradebookProvider.mock.calls[0]?.[0];
    const providerConfig =
      providerInput !== null &&
      typeof providerInput === "object" &&
      "config" in providerInput &&
      providerInput.config !== null &&
      typeof providerInput.config === "object"
        ? providerInput.config
        : null;

    expect(providerConfig).not.toBeNull();
    expect(providerConfig && "kind" in providerConfig ? providerConfig.kind : null).toBe("sakai");
    expect(
      providerConfig && "apiBaseUrl" in providerConfig ? providerConfig.apiBaseUrl : null,
    ).toBe("https://sakai.example.edu");
  });

  it("returns 422 when preview evaluation references a missing LMS connection", async () => {
    const env = createEnv();
    mockedFindTenantLmsConnectionById.mockResolvedValue(null);

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/preview-evaluate",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          definition: {
            conditions: {
              type: "grade_threshold",
              courseId: "course_101",
              minScore: 80,
            },
          },
          lmsProviderKind: "canvas",
          lmsConnectionId: "missing_lms",
          learnerId: "learner_123",
        }),
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(422);
    expect(body.error).toBe("Selected LMS connection was not found");
    expect(mockedCreateGradebookProvider).not.toHaveBeenCalled();
  });

  it("returns 422 when a prerequisite badge preview has no credential email", async () => {
    const env = createEnv();

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/preview-evaluate",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          definition: {
            conditions: {
              type: "prerequisite_badge",
              badgeTemplateId: "badge_template_foundations",
            },
          },
          lmsProviderKind: "canvas",
          lmsConnectionId: "lms_123",
          learnerId: "learner_123",
        }),
      },
      env,
    );
    const body = await response.json<{ error: string }>();

    expect(response.status).toBe(422);
    expect(body.error).toBe(
      "Credential email is required to test a prerequisite badge requirement",
    );
    expect(mockedCreateGradebookProvider).not.toHaveBeenCalled();
  });

  it("simulates draft impact against historical evaluations", async () => {
    const env = createEnv();
    mockedListBadgeIssuanceRuleEvaluations.mockResolvedValue([
      sampleEvaluationRecord({
        matched: true,
        issuanceStatus: "issued",
        evaluationJson: JSON.stringify({
          facts: {
            learnerId: "learner_123",
            nowIso: "2026-02-17T00:00:00.000Z",
            grades: [
              {
                courseId: "course_101",
                learnerId: "learner_123",
                finalScore: 91,
              },
            ],
            completions: [
              {
                courseId: "course_101",
                learnerId: "learner_123",
                completed: true,
                completionPercent: 100,
              },
            ],
            submissions: [],
            earnedBadgeTemplateIds: [],
          },
          evaluation: {
            matched: true,
            tree: {
              type: "all",
              matched: true,
              detail: "All conditions passed",
              children: [],
            },
          },
        }),
      }),
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/preview-simulate",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          badgeTemplateId: "badge_template_cs101",
          sampleLimit: 10,
          definition: {
            conditions: {
              all: [
                {
                  type: "course_completion",
                  courseId: "course_101",
                  minCompletionPercent: 100,
                },
                {
                  type: "grade_threshold",
                  courseId: "course_101",
                  minScore: 80,
                },
              ],
            },
          },
        }),
      },
      env,
    );
    const body = await response.json<{
      sampleCount: number;
      summary: {
        matchedCount: number;
        changedCount: number;
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.sampleCount).toBe(1);
    expect(body.summary.matchedCount).toBe(1);
    expect(body.summary.changedCount).toBe(0);
  });

  it("does not expose a second saved-rule evaluation and issuance path", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/brl_123/evaluate",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          learnerId: "learner_123",
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          dryRun: false,
        }),
      },
      createEnv(),
    );

    expect(response.status).toBe(404);
    expect(mockedIssueBadgeForTenant).not.toHaveBeenCalled();
  });

  it("lists the rule review queue with evaluation summaries", async () => {
    const env = createEnv();
    mockedFindBadgeIssuanceRuleVersionById.mockResolvedValue(
      sampleVersion({
        snapshot: {
          name: "CS101 Rule",
          badgeTemplateId: "badge_template_cs101",
        },
      }),
    );
    mockedListBadgeIssuanceRuleEvaluations.mockResolvedValue([
      sampleEvaluationRecord({
        matched: false,
        issuanceStatus: "review_required",
        reviewStatus: "pending",
        evaluationJson: JSON.stringify({
          facts: {
            learnerId: "learner_123",
            nowIso: "2026-02-17T00:00:00.000Z",
            grades: [],
            completions: [],
            submissions: [],
            earnedBadgeTemplateIds: [],
          },
          evaluation: {
            matched: false,
            tree: {
              type: "all",
              matched: false,
              detail: "Missing facts",
              children: [
                {
                  type: "grade_threshold",
                  matched: false,
                  resultKind: "missing_data",
                  detail: "No grade facts were found for course_101",
                },
              ],
            },
          },
        }),
      }),
    ]);

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/review-queue?status=pending",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.json<{
      queue: {
        ruleName: string | null;
        evaluationSummary: {
          missingDataCount: number;
        } | null;
      }[];
    }>();

    expect(response.status).toBe(200);
    expect(body.queue).toHaveLength(1);
    expect(body.queue[0]?.ruleName).toBe("CS101 Rule");
    expect(body.queue[0]?.evaluationSummary?.missingDataCount).toBe(1);
    expect(mockedFindBadgeIssuanceRuleVersionById).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
    });
  });

  it("resolves review queue entries by issuing the badge", async () => {
    const env = createEnv();
    mockedFindBadgeIssuanceRuleEvaluationById.mockResolvedValue(
      sampleEvaluationRecord({
        matched: false,
        issuanceStatus: "review_required",
        reviewStatus: "pending",
      }),
    );
    mockedFindBadgeIssuanceRuleVersionById.mockResolvedValue(sampleVersion());
    mockedIssueBadgeForTenant.mockResolvedValue({
      status: "issued",
      assertionId: "tenant_123:assertion_1",
    });
    mockedResolveBadgeIssuanceRuleEvaluationReview.mockResolvedValue(
      sampleEvaluationRecord({
        issuanceStatus: "issued",
        reviewStatus: "resolved",
        reviewDecision: "issue",
        assertionId: "tenant_123:assertion_1",
        reviewedByUserId: "usr_123",
        reviewedAt: "2026-02-17T00:05:00.000Z",
      }),
    );

    const response = await app.request(
      "/v1/tenants/tenant_123/badge-rules/review-queue/bre_123/resolve",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          decision: "issue",
          comment: "Registrar review approved issuance.",
        }),
      },
      env,
    );
    const body = await response.json<{
      review: {
        issuanceStatus: string;
        reviewDecision: string | null;
      };
      issuance: {
        status: string;
      };
    }>();

    expect(response.status).toBe(200);
    expect(body.review.issuanceStatus).toBe("issued");
    expect(body.review.reviewDecision).toBe("issue");
    expect(body.issuance.status).toBe("issued");
    expect(mockedIssueBadgeForTenant).toHaveBeenCalledWith(
      expect.anything(),
      "tenant_123",
      expect.objectContaining({
        achievementSource: expect.objectContaining({
          kind: "rule_version",
          provenance: expect.objectContaining({
            ruleId: "brl_123",
            versionId: "brv_123",
          }),
        }),
      }),
      "usr_123",
    );
    expect(mockedResolveBadgeIssuanceRuleEvaluationReview).toHaveBeenCalledTimes(1);
  });
});
