import { beforeEach, expect, vi } from "vitest";

import {
  mockedEnqueueJobQueueMessageOnce,
  mockedFindLtiResourceLinkPlacementForRule,
  mockedFindTenantAuthPolicy,
  mockedListAccessibleTenantContextsForUser,
  mockedListActiveLtiLaunchSessionsForPlatform,
  mockedListBadgeIssuanceRuleVersionApprovalEvents,
  mockedListPendingBadgeIssuanceRuleApprovalsForActor,
  mockedListTenantAuthProviders,
  mockedListTenantBreakGlassAccounts,
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
} from "./register-mocks";

import {
  createLearnerRecordImportPreview,
  countBadgeTemplateImageRevisions,
  createAuditLog,
  createBadgeTemplate,
  createBadgeTemplateImageRevision,
  findBadgeTemplateById,
  findBadgeTemplateImageRevisionById,
  setBadgeTemplateArchivedState,
  updateBadgeTemplate,
  findActiveLearnerRecordImportPreview,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  findTenantById,
  findTenantMembership,
  findUserById,
  getTenantReportingEngagementCounts,
  listDelegatedIssuingAuthorityGrants,
  listAuditLogs,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  findBadgeIssuanceRuleBuilderDraft,
  findBadgeIssuanceRuleVersionById,
  submitBadgeIssuanceRuleVersionForApproval,
  listBadgeIssuanceRuleVersionApprovalSteps,
  resolveBadgeRuleApprovalPolicy,
  resolveTenantDefaultBadgeRuleApprovalPolicy,
  decideBadgeIssuanceRuleVersion,
  recertifyBadgeIssuanceRuleVersion,
  createBadgeRuleApproverGroup,
  addBadgeRuleApproverGroupMember,
  listBadgeRuleApproverGroupsWithMembers,
  removeBadgeRuleApproverGroupMember,
  removeBadgeRuleApproverGroup,
  upsertBadgeRuleApprovalPolicy,
  listBadgeIssuanceRuleEvaluations,
  listBadgeIssuanceRuleValueLists,
  createBadgeIssuanceRuleValueList,
  deleteDraftBadgeIssuanceRule,
  findBadgeIssuanceRuleEvaluationById,
  resolveBadgeIssuanceRuleEvaluationReview,
  findBadgeIssuanceRuleById,
  listBadgeTemplateImageRevisions,
  listBadgeTemplateImageRevisionCountsByTenant,
  listBadgeTemplateOwnershipEvents,
  listBadgeTemplates,
  listImportLearnerRecordBatchQueueMessages,
  listTenantApiKeys,
  listTenantAssertions,
  findAssertionById,
  findAssertionIssuanceProvenanceByAssertionId,
  findAssertionReportingAttributionByAssertionId,
  findBadgeIssuanceRuleEvaluationByAssertionId,
  findTenantOrgUnitById,
  findUsersByIds,
  listAssertionLifecycleEvents,
  listAuditLogsForAssertion,
  recordAssertionLifecycleTransition,
  resolveAssertionLifecycleState,
  createTenantApiKey,
  revokeTenantApiKey,
  upsertTenantLmsConnection,
  findTenantLmsConnectionById,
  listTenantLmsConnections,
  listTenantMembers,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  markLearnerRecordImportPreviewQueued,
  getTenantReportingOverview,
  getTenantReportingTrends,
  listLearnerRecordAssertionExports,
  listLearnerRecordEntries,
  listTenantReportingComparisons,
  type LearnerProfileRecord,
  type LearnerRecordAssertionExportRecord,
  type LearnerRecordEntryRecord,
  type SqlDatabase,
  type TenantAssertionSummaryRecord,
  type TenantLmsConnectionRecord,
  type TenantMembershipRecord,
  type TenantMemberRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

export const mockedCountBadgeTemplateImageRevisions = vi.mocked(countBadgeTemplateImageRevisions);
export const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
export const mockedFindBadgeTemplateImageRevisionById = vi.mocked(
  findBadgeTemplateImageRevisionById,
);
export const mockedSetBadgeTemplateArchivedState = vi.mocked(setBadgeTemplateArchivedState);
export const mockedCreateBadgeTemplate = vi.mocked(createBadgeTemplate);
export const mockedUpdateBadgeTemplate = vi.mocked(updateBadgeTemplate);
export const mockedCreateAuditLogDb = vi.mocked(createAuditLog);
export const mockedListAuditLogs = vi.mocked(listAuditLogs);
export const mockedListBadgeTemplateImageRevisions = vi.mocked(listBadgeTemplateImageRevisions);
export const mockedListBadgeTemplateOwnershipEvents = vi.mocked(listBadgeTemplateOwnershipEvents);
export const mockedCreateLearnerRecordImportPreviewDb = vi.mocked(createLearnerRecordImportPreview);
export const mockedFindActiveLearnerRecordImportPreviewDb = vi.mocked(
  findActiveLearnerRecordImportPreview,
);
export const mockedFindLearnerProfileByIdDb = vi.mocked(findLearnerProfileById);
export const mockedFindLearnerProfileByIdentityDb = vi.mocked(findLearnerProfileByIdentity);
export const mockedFindTenantMembership = vi.mocked(findTenantMembership);
export const mockedFindTenantById = vi.mocked(findTenantById);
export const mockedFindUserById = vi.mocked(findUserById);
export const mockedListDelegatedIssuingAuthorityGrants = vi.mocked(
  listDelegatedIssuingAuthorityGrants,
);
export const mockedListBadgeIssuanceRules = vi.mocked(listBadgeIssuanceRules);
export const mockedListBadgeIssuanceRuleVersions = vi.mocked(listBadgeIssuanceRuleVersions);
export const mockedFindBadgeIssuanceRuleVersionByIdDb = vi.mocked(findBadgeIssuanceRuleVersionById);
export const mockedFindBadgeIssuanceRuleBuilderDraftDb = vi.mocked(
  findBadgeIssuanceRuleBuilderDraft,
);
export const mockedSubmitBadgeIssuanceRuleVersionForApprovalDb = vi.mocked(
  submitBadgeIssuanceRuleVersionForApproval,
);
export const mockedListBadgeIssuanceRuleVersionApprovalStepsDb = vi.mocked(
  listBadgeIssuanceRuleVersionApprovalSteps,
);
export const mockedResolveBadgeRuleApprovalPolicyDb = vi.mocked(resolveBadgeRuleApprovalPolicy);
export const mockedResolveTenantDefaultBadgeRuleApprovalPolicyDb = vi.mocked(
  resolveTenantDefaultBadgeRuleApprovalPolicy,
);
export const mockedDecideBadgeIssuanceRuleVersionDb = vi.mocked(decideBadgeIssuanceRuleVersion);
export const mockedRecertifyBadgeIssuanceRuleVersionDb = vi.mocked(
  recertifyBadgeIssuanceRuleVersion,
);
export const mockedCreateBadgeRuleApproverGroupDb = vi.mocked(createBadgeRuleApproverGroup);
export const mockedAddBadgeRuleApproverGroupMemberDb = vi.mocked(addBadgeRuleApproverGroupMember);
export const mockedListBadgeRuleApproverGroupsWithMembersDb = vi.mocked(
  listBadgeRuleApproverGroupsWithMembers,
);
export const mockedRemoveBadgeRuleApproverGroupMemberDb = vi.mocked(
  removeBadgeRuleApproverGroupMember,
);
export const mockedRemoveBadgeRuleApproverGroupDb = vi.mocked(removeBadgeRuleApproverGroup);
export const mockedUpsertBadgeRuleApprovalPolicyDb = vi.mocked(upsertBadgeRuleApprovalPolicy);
export const mockedListBadgeIssuanceRuleEvaluations = vi.mocked(listBadgeIssuanceRuleEvaluations);
export const mockedListBadgeIssuanceRuleValueLists = vi.mocked(listBadgeIssuanceRuleValueLists);
export const mockedCreateBadgeIssuanceRuleValueList = vi.mocked(createBadgeIssuanceRuleValueList);
export const mockedDeleteDraftBadgeIssuanceRuleDb = vi.mocked(deleteDraftBadgeIssuanceRule);
export const mockedFindBadgeIssuanceRuleEvaluationById = vi.mocked(
  findBadgeIssuanceRuleEvaluationById,
);
export const mockedResolveBadgeIssuanceRuleEvaluationReview = vi.mocked(
  resolveBadgeIssuanceRuleEvaluationReview,
);
export const mockedFindBadgeIssuanceRuleById = vi.mocked(findBadgeIssuanceRuleById);
export const mockedListBadgeTemplateImageRevisionCountsByTenant = vi.mocked(
  listBadgeTemplateImageRevisionCountsByTenant,
);
export const mockedListBadgeTemplates = vi.mocked(listBadgeTemplates);
export const mockedListImportLearnerRecordBatchQueueMessagesDb = vi.mocked(
  listImportLearnerRecordBatchQueueMessages,
);
export const mockedListTenantOrgUnits = vi.mocked(listTenantOrgUnits);
export const mockedListTenantApiKeys = vi.mocked(listTenantApiKeys);
export const mockedListTenantAssertions = vi.mocked(listTenantAssertions);
export const mockedFindAssertionById = vi.mocked(findAssertionById);
export const mockedFindAssertionIssuanceProvenanceByAssertionId = vi.mocked(
  findAssertionIssuanceProvenanceByAssertionId,
);
export const mockedFindAssertionReportingAttributionByAssertionId = vi.mocked(
  findAssertionReportingAttributionByAssertionId,
);
export const mockedFindBadgeIssuanceRuleEvaluationByAssertionId = vi.mocked(
  findBadgeIssuanceRuleEvaluationByAssertionId,
);
export const mockedFindTenantOrgUnitById = vi.mocked(findTenantOrgUnitById);
export const mockedFindUsersByIds = vi.mocked(findUsersByIds);
export const mockedListAssertionLifecycleEvents = vi.mocked(listAssertionLifecycleEvents);
export const mockedListAuditLogsForAssertion = vi.mocked(listAuditLogsForAssertion);
export const mockedResolveAssertionLifecycleState = vi.mocked(resolveAssertionLifecycleState);
export const mockedRecordAssertionLifecycleTransition = vi.mocked(
  recordAssertionLifecycleTransition,
);
export const mockedCreateTenantApiKey = vi.mocked(createTenantApiKey);
export const mockedRevokeTenantApiKey = vi.mocked(revokeTenantApiKey);
export const mockedUpsertTenantLmsConnection = vi.mocked(upsertTenantLmsConnection);
export const mockedFindTenantLmsConnectionByIdDb = vi.mocked(findTenantLmsConnectionById);
export const mockedListTenantLmsConnectionsDb = vi.mocked(listTenantLmsConnections);
export const mockedListTenantMembersDb = vi.mocked(listTenantMembers);
export const mockedListTenantMembershipOrgUnitScopes = vi.mocked(listTenantMembershipOrgUnitScopes);
export const mockedMarkLearnerRecordImportPreviewQueuedDb = vi.mocked(
  markLearnerRecordImportPreviewQueued,
);
export const mockedGetTenantReportingComparisonsDb = vi.mocked(listTenantReportingComparisons);
export const mockedGetTenantReportingEngagementCountsDb = vi.mocked(
  getTenantReportingEngagementCounts,
);
export const mockedGetTenantReportingOverviewDb = vi.mocked(getTenantReportingOverview);
export const mockedGetTenantReportingTrendsDb = vi.mocked(getTenantReportingTrends);
export const mockedListLearnerRecordAssertionExportsDb = vi.mocked(
  listLearnerRecordAssertionExports,
);
export const mockedListLearnerRecordEntriesDb = vi.mocked(listLearnerRecordEntries);
export const mockedCreatePostgresDatabase = vi.mocked(createPostgresDatabase);
export const fakeDbPrepare = vi.fn();
export const fakeDb = {
  prepare: fakeDbPrepare,
} as unknown as SqlDatabase;

export const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  BETTER_AUTH_SECRET: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    BETTER_AUTH_SECRET: "test-better-auth-secret",
  };
};

export const sampleMembership = (role: TenantMembershipRecord["role"]): TenantMembershipRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_admin",
    role,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  };
};

export const sampleTenantMember = (overrides?: Partial<TenantMemberRecord>): TenantMemberRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_member",
    email: "member@tenant-123.edu",
    role: "issuer",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:30:00.000Z",
    ...overrides,
  };
};

export const sampleLearnerProfile = (
  overrides?: Partial<LearnerProfileRecord>,
): LearnerProfileRecord => {
  return {
    id: "lpr_123",
    tenantId: "tenant_123",
    subjectId: "urn:credtrail:learner:tenant_123:lpr_123",
    displayName: "Learner One",
    createdAt: "2026-03-25T12:00:00.000Z",
    updatedAt: "2026-03-25T12:00:00.000Z",
    ...overrides,
  };
};

export const sampleLearnerRecordAssertionExport = (
  overrides?: Partial<LearnerRecordAssertionExportRecord>,
): LearnerRecordAssertionExportRecord => {
  return {
    assertionId: "tenant_123:assertion_456",
    assertionPublicId: "public_assertion_456",
    tenantId: "tenant_123",
    learnerProfileId: "lpr_123",
    badgeTemplateId: "badge_template_001",
    badgeTitle: "Applied Analytics Badge",
    badgeDescription: "Awarded for applied analytics work.",
    badgeCriteriaUri: "https://credtrail.example.edu/badges/applied-analytics/criteria",
    badgeImageUri: "https://credtrail.example.edu/badges/applied-analytics/image.png",
    recipientIdentity: "learner@example.edu",
    recipientIdentityType: "email",
    vcR2Key: "tenants/tenant_123/assertions/assertion_456.jsonld",
    statusListIndex: 12,
    idempotencyKey: "idem_123",
    issuedAt: "2026-03-24T15:00:00.000Z",
    issuedByUserId: "usr_admin",
    revokedAt: null,
    issuerName: "CredTrail University",
    createdAt: "2026-03-24T15:00:00.000Z",
    updatedAt: "2026-03-24T15:00:00.000Z",
    ...overrides,
  };
};

export const sampleTenantAssertionSummary = (
  overrides?: Partial<TenantAssertionSummaryRecord>,
): TenantAssertionSummaryRecord => {
  const assertion = sampleLearnerRecordAssertionExport();

  return {
    assertionId: assertion.assertionId,
    tenantId: assertion.tenantId,
    publicId: assertion.assertionPublicId,
    badgeTemplateId: assertion.badgeTemplateId,
    badgeTitle: assertion.badgeTitle,
    badgeImageUri: assertion.badgeImageUri,
    recipientIdentity: assertion.recipientIdentity,
    recipientIdentityType: assertion.recipientIdentityType,
    issuedAt: assertion.issuedAt,
    issuedByUserId: assertion.issuedByUserId,
    revokedAt: assertion.revokedAt,
    state: "active",
    source: "default_active",
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    ...overrides,
  };
};

export const stubAssertionEvidenceMocks = (
  assertion = sampleLearnerRecordAssertionExport(),
): void => {
  mockedFindAssertionById.mockResolvedValue({
    id: assertion.assertionId,
    tenantId: assertion.tenantId,
    publicId: assertion.assertionPublicId,
    learnerProfileId: assertion.learnerProfileId,
    badgeTemplateId: assertion.badgeTemplateId,
    recipientIdentity: assertion.recipientIdentity,
    recipientIdentityType: assertion.recipientIdentityType,
    vcR2Key: assertion.vcR2Key,
    statusListIndex: assertion.statusListIndex,
    idempotencyKey: assertion.idempotencyKey,
    issuedAt: assertion.issuedAt,
    issuedByUserId: assertion.issuedByUserId,
    revokedAt: assertion.revokedAt,
    createdAt: assertion.createdAt,
    updatedAt: assertion.updatedAt,
  });
  mockedFindBadgeTemplateById.mockResolvedValue({
    id: assertion.badgeTemplateId,
    tenantId: assertion.tenantId,
    slug: "applied-analytics",
    title: assertion.badgeTitle,
    description: assertion.badgeDescription,
    criteriaUri: assertion.badgeCriteriaUri,
    imageUri: assertion.badgeImageUri,
    createdByUserId: "usr_admin",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: assertion.createdAt,
    updatedAt: assertion.updatedAt,
  });
  mockedResolveAssertionLifecycleState.mockResolvedValue({
    state: assertion.revokedAt === null ? "active" : "revoked",
    source: "default_active",
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    revokedAt: assertion.revokedAt,
  });
  mockedFindUsersByIds.mockResolvedValue(
    new Map([
      [
        assertion.issuedByUserId ?? "usr_admin",
        {
          id: assertion.issuedByUserId ?? "usr_admin",
          email: "admin@tenant-123.edu",
        },
      ],
    ]),
  );
};

export const sampleLearnerRecordEntry = (
  overrides?: Partial<LearnerRecordEntryRecord>,
): LearnerRecordEntryRecord => {
  return {
    id: "lre_123",
    tenantId: "tenant_123",
    learnerProfileId: "lpr_123",
    trustLevel: "issuer_verified",
    recordType: "course",
    status: "active",
    title: "Clinical Placement Seminar",
    description: "Completed with distinction.",
    issuerName: "CredTrail University",
    issuerUserId: "usr_admin",
    sourceSystem: "credtrail_admin",
    sourceRecordId: null,
    issuedAt: "2026-03-23T15:00:00.000Z",
    revisedAt: null,
    revokedAt: null,
    evidenceLinksJson: '["https://credtrail.example.edu/evidence/clinical-placement-seminar"]',
    detailsJson: '{"grade":"A"}',
    createdAt: "2026-03-23T15:00:00.000Z",
    updatedAt: "2026-03-23T15:00:00.000Z",
    ...overrides,
  };
};

export const sampleTenantLmsConnection = (
  overrides?: Partial<TenantLmsConnectionRecord>,
): TenantLmsConnectionRecord => {
  return {
    id: "lms_123",
    tenantId: "tenant_123",
    displayName: "TrySakai",
    providerKind: "sakai",
    apiBaseUrl: "https://trysakai.example.edu",
    authorizationEndpoint: null,
    tokenEndpoint: null,
    clientId: null,
    clientSecret: null,
    scope: null,
    accessToken: "sakai-token",
    refreshToken: null,
    accessTokenExpiresAt: null,
    refreshTokenExpiresAt: null,
    connectedAt: "2026-02-18T12:00:00.000Z",
    ltiIssuer: "https://trysakai.example.edu",
    ltiClientId: "sakai-client",
    ltiDeploymentId: "deployment-123",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
    ...overrides,
  };
};

export const sampleReportingOrgUnits = () => {
  return [
    {
      id: "tenant_123:org:institution",
      tenantId: "tenant_123",
      unitType: "institution" as const,
      slug: "institution",
      displayName: "Institution",
      parentOrgUnitId: null,
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:college-eng",
      tenantId: "tenant_123",
      unitType: "college" as const,
      slug: "college-eng",
      displayName: "College of Engineering",
      parentOrgUnitId: "tenant_123:org:institution",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:college-arts",
      tenantId: "tenant_123",
      unitType: "college" as const,
      slug: "college-arts",
      displayName: "College of Arts",
      parentOrgUnitId: "tenant_123:org:institution",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-cs",
      tenantId: "tenant_123",
      unitType: "department" as const,
      slug: "department-cs",
      displayName: "Computer Science",
      parentOrgUnitId: "tenant_123:org:college-eng",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-math",
      tenantId: "tenant_123",
      unitType: "department" as const,
      slug: "department-math",
      displayName: "Mathematics",
      parentOrgUnitId: "tenant_123:org:college-eng",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-history",
      tenantId: "tenant_123",
      unitType: "department" as const,
      slug: "department-history",
      displayName: "History",
      parentOrgUnitId: "tenant_123:org:college-arts",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:department-design",
      tenantId: "tenant_123",
      unitType: "department" as const,
      slug: "department-design",
      displayName: "Design",
      parentOrgUnitId: "tenant_123:org:college-arts",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:program-cs",
      tenantId: "tenant_123",
      unitType: "program" as const,
      slug: "program-cs",
      displayName: "Computer Science Program",
      parentOrgUnitId: "tenant_123:org:department-cs",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tenant_123:org:program-design",
      tenantId: "tenant_123",
      unitType: "program" as const,
      slug: "program-design",
      displayName: "Design Foundations",
      parentOrgUnitId: "tenant_123:org:department-design",
      isActive: true,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ];
};

export const getReportingPanelMarkup = (html: string, heading: string): string => {
  const headingMarkup = `<h2>${heading}</h2>`;
  const start = html.indexOf(headingMarkup);

  expect(start).toBeGreaterThan(-1);

  const end = html.indexOf("</article>", start);

  expect(end).toBeGreaterThan(start);

  return html.slice(start, end);
};

export const getReportingPanelArticleMarkup = (html: string, heading: string): string => {
  const headingMarkup = `<h2>${heading}</h2>`;
  const headingIndex = html.indexOf(headingMarkup);

  expect(headingIndex).toBeGreaterThan(-1);

  const start = html.lastIndexOf("<article", headingIndex);

  expect(start).toBeGreaterThan(-1);

  const end = html.indexOf("</article>", headingIndex);

  expect(end).toBeGreaterThan(start);

  return html.slice(start, end);
};

beforeEach(() => {
  fakeDbPrepare.mockReset();
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindTenantMembership.mockReset();
  mockedFindTenantMembership.mockResolvedValue(sampleMembership("admin"));
  mockedFindTenantById.mockReset();
  mockedFindTenantById.mockResolvedValue({
    id: "tenant_123",
    slug: "tenant-123",
    displayName: "Tenant 123",
    planTier: "team",
    issuerDomain: "tenant-123.credtrail.test",
    didWeb: "did:web:credtrail.test:tenant_123",
    isActive: true,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedFindBadgeTemplateById.mockReset();
  mockedFindBadgeTemplateById.mockResolvedValue(null);
  mockedFindBadgeTemplateImageRevisionById.mockReset();
  mockedFindBadgeTemplateImageRevisionById.mockResolvedValue(null);
  mockedSetBadgeTemplateArchivedState.mockReset();
  mockedSetBadgeTemplateArchivedState.mockResolvedValue(null);
  mockedCreateBadgeTemplate.mockReset();
  mockedCreateBadgeTemplate.mockResolvedValue({
    id: "badge_template_created",
    tenantId: "tenant_123",
    slug: "created-template",
    title: "Created Template",
    description: null,
    criteriaUri: null,
    imageUri: null,
    createdByUserId: "usr_admin",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedUpdateBadgeTemplate.mockReset();
  mockedUpdateBadgeTemplate.mockResolvedValue(null);
  mockedListAuditLogs.mockReset();
  mockedListAuditLogs.mockResolvedValue([]);
  mockedListBadgeTemplateOwnershipEvents.mockReset();
  mockedListBadgeTemplateOwnershipEvents.mockResolvedValue([]);
  mockedListBadgeTemplateImageRevisions.mockReset();
  mockedListBadgeTemplateImageRevisions.mockResolvedValue([]);
  mockedCountBadgeTemplateImageRevisions.mockReset();
  mockedCountBadgeTemplateImageRevisions.mockResolvedValue(0);
  mockedCreateAuditLogDb.mockReset();
  mockedCreateAuditLogDb.mockResolvedValue({
    id: "aud_test",
    tenantId: "tenant_123",
    actorUserId: "usr_admin",
    action: "badge_template.image_restored",
    targetType: "badge_template",
    targetId: "badge_template_001",
    metadataJson: null,
    occurredAt: "2026-02-18T12:00:00.000Z",
    createdAt: "2026-02-18T12:00:00.000Z",
  });
  vi.mocked(createBadgeTemplateImageRevision).mockReset();
  vi.mocked(createBadgeTemplateImageRevision).mockResolvedValue({
    id: "btir_test",
    tenantId: "tenant_123",
    badgeTemplateId: "badge_template_001",
    previousImageUri: "https://example.edu/new.png",
    newImageUri: "https://example.edu/old.png",
    sourceType: "restore",
    promptText: null,
    provider: null,
    model: null,
    metadataJson: null,
    createdByUserId: "usr_admin",
    createdAt: "2026-02-18T12:00:00.000Z",
  });
  mockedFindTenantAuthPolicy.mockReset();
  mockedFindTenantAuthPolicy.mockResolvedValue({
    tenantId: "tenant_123",
    loginMode: "hybrid",
    breakGlassEnabled: true,
    localMfaRequired: true,
    defaultProviderId: "tap_oidc",
    enforceForRoles: "all_users",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedFindUserById.mockReset();
  mockedFindUserById.mockResolvedValue({
    id: "usr_admin",
    email: "admin@tenant-123.edu",
  });
  mockedListBadgeTemplateImageRevisionCountsByTenant.mockReset();
  mockedListBadgeTemplateImageRevisionCountsByTenant.mockResolvedValue([
    {
      badgeTemplateId: "badge_template_001",
      revisionCount: 3,
    },
  ]);
  mockedListBadgeTemplates.mockReset();
  mockedListBadgeTemplates.mockResolvedValue([
    {
      id: "badge_template_001",
      tenantId: "tenant_123",
      slug: "typescript-foundations",
      title: "TypeScript Foundations",
      description: "Awarded for TypeScript basics.",
      criteriaUri: "https://example.edu/criteria",
      imageUri: "https://example.edu/badges/typescript.png",
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: false,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ]);
  mockedListBadgeIssuanceRules.mockReset();
  mockedListBadgeIssuanceRules.mockResolvedValue([
    {
      id: "brl_123",
      tenantId: "tenant_123",
      name: "CS101 Excellence Rule",
      description: "Issue badge for CS101 completion and grade threshold.",
      badgeTemplateId: "badge_template_001",
      orgUnitId: "tenant_123:org:institution",
      ownerOrgUnitId: "tenant_123:org:institution",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_canvas",
      activeVersionId: "brv_123",
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ]);
  mockedListBadgeIssuanceRuleVersions.mockReset();
  mockedListBadgeIssuanceRuleVersions.mockResolvedValue([
    {
      id: "brv_123",
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionNumber: 1,
      status: "draft",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"CS101","minScore":80}}',
      changeSummary: "Initial draft",
      createdByUserId: "usr_admin",
      submittedByUserId: null,
      submittedAt: null,
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      effectiveStartsAt: null,
      expiresAt: null,
      expiredAt: null,
      suspendedAt: null,
      suspendedByUserId: null,
      suspensionReason: null,
      recertifiedAt: null,
      recertificationDueAt: null,
      expiryReminderSentAt: null,
      recertificationReminderSentAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ]);
  mockedFindBadgeIssuanceRuleVersionByIdDb.mockReset();
  mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValue(null);
  mockedFindBadgeIssuanceRuleBuilderDraftDb.mockReset();
  mockedFindBadgeIssuanceRuleBuilderDraftDb.mockResolvedValue(null);
  mockedFindLtiResourceLinkPlacementForRule.mockReset();
  mockedFindLtiResourceLinkPlacementForRule.mockResolvedValue(null);
  mockedListActiveLtiLaunchSessionsForPlatform.mockReset();
  mockedListActiveLtiLaunchSessionsForPlatform.mockResolvedValue([]);
  mockedListPendingBadgeIssuanceRuleApprovalsForActor.mockReset();
  mockedListPendingBadgeIssuanceRuleApprovalsForActor.mockResolvedValue([]);
  mockedSubmitBadgeIssuanceRuleVersionForApprovalDb.mockReset();
  mockedSubmitBadgeIssuanceRuleVersionForApprovalDb.mockResolvedValue({ status: "not_found" });
  mockedListBadgeIssuanceRuleVersionApprovalStepsDb.mockReset();
  mockedListBadgeIssuanceRuleVersionApprovalStepsDb.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleVersionApprovalEvents.mockReset();
  mockedListBadgeIssuanceRuleVersionApprovalEvents.mockResolvedValue([]);
  mockedResolveBadgeRuleApprovalPolicyDb.mockReset();
  mockedResolveBadgeRuleApprovalPolicyDb.mockResolvedValue({
    id: null,
    tenantId: "tenant_123",
    orgUnitId: null,
    approvalRequirement: "always",
    allowSelfCertification: false,
    recertificationIntervalMonths: null,
    approvalSteps: [
      {
        targetType: "role_threshold",
        requiredRole: "admin",
        targetUserId: null,
        targetApproverGroupId: null,
        orgUnitId: null,
        label: "Administrative approval",
      },
    ],
    createdByUserId: null,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedResolveTenantDefaultBadgeRuleApprovalPolicyDb.mockReset();
  mockedResolveTenantDefaultBadgeRuleApprovalPolicyDb.mockResolvedValue({
    id: "tenant_123:badge-rule-approval-policy:default",
    tenantId: "tenant_123",
    orgUnitId: null,
    approvalRequirement: "always",
    allowSelfCertification: false,
    recertificationIntervalMonths: null,
    approvalSteps: [
      {
        targetType: "role_threshold",
        requiredRole: "admin",
        targetUserId: null,
        targetApproverGroupId: null,
        orgUnitId: null,
        label: "Administrative approval",
      },
    ],
    createdByUserId: null,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedListBadgeRuleApproverGroupsWithMembersDb.mockReset();
  mockedListBadgeRuleApproverGroupsWithMembersDb.mockResolvedValue([
    {
      id: "brag_registrar",
      tenantId: "tenant_123",
      orgUnitId: "tenant_123:org:institution",
      name: "Registrar office",
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
      members: [
        {
          tenantId: "tenant_123",
          groupId: "brag_registrar",
          userId: "usr_issuer",
          email: "issuer@tenant-123.edu",
          role: "issuer",
          createdByUserId: "usr_admin",
          createdAt: "2026-02-18T12:00:00.000Z",
        },
      ],
    },
  ]);
  mockedCreateBadgeRuleApproverGroupDb.mockReset();
  mockedCreateBadgeRuleApproverGroupDb.mockResolvedValue({
    id: "brag_created",
    tenantId: "tenant_123",
    orgUnitId: "tenant_123:org:institution",
    name: "Registrar office",
    createdByUserId: "usr_admin",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedAddBadgeRuleApproverGroupMemberDb.mockReset();
  mockedAddBadgeRuleApproverGroupMemberDb.mockResolvedValue({ status: "added" });
  mockedRemoveBadgeRuleApproverGroupMemberDb.mockReset();
  mockedRemoveBadgeRuleApproverGroupMemberDb.mockResolvedValue({ status: "removed" });
  mockedRemoveBadgeRuleApproverGroupDb.mockReset();
  mockedRemoveBadgeRuleApproverGroupDb.mockResolvedValue({ status: "removed" });
  mockedDecideBadgeIssuanceRuleVersionDb.mockReset();
  mockedDecideBadgeIssuanceRuleVersionDb.mockResolvedValue({ status: "not_found" });
  mockedRecertifyBadgeIssuanceRuleVersionDb.mockReset();
  mockedRecertifyBadgeIssuanceRuleVersionDb.mockResolvedValue(null);
  mockedUpsertBadgeRuleApprovalPolicyDb.mockReset();
  mockedUpsertBadgeRuleApprovalPolicyDb.mockResolvedValue({
    id: "brap_123",
    tenantId: "tenant_123",
    orgUnitId: null,
    approvalRequirement: "always",
    allowSelfCertification: false,
    recertificationIntervalMonths: null,
    approvalSteps: [
      {
        targetType: "role_threshold",
        requiredRole: "admin",
        targetUserId: null,
        targetApproverGroupId: null,
        orgUnitId: null,
        label: "Badge rule approval",
      },
    ],
    createdByUserId: "usr_admin",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedListBadgeIssuanceRuleEvaluations.mockReset();
  mockedListBadgeIssuanceRuleEvaluations.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleValueLists.mockReset();
  mockedListBadgeIssuanceRuleValueLists.mockResolvedValue([]);
  mockedCreateBadgeIssuanceRuleValueList.mockReset();
  mockedCreateBadgeIssuanceRuleValueList.mockResolvedValue({
    id: "brvl_123",
    tenantId: "tenant_123",
    label: "Core CS sequence",
    kind: "course_ids",
    values: ["CS101", "CS102"],
    createdByUserId: "usr_admin",
    archivedAt: null,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedDeleteDraftBadgeIssuanceRuleDb.mockReset();
  mockedDeleteDraftBadgeIssuanceRuleDb.mockResolvedValue({ status: "not_found" });
  mockedFindBadgeIssuanceRuleEvaluationById.mockReset();
  mockedFindBadgeIssuanceRuleEvaluationById.mockResolvedValue(null);
  mockedResolveBadgeIssuanceRuleEvaluationReview.mockReset();
  mockedResolveBadgeIssuanceRuleEvaluationReview.mockResolvedValue(null);
  mockedFindBadgeIssuanceRuleById.mockReset();
  mockedFindBadgeIssuanceRuleById.mockResolvedValue(null);
  mockedListTenantOrgUnits.mockReset();
  mockedListTenantOrgUnits.mockResolvedValue(sampleReportingOrgUnits());
  mockedListTenantMembershipOrgUnitScopes.mockReset();
  mockedListTenantMembershipOrgUnitScopes.mockResolvedValue([
    {
      tenantId: "tenant_123",
      userId: "usr_issuer",
      orgUnitId: "tenant_123:org:institution",
      role: "issuer",
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:30:00.000Z",
    },
  ]);
  mockedListTenantAssertions.mockReset();
  mockedListTenantAssertions.mockResolvedValue([]);
  mockedFindAssertionById.mockReset();
  mockedFindAssertionById.mockResolvedValue(null);
  mockedFindAssertionIssuanceProvenanceByAssertionId.mockReset();
  mockedFindAssertionIssuanceProvenanceByAssertionId.mockResolvedValue(null);
  mockedFindAssertionReportingAttributionByAssertionId.mockReset();
  mockedFindAssertionReportingAttributionByAssertionId.mockResolvedValue(null);
  mockedFindBadgeIssuanceRuleEvaluationByAssertionId.mockReset();
  mockedFindBadgeIssuanceRuleEvaluationByAssertionId.mockResolvedValue(null);
  mockedFindTenantOrgUnitById.mockReset();
  mockedFindTenantOrgUnitById.mockResolvedValue(null);
  mockedFindUsersByIds.mockReset();
  mockedFindUsersByIds.mockResolvedValue(new Map());
  mockedListAssertionLifecycleEvents.mockReset();
  mockedListAssertionLifecycleEvents.mockResolvedValue([]);
  mockedListAuditLogsForAssertion.mockReset();
  mockedListAuditLogsForAssertion.mockResolvedValue([]);
  mockedResolveAssertionLifecycleState.mockReset();
  mockedResolveAssertionLifecycleState.mockResolvedValue(null);
  mockedRecordAssertionLifecycleTransition.mockReset();
  mockedRecordAssertionLifecycleTransition.mockResolvedValue({
    status: "transitioned",
    fromState: "active",
    toState: "revoked",
    currentState: "revoked",
    event: null,
    message: null,
  });
  mockedUpsertTenantLmsConnection.mockReset();
  mockedUpsertTenantLmsConnection.mockResolvedValue(
    sampleTenantLmsConnection({
      id: "lms_new",
      displayName: "New LMS",
    }),
  );
  mockedCreateTenantApiKey.mockReset();
  mockedCreateTenantApiKey.mockResolvedValue({
    id: "tak_new",
    tenantId: "tenant_123",
    label: "Integration key",
    keyPrefix: "ctak_newkey",
    keyHash: "hash_new",
    scopesJson: '["queue.issue","queue.revoke"]',
    createdByUserId: "usr_admin",
    expiresAt: null,
    lastUsedAt: null,
    revokedAt: null,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedRevokeTenantApiKey.mockReset();
  mockedRevokeTenantApiKey.mockResolvedValue(true);
  mockedListTenantApiKeys.mockReset();
  mockedListTenantApiKeys.mockResolvedValue([
    {
      id: "tak_active",
      tenantId: "tenant_123",
      label: "Issuer integration",
      keyPrefix: "ctak_abc123",
      keyHash: "hash_active",
      scopesJson: '["queue.issue","queue.revoke"]',
      createdByUserId: "usr_admin",
      expiresAt: null,
      lastUsedAt: null,
      revokedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
    {
      id: "tak_revoked",
      tenantId: "tenant_123",
      label: "Old key",
      keyPrefix: "ctak_old123",
      keyHash: "hash_revoked",
      scopesJson: '["queue.issue"]',
      createdByUserId: "usr_admin",
      expiresAt: null,
      lastUsedAt: null,
      revokedAt: "2026-02-18T12:30:00.000Z",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:30:00.000Z",
    },
  ]);
  mockedListTenantLmsConnectionsDb.mockReset();
  const lmsConnections = [
    sampleTenantLmsConnection({
      id: "lms_canvas",
      displayName: "Canvas Test",
      providerKind: "canvas",
      apiBaseUrl: "https://canvas.example.edu",
      accessToken: "canvas-token",
      ltiIssuer: "https://canvas.example.edu",
      ltiClientId: "canvas-client",
      ltiDeploymentId: "canvas-deployment",
    }),
  ];
  mockedListTenantLmsConnectionsDb.mockResolvedValue(lmsConnections);
  mockedFindTenantLmsConnectionByIdDb.mockReset();
  mockedFindTenantLmsConnectionByIdDb.mockImplementation(async (_db, input) => {
    return lmsConnections.find((connection) => connection.id === input.connectionId) ?? null;
  });
  mockedListDelegatedIssuingAuthorityGrants.mockReset();
  mockedListDelegatedIssuingAuthorityGrants.mockResolvedValue([
    {
      id: "dag_123",
      tenantId: "tenant_123",
      delegateUserId: "usr_delegate",
      delegatedByUserId: "usr_admin",
      orgUnitId: "tenant_123:org:institution",
      allowedActions: ["issue_badge"],
      badgeTemplateIds: [],
      startsAt: "2026-02-18T12:00:00.000Z",
      endsAt: "2026-05-18T12:00:00.000Z",
      revokedAt: null,
      revokedByUserId: null,
      revokedReason: null,
      status: "active",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ]);
  mockedListTenantAuthProviders.mockReset();
  mockedListTenantAuthProviders.mockResolvedValue([
    {
      id: "tap_oidc",
      tenantId: "tenant_123",
      protocol: "oidc",
      label: "Campus OIDC",
      enabled: true,
      isDefault: true,
      configJson:
        '{"issuer":"https://idp.example.edu","clientId":"credtrail","clientSecret":"secret"}',
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ]);
  mockedListTenantBreakGlassAccounts.mockReset();
  mockedListTenantBreakGlassAccounts.mockResolvedValue([
    {
      tenantId: "tenant_123",
      userId: "usr_break_glass",
      email: "admin@tenant-123.edu",
      createdByUserId: "usr_admin",
      lastUsedAt: null,
      lastEnrollmentEmailSentAt: "2026-02-18T12:05:00.000Z",
      revokedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:05:00.000Z",
      betterAuthUserId: "ba_usr_break_glass",
      localCredentialEnabled: true,
      twoFactorEnabled: true,
    },
  ]);
  mockedListTenantMembersDb.mockReset();
  mockedListTenantMembersDb.mockResolvedValue([
    sampleTenantMember({
      userId: "usr_admin",
      email: "admin@tenant-123.edu",
      role: "admin",
    }),
    sampleTenantMember({
      userId: "usr_issuer",
      email: "issuer@tenant-123.edu",
      role: "issuer",
    }),
  ]);
  mockedListAccessibleTenantContextsForUser.mockReset();
  mockedListAccessibleTenantContextsForUser.mockResolvedValue([
    {
      tenantId: "tenant_123",
      tenantSlug: "tenant-123",
      tenantDisplayName: "Tenant 123",
      tenantPlanTier: "team",
      membershipRole: "admin",
    },
  ]);
  mockedListImportLearnerRecordBatchQueueMessagesDb.mockReset();
  mockedListImportLearnerRecordBatchQueueMessagesDb.mockResolvedValue([]);
  mockedCreateLearnerRecordImportPreviewDb.mockReset();
  mockedCreateLearnerRecordImportPreviewDb.mockImplementation(async (_db, input) => ({
    tenantId: input.tenantId,
    batchId: input.batchId,
    fileName: input.fileName,
    format: input.format,
    defaultsJson: input.defaultsJson,
    reportsJson: input.reportsJson,
    queuePayloadsJson: input.queuePayloadsJson,
    createdByUserId: input.createdByUserId ?? null,
    createdAt: input.createdAt,
    expiresAt: input.expiresAt,
    queuedAt: null,
  }));
  mockedEnqueueJobQueueMessageOnce.mockReset();
  mockedEnqueueJobQueueMessageOnce.mockResolvedValue(true);
  mockedFindActiveLearnerRecordImportPreviewDb.mockReset();
  mockedFindActiveLearnerRecordImportPreviewDb.mockResolvedValue(null);
  mockedMarkLearnerRecordImportPreviewQueuedDb.mockReset();
  mockedMarkLearnerRecordImportPreviewQueuedDb.mockResolvedValue(true);
  mockedFindLearnerProfileByIdDb.mockReset();
  mockedFindLearnerProfileByIdDb.mockResolvedValue(sampleLearnerProfile());
  mockedFindLearnerProfileByIdentityDb.mockReset();
  mockedFindLearnerProfileByIdentityDb.mockResolvedValue(sampleLearnerProfile());
  mockedListLearnerRecordAssertionExportsDb.mockReset();
  mockedListLearnerRecordAssertionExportsDb.mockResolvedValue([
    sampleLearnerRecordAssertionExport(),
  ]);
  mockedListLearnerRecordEntriesDb.mockReset();
  mockedListLearnerRecordEntriesDb.mockResolvedValue([
    sampleLearnerRecordEntry(),
    sampleLearnerRecordEntry({
      id: "lre_supp_001",
      trustLevel: "learner_supplemental",
      recordType: "supplemental_artifact",
      title: "Portfolio Reflection",
      description: "Learner-supplied capstone reflection.",
      issuerName: "Learner self report",
      issuerUserId: null,
      sourceSystem: "learner_self_reported",
      sourceRecordId: null,
      evidenceLinksJson: '["https://portfolio.example.edu/learner-one"]',
      detailsJson: '{"portfolioUrl":"https://portfolio.example.edu/learner-one"}',
    }),
    sampleLearnerRecordEntry({
      id: "lre_revoked_001",
      recordType: "membership",
      title: "Membership Standing",
      status: "revoked",
      sourceSystem: "csv_import",
      sourceRecordId: "legacy:membership:001",
      revokedAt: "2026-03-22T15:00:00.000Z",
    }),
  ]);
  mockedGetTenantReportingOverviewDb.mockReset();
  mockedGetTenantReportingOverviewDb.mockResolvedValue({
    tenantId: "tenant_123",
    filters: {
      issuedFrom: null,
      issuedTo: null,
      badgeTemplateId: null,
      orgUnitId: null,
      state: null,
    },
    counts: {
      issued: 14,
      active: 12,
      suspended: 1,
      revoked: 1,
      pendingReview: 1,
    },
    generatedAt: "2026-03-21T12:00:00.000Z",
  });
  mockedGetTenantReportingEngagementCountsDb.mockReset();
  mockedGetTenantReportingEngagementCountsDb.mockResolvedValue({
    issuedCount: 14,
    publicBadgeViewCount: 41,
    verificationViewCount: 16,
    shareClickCount: 7,
    learnerClaimCount: 5,
    walletAcceptCount: 4,
    claimRate: 35.7,
    shareRate: 28.6,
  });
  mockedGetTenantReportingTrendsDb.mockReset();
  mockedGetTenantReportingTrendsDb.mockResolvedValue({
    tenantId: "tenant_123",
    filters: {
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: null,
      orgUnitId: null,
      state: null,
    },
    bucket: "day",
    series: [
      {
        bucketStart: "2026-03-01",
        issuedCount: 3,
        publicBadgeViewCount: 8,
        verificationViewCount: 2,
        shareClickCount: 1,
        learnerClaimCount: 1,
        walletAcceptCount: 1,
      },
      {
        bucketStart: "2026-03-02",
        issuedCount: 2,
        publicBadgeViewCount: 5,
        verificationViewCount: 3,
        shareClickCount: 2,
        learnerClaimCount: 1,
        walletAcceptCount: 1,
      },
    ],
    generatedAt: "2026-03-21T12:00:00.000Z",
  });
  mockedGetTenantReportingComparisonsDb.mockReset();
  mockedGetTenantReportingComparisonsDb.mockImplementation(
    async (_db, input: { groupBy: "badgeTemplate" | "orgUnit" }) => {
      if (input.groupBy === "orgUnit") {
        return [
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:program-cs",
            issuedCount: 8,
            publicBadgeViewCount: 24,
            verificationViewCount: 9,
            shareClickCount: 5,
            learnerClaimCount: 4,
            walletAcceptCount: 2,
            claimRate: 50,
            shareRate: 37.5,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-math",
            issuedCount: 4,
            publicBadgeViewCount: 10,
            verificationViewCount: 3,
            shareClickCount: 1,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 50,
            shareRate: 25,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-history",
            issuedCount: 6,
            publicBadgeViewCount: 14,
            verificationViewCount: 5,
            shareClickCount: 2,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 33.3,
            shareRate: 16.7,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:program-design",
            issuedCount: 1,
            publicBadgeViewCount: 3,
            verificationViewCount: 1,
            shareClickCount: 1,
            learnerClaimCount: 1,
            walletAcceptCount: 0,
            claimRate: 100,
            shareRate: 100,
          },
        ];
      }

      return [
        {
          groupBy: "badgeTemplate",
          groupId: "badge_template_001",
          issuedCount: 9,
          publicBadgeViewCount: 28,
          verificationViewCount: 11,
          shareClickCount: 5,
          learnerClaimCount: 4,
          walletAcceptCount: 3,
          claimRate: 44.4,
          shareRate: 33.3,
        },
      ];
    },
  );
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthPrincipal.mockImplementation(
    (context: { req: { header(name: string): string | undefined } }) => {
      const cookieHeader = context.req.header("cookie") ?? "";

      if (!cookieHeader.includes("better-auth.session_token=")) {
        return null;
      }

      return {
        userId: "usr_admin",
        authSessionId: "ba_ses_123",
        authMethod: "better_auth" as const,
        expiresAt: "2026-02-18T23:00:00.000Z",
      };
    },
  );
  mockedResolveBetterAuthRequestedTenant.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue(null);
});
