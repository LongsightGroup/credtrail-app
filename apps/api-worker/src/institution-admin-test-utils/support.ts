import { expect, vi } from "vitest";
import { buildBadgeRuleVersionRecord } from "../test-support/badge-rule-version";

import {
  mockedListBadgeIssuanceRuleBuilderDraftsForUser,
  mockedDeleteBadgeIssuanceRuleBuilderDraftById,
  mockedListBadgeTemplateRuleUsages,
} from "./register-mocks";

import {
  createLearnerRecordImportPreview,
  countBadgeTemplateImageRevisions,
  createAuditLog,
  createBadgeTemplate,
  createBadgeTemplateImageRevision,
  createDelegatedIssuingAuthorityGrant,
  findBadgeTemplateById,
  findBadgeTemplateImageRevisionById,
  setBadgeTemplateArchivedState,
  updateBadgeTemplate,
  findActiveLearnerRecordImportPreview,
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  listLearnerProfilesForRecordLookup,
  findTenantById,
  findDelegatedIssuingAuthorityGrantById,
  findTenantMembership,
  findUserById,
  getTenantReportingEngagementCounts,
  listDelegatedIssuingAuthorityGrants,
  listAuditLogs,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleRegistryPage,
  listBadgeIssuanceRuleVersions,
  listBadgeIssuanceRuleVersionsForRules,
  findBadgeIssuanceRuleBuilderDraftById,
  findBadgeIssuanceRuleVersionById,
  submitBadgeIssuanceRuleVersionForApproval,
  listBadgeIssuanceRuleVersionApprovalSteps,
  resolveBadgeRuleApprovalPolicy,
  resolveTenantDefaultBadgeRuleApprovalPolicy,
  decideBadgeIssuanceRuleVersion,
  reopenApprovedBadgeIssuanceRuleVersion,
  withdrawBadgeIssuanceRuleVersionSubmission,
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
  deleteNeverActiveBadgeIssuanceRule,
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
  removeTenantMembershipOrgUnitScope,
  revokeDelegatedIssuingAuthorityGrant,
  upsertTenantMembershipOrgUnitScope,
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
import { createBadgeTemplateArtworkBucket } from "../test-support/badge-template-artwork-bucket";

export const mockedCountBadgeTemplateImageRevisions = vi.mocked(countBadgeTemplateImageRevisions);
export const mockedFindBadgeTemplateById = vi.mocked(findBadgeTemplateById);
export const mockedFindBadgeTemplateImageRevisionById = vi.mocked(
  findBadgeTemplateImageRevisionById,
);
export const mockedSetBadgeTemplateArchivedState = vi.mocked(setBadgeTemplateArchivedState);
export const mockedCreateBadgeTemplate = vi.mocked(createBadgeTemplate);
export const mockedCreateBadgeTemplateImageRevision = vi.mocked(createBadgeTemplateImageRevision);
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
export const mockedListLearnerProfilesForRecordLookupDb = vi.mocked(
  listLearnerProfilesForRecordLookup,
);
export const mockedFindTenantMembership = vi.mocked(findTenantMembership);
export const mockedFindTenantById = vi.mocked(findTenantById);
export const mockedFindUserById = vi.mocked(findUserById);
export const mockedListDelegatedIssuingAuthorityGrants = vi.mocked(
  listDelegatedIssuingAuthorityGrants,
);
export const mockedCreateDelegatedIssuingAuthorityGrantDb = vi.mocked(
  createDelegatedIssuingAuthorityGrant,
);
export const mockedFindDelegatedIssuingAuthorityGrantByIdDb = vi.mocked(
  findDelegatedIssuingAuthorityGrantById,
);
export const mockedRevokeDelegatedIssuingAuthorityGrantDb = vi.mocked(
  revokeDelegatedIssuingAuthorityGrant,
);
export const mockedListBadgeIssuanceRules = vi.mocked(listBadgeIssuanceRules);
export const mockedListBadgeIssuanceRuleRegistryPageDb = vi.mocked(
  listBadgeIssuanceRuleRegistryPage,
);
export const mockedListBadgeIssuanceRuleVersions = vi.mocked(listBadgeIssuanceRuleVersions);
export const mockedListBadgeIssuanceRuleVersionsForRules = vi.mocked(
  listBadgeIssuanceRuleVersionsForRules,
);
export const mockedListBadgeTemplateRuleUsagesDb = mockedListBadgeTemplateRuleUsages;
export const mockedFindBadgeIssuanceRuleVersionByIdDb = vi.mocked(findBadgeIssuanceRuleVersionById);
export const mockedFindBadgeIssuanceRuleBuilderDraftDb = vi.mocked(
  findBadgeIssuanceRuleBuilderDraftById,
);
export const mockedListBadgeIssuanceRuleBuilderDraftsForUserDb =
  mockedListBadgeIssuanceRuleBuilderDraftsForUser;
export const mockedDeleteBadgeIssuanceRuleBuilderDraftByIdDb =
  mockedDeleteBadgeIssuanceRuleBuilderDraftById;
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
export const mockedReopenApprovedBadgeIssuanceRuleVersionDb = vi.mocked(
  reopenApprovedBadgeIssuanceRuleVersion,
);
export const mockedWithdrawBadgeIssuanceRuleVersionSubmissionDb = vi.mocked(
  withdrawBadgeIssuanceRuleVersionSubmission,
);
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
export const mockedDeleteNeverActiveBadgeIssuanceRuleDb = vi.mocked(
  deleteNeverActiveBadgeIssuanceRule,
);
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
export const mockedUpsertTenantMembershipOrgUnitScopeDb = vi.mocked(
  upsertTenantMembershipOrgUnitScope,
);
export const mockedRemoveTenantMembershipOrgUnitScopeDb = vi.mocked(
  removeTenantMembershipOrgUnitScope,
);
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
const runFakeTransaction = async <T>(
  callback: (transaction: SqlDatabase) => Promise<T>,
): Promise<T> => callback(fakeDb);
export const fakeDb: SqlDatabase = {
  prepare: fakeDbPrepare,
  transaction: runFakeTransaction,
};

export const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  PUBLIC_APP_ORIGIN: string;
  BETTER_AUTH_SECRET: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: createBadgeTemplateArtworkBucket(),
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
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
    achievementSnapshotStatus: "captured",
    achievementSnapshot: {
      badgeTemplateId: assertion.badgeTemplateId,
      title: assertion.badgeTitle,
      description: assertion.badgeDescription,
      criteriaUri: assertion.badgeCriteriaUri,
      imageUri: assertion.badgeImageUri,
      trustedCredentialMetadataJson: null,
    },
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
  mockedFindAssertionIssuanceProvenanceByAssertionId.mockResolvedValue({
    assertionId: assertion.assertionId,
    tenantId: assertion.tenantId,
    source: "manual",
    ruleId: null,
    versionId: null,
    provenanceJson: null,
    createdAt: assertion.issuedAt,
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

export const defaultBadgeRuleVersion = buildBadgeRuleVersionRecord({
  ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"CS101","minScore":80}}',
  changeSummary: "Initial draft",
  snapshot: {
    name: "CS101 Excellence Rule",
    description: "Issue badge for CS101 completion and grade threshold.",
    badgeTemplateTitle: "TypeScript Foundations",
    badgeTemplateImageUri: "https://example.edu/badges/typescript.png",
    lmsConnectionId: "lms_canvas",
  },
});
