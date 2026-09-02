import type { DelegatedIssuingAuthorityGrantRecord } from "@credtrail/db";
import { vi } from "vitest";
import {
  mockedEnqueueJobQueueMessageOnce,
  mockedEnqueueJobQueueMessagesOnce,
  mockedFindLtiResourceLinkPlacementForRule,
  mockedFindTenantAuthPolicy,
  mockedListAccessibleTenantContextsForUser,
  mockedListActiveLtiLaunchSessionsForPlatform,
  mockedListBadgeIssuanceRuleRegistryPage,
  mockedListBadgeIssuanceRuleVersionApprovalEvents,
  mockedListPendingBadgeIssuanceRuleApprovalsForActor,
  mockedListTenantAuthProviders,
  mockedListTenantBreakGlassAccounts,
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
} from "./register-mocks";
import {
  defaultBadgeRuleVersion,
  fakeDb,
  mockedAddBadgeRuleApproverGroupMemberDb,
  mockedCountBadgeTemplateImageRevisions,
  mockedCreateAuditLogDb,
  mockedCreateBadgeIssuanceRuleValueList,
  mockedCreateBadgeRuleApproverGroupDb,
  mockedCreateBadgeTemplate,
  mockedCreateBadgeTemplateImageRevision,
  mockedCreateDelegatedIssuingAuthorityGrantDb,
  mockedCreateLearnerRecordImportPreviewDb,
  mockedCreatePostgresDatabase,
  mockedCreateTenantApiKey,
  mockedDecideBadgeIssuanceRuleVersionDb,
  mockedDeleteBadgeIssuanceRuleBuilderDraftByIdDb,
  mockedDeleteNeverActiveBadgeIssuanceRuleDb,
  mockedFindActiveLearnerRecordImportPreviewDb,
  mockedFindAssertionById,
  mockedFindAssertionIssuanceProvenanceByAssertionId,
  mockedFindAssertionReportingAttributionByAssertionId,
  mockedFindBadgeIssuanceRuleBuilderDraftDb,
  mockedFindBadgeIssuanceRuleById,
  mockedFindBadgeIssuanceRuleEvaluationByAssertionId,
  mockedFindBadgeIssuanceRuleEvaluationById,
  mockedFindBadgeIssuanceRuleVersionByIdDb,
  mockedFindAutomatedBadgeRuleEvaluationStatusDb,
  mockedFindBadgeTemplateById,
  mockedFindBadgeTemplateImageRevisionById,
  mockedFindDelegatedIssuingAuthorityGrantByIdDb,
  mockedFindLearnerProfileByIdDb,
  mockedFindLearnerProfileByIdentityDb,
  mockedFindTenantById,
  mockedFindTenantLmsConnectionByIdDb,
  mockedFindTenantMembership,
  mockedFindTenantOrgUnitById,
  mockedFindUserById,
  mockedFindUsersByIds,
  mockedGetTenantReportingComparisonsDb,
  mockedGetTenantReportingEngagementCountsDb,
  mockedGetTenantReportingOverviewDb,
  mockedGetTenantReportingTrendsDb,
  mockedListAssertionLifecycleEvents,
  mockedListAuditLogs,
  mockedListAuditLogsForAssertion,
  mockedListBadgeIssuanceRuleBuilderDraftsForUserDb,
  mockedListBadgeIssuanceRuleEvaluations,
  mockedListBadgeIssuanceRuleValueLists,
  mockedListBadgeIssuanceRuleVersionApprovalStepsDb,
  mockedListBadgeIssuanceRuleVersions,
  mockedListBadgeIssuanceRuleVersionsForRules,
  mockedListBadgeIssuanceRules,
  mockedListBadgeRuleApproverGroupsWithMembersDb,
  mockedListBadgeTemplateImageRevisionCountsByTenant,
  mockedListBadgeTemplateImageRevisions,
  mockedListBadgeTemplateOwnershipEvents,
  mockedListBadgeTemplateRuleUsagesDb,
  mockedListBadgeTemplates,
  mockedListDelegatedIssuingAuthorityGrants,
  mockedListImportLearnerRecordBatchQueueMessagesDb,
  mockedListLearnerProfilesForRecordLookupDb,
  mockedListLearnerRecordAssertionExportsDb,
  mockedListLearnerRecordEntriesDb,
  mockedListTenantApiKeys,
  mockedListTenantAssertions,
  mockedListTenantLmsConnectionsDb,
  mockedListTenantMembersDb,
  mockedListTenantMembershipOrgUnitScopes,
  mockedListTenantOrgUnits,
  mockedMarkLearnerRecordImportPreviewQueuedDb,
  mockedRecertifyBadgeIssuanceRuleVersionDb,
  mockedRequestManualAutomatedBadgeRuleEvaluationDb,
  mockedRecordAssertionLifecycleTransition,
  mockedRemoveBadgeRuleApproverGroupDb,
  mockedRemoveBadgeRuleApproverGroupMemberDb,
  mockedRemoveTenantMembershipOrgUnitScopeDb,
  mockedReopenApprovedBadgeIssuanceRuleVersionDb,
  mockedResolveAssertionLifecycleState,
  mockedResolveBadgeIssuanceRuleEvaluationReview,
  mockedResolveBadgeRuleApprovalPolicyDb,
  mockedResolveTenantDefaultBadgeRuleApprovalPolicyDb,
  mockedRevokeDelegatedIssuingAuthorityGrantDb,
  mockedRevokeTenantApiKey,
  mockedSetBadgeTemplateArchivedState,
  mockedSubmitBadgeIssuanceRuleVersionForApprovalDb,
  mockedUpdateBadgeTemplate,
  mockedUpsertBadgeRuleApprovalPolicyDb,
  mockedUpsertTenantLmsConnection,
  mockedUpsertTenantMembershipOrgUnitScopeDb,
  mockedWithdrawBadgeIssuanceRuleVersionSubmissionDb,
  sampleLearnerProfile,
  sampleLearnerRecordAssertionExport,
  sampleLearnerRecordEntry,
  sampleMembership,
  sampleReportingOrgUnits,
  sampleTenantLmsConnection,
  sampleTenantMember,
} from "./support";

export const resetInstitutionAdminTestDefaults = (): void => {
  vi.resetAllMocks();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedFindTenantMembership.mockResolvedValue(sampleMembership("admin"));
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
  mockedFindBadgeTemplateById.mockResolvedValue(null);
  mockedFindBadgeTemplateImageRevisionById.mockResolvedValue(null);
  mockedSetBadgeTemplateArchivedState.mockResolvedValue(null);
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
  mockedUpdateBadgeTemplate.mockResolvedValue(null);
  mockedListAuditLogs.mockResolvedValue([]);
  mockedListBadgeTemplateOwnershipEvents.mockResolvedValue([]);
  mockedListBadgeTemplateImageRevisions.mockResolvedValue([]);
  mockedCountBadgeTemplateImageRevisions.mockResolvedValue(0);
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
  mockedCreateBadgeTemplateImageRevision.mockResolvedValue({
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
  mockedFindUserById.mockResolvedValue({
    id: "usr_admin",
    email: "admin@tenant-123.edu",
  });
  mockedListBadgeTemplateImageRevisionCountsByTenant.mockResolvedValue([
    {
      badgeTemplateId: "badge_template_001",
      revisionCount: 3,
    },
  ]);
  mockedListBadgeTemplates.mockResolvedValue([
    {
      id: "badge_template_001",
      tenantId: "tenant_123",
      slug: "typescript-foundations",
      title: "TypeScript Foundations",
      description: "Awarded for TypeScript basics.",
      criteriaUri: "https://example.edu/criteria",
      imageUri:
        "https://credtrail.test/badges/assets/tenant_123/badge_template_001/asset_typescript",
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: false,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ]);
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
  mockedListBadgeIssuanceRuleRegistryPage.mockImplementation(async (db, input) => {
    const rules = await mockedListBadgeIssuanceRules(db, input);
    return {
      rules,
      totalCount: rules.length,
      previousCursor: null,
      nextCursor: null,
    };
  });
  mockedListBadgeIssuanceRuleVersions.mockResolvedValue([defaultBadgeRuleVersion]);
  mockedListBadgeIssuanceRuleVersionsForRules.mockImplementation(async (db, input) => {
    const versionLists = await Promise.all(
      input.ruleIds.map((ruleId) =>
        mockedListBadgeIssuanceRuleVersions(db, {
          tenantId: input.tenantId,
          ruleId,
        }),
      ),
    );

    return versionLists.flat();
  });
  mockedListBadgeTemplateRuleUsagesDb.mockImplementation(async (_db, input) => {
    if (
      input.excludingRuleId === "brl_123" ||
      !input.badgeTemplateIds.includes(defaultBadgeRuleVersion.snapshot.badgeTemplateId)
    ) {
      return [];
    }

    return [
      {
        badgeTemplateId: defaultBadgeRuleVersion.snapshot.badgeTemplateId,
        ruleId: "brl_123",
        ruleName: defaultBadgeRuleVersion.snapshot.name,
        versionNumber: defaultBadgeRuleVersion.versionNumber,
        isActiveVersion: true,
      },
    ];
  });
  mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValue(null);
  mockedFindBadgeIssuanceRuleBuilderDraftDb.mockResolvedValue(null);
  mockedListBadgeIssuanceRuleBuilderDraftsForUserDb.mockResolvedValue([]);
  mockedDeleteBadgeIssuanceRuleBuilderDraftByIdDb.mockResolvedValue(null);
  mockedFindLtiResourceLinkPlacementForRule.mockResolvedValue(null);
  mockedListActiveLtiLaunchSessionsForPlatform.mockResolvedValue([]);
  mockedListPendingBadgeIssuanceRuleApprovalsForActor.mockResolvedValue([]);
  mockedSubmitBadgeIssuanceRuleVersionForApprovalDb.mockResolvedValue({ status: "not_found" });
  mockedListBadgeIssuanceRuleVersionApprovalStepsDb.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleVersionApprovalEvents.mockResolvedValue([]);
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
  mockedCreateBadgeRuleApproverGroupDb.mockResolvedValue({
    id: "brag_created",
    tenantId: "tenant_123",
    orgUnitId: "tenant_123:org:institution",
    name: "Registrar office",
    createdByUserId: "usr_admin",
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  });
  mockedAddBadgeRuleApproverGroupMemberDb.mockResolvedValue({ status: "added" });
  mockedRemoveBadgeRuleApproverGroupMemberDb.mockResolvedValue({ status: "removed" });
  mockedRemoveBadgeRuleApproverGroupDb.mockResolvedValue({ status: "removed" });
  mockedDecideBadgeIssuanceRuleVersionDb.mockResolvedValue({ status: "not_found" });
  mockedReopenApprovedBadgeIssuanceRuleVersionDb.mockResolvedValue({ status: "not_found" });
  mockedWithdrawBadgeIssuanceRuleVersionSubmissionDb.mockResolvedValue({
    status: "not_found",
  });
  mockedRecertifyBadgeIssuanceRuleVersionDb.mockResolvedValue(null);
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
  mockedListBadgeIssuanceRuleEvaluations.mockResolvedValue([]);
  mockedListBadgeIssuanceRuleValueLists.mockResolvedValue([]);
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
  mockedDeleteNeverActiveBadgeIssuanceRuleDb.mockResolvedValue({ status: "not_found" });
  mockedFindBadgeIssuanceRuleEvaluationById.mockResolvedValue(null);
  mockedResolveBadgeIssuanceRuleEvaluationReview.mockResolvedValue(null);
  mockedFindBadgeIssuanceRuleById.mockResolvedValue(null);
  mockedFindAutomatedBadgeRuleEvaluationStatusDb.mockResolvedValue(null);
  mockedRequestManualAutomatedBadgeRuleEvaluationDb.mockResolvedValue("queued");
  mockedListTenantOrgUnits.mockResolvedValue(sampleReportingOrgUnits());
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
  mockedUpsertTenantMembershipOrgUnitScopeDb.mockResolvedValue({
    scope: {
      tenantId: "tenant_123",
      userId: "usr_issuer",
      orgUnitId: "tenant_123:org:institution",
      role: "issuer",
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:30:00.000Z",
    },
    previousRole: null,
    changed: true,
  });
  mockedRemoveTenantMembershipOrgUnitScopeDb.mockResolvedValue(true);
  mockedListTenantAssertions.mockResolvedValue([]);
  mockedFindAssertionById.mockResolvedValue(null);
  mockedFindAssertionIssuanceProvenanceByAssertionId.mockResolvedValue(null);
  mockedFindAssertionReportingAttributionByAssertionId.mockResolvedValue(null);
  mockedFindBadgeIssuanceRuleEvaluationByAssertionId.mockResolvedValue(null);
  mockedFindTenantOrgUnitById.mockResolvedValue(null);
  mockedFindUsersByIds.mockResolvedValue(new Map());
  mockedListAssertionLifecycleEvents.mockResolvedValue([]);
  mockedListAuditLogsForAssertion.mockResolvedValue([]);
  mockedResolveAssertionLifecycleState.mockResolvedValue(null);
  mockedRecordAssertionLifecycleTransition.mockResolvedValue({
    status: "transitioned",
    fromState: "active",
    toState: "revoked",
    currentState: "revoked",
    event: null,
    message: null,
  });
  mockedUpsertTenantLmsConnection.mockResolvedValue(
    sampleTenantLmsConnection({
      id: "lms_new",
      displayName: "New LMS",
    }),
  );
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
  mockedRevokeTenantApiKey.mockResolvedValue(true);
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
  mockedFindTenantLmsConnectionByIdDb.mockImplementation(async (_db, input) => {
    return lmsConnections.find((connection) => connection.id === input.connectionId) ?? null;
  });
  const activeDelegatedIssuingAuthorityGrant: DelegatedIssuingAuthorityGrantRecord = {
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
  };
  mockedListDelegatedIssuingAuthorityGrants.mockResolvedValue([
    activeDelegatedIssuingAuthorityGrant,
  ]);
  mockedCreateDelegatedIssuingAuthorityGrantDb.mockResolvedValue(
    activeDelegatedIssuingAuthorityGrant,
  );
  mockedFindDelegatedIssuingAuthorityGrantByIdDb.mockResolvedValue(
    activeDelegatedIssuingAuthorityGrant,
  );
  mockedRevokeDelegatedIssuingAuthorityGrantDb.mockResolvedValue({
    status: "revoked",
    grant: {
      ...activeDelegatedIssuingAuthorityGrant,
      revokedAt: "2026-02-18T12:30:00.000Z",
      revokedByUserId: "usr_admin",
      status: "revoked",
    },
  });
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
  mockedListAccessibleTenantContextsForUser.mockResolvedValue([
    {
      tenantId: "tenant_123",
      tenantSlug: "tenant-123",
      tenantDisplayName: "Tenant 123",
      tenantPlanTier: "team",
      membershipRole: "admin",
    },
  ]);
  mockedListImportLearnerRecordBatchQueueMessagesDb.mockResolvedValue([]);
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
  mockedEnqueueJobQueueMessageOnce.mockResolvedValue(true);
  mockedEnqueueJobQueueMessagesOnce.mockResolvedValue(1);
  mockedFindActiveLearnerRecordImportPreviewDb.mockResolvedValue(null);
  mockedMarkLearnerRecordImportPreviewQueuedDb.mockResolvedValue(true);
  mockedFindLearnerProfileByIdDb.mockResolvedValue(sampleLearnerProfile());
  mockedFindLearnerProfileByIdentityDb.mockResolvedValue(sampleLearnerProfile());
  mockedListLearnerProfilesForRecordLookupDb.mockResolvedValue([sampleLearnerProfile()]);
  mockedListLearnerRecordAssertionExportsDb.mockResolvedValue([
    sampleLearnerRecordAssertionExport(),
  ]);
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
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue(null);
};
