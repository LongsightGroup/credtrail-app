import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedFindLearnerProfileById,
  mockedFindLearnerProfileByIdentity,
  mockedFindTenantAuthPolicy,
  mockedGetTenantReportingComparisons,
  mockedGetTenantReportingEngagementCounts,
  mockedListTenantAuthProviders,
  mockedListTenantBreakGlassAccounts,
  mockedListTenantMembers,
  mockedListImportLearnerRecordBatchQueueMessages,
  mockedListAccessibleTenantContextsForUser,
  mockedListLearnerRecordAssertionExports,
  mockedListLearnerRecordEntries,
  mockedGetTenantReportingOverview,
  mockedGetTenantReportingTrends,
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
} = vi.hoisted(() => {
  return {
    mockedFindLearnerProfileById: vi.fn(),
    mockedFindLearnerProfileByIdentity: vi.fn(),
    mockedFindTenantAuthPolicy: vi.fn(),
    mockedGetTenantReportingComparisons: vi.fn(),
    mockedGetTenantReportingEngagementCounts: vi.fn(),
    mockedListTenantAuthProviders: vi.fn(),
    mockedListTenantBreakGlassAccounts: vi.fn(),
    mockedListTenantMembers: vi.fn(),
    mockedListImportLearnerRecordBatchQueueMessages: vi.fn(),
    mockedListAccessibleTenantContextsForUser: vi.fn(),
    mockedListLearnerRecordAssertionExports: vi.fn(),
    mockedListLearnerRecordEntries: vi.fn(),
    mockedGetTenantReportingOverview: vi.fn(),
    mockedGetTenantReportingTrends: vi.fn(),
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findLearnerProfileById: mockedFindLearnerProfileById,
    findLearnerProfileByIdentity: mockedFindLearnerProfileByIdentity,
    findTenantAuthPolicy: mockedFindTenantAuthPolicy,
    findTenantById: vi.fn(),
    findTenantMembership: vi.fn(),
    findUserById: vi.fn(),
    getTenantReportingEngagementCounts: mockedGetTenantReportingEngagementCounts,
    getTenantReportingOverview: mockedGetTenantReportingOverview,
    getTenantReportingTrends: mockedGetTenantReportingTrends,
    listImportLearnerRecordBatchQueueMessages: mockedListImportLearnerRecordBatchQueueMessages,
    listDelegatedIssuingAuthorityGrants: vi.fn(),
    listAccessibleTenantContextsForUser: mockedListAccessibleTenantContextsForUser,
    listLearnerRecordAssertionExports: mockedListLearnerRecordAssertionExports,
    listLearnerRecordEntries: mockedListLearnerRecordEntries,
    listBadgeIssuanceRules: vi.fn(),
    listBadgeIssuanceRuleVersions: vi.fn(),
    listTenantReportingComparisons: mockedGetTenantReportingComparisons,
    listTenantBreakGlassAccounts: mockedListTenantBreakGlassAccounts,
    listTenantMembers: mockedListTenantMembers,
    listTenantMembershipOrgUnitScopes: vi.fn(),
    listTenantAuthProviders: mockedListTenantAuthProviders,
    listBadgeTemplates: vi.fn(),
    listTenantApiKeys: vi.fn(),
    listTenantOrgUnits: vi.fn(),
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
      revokeCurrentSession: vi.fn(() => Promise.resolve()),
    })),
  };
});

import {
  findLearnerProfileById,
  findLearnerProfileByIdentity,
  findTenantById,
  findTenantMembership,
  findUserById,
  getTenantReportingEngagementCounts,
  listDelegatedIssuingAuthorityGrants,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  listBadgeTemplates,
  listImportLearnerRecordBatchQueueMessages,
  listTenantApiKeys,
  listTenantMembers,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  getTenantReportingOverview,
  getTenantReportingTrends,
  listLearnerRecordAssertionExports,
  listLearnerRecordEntries,
  listTenantReportingComparisons,
  type LearnerProfileRecord,
  type LearnerRecordAssertionExportRecord,
  type LearnerRecordEntryRecord,
  type SqlDatabase,
  type TenantMembershipRecord,
  type TenantMemberRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";

import { app } from "./index";
import { getSeededDemoLearnerRecordFixture } from "./learner-record/seeded-demo-learner-record-fixture";
import { getSeededDemoReportingRouteFixture } from "./reporting/seeded-demo-reporting-fixture";
import { INSTITUTION_ADMIN_CSS } from "./ui/page-assets/content/institution-admin-css";
import { INSTITUTION_ADMIN_JS } from "./ui/page-assets/content/institution-admin-js";

const mockedFindLearnerProfileByIdDb = vi.mocked(findLearnerProfileById);
const mockedFindLearnerProfileByIdentityDb = vi.mocked(findLearnerProfileByIdentity);
const mockedFindTenantMembership = vi.mocked(findTenantMembership);
const mockedFindTenantById = vi.mocked(findTenantById);
const mockedFindUserById = vi.mocked(findUserById);
const mockedListDelegatedIssuingAuthorityGrants = vi.mocked(listDelegatedIssuingAuthorityGrants);
const mockedListBadgeIssuanceRules = vi.mocked(listBadgeIssuanceRules);
const mockedListBadgeIssuanceRuleVersions = vi.mocked(listBadgeIssuanceRuleVersions);
const mockedListBadgeTemplates = vi.mocked(listBadgeTemplates);
const mockedListImportLearnerRecordBatchQueueMessagesDb = vi.mocked(
  listImportLearnerRecordBatchQueueMessages,
);
const mockedListTenantOrgUnits = vi.mocked(listTenantOrgUnits);
const mockedListTenantApiKeys = vi.mocked(listTenantApiKeys);
const mockedListTenantMembersDb = vi.mocked(listTenantMembers);
const mockedListTenantMembershipOrgUnitScopes = vi.mocked(listTenantMembershipOrgUnitScopes);
const mockedGetTenantReportingComparisonsDb = vi.mocked(listTenantReportingComparisons);
const mockedGetTenantReportingEngagementCountsDb = vi.mocked(getTenantReportingEngagementCounts);
const mockedGetTenantReportingOverviewDb = vi.mocked(getTenantReportingOverview);
const mockedGetTenantReportingTrendsDb = vi.mocked(getTenantReportingTrends);
const mockedListLearnerRecordAssertionExportsDb = vi.mocked(listLearnerRecordAssertionExports);
const mockedListLearnerRecordEntriesDb = vi.mocked(listLearnerRecordEntries);
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

const sampleMembership = (role: TenantMembershipRecord["role"]): TenantMembershipRecord => {
  return {
    tenantId: "tenant_123",
    userId: "usr_admin",
    role,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  };
};

const sampleTenantMember = (overrides?: Partial<TenantMemberRecord>): TenantMemberRecord => {
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

const sampleLearnerProfile = (overrides?: Partial<LearnerProfileRecord>): LearnerProfileRecord => {
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

const sampleLearnerRecordAssertionExport = (
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

const sampleLearnerRecordEntry = (
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

const sampleReportingOrgUnits = () => {
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

const getReportingPanelMarkup = (html: string, heading: string): string => {
  const headingMarkup = `<h2>${heading}</h2>`;
  const start = html.indexOf(headingMarkup);

  expect(start).toBeGreaterThan(-1);

  const end = html.indexOf("</article>", start);

  expect(end).toBeGreaterThan(start);

  return html.slice(start, end);
};

const getReportingPanelArticleMarkup = (html: string, heading: string): string => {
  const headingMarkup = `<h2>${heading}</h2>`;
  const headingIndex = html.indexOf(headingMarkup);

  expect(headingIndex).toBeGreaterThan(-1);

  const start = html.lastIndexOf("<article", headingIndex);

  expect(start).toBeGreaterThan(-1);

  const end = html.indexOf("</article>", headingIndex);

  expect(end).toBeGreaterThan(start);

  return html.slice(start, end);
};

const getReportingPanelVisualMarkup = (panelMarkup: string): string => {
  const tableWrapStart = panelMarkup.indexOf('<div class="ct-admin__table-wrap">');

  expect(tableWrapStart).toBeGreaterThan(-1);

  return panelMarkup.slice(0, tableWrapStart);
};

beforeEach(() => {
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
      lmsProviderKind: "canvas",
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
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    },
  ]);
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
    {
      id: "tap_saml",
      tenantId: "tenant_123",
      protocol: "saml",
      label: "Legacy SAML",
      enabled: true,
      isDefault: false,
      configJson:
        '{"ssoLoginUrl":"https://idp.example.edu/sso","idpEntityId":"https://idp.example.edu/entity"}',
      createdAt: "2026-02-18T12:05:00.000Z",
      updatedAt: "2026-02-18T12:05:00.000Z",
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

describe("GET /tenants/:tenantId/admin", () => {
  it("redirects to login when no session cookie is present", async () => {
    const env = createEnv();
    const response = await app.request("/tenants/tenant_123/admin", undefined, env);

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/login?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin&reason=auth_required",
    );
  });

  it("returns 403 page when membership role is below admin", async () => {
    const env = createEnv();
    mockedFindTenantMembership.mockResolvedValue(sampleMembership("viewer"));

    const response = await app.request(
      "/tenants/tenant_123/admin",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(403);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(body).toContain("Admin role required");
    expect(body).toContain("institution admin access");
  });

  it("shows empty-state CTA when no rules exist", async () => {
    const env = createEnv();
    mockedListBadgeIssuanceRules.mockResolvedValue([]);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([]);

    const response = await app.request(
      "/tenants/tenant_123/admin",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("No badge rules found.");
    expect(body).toContain("/tenants/tenant_123/admin/rules/new");
    expect(body).toContain("Create first rule");
  });

  it("renders institution admin dashboard for admin membership", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("Institution Admin");
    expect(body).toContain("Choose a workspace instead of forcing every task onto one page.");
    expect(body).toContain("Institution admin workspaces");
    expect(body).toContain("Operations");
    expect(body).toContain("Reporting");
    expect(body).toContain("Rules");
    expect(body).toContain("Access");
    expect(body).toContain("Open operations");
    expect(body).toContain("Open reporting");
    expect(body).toContain("Open rules");
    expect(body).toContain("Open access");
    expect(body).toContain("Manage members");
    expect(body).not.toContain("Enterprise Auth");
    expect(body).not.toContain("Manual Issue Badge");
    expect(body).not.toContain("Create Tenant API Key");
    expect(body).not.toContain("Issued Badges Ledger");
    expect(body).toContain('href="/tenants/tenant_123/admin/operations"');
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/new"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access"');
    expect(body).toContain('href="/admin/audit-logs?tenantId=tenant_123"');
    expect(body).toContain('href="/showcase/tenant_123"');
    expect(body).toContain("/v1/tenants/tenant_123/assertions/manual-issue");
    expect(body).toContain("/v1/tenants/tenant_123/api-keys");
    expect(body).toContain("/v1/tenants/tenant_123/org-units");
    expect(body).toContain("/v1/tenants/tenant_123/badge-templates");
    expect(body).toContain("/v1/tenants/tenant_123/users");
    expect(body).toContain("/v1/tenants/tenant_123/badge-rules");
    expect(body).toContain("/v1/tenants/tenant_123/badge-rule-value-lists");
    expect(body).toContain("/v1/tenants/tenant_123/badge-rules/preview-simulate");
    expect(body).toContain("/v1/tenants/tenant_123/badge-rules/review-queue");
    expect(body).toContain("admin@tenant-123.edu");
    expect(body).toContain('title="User ID: usr_admin"');
    expect(body).toContain("/assets/ui/foundation.");
    expect(body).toContain("/assets/ui/institution-admin.");
    expect(body).not.toContain("Switch organization");
    expect(mockedListBadgeTemplates).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      includeArchived: false,
    });
    expect(mockedFindUserById).toHaveBeenCalledWith(fakeDb, "usr_admin");
    expect(mockedListBadgeIssuanceRules).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
    });
    expect(mockedListBadgeIssuanceRuleVersions).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
    });
  });

  it("shows an explicit switch-organization entry point only for multi-tenant admins", async () => {
    const env = createEnv();
    mockedListAccessibleTenantContextsForUser.mockResolvedValue([
      {
        tenantId: "tenant_123",
        tenantSlug: "tenant-123",
        tenantDisplayName: "Tenant 123",
        tenantPlanTier: "team",
        membershipRole: "admin",
      },
      {
        tenantId: "tenant_456",
        tenantSlug: "tenant-456",
        tenantDisplayName: "Tenant 456",
        tenantPlanTier: "enterprise",
        membershipRole: "admin",
      },
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Switch organization");
    expect(body).toContain("/account/organizations?next=%2Ftenants%2Ftenant_123%2Fadmin");
    expect(body).not.toContain("Choose a CredTrail organization");
  });

  it("keeps enterprise auth off the admin hub even for enterprise tenants", async () => {
    const env = createEnv();
    mockedFindTenantById.mockResolvedValue({
      id: "tenant_123",
      slug: "tenant-123",
      displayName: "Tenant 123",
      planTier: "enterprise",
      issuerDomain: "tenant-123.credtrail.test",
      didWeb: "did:web:credtrail.test:tenant_123",
      isActive: true,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).not.toContain("Enterprise Auth");
    expect(body).not.toContain("Login mode");
    expect(body).not.toContain('id="enterprise-auth-policy-form"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access"');
  });
});

describe("GET /tenants/:tenantId/admin/operations", () => {
  it("renders the operations workspace", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain(">Operations<");
    expect(body).toContain("Manual Issue Badge");
    expect(body).toContain("Learner Records");
    expect(body).toContain("Learner Record Imports");
    expect(body).toContain('id="manual-issue-form"');
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/learner-records"');
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/learner-record-imports"');
    expect(body).toContain("Review Queue");
    expect(body).toContain("Issued Badges");
    expect(body).toContain("Badge Status");
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/review-queue"');
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/issued-badges"');
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/badge-status"');
    expect(body).not.toContain('id="assertion-lifecycle-view-form"');
    expect(body).not.toContain('id="rule-review-queue-refresh"');
    expect(body).not.toContain('id="issued-badges-filter-form"');
    expect(body).not.toContain("Create Tenant API Key");
    expect(body).not.toContain("Rule Value Lists");
  });
});

describe("GET /tenants/:tenantId/admin/operations/learner-records", () => {
  it("renders a bounded learner-record review page with truthful idle state", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-records",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner Records");
    expect(body).toContain("Load learner record");
    expect(body).toContain('name="learnerProfileId"');
    expect(body).toContain('name="email"');
    expect(body).toContain("Choose one learner");
    expect(body).not.toContain("No learner record found");
  });

  it("renders one learner review with real export and standards-mapping links", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-records?learnerProfileId=lpr_123",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner overview");
    expect(body).toContain("Learner One");
    expect(body).toContain("Institution-verified record");
    expect(body).toContain("Learner-supplemental record");
    expect(body).toContain("Historical record");
    expect(body).toContain("Applied Analytics Badge");
    expect(body).toContain("Clinical Placement Seminar");
    expect(body).toContain("Portfolio Reflection");
    expect(body).toContain("Membership Standing");
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/learner-records/lpr_123/export?profile=native_portable_json"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/learner-records/lpr_123/standards-mapping?profile=clr_alignment_json"',
    );
    expect(mockedFindLearnerProfileByIdDb).toHaveBeenCalledWith(fakeDb, "tenant_123", "lpr_123");
  });

  it("can verify a seeded-demo learner review on the normal admin operations route", async () => {
    const seededDemo = getSeededDemoLearnerRecordFixture();

    mockedFindLearnerProfileByIdDb.mockResolvedValueOnce(seededDemo.learnerProfile);
    mockedListLearnerRecordAssertionExportsDb.mockResolvedValueOnce([
      ...seededDemo.assertionExports,
    ]);
    mockedListLearnerRecordEntriesDb.mockResolvedValueOnce([...seededDemo.recordEntries]);

    const response = await app.request(
      seededDemo.routeFamily.adminReview,
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner overview");
    expect(body).toContain("Applied Analytics Badge");
    expect(body).toContain("Clinical Placement Seminar");
    expect(body).toContain("Portfolio Reflection");
    expect(body).toContain("Leadership Society Membership");
    expect(body).toContain(`href="${seededDemo.routeFamily.nativeExport}"`);
    expect(body).toContain(`href="${seededDemo.routeFamily.standardsMapping}"`);
  });

  it("renders a truthful unresolved state for missing learner lookups", async () => {
    const env = createEnv();
    mockedFindLearnerProfileByIdentityDb.mockResolvedValueOnce(null);

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-records?email=missing%40example.edu",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("No learner record found");
    expect(body).toContain("No learner profile matched this lookup");
  });
});

describe("GET and POST /tenants/:tenantId/admin/operations/learner-record-imports", () => {
  it("renders a dedicated learner-record import page with template, upload, and progress affordances", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-record-imports",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner Record Imports");
    expect(body).toContain("Download CSV template");
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/operations/learner-record-imports/preview"',
    );
    expect(body).toContain(
      'formaction="/tenants/tenant_123/admin/operations/learner-record-imports/apply"',
    );
    expect(body).toContain("Current import progress");
    expect(body).toContain("No learner-record import batches have been queued");
  });

  it("renders preview results with trust and smart-default explanation on the admin page", async () => {
    const env = createEnv();
    const formData = new FormData();
    formData.set(
      "file",
      new File(
        [
          [
            "learnerEmail,title,recordType,issuedAt,badgeTemplateSlug,pathwayLabel",
            "learner@example.edu,Clinical Placement Seminar,course,2026-03-26T12:00:00.000Z,applied-analytics,Clinical readiness",
          ].join("\n"),
        ],
        "learner-records.csv",
        {
          type: "text/csv",
        },
      ),
    );
    formData.set("defaultTrustLevel", "issuer_verified");

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/learner-record-imports/preview",
      {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
        body: formData,
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Learner-record import preview ready");
    expect(body).toContain("Clinical Placement Seminar");
    expect(body).toContain("Pathway hint: Clinical readiness");
    expect(body).toContain(
      "Review trust classification, smart defaults, and warnings below before queueing the import.",
    );
    expect(body).toContain('data-learner-record-import-state="preview"');
  });
});

describe("GET /tenants/:tenantId/admin/operations/review-queue", () => {
  it("renders the rule review queue on its own page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/review-queue",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(">Operations<");
    expect(body).toContain("Rule Review Queue");
    expect(body).toContain('id="rule-review-queue-refresh"');
    expect(body).not.toContain('id="manual-issue-form"');
    expect(body).not.toContain('id="issued-badges-filter-form"');
    expect(body).not.toContain('id="assertion-lifecycle-view-form"');
  });
});

describe("GET /tenants/:tenantId/admin/operations/issued-badges", () => {
  it("renders the issued badges ledger on its own page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Issued Badges");
    expect(body).toContain('id="issued-badges-filter-form"');
    expect(body).not.toContain('id="manual-issue-form"');
    expect(body).not.toContain('id="rule-review-queue-refresh"');
    expect(body).not.toContain('id="assertion-lifecycle-view-form"');
  });

  it("renders a separate admin ledger export form with audit filters", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/issued-badges",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('id="issued-badges-export-form"');
    expect(body).toContain('action="/v1/tenants/tenant_123/assertions/ledger-export.csv"');
    expect(body).toContain('method="get"');
    expect(body).toContain('name="issuedFrom" type="date"');
    expect(body).toContain('name="issuedTo" type="date"');
    expect(body).toContain('name="badgeTemplateId"');
    expect(body).toContain('name="orgUnitId"');
    expect(body).toContain('name="state"');
    expect(body).toContain('name="recipientQuery"');
    expect(body).toContain('type="text"');
    expect(body).toContain("Synchronous CSV export is capped at 5000 rows");
    expect(body).toContain("Ancestor lineage columns reflect the current org tree only");
    expect(body).toContain("stable leaf attribution remains the historical contract");
  });
});

describe("GET /tenants/:tenantId/admin/operations/badge-status", () => {
  it("renders badge status on its own page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/badge-status",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Badge Status");
    expect(body).toContain('id="assertion-lifecycle-view-form"');
    expect(body).not.toContain("Credential Lifecycle");
    expect(body).not.toContain('id="manual-issue-form"');
    expect(body).not.toContain('id="rule-review-queue-refresh"');
    expect(body).not.toContain('id="issued-badges-filter-form"');
  });
});

describe("GET /tenants/:tenantId/admin/reporting", () => {
  it("renders an executive summary band before the deeper reporting sections", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Reporting");
    expect(body).toContain("Executive Summary");
    expect(body).toContain('class="ct-admin__reporting-summary-band"');
    expect(body).toContain('data-reporting-summary-metric="issued"');
    expect(body).toContain('data-reporting-summary-metric="claim-rate"');
    expect(body).toContain('data-reporting-summary-metric="share-rate"');
    expect(body).toContain('data-reporting-summary-metric="public-badge-views"');
    expect(body).toContain("First read");
    expect(body).toContain("Reporting Overview");
    expect(body).toContain("Engagement Counts");
    expect(body).toContain("Trend lines");
    expect(body).toContain("Compare by badge template");
    expect(body).toContain("Compare by org unit");
    expect(body).toContain("Metric Definitions");
    expect(body).toContain("Raw counts show event totals");
    expect(body).toContain("Rates use distinct engaged assertions");
    expect(body).toContain("Public badge views");
    expect(body).toContain("35.7");
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting"');
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting/trends');
    expect(body).toContain("14");
    expect(body.indexOf('data-reporting-summary-metric="issued"')).toBeLessThan(
      body.indexOf("<h2>Reporting Overview</h2>"),
    );
    expect(body.indexOf('data-reporting-summary-metric="issued"')).toBeLessThan(
      body.indexOf("Engagement Counts"),
    );
    expect(body.indexOf("Trend lines")).toBeLessThan(body.indexOf("Export CSV"));
    expect(body).not.toContain("Phase 11 Scope");
    expect(body).not.toContain("Manual Issue Badge");
    expect(body).not.toContain('id="issued-badges-filter-form"');
    expect(mockedGetTenantReportingOverviewDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      issuedFrom: "2026-03-01",
      issuedTo: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      state: undefined,
    });
    expect(mockedGetTenantReportingEngagementCountsDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
    });
    expect(mockedGetTenantReportingTrendsDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      bucket: "day",
    });
    expect(mockedGetTenantReportingComparisonsDb).toHaveBeenNthCalledWith(1, fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      groupBy: "badgeTemplate",
    });
    expect(mockedGetTenantReportingComparisonsDb).toHaveBeenNthCalledWith(2, fakeDb, {
      tenantId: "tenant_123",
      from: "2026-03-01",
      to: "2026-03-31",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      groupBy: "orgUnit",
    });
  });

  it("keeps the current slice and generated-at context visible at the top of reporting", async () => {
    const env = createEnv();
    mockedGetTenantReportingOverviewDb.mockImplementationOnce(async (_db, input) => {
      return {
        tenantId: "tenant_123",
        filters: {
          issuedFrom: input.issuedFrom ?? null,
          issuedTo: input.issuedTo ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        counts: {
          issued: 14,
          active: 12,
          suspended: 1,
          revoked: 1,
          pendingReview: 1,
        },
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31&badgeTemplateId=badge_template_001&orgUnitId=tenant_123%3Aorg%3Adepartment-cs&state=active",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('class="ct-admin__reporting-summary-context"');
    expect(body).toContain("Current slice");
    expect(body).toContain("Mar 1");
    expect(body).toContain("Mar 31");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Computer Science");
    expect(body).toContain("active");
    expect(body).toContain("Generated Mar 21, 2026, 12:00 PM");
  });

  it("renders aggregate export links that preserve the current reporting filters", async () => {
    const env = createEnv();
    mockedGetTenantReportingOverviewDb.mockImplementationOnce(async (_db, input) => {
      return {
        tenantId: "tenant_123",
        filters: {
          issuedFrom: input.issuedFrom ?? null,
          issuedTo: input.issuedTo ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        counts: {
          issued: 14,
          active: 12,
          suspended: 1,
          revoked: 1,
          pendingReview: 1,
        },
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31&badgeTemplateId=badge_template_001&orgUnitId=tenant_123%3Aorg%3Adepartment-cs&state=active",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Export CSV");
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/overview/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/engagement/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/trends/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active&amp;bucket=day"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/comparisons/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active&amp;groupBy=badgeTemplate"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/comparisons/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active&amp;groupBy=orgUnit"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/hierarchy/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;badgeTemplateId=badge_template_001&amp;orgUnitId=tenant_123%3Aorg%3Adepartment-cs&amp;state=active&amp;focusOrgUnitId=tenant_123%3Aorg%3Acollege-eng&amp;level=department"',
    );
    expect(body).not.toContain('href="/v1/tenants/tenant_123/assertions/ledger-export.csv"');
  });

  it("adds presentation-fit reporting wrappers without changing the real reporting story", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('class="ct-admin__reporting-presentation-shell');
    expect(body).toContain('class="ct-admin__reporting-presentation-note');
    expect(body).toContain("Selected reporting slice");
    expect(body).toContain(
      "Filters, exports, and drilldown links stay aligned with the visible issue-date, badge, organization, and lifecycle selections.",
    );
    expect(body).toContain('class="ct-admin__reporting-primary-story');
    expect(body).toContain('class="ct-admin__reporting-secondary-story');
    expect(body).toContain('class="ct-admin__reporting-first-screen');
    expect(body).toContain('class="ct-admin__reporting-supporting-grid');
    expect(body).toContain('class="ct-admin__reporting-lower-story"');
    expect(body).toContain("Metric Definitions");
    expect(body.indexOf("Selected reporting slice")).toBeLessThan(
      body.indexOf("Executive Summary"),
    );
    expect(body.indexOf('class="ct-admin__reporting-first-screen')).toBeLessThan(
      body.indexOf("Trend lines"),
    );
    expect(body.indexOf("Trend lines")).toBeLessThan(
      body.indexOf('class="ct-admin__reporting-supporting-grid'),
    );
    expect(body.indexOf('class="ct-admin__reporting-supporting-grid')).toBeLessThan(
      body.indexOf('class="ct-admin__reporting-secondary-story'),
    );
    expect(body.indexOf('class="ct-admin__reporting-secondary-story')).toBeLessThan(
      body.indexOf("Metric Definitions"),
    );
    expect(body).not.toContain("demo mode");
    expect(body).not.toContain("presentation-only");
  });

  it("renders shared reporting visuals without losing filter and export affordances", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('class="ct-reporting-visual"');
    expect(body).toContain('data-reporting-visual-kind="comparison-bars"');
    expect(body).toContain('data-reporting-visual-kind="stacked-summary"');
    expect(body).toContain('data-reporting-visual-kind="trend-series"');
    expect(body).toContain('class="ct-reporting-visual__legend"');
    expect(body).toContain('class="ct-admin__reporting-panel-media"');
    expect(body).toContain("Legend");
    expect(body).toContain("Current badge-state mix");
    expect(body).toContain("Public badge views");
    expect(body).toContain("Claim rate");
    expect(body).toContain('id="reporting-filters-form"');
    expect(body).toContain('method="get" action="/tenants/tenant_123/admin/reporting"');
    expect(body).toContain("Overview CSV");
  });

  it("ships a mid-width reporting breakpoint for walkthrough layouts", () => {
    expect(INSTITUTION_ADMIN_CSS).toContain("@media (max-width: 900px)");
    expect(INSTITUTION_ADMIN_CSS).toContain(
      ".ct-admin__reporting-presentation-shell,\n  .ct-admin__reporting-secondary-story {\n    gap: 0.9rem;",
    );
    expect(INSTITUTION_ADMIN_CSS).toContain(
      ".ct-admin__reporting-supporting-grid,\n  .ct-admin__reporting-panel-media,\n  .ct-admin__reporting-focus-summary-grid {\n    grid-template-columns: minmax(0, 1fr);",
    );
    expect(INSTITUTION_ADMIN_CSS).toContain(
      ".ct-admin__reporting-presentation-note {\n    gap: 0.6rem;",
    );
  });

  it("renders a chart-first trend preview and links the detailed trend table to a sub-page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Trend lines");
    expect(body).toContain('class="ct-admin__reporting-trend-hero"');
    expect(body).toContain('class="ct-admin__reporting-trend-callouts"');
    expect(body).toContain("Peak day");
    expect(body).toContain("Latest day");
    expect(body).toContain("Open trend detail");
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting/trends');
    expect(body).not.toContain("Detailed trend table");
    expect(body).toContain("Public badge views");
    expect(body).toContain("Wallet accepts");
    expect(body.indexOf("Trend lines")).toBeLessThan(body.indexOf("Export CSV"));
  });

  it("renders the detailed trend table on the trend detail sub-page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting/trends?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Trend Detail");
    expect(body).toContain("Trend filters");
    expect(body).toContain('method="get" action="/tenants/tenant_123/admin/reporting/trends"');
    expect(body).toContain("Trend lines");
    expect(body).toContain("Detailed trend table");
    expect(body).not.toContain("Executive Summary");
    expect(body).not.toContain("Selected reporting slice");
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting"');
  });

  it("renders deliberate empty shells for trend, comparison, hierarchy, and performer panels", async () => {
    const env = createEnv();
    mockedGetTenantReportingOverviewDb.mockResolvedValueOnce({
      tenantId: "tenant_123",
      filters: {
        issuedFrom: null,
        issuedTo: null,
        badgeTemplateId: null,
        orgUnitId: null,
        state: null,
      },
      counts: {
        issued: 0,
        active: 0,
        suspended: 0,
        revoked: 0,
        pendingReview: 0,
      },
      generatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedGetTenantReportingEngagementCountsDb.mockResolvedValueOnce({
      issuedCount: 0,
      publicBadgeViewCount: 0,
      verificationViewCount: 0,
      shareClickCount: 0,
      learnerClaimCount: 0,
      walletAcceptCount: 0,
      claimRate: 0,
      shareRate: 0,
    });
    mockedGetTenantReportingTrendsDb.mockResolvedValueOnce({
      tenantId: "tenant_123",
      filters: {
        from: "2026-03-01",
        to: "2026-03-31",
        badgeTemplateId: null,
        orgUnitId: null,
        state: null,
      },
      bucket: "day",
      series: [],
      generatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedGetTenantReportingComparisonsDb.mockResolvedValueOnce([]);
    mockedGetTenantReportingComparisonsDb.mockResolvedValueOnce([]);

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();
    const trendPanel = getReportingPanelArticleMarkup(body, "Trend lines");
    const templatePanel = getReportingPanelArticleMarkup(body, "Compare by badge template");
    const orgUnitPanel = getReportingPanelArticleMarkup(body, "Compare by org unit");
    const hierarchyPanel = getReportingPanelArticleMarkup(body, "Hierarchy drilldown");
    const performerPanel = getReportingPanelArticleMarkup(body, "Performer panels");

    expect(response.status).toBe(200);
    expect(trendPanel).toContain('data-reporting-state="empty"');
    expect(trendPanel).toContain(
      "This reporting slice does not have enough activity to chart yet.",
    );
    expect(templatePanel).toContain('data-reporting-state="empty"');
    expect(templatePanel).toContain("No badge-template rows are visible for this slice yet.");
    expect(orgUnitPanel).toContain('data-reporting-state="empty"');
    expect(orgUnitPanel).toContain("No org-unit rows are visible for this slice yet.");
    expect(hierarchyPanel).toContain('data-reporting-state="empty"');
    expect(hierarchyPanel).toContain(
      "Hierarchy drilldowns appear here once visible org-unit rows exist for this slice.",
    );
    expect(performerPanel).toContain('data-reporting-state="empty"');
    expect(performerPanel).toContain(
      "Performer rankings appear once this slice includes comparable hierarchy rows.",
    );
  });

  it("marks thin-data reporting slices as sparse and drops momentum or ranking language", async () => {
    const env = createEnv();
    mockedGetTenantReportingOverviewDb.mockResolvedValueOnce({
      tenantId: "tenant_123",
      filters: {
        issuedFrom: null,
        issuedTo: null,
        badgeTemplateId: null,
        orgUnitId: null,
        state: null,
      },
      counts: {
        issued: 5,
        active: 5,
        suspended: 0,
        revoked: 0,
        pendingReview: 0,
      },
      generatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedGetTenantReportingEngagementCountsDb.mockResolvedValueOnce({
      issuedCount: 5,
      publicBadgeViewCount: 14,
      verificationViewCount: 5,
      shareClickCount: 2,
      learnerClaimCount: 2,
      walletAcceptCount: 1,
      claimRate: 40,
      shareRate: 20,
    });
    mockedGetTenantReportingTrendsDb.mockResolvedValueOnce({
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
          issuedCount: 5,
          publicBadgeViewCount: 14,
          verificationViewCount: 5,
          shareClickCount: 2,
          learnerClaimCount: 2,
          walletAcceptCount: 1,
        },
      ],
      generatedAt: "2026-03-21T12:00:00.000Z",
    });
    mockedGetTenantReportingComparisonsDb.mockImplementationOnce(async () => {
      return [
        {
          groupBy: "badgeTemplate",
          groupId: "badge_template_001",
          issuedCount: 5,
          publicBadgeViewCount: 14,
          verificationViewCount: 5,
          shareClickCount: 2,
          learnerClaimCount: 2,
          walletAcceptCount: 1,
          claimRate: 40,
          shareRate: 20,
        },
      ];
    });
    mockedGetTenantReportingComparisonsDb.mockImplementationOnce(async () => {
      return [
        {
          groupBy: "orgUnit",
          groupId: "tenant_123:org:program-cs",
          issuedCount: 5,
          publicBadgeViewCount: 14,
          verificationViewCount: 5,
          shareClickCount: 2,
          learnerClaimCount: 2,
          walletAcceptCount: 1,
          claimRate: 40,
          shareRate: 20,
        },
      ];
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();
    const trendPanel = getReportingPanelArticleMarkup(body, "Trend lines");
    const templatePanel = getReportingPanelArticleMarkup(body, "Compare by badge template");
    const orgUnitPanel = getReportingPanelArticleMarkup(body, "Compare by org unit");
    const hierarchyPanel = getReportingPanelArticleMarkup(body, "Hierarchy drilldown");
    const performerPanel = getReportingPanelArticleMarkup(body, "Performer panels");

    expect(response.status).toBe(200);
    expect(trendPanel).toContain('data-reporting-state="sparse"');
    expect(trendPanel).toContain(
      "Only one visible time bucket matches this reporting slice, so treat it as a current snapshot rather than a momentum read.",
    );
    expect(trendPanel).not.toContain("Read issued badge momentum first");
    expect(templatePanel).toContain('data-reporting-state="sparse"');
    expect(templatePanel).toContain(
      "Only one badge template row is visible in this slice, so the exact row below carries the full comparison detail.",
    );
    expect(templatePanel).not.toContain("Start with the ranked visual");
    expect(orgUnitPanel).toContain('data-reporting-state="sparse"');
    expect(orgUnitPanel).toContain(
      "Only one org-unit row is visible in this slice, so use the exact row below to read the current context.",
    );
    expect(orgUnitPanel).not.toContain("Start with the ranked visual");
    expect(hierarchyPanel).toContain('data-reporting-state="sparse"');
    expect(hierarchyPanel).toContain(
      "This slice currently resolves to one visible reporting path.",
    );
    expect(performerPanel).toContain('data-reporting-state="sparse"');
    expect(performerPanel).toContain(
      "Rankings stay paused until this slice has more than one comparable hierarchy row.",
    );
  });

  it("renders an SSR-honest pending hook on the reporting filter form", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();
    const overviewPanel = getReportingPanelArticleMarkup(body, "Reporting Overview");

    expect(response.status).toBe(200);
    expect(overviewPanel).toContain('id="reporting-filters-form"');
    expect(overviewPanel).toContain('data-reporting-submit-state="idle"');
    expect(overviewPanel).toContain('id="reporting-filters-status"');
    expect(overviewPanel).toContain("data-reporting-submit-status");
    expect(overviewPanel).toContain(
      "Applying filters refreshes this page with the selected reporting slice.",
    );
    expect(INSTITUTION_ADMIN_JS).toContain("reporting-filters-form");
    expect(INSTITUTION_ADMIN_JS).toContain(
      "reportingFiltersForm.dataset.reportingSubmitState = 'pending'",
    );
    expect(INSTITUTION_ADMIN_JS).toContain(
      "Refreshing this page with the selected reporting slice...",
    );
    expect(overviewPanel).not.toContain("Loading dashboard");
  });

  it("renders reporting chart markup directly in the server response", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('<svg class="ct-reporting-visual__graphic"');
    expect(body).toContain('role="img"');
    expect(body).toContain("Visible labels and numeric values are listed in the legend below.");
    expect(body).toContain("Cards below retain the exact lifecycle counts");
  });

  it("can verify a seeded-demo reporting slice on the normal reporting route from the canonical fixture", async () => {
    const env = createEnv();
    const seededDemo = getSeededDemoReportingRouteFixture();

    mockedListTenantOrgUnits.mockResolvedValueOnce([...seededDemo.orgUnits]);
    mockedListBadgeTemplates.mockResolvedValueOnce([...seededDemo.badgeTemplates]);
    mockedGetTenantReportingOverviewDb.mockResolvedValueOnce(seededDemo.overview);
    mockedGetTenantReportingEngagementCountsDb.mockResolvedValueOnce(seededDemo.engagementCounts);
    mockedGetTenantReportingTrendsDb.mockResolvedValueOnce(seededDemo.trends);
    mockedGetTenantReportingComparisonsDb.mockImplementationOnce(async (_db, input) => {
      expect(input.groupBy).toBe("badgeTemplate");
      return [...seededDemo.templateComparisons];
    });
    mockedGetTenantReportingComparisonsDb.mockImplementationOnce(async (_db, input) => {
      expect(input.groupBy).toBe("orgUnit");
      return [...seededDemo.orgUnitComparisons];
    });

    const response = await app.request(
      seededDemo.routePath,
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting"');
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Applied Analytics");
    expect(body).toContain("Design Systems");
    expect(body).toContain("Computer Science");
    expect(body).toContain("Mathematics");
    expect(body).toContain("History");
    expect(body).toContain('data-reporting-visual-kind="comparison-ranked"');
  });

  it("renders ranked comparison modules while keeping the full comparison tables below", async () => {
    const env = createEnv();
    mockedListBadgeTemplates.mockResolvedValue([
      {
        id: "badge_template_alpha",
        tenantId: "tenant_123",
        slug: "applied-analytics",
        title: "Applied Analytics",
        description: "Awarded for applied analytics coursework.",
        criteriaUri: "https://example.edu/criteria/applied-analytics",
        imageUri: "https://example.edu/badges/applied-analytics.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_beta",
        tenantId: "tenant_123",
        slug: "biotech-lab",
        title: "Biotech Lab",
        description: "Awarded for biotech lab completion.",
        criteriaUri: "https://example.edu/criteria/biotech-lab",
        imageUri: "https://example.edu/badges/biotech-lab.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_gamma",
        tenantId: "tenant_123",
        slug: "civic-history",
        title: "Civic History",
        description: "Awarded for civic history work.",
        criteriaUri: "https://example.edu/criteria/civic-history",
        imageUri: "https://example.edu/badges/civic-history.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_delta",
        tenantId: "tenant_123",
        slug: "digital-design",
        title: "Digital Design",
        description: "Awarded for digital design work.",
        criteriaUri: "https://example.edu/criteria/digital-design",
        imageUri: "https://example.edu/badges/digital-design.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_epsilon",
        tenantId: "tenant_123",
        slug: "ethics-capstone",
        title: "Ethics Capstone",
        description: "Awarded for ethics capstone completion.",
        criteriaUri: "https://example.edu/criteria/ethics-capstone",
        imageUri: "https://example.edu/badges/ethics-capstone.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_zeta",
        tenantId: "tenant_123",
        slug: "zoology-fieldwork",
        title: "Zoology Fieldwork",
        description: "Awarded for zoology fieldwork.",
        criteriaUri: "https://example.edu/criteria/zoology-fieldwork",
        imageUri: "https://example.edu/badges/zoology-fieldwork.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
    ]);
    mockedGetTenantReportingComparisonsDb.mockImplementation(
      async (_db, input: { groupBy: "badgeTemplate" | "orgUnit" }) => {
        if (input.groupBy === "badgeTemplate") {
          return [
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_beta",
              issuedCount: 19,
              publicBadgeViewCount: 40,
              verificationViewCount: 14,
              shareClickCount: 6,
              learnerClaimCount: 8,
              walletAcceptCount: 4,
              claimRate: 42.1,
              shareRate: 31.6,
            },
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_alpha",
              issuedCount: 24,
              publicBadgeViewCount: 51,
              verificationViewCount: 18,
              shareClickCount: 8,
              learnerClaimCount: 11,
              walletAcceptCount: 6,
              claimRate: 45.8,
              shareRate: 33.3,
            },
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_zeta",
              issuedCount: 5,
              publicBadgeViewCount: 11,
              verificationViewCount: 4,
              shareClickCount: 1,
              learnerClaimCount: 1,
              walletAcceptCount: 0,
              claimRate: 20,
              shareRate: 10,
            },
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_epsilon",
              issuedCount: 12,
              publicBadgeViewCount: 25,
              verificationViewCount: 10,
              shareClickCount: 4,
              learnerClaimCount: 5,
              walletAcceptCount: 2,
              claimRate: 41.7,
              shareRate: 33.3,
            },
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_delta",
              issuedCount: 9,
              publicBadgeViewCount: 18,
              verificationViewCount: 7,
              shareClickCount: 2,
              learnerClaimCount: 3,
              walletAcceptCount: 1,
              claimRate: 33.3,
              shareRate: 22.2,
            },
            {
              groupBy: "badgeTemplate",
              groupId: "badge_template_gamma",
              issuedCount: 24,
              publicBadgeViewCount: 47,
              verificationViewCount: 15,
              shareClickCount: 7,
              learnerClaimCount: 10,
              walletAcceptCount: 5,
              claimRate: 41.7,
              shareRate: 29.2,
            },
          ];
        }

        return [
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-cs",
            issuedCount: 14,
            publicBadgeViewCount: 30,
            verificationViewCount: 11,
            shareClickCount: 5,
            learnerClaimCount: 6,
            walletAcceptCount: 3,
            claimRate: 42.9,
            shareRate: 35.7,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:college-arts",
            issuedCount: 17,
            publicBadgeViewCount: 39,
            verificationViewCount: 13,
            shareClickCount: 6,
            learnerClaimCount: 7,
            walletAcceptCount: 4,
            claimRate: 41.2,
            shareRate: 35.3,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-history",
            issuedCount: 11,
            publicBadgeViewCount: 22,
            verificationViewCount: 8,
            shareClickCount: 3,
            learnerClaimCount: 4,
            walletAcceptCount: 1,
            claimRate: 36.4,
            shareRate: 27.3,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:program-design",
            issuedCount: 4,
            publicBadgeViewCount: 10,
            verificationViewCount: 3,
            shareClickCount: 1,
            learnerClaimCount: 1,
            walletAcceptCount: 0,
            claimRate: 25,
            shareRate: 25,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:college-eng",
            issuedCount: 17,
            publicBadgeViewCount: 42,
            verificationViewCount: 15,
            shareClickCount: 7,
            learnerClaimCount: 8,
            walletAcceptCount: 4,
            claimRate: 47.1,
            shareRate: 41.2,
          },
          {
            groupBy: "orgUnit",
            groupId: "tenant_123:org:department-math",
            issuedCount: 8,
            publicBadgeViewCount: 16,
            verificationViewCount: 6,
            shareClickCount: 2,
            learnerClaimCount: 2,
            walletAcceptCount: 1,
            claimRate: 25,
            shareRate: 25,
          },
        ];
      },
    );

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();
    const templatePanel = getReportingPanelMarkup(body, "Compare by badge template");
    const orgUnitPanel = getReportingPanelMarkup(body, "Compare by org unit");
    const templateVisual = getReportingPanelVisualMarkup(templatePanel);
    const orgUnitVisual = getReportingPanelVisualMarkup(orgUnitPanel);

    expect(response.status).toBe(200);
    expect(templatePanel).toContain('data-reporting-visual-kind="comparison-ranked"');
    expect(orgUnitPanel).toContain('data-reporting-visual-kind="comparison-ranked"');
    expect(templatePanel).toContain(
      "The table below keeps the full row set with exact counts and rate definitions.",
    );
    expect(orgUnitPanel).toContain(
      "The table below keeps the full row set with exact counts and rate definitions.",
    );
    expect(templateVisual).toContain(
      "Top 5 shown here. The exact table below keeps all 6 visible rows.",
    );
    expect(orgUnitVisual).toContain(
      "Top 5 shown here. The exact table below keeps all 6 visible rows.",
    );
    expect(templateVisual).toContain("51 public views · 45.8% claim · 33.3% share");
    expect(orgUnitVisual).toContain("42 public views · 47.1% claim · 41.2% share");
    expect(templateVisual.indexOf("Applied Analytics")).toBeLessThan(
      templateVisual.indexOf("Civic History"),
    );
    expect(orgUnitVisual.indexOf("College of Arts")).toBeLessThan(
      orgUnitVisual.indexOf("College of Engineering"),
    );
    expect(templateVisual).not.toContain("Zoology Fieldwork");
    expect(orgUnitVisual).not.toContain("Design Foundations");
    expect(templatePanel).toContain("Zoology Fieldwork");
    expect(orgUnitPanel).toContain("Design Foundations");
  });

  it("renders hierarchy drilldown sections with breadcrumb context and reporting-local drill links", async () => {
    const env = createEnv();
    mockedGetTenantReportingOverviewDb.mockImplementationOnce(async (_db, input) => {
      return {
        tenantId: "tenant_123",
        filters: {
          issuedFrom: input.issuedFrom ?? null,
          issuedTo: input.issuedTo ?? null,
          badgeTemplateId: input.badgeTemplateId ?? null,
          orgUnitId: input.orgUnitId ?? null,
          state: input.state ?? null,
        },
        counts: {
          issued: 14,
          active: 12,
          suspended: 1,
          revoked: 1,
          pendingReview: 1,
        },
        generatedAt: "2026-03-21T12:00:00.000Z",
      };
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting?issuedFrom=2026-03-01&issuedTo=2026-03-31",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Hierarchy drilldown");
    expect(body).toContain("Visible roots stay inside the reporting workspace.");
    expect(body).toContain("Institution");
    expect(body).toContain("College of Engineering");
    expect(body).toContain("Computer Science");
    expect(body).toContain("Computer Science Program");
    expect(body).toContain("Breadcrumb");
    expect(body).toContain('aria-label="Reporting hierarchy breadcrumb"');
    expect(body).toContain('class="ct-admin__reporting-breadcrumb-list"');
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/reporting#reporting-hierarchy-focus-tenant_123%3Aorg%3Ainstitution"',
    );
    expect(body).toContain('aria-current="page">College of Engineering</span>');
    expect(body).toContain('aria-current="page">Computer Science</span>');
    expect(body).toContain("ct-admin__reporting-focus-summary");
    expect(body).toContain("Current focus");
    expect(body).toContain("Current hierarchy level");
    expect(body).toContain("Next child level");
    expect(body).toContain("Reporting workspace");
    expect(body).toContain("Keeps this drilldown inside reporting");
    expect(body).toContain("data-reporting-root-link");
    expect(body).toContain(
      'data-reporting-focus-target="reporting-hierarchy-focus-tenant_123%3Aorg%3Acollege-eng"',
    );
    expect(body).toContain(
      'data-reporting-focus-root="reporting-hierarchy-focus-tenant_123%3Aorg%3Ainstitution"',
    );
    expect(body).not.toContain("Institution / College of Engineering");
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/reporting#reporting-hierarchy-focus-tenant_123%3Aorg%3Acollege-eng"',
    );
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/reporting#reporting-hierarchy-focus-tenant_123%3Aorg%3Adepartment-cs"',
    );
    expect(body).toContain(
      'href="/v1/tenants/tenant_123/reporting/hierarchy/export.csv?issuedFrom=2026-03-01&amp;issuedTo=2026-03-31&amp;focusOrgUnitId=tenant_123%3Aorg%3Acollege-eng&amp;level=department"',
    );
    expect(body).not.toContain(
      'href="/tenants/tenant_123/admin/access/org-units" data-reporting-drill-link',
    );
  });

  it("renders honest performer panels with separate volume and rate rankings", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/reporting",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Performer panels");
    expect(body).toContain('class="ct-admin__reporting-performer-groups"');
    expect(body).toContain("Volume rankings");
    expect(body).toContain("Rate rankings");
    expect(body).toContain("Compare level: department rows in the current visible hierarchy.");
    expect(body).toContain(
      "Rate rankings require at least 5 issued badges so issued totals stay visible beside every rate callout.",
    );
    expect(body).toContain("Highest issuance volume");
    expect(body).toContain("Lowest issuance volume");
    expect(body).toContain("Highest claim rate");
    expect(body).toContain("Lowest share rate");
    expect(body).toContain("Comparing department rows by claim rate.");
    expect(body).toContain("Issued totals stay visible beside each ranked rate row.");
    expect(body).toContain("Computer Science");
    expect(body).toContain("History");
    expect(body).not.toContain(
      'Design Foundations</strong><div class="ct-admin__meta">Below the minimum sample',
    );
    expect(body).toContain('class="ct-admin__reporting-lower-story"');
    expect(body.indexOf("Compare by badge template")).toBeLessThan(
      body.indexOf("Hierarchy drilldown"),
    );
    expect(body.indexOf("Hierarchy drilldown")).toBeLessThan(body.indexOf("Performer panels"));
    expect(body.indexOf("Performer panels")).toBeLessThan(body.indexOf("Compare by org unit"));
  });
});

describe("GET /tenants/:tenantId/admin/rules", () => {
  it("renders the rules workspace", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/rules",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain(">Rules<");
    expect(body).toContain("Rule Builder Workspace");
    expect(body).toContain("Open rule builder");
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/new"');
    expect(body).toContain("Upload Badge Template Image");
    expect(body).toContain('id="badge-template-image-upload-form"');
    expect(body).toContain("Rule Value Lists");
    expect(body).toContain('id="rule-value-list-form"');
    expect(body).toContain("Evaluate Rule");
    expect(body).toContain('id="rule-evaluate-form"');
    expect(body).toContain("Rule Governance Context");
    expect(body).toContain("Badge Rules (1)");
    expect(body).toContain("Badge Templates (1)");
    expect(body).not.toContain("Create Tenant API Key");
    expect(body).not.toContain("Issued Badges Ledger");
  });
});

describe("GET /tenants/:tenantId/admin/access", () => {
  it("renders the access workspace", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain(">Access<");
    expect(body).toContain("Members");
    expect(body).toContain('href="/tenants/tenant_123/admin/access/members"');
    expect(body).toContain("Manage members");
    expect(body).toContain("Access pages");
    expect(body).toContain("Governance");
    expect(body).toContain('href="/tenants/tenant_123/admin/access/governance"');
    expect(body).toContain("API Keys");
    expect(body).toContain("Org Units");
    expect(body).toContain('href="/tenants/tenant_123/admin/access/api-keys"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/org-units"');
    expect(body).not.toContain("Save scoped role");
    expect(body).not.toContain('id="tenant-member-form"');
    expect(body).not.toContain('id="membership-scope-form"');
    expect(body).not.toContain('id="api-key-form"');
    expect(body).not.toContain('id="org-unit-form"');
    expect(body).not.toContain("Manual Issue Badge");
    expect(body).not.toContain("Rule Value Lists");
  });

  it("renders enterprise auth settings inside the access workspace for enterprise tenants", async () => {
    const env = createEnv();
    mockedFindTenantById.mockResolvedValue({
      id: "tenant_123",
      slug: "tenant-123",
      displayName: "Tenant 123",
      planTier: "enterprise",
      issuerDomain: "tenant-123.credtrail.test",
      didWeb: "did:web:credtrail.test:tenant_123",
      isActive: true,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/access",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Enterprise Auth");
    expect(body).toContain("Login mode");
    expect(body).toContain("Campus OIDC");
    expect(body).toContain("Hosted enterprise sign-in supports OIDC providers.");
    expect(body).toContain("Legacy SAML compatibility");
    expect(body).toContain("Members");
    expect(body).toContain("Governance");
    expect(body).toContain("API Keys");
    expect(body).toContain("Org Units");
    expect(body).not.toContain("OIDC or SAML connection metadata");
    expect(body).not.toContain('name="enforceForRoles"');
    expect(body).not.toContain('<option value="saml">');
    expect(body).toContain('id="enterprise-auth-policy-form"');
    expect(body).toContain('id="enterprise-auth-provider-form"');
    expect(body).toContain("Break-glass local accounts");
    expect(body).toContain("admin@tenant-123.edu");
    expect(body).toContain("/v1/tenants/tenant_123/break-glass-accounts");
    expect(body).toContain("/v1/tenants/tenant_123/auth-policy");
    expect(body).toContain("/v1/tenants/tenant_123/auth-providers");
  });
});

describe("GET /tenants/:tenantId/admin/access/governance", () => {
  it("renders governance delegation on its own page with current assignments", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Governance Delegation");
    expect(body).toContain("must already exist in this tenant");
    expect(body).toContain('id="membership-scope-form"');
    expect(body).toContain("Scoped Roles");
    expect(body).toContain("Current Scoped Roles (1)");
    expect(body).toContain('data-membership-scope-remove-user-id="usr_issuer"');
    expect(body).toContain("Current Delegations (1)");
    expect(body).toContain('data-delegated-grant-remove-id="dag_123"');
    expect(body).toContain("Issue badges");
    expect(body).not.toContain('id="api-key-form"');
    expect(body).not.toContain('id="org-unit-form"');
  });
});

describe("GET /tenants/:tenantId/admin/access/members", () => {
  it("renders tenant members on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/members",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Members");
    expect(body).toContain("Add colleagues");
    expect(body).toContain('<details class="ct-admin__panel ct-admin__add-disclosure">');
    expect(body).toContain("Open form");
    expect(body).toContain('id="tenant-member-form"');
    expect(body).toContain('name="email"');
    expect(body).toContain('name="role"');
    expect(body).toContain('name="sendInvite"');
    expect(body).toContain("Hide form");
    expect(body).toContain("Save member");
    expect(body).toContain(
      'class="ct-admin__panel ct-admin__panel--table ct-admin__members-table ct-stack"',
    );
    expect(body).toContain("/v1/tenants/tenant_123/members");
    expect(body).toContain("admin@tenant-123.edu");
    expect(body).toContain("issuer@tenant-123.edu");
    expect(body).toContain('data-tenant-member-role-user-id="usr_issuer"');
    expect(body).toContain('data-tenant-member-invite-user-id="usr_issuer"');
    expect(body).toContain('data-tenant-member-remove-user-id="usr_issuer"');
    expect(body).toContain("Current user");
    expect(body).not.toContain('id="membership-scope-form"');
    expect(body).not.toContain('id="api-key-form"');
    expect(body).not.toContain('id="org-unit-form"');
  });
});

describe("GET /tenants/:tenantId/admin/access/api-keys", () => {
  it("renders API keys on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/api-keys",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("API Keys");
    expect(body).toContain(
      '<details id="api-key-panel" class="ct-admin__panel ct-admin__add-disclosure">',
    );
    expect(body).toContain("Open form");
    expect(body).toContain("Hide form");
    expect(body).toContain('id="api-key-form"');
    expect(body).toContain("Create API key");
    expect(body).toContain("Active API Keys (1)");
    expect(body).toContain(
      'class="ct-admin__panel ct-admin__panel--table ct-admin__api-keys-table ct-stack"',
    );
    expect(body).not.toContain('id="org-unit-form"');
    expect(body).not.toContain('id="membership-scope-form"');
  });
});

describe("GET /tenants/:tenantId/admin/access/org-units", () => {
  it("renders org units on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/org-units",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Org Units");
    expect(body).toContain(
      '<details id="org-unit-panel" class="ct-admin__panel ct-admin__add-disclosure">',
    );
    expect(body).toContain("Open form");
    expect(body).toContain("Hide form");
    expect(body).toContain('id="org-unit-form"');
    expect(body).toContain("Create org unit");
    expect(body).toContain("Org Units (");
    expect(body).toContain(
      'class="ct-admin__panel ct-admin__panel--table ct-admin__org-units-table ct-stack"',
    );
    expect(body).not.toContain('id="api-key-form"');
    expect(body).not.toContain('id="membership-scope-form"');
  });
});

describe("GET /tenants/:tenantId/admin/rules/new", () => {
  it("redirects to login when no session cookie is present", async () => {
    const env = createEnv();
    const response = await app.request("/tenants/tenant_123/admin/rules/new", undefined, env);

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/login?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin%2Frules%2Fnew&reason=auth_required",
    );
  });

  it("renders dedicated rule-builder page for admin membership", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/new",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("Rule Builder");
    expect(body).toContain("Create one badge issuance rule at a time.");
    expect(body).toContain('class="ct-admin-content ct-admin-content--rule-builder"');
    expect(body).toContain('class="ct-admin__builder-shell ct-stack"');
    expect(body).not.toContain('class="ct-admin__builder-shell ct-grid"');
    expect(body).toContain('id="rule-create-form"');
    expect(body).toContain('data-rule-step-target="metadata"');
    expect(body).toContain('data-rule-step-target="conditions"');
    expect(body).toContain('data-rule-step-target="test"');
    expect(body).toContain('data-rule-step-target="review"');
    expect(body).toContain('id="rule-builder-condition-list"');
    expect(body).toContain('id="rule-builder-definition-json"');
    expect(body).toContain('id="rule-builder-summary-validity"');
    expect(body).toContain('id="rule-builder-summary-last-test"');
    expect(body).toContain('id="rule-builder-step-prev"');
    expect(body).toContain('id="rule-builder-step-next"');
    expect(body).toContain('id="rule-builder-submit"');
    expect(body).toContain('id="rule-builder-test-preset"');
    expect(body).toContain('id="rule-builder-apply-test-preset"');
    expect(body).toContain('id="rule-builder-test-output"');
    expect(body).toContain('id="rule-builder-value-list-body"');
    expect(body).toContain('name="reviewOnMissingFacts"');
    expect(body).toContain('id="rule-builder-simulate"');
    expect(body).toContain('id="rule-builder-simulate-output"');
    expect(body).toContain("Build in four passes");
    expect(body).toContain("Templates, imports, and help");
    expect(body).toContain("Start from template or clone");
    expect(body).toContain("Draft summary");
    expect(body).toContain("Authoring approach");
    expect(body).toContain("Condition types");
    expect(body).not.toContain("Five-minute walkthrough");
    expect(body).not.toContain("RULE_BUILDER_TUTORIAL_EMBED_URL");
    expect(body).not.toContain("Model, test, then release");
    expect(body).not.toContain('aria-label="Rule builder setup"');
    expect(body).toContain('href="/tenants/tenant_123/admin"');
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/learner-records"');
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/new" aria-current="page"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/members"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/governance"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/api-keys"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/org-units"');
    expect(body).toContain('href="/admin/audit-logs?tenantId=tenant_123"');
  });

  it("keeps the switch-organization sidebar link on the dedicated rule-builder page", async () => {
    const env = createEnv();
    mockedListAccessibleTenantContextsForUser.mockResolvedValue([
      {
        tenantId: "tenant_123",
        tenantSlug: "tenant-123",
        tenantDisplayName: "Tenant 123",
        tenantPlanTier: "team",
        membershipRole: "admin",
      },
      {
        tenantId: "tenant_456",
        tenantSlug: "tenant-456",
        tenantDisplayName: "Tenant 456",
        tenantPlanTier: "enterprise",
        membershipRole: "admin",
      },
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/new",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Switch organization");
    expect(body).toContain(
      "/account/organizations?next=%2Ftenants%2Ftenant_123%2Fadmin%2Frules%2Fnew",
    );
  });
});
