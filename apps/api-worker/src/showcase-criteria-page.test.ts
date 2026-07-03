import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    listBadgeTemplates: vi.fn(),
    listTenantOrgUnits: vi.fn(),
    listBadgeTemplateOwnershipEvents: vi.fn(),
    listBadgeIssuanceRules: vi.fn(),
    listBadgeIssuanceRuleVersions: vi.fn(),
    listBadgeIssuanceRuleVersionApprovalSteps: vi.fn(),
    listBadgeIssuanceRuleVersionApprovalEvents: vi.fn(),
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(),
  };
});

import {
  listBadgeTemplates,
  listTenantOrgUnits,
  listBadgeTemplateOwnershipEvents,
  listBadgeIssuanceRules,
  listBadgeIssuanceRuleVersions,
  listBadgeIssuanceRuleVersionApprovalSteps,
  listBadgeIssuanceRuleVersionApprovalEvents,
  type BadgeIssuanceRuleApprovalEventRecord,
  type BadgeIssuanceRuleApprovalStepRecord,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type BadgeTemplateOwnershipEventRecord,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type TenantOrgUnitRecord,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { app } from "./index";
import { readStyleAssetSource } from "./page-asset-test-utils";

const PUBLIC_BADGE_CSS = readStyleAssetSource("publicBadgeCss");
const mockedListBadgeTemplates = vi.mocked(listBadgeTemplates);
const mockedListTenantOrgUnits = vi.mocked(listTenantOrgUnits);
const mockedListBadgeTemplateOwnershipEvents = vi.mocked(listBadgeTemplateOwnershipEvents);
const mockedListBadgeIssuanceRules = vi.mocked(listBadgeIssuanceRules);
const mockedListBadgeIssuanceRuleVersions = vi.mocked(listBadgeIssuanceRuleVersions);
const mockedListBadgeIssuanceRuleVersionApprovalSteps = vi.mocked(
  listBadgeIssuanceRuleVersionApprovalSteps,
);
const mockedListBadgeIssuanceRuleVersionApprovalEvents = vi.mocked(
  listBadgeIssuanceRuleVersionApprovalEvents,
);
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

const sampleTemplate = (overrides?: Partial<BadgeTemplateRecord>): BadgeTemplateRecord => {
  return {
    id: "badge_template_sakai_1000",
    tenantId: "sakai",
    slug: "sakai-1000-commits-contributor",
    title: "Sakai 1000+ Commits Contributor",
    description: "Awarded for contributing at least 1000 commits.",
    criteriaUri: "https://github.com/sakaiproject/sakai",
    imageUri: "https://credtrail.org/badges/sakai-1000.png",
    createdByUserId: "usr_owner",
    ownerOrgUnitId: "sakai:org:institution",
    governanceMetadataJson: '{"approverChain":"department-chair,registrar"}',
    isArchived: false,
    createdAt: "2026-02-11T01:00:00.000Z",
    updatedAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  };
};

const sampleOrgUnit = (overrides?: Partial<TenantOrgUnitRecord>): TenantOrgUnitRecord => {
  return {
    id: "sakai:org:institution",
    tenantId: "sakai",
    unitType: "institution",
    slug: "institution",
    displayName: "Sakai Project Institution",
    parentOrgUnitId: null,
    createdByUserId: "usr_owner",
    isActive: true,
    createdAt: "2026-02-11T01:00:00.000Z",
    updatedAt: "2026-02-11T01:00:00.000Z",
    ...overrides,
  };
};

const sampleRule = (overrides?: Partial<BadgeIssuanceRuleRecord>): BadgeIssuanceRuleRecord => {
  return {
    id: "brl_123",
    tenantId: "sakai",
    name: "Sakai Contributor Eligibility",
    description: "Determine contribution milestone eligibility",
    badgeTemplateId: "badge_template_sakai_1000",
    ownerOrgUnitId: "sakai:org:institution",
    lmsProviderKind: "sakai",
    lmsConnectionId: null,
    activeVersionId: "brv_123",
    createdByUserId: "usr_owner",
    createdAt: "2026-02-11T01:10:00.000Z",
    updatedAt: "2026-02-17T00:00:00.000Z",
    ...overrides,
  };
};

const sampleVersion = (
  overrides?: Partial<BadgeIssuanceRuleVersionRecord>,
): BadgeIssuanceRuleVersionRecord => {
  return {
    id: "brv_123",
    tenantId: "sakai",
    ruleId: "brl_123",
    versionNumber: 2,
    status: "active",
    ruleJson: JSON.stringify({
      conditions: {
        type: "grade_threshold",
        courseId: "SAKAI-COMMITS",
        scoreField: "final_score",
        minScore: 80,
      },
    }),
    changeSummary: "Raised final score threshold to 80.",
    createdByUserId: "usr_owner",
    submittedByUserId: "usr_owner",
    submittedAt: "2026-02-16T10:30:00.000Z",
    approvedByUserId: "usr_admin",
    approvedAt: "2026-02-16T12:00:00.000Z",
    activatedByUserId: "usr_admin",
    activatedAt: "2026-02-17T00:00:00.000Z",
    createdAt: "2026-02-16T10:00:00.000Z",
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
    id: "brs_001",
    tenantId: "sakai",
    versionId: "brv_123",
    stepNumber: 1,
    targetType: "role_threshold",
    requiredRole: "admin",
    targetUserId: null,
    targetApproverGroupId: null,
    orgUnitId: null,
    label: "Institution approval",
    status: "approved",
    decidedByUserId: "usr_admin",
    decidedAt: "2026-02-16T12:00:00.000Z",
    decisionComment: "Approved for publication",
    createdAt: "2026-02-16T10:00:00.000Z",
    updatedAt: "2026-02-16T12:00:00.000Z",
    ...overrides,
  };
};

const sampleApprovalEvent = (
  overrides?: Partial<BadgeIssuanceRuleApprovalEventRecord>,
): BadgeIssuanceRuleApprovalEventRecord => {
  return {
    id: "bre_001",
    tenantId: "sakai",
    versionId: "brv_123",
    stepNumber: 1,
    action: "approved",
    actorUserId: "usr_admin",
    actorRole: "admin",
    comment: "Aligned with governance policy",
    occurredAt: "2026-02-16T12:00:00.000Z",
    createdAt: "2026-02-16T12:00:00.000Z",
    ...overrides,
  };
};

const sampleOwnershipEvent = (
  overrides?: Partial<BadgeTemplateOwnershipEventRecord>,
): BadgeTemplateOwnershipEventRecord => {
  return {
    id: "bto_001",
    tenantId: "sakai",
    badgeTemplateId: "badge_template_sakai_1000",
    fromOrgUnitId: null,
    toOrgUnitId: "sakai:org:institution",
    reasonCode: "administrative_transfer",
    reason: "Registrar governance handoff",
    governanceMetadataJson: '{"policy":"2026.1"}',
    transferredByUserId: "usr_admin",
    transferredAt: "2026-02-15T10:00:00.000Z",
    createdAt: "2026-02-15T10:00:00.000Z",
    ...overrides,
  };
};

beforeEach(() => {
  mockedCreatePostgresDatabase.mockReset();
  mockedCreatePostgresDatabase.mockReturnValue(fakeDb);
  mockedListBadgeTemplates.mockReset();
  mockedListTenantOrgUnits.mockReset();
  mockedListBadgeTemplateOwnershipEvents.mockReset();
  mockedListBadgeIssuanceRules.mockReset();
  mockedListBadgeIssuanceRuleVersions.mockReset();
  mockedListBadgeIssuanceRuleVersionApprovalSteps.mockReset();
  mockedListBadgeIssuanceRuleVersionApprovalEvents.mockReset();

  mockedListBadgeTemplates.mockResolvedValue([sampleTemplate()]);
  mockedListTenantOrgUnits.mockResolvedValue([sampleOrgUnit()]);
  mockedListBadgeTemplateOwnershipEvents.mockResolvedValue([sampleOwnershipEvent()]);
  mockedListBadgeIssuanceRules.mockResolvedValue([sampleRule()]);
  mockedListBadgeIssuanceRuleVersions.mockResolvedValue([sampleVersion()]);
  mockedListBadgeIssuanceRuleVersionApprovalSteps.mockResolvedValue([sampleApprovalStep()]);
  mockedListBadgeIssuanceRuleVersionApprovalEvents.mockResolvedValue([sampleApprovalEvent()]);
});

describe("GET /showcase/:tenantId/criteria", () => {
  it("renders public criteria and governance registry details", async () => {
    const response = await app.request(
      "/showcase/sakai/criteria?badgeTemplateId=badge_template_sakai_1000",
      undefined,
      createEnv(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("Badge Criteria Registry · sakai");
    expect(body).toContain("Sakai 1000+ Commits Contributor");
    expect(body).toContain("Sakai Project Institution");
    expect(body).toContain(
      "Use this page to understand what this public badge recognizes, who publishes it, and how qualification rules are reviewed.",
    );
    expect(body).toContain("https://github.com/sakaiproject/sakai");
    expect(body).toContain("Published criteria");
    expect(body).toContain("Current badge owner");
    expect(body).toContain("Sakai Contributor Eligibility");
    expect(body).toContain("For course SAKAI-COMMITS, final_score must be at least 80.");
    expect(body).toContain("How someone qualifies");
    expect(body).toContain("Required role: admin");
    expect(body).toContain("approved by usr_admin (admin)");
    expect(body).toContain("administrative_transfer");
    expect(body).toContain("Governance and ownership");
    expect(body).toContain("View public badge examples");
    expect(body).toContain("Badge record details and raw metadata");
    expect(body).toContain("Template ID: badge_template_sakai_1000");
    expect(body).not.toContain("Slug:");
    expect(body).toContain("/showcase/sakai?badgeTemplateId=badge_template_sakai_1000");
    expect(body).toContain(
      '<link rel="canonical" href="http://localhost/showcase/sakai/criteria?badgeTemplateId=badge_template_sakai_1000"',
    );
    expect(body).toContain(
      '<meta property="og:title" content="Badge Criteria Registry · sakai | CredTrail"',
    );
    expect(body).toContain('<meta property="og:type" content="website"');
    expect(body).toContain('<meta name="twitter:card" content="summary_large_image"');
    expect(body).toContain(
      '<meta name="description" content="Public criteria and governance metadata for tenant &quot;sakai&quot; badge template &quot;badge_template_sakai_1000&quot;."',
    );
    expect(body).toContain('rel="stylesheet" href="/assets/ui/public-badge.');
    expect(PUBLIC_BADGE_CSS).toContain(".criteria-registry__hero-link:hover");

    expect(mockedListBadgeTemplates).toHaveBeenCalledWith(fakeDb, {
      tenantId: "sakai",
      includeArchived: false,
    });
    expect(mockedListBadgeTemplateOwnershipEvents).toHaveBeenCalledWith(fakeDb, {
      tenantId: "sakai",
      badgeTemplateId: "badge_template_sakai_1000",
      limit: 20,
    });
  });

  it("applies default showcase template filter for sakai tenant when query is omitted", async () => {
    mockedListBadgeTemplates.mockResolvedValue([]);
    mockedListBadgeIssuanceRules.mockResolvedValue([]);

    const response = await app.request("/showcase/sakai/criteria", undefined, createEnv());
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("badge template &quot;badge_template_sakai_1000&quot;");
    expect(body).toContain("No public badge templates matched this view.");
  });

  it("renders empty state when no templates are available for tenant", async () => {
    mockedListBadgeTemplates.mockResolvedValue([]);
    mockedListTenantOrgUnits.mockResolvedValue([]);
    mockedListBadgeIssuanceRules.mockResolvedValue([]);

    const response = await app.request(
      "/showcase/tenant_123/criteria?badgeTemplateId=badge_template_missing",
      undefined,
      createEnv(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Badge Criteria Registry · tenant_123");
    expect(body).toContain("No public badge templates matched this view.");
    expect(body).toContain("/showcase/tenant_123?badgeTemplateId=badge_template_missing");
  });
});
