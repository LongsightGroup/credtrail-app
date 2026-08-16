import type {
  BadgeTemplateRecord,
  TenantOrgUnitRecord,
  TenantReportingComparisonRowRecord,
  TenantReportingEngagementCounts,
  TenantReportingOverviewRecord,
  TenantReportingTrendRecord,
} from "@credtrail/db";

const GENERATED_AT = "2026-03-21T12:00:00.000Z";
const TENANT_ID = "tenant_123";
const ROUTE_PATH = `/tenants/${TENANT_ID}/admin/reporting`;

const createOrgUnit = (input: {
  id: string;
  unitType: TenantOrgUnitRecord["unitType"];
  slug: string;
  displayName: string;
  parentOrgUnitId: string | null;
}): TenantOrgUnitRecord => {
  return {
    id: input.id,
    tenantId: TENANT_ID,
    unitType: input.unitType,
    slug: input.slug,
    displayName: input.displayName,
    parentOrgUnitId: input.parentOrgUnitId,
    createdByUserId: "usr_admin",
    isActive: true,
    createdAt: "2026-03-01T09:00:00.000Z",
    updatedAt: "2026-03-01T09:00:00.000Z",
  };
};

const createBadgeTemplate = (input: {
  id: string;
  slug: string;
  title: string;
  ownerOrgUnitId: string;
}): BadgeTemplateRecord => {
  return {
    id: input.id,
    tenantId: TENANT_ID,
    slug: input.slug,
    title: input.title,
    description: `Seeded demo template for ${input.title}.`,
    criteriaUri: null,
    imageUri: null,
    createdByUserId: "usr_admin",
    ownerOrgUnitId: input.ownerOrgUnitId,
    governanceMetadataJson: '{"source":"seeded_demo_fixture"}',
    isArchived: false,
    createdAt: "2026-03-01T09:00:00.000Z",
    updatedAt: "2026-03-01T09:00:00.000Z",
  };
};

const createOverview = (input: {
  issued: number;
  active: number;
  suspended: number;
  revoked: number;
  pendingReview: number;
  claimRate: number;
  shareRate: number;
  orgUnitId?: string;
}): TenantReportingOverviewRecord => {
  return {
    tenantId: TENANT_ID,
    filters: {
      issuedFrom: null,
      issuedTo: null,
      badgeTemplateId: null,
      orgUnitId: input.orgUnitId ?? null,
      state: null,
    },
    counts: {
      issued: input.issued,
      active: input.active,
      suspended: input.suspended,
      revoked: input.revoked,
      pendingReview: input.pendingReview,
      claimRate: input.claimRate,
      shareRate: input.shareRate,
    },
    generatedAt: GENERATED_AT,
  };
};

const createEngagementCounts = (input: {
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
}): TenantReportingEngagementCounts => {
  return {
    issuedCount: input.issuedCount,
    publicBadgeViewCount: input.publicBadgeViewCount,
    verificationViewCount: input.verificationViewCount,
    shareClickCount: input.shareClickCount,
    learnerClaimCount: input.learnerClaimCount,
    walletAcceptCount: input.walletAcceptCount,
    claimRate: input.claimRate,
    shareRate: input.shareRate,
  };
};

const createTrends = (input: {
  orgUnitId?: string;
  series: TenantReportingTrendRecord["series"];
}): TenantReportingTrendRecord => {
  return {
    tenantId: TENANT_ID,
    filters: {
      from: null,
      to: null,
      badgeTemplateId: null,
      orgUnitId: input.orgUnitId ?? null,
      state: null,
    },
    bucket: "day",
    series: input.series,
    generatedAt: GENERATED_AT,
  };
};

const createComparisonRow = (input: {
  groupBy: TenantReportingComparisonRowRecord["groupBy"];
  groupId: string;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
}): TenantReportingComparisonRowRecord => {
  return {
    groupBy: input.groupBy,
    groupId: input.groupId,
    issuedCount: input.issuedCount,
    publicBadgeViewCount: input.publicBadgeViewCount,
    verificationViewCount: input.verificationViewCount,
    shareClickCount: input.shareClickCount,
    learnerClaimCount: input.learnerClaimCount,
    walletAcceptCount: input.walletAcceptCount,
    claimRate: input.claimRate,
    shareRate: input.shareRate,
  };
};

interface SeededDemoReportingHierarchyFixture {
  focusOrgUnitId: string;
  level: TenantOrgUnitRecord["unitType"];
  orgUnitLineageIds: readonly string[];
  rows: readonly TenantReportingComparisonRowRecord[];
}

interface SeededDemoReportingScopedOrgContext {
  rootOrgUnitId: string;
  orgUnitId: string;
  visibleOrgUnitIds: readonly string[];
  overview: TenantReportingOverviewRecord;
  engagementCounts: TenantReportingEngagementCounts;
  trends: TenantReportingTrendRecord;
  templateComparisons: readonly TenantReportingComparisonRowRecord[];
  orgUnitComparisons: readonly TenantReportingComparisonRowRecord[];
  rawOrgUnitComparisons: readonly TenantReportingComparisonRowRecord[];
}

interface SeededDemoReportingFixture {
  tenantId: string;
  routePath: string;
  badgeTemplates: readonly BadgeTemplateRecord[];
  orgUnits: readonly TenantOrgUnitRecord[];
  overview: TenantReportingOverviewRecord;
  engagementCounts: TenantReportingEngagementCounts;
  trends: TenantReportingTrendRecord;
  templateComparisons: readonly TenantReportingComparisonRowRecord[];
  orgUnitComparisons: readonly TenantReportingComparisonRowRecord[];
  hierarchy: SeededDemoReportingHierarchyFixture;
  scopedOrgContext: SeededDemoReportingScopedOrgContext;
}

const orgUnits = [
  createOrgUnit({
    id: "tenant_123:org:institution",
    unitType: "institution",
    slug: "institution",
    displayName: "Tenant 123 Institution",
    parentOrgUnitId: null,
  }),
  createOrgUnit({
    id: "tenant_123:org:college-eng",
    unitType: "college",
    slug: "college-eng",
    displayName: "College of Engineering",
    parentOrgUnitId: "tenant_123:org:institution",
  }),
  createOrgUnit({
    id: "tenant_123:org:college-arts",
    unitType: "college",
    slug: "college-arts",
    displayName: "College of Arts",
    parentOrgUnitId: "tenant_123:org:institution",
  }),
  createOrgUnit({
    id: "tenant_123:org:department-cs",
    unitType: "department",
    slug: "department-cs",
    displayName: "Computer Science",
    parentOrgUnitId: "tenant_123:org:college-eng",
  }),
  createOrgUnit({
    id: "tenant_123:org:department-math",
    unitType: "department",
    slug: "department-math",
    displayName: "Mathematics",
    parentOrgUnitId: "tenant_123:org:college-eng",
  }),
  createOrgUnit({
    id: "tenant_123:org:department-history",
    unitType: "department",
    slug: "department-history",
    displayName: "History",
    parentOrgUnitId: "tenant_123:org:college-arts",
  }),
  createOrgUnit({
    id: "tenant_123:org:program-cs",
    unitType: "program",
    slug: "program-cs",
    displayName: "Computer Science Program",
    parentOrgUnitId: "tenant_123:org:department-cs",
  }),
] as const satisfies readonly TenantOrgUnitRecord[];

const badgeTemplates = [
  createBadgeTemplate({
    id: "badge_template_001",
    slug: "typescript-foundations",
    title: "TypeScript Foundations",
    ownerOrgUnitId: "tenant_123:org:department-cs",
  }),
  createBadgeTemplate({
    id: "badge_template_analytics",
    slug: "applied-analytics",
    title: "Applied Analytics",
    ownerOrgUnitId: "tenant_123:org:department-math",
  }),
  createBadgeTemplate({
    id: "badge_template_design",
    slug: "design-systems",
    title: "Design Systems",
    ownerOrgUnitId: "tenant_123:org:college-arts",
  }),
  createBadgeTemplate({
    id: "badge_template_chem",
    slug: "chemistry-lab",
    title: "Chemistry Lab",
    ownerOrgUnitId: "tenant_123:org:department-history",
  }),
] as const satisfies readonly BadgeTemplateRecord[];

const templateComparisons = [
  createComparisonRow({
    groupBy: "badgeTemplate",
    groupId: "badge_template_001",
    issuedCount: 8,
    publicBadgeViewCount: 24,
    verificationViewCount: 9,
    shareClickCount: 4,
    learnerClaimCount: 3,
    walletAcceptCount: 3,
    claimRate: 37.5,
    shareRate: 25,
  }),
  createComparisonRow({
    groupBy: "badgeTemplate",
    groupId: "badge_template_analytics",
    issuedCount: 6,
    publicBadgeViewCount: 18,
    verificationViewCount: 7,
    shareClickCount: 4,
    learnerClaimCount: 3,
    walletAcceptCount: 2,
    claimRate: 50,
    shareRate: 33.3,
  }),
  createComparisonRow({
    groupBy: "badgeTemplate",
    groupId: "badge_template_design",
    issuedCount: 4,
    publicBadgeViewCount: 12,
    verificationViewCount: 5,
    shareClickCount: 2,
    learnerClaimCount: 1,
    walletAcceptCount: 1,
    claimRate: 25,
    shareRate: 25,
  }),
] as const satisfies readonly TenantReportingComparisonRowRecord[];

const orgUnitComparisons = [
  createComparisonRow({
    groupBy: "orgUnit",
    groupId: "tenant_123:org:department-cs",
    issuedCount: 8,
    publicBadgeViewCount: 24,
    verificationViewCount: 9,
    shareClickCount: 4,
    learnerClaimCount: 3,
    walletAcceptCount: 3,
    claimRate: 37.5,
    shareRate: 25,
  }),
  createComparisonRow({
    groupBy: "orgUnit",
    groupId: "tenant_123:org:department-math",
    issuedCount: 6,
    publicBadgeViewCount: 18,
    verificationViewCount: 7,
    shareClickCount: 4,
    learnerClaimCount: 3,
    walletAcceptCount: 2,
    claimRate: 50,
    shareRate: 33.3,
  }),
  createComparisonRow({
    groupBy: "orgUnit",
    groupId: "tenant_123:org:department-history",
    issuedCount: 4,
    publicBadgeViewCount: 12,
    verificationViewCount: 5,
    shareClickCount: 2,
    learnerClaimCount: 1,
    walletAcceptCount: 1,
    claimRate: 25,
    shareRate: 25,
  }),
] as const satisfies readonly TenantReportingComparisonRowRecord[];

const hierarchyRows = [
  createComparisonRow({
    groupBy: "orgUnit",
    groupId: "tenant_123:org:department-cs",
    issuedCount: 8,
    publicBadgeViewCount: 24,
    verificationViewCount: 9,
    shareClickCount: 4,
    learnerClaimCount: 3,
    walletAcceptCount: 3,
    claimRate: 37.5,
    shareRate: 25,
  }),
  createComparisonRow({
    groupBy: "orgUnit",
    groupId: "tenant_123:org:department-math",
    issuedCount: 6,
    publicBadgeViewCount: 18,
    verificationViewCount: 7,
    shareClickCount: 4,
    learnerClaimCount: 3,
    walletAcceptCount: 2,
    claimRate: 50,
    shareRate: 33.3,
  }),
] as const satisfies readonly TenantReportingComparisonRowRecord[];

const scopedTemplateComparisons = [
  createComparisonRow({
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
  }),
] as const satisfies readonly TenantReportingComparisonRowRecord[];

const scopedRawOrgUnitComparisons = [
  createComparisonRow({
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
  }),
  createComparisonRow({
    groupBy: "orgUnit",
    groupId: "tenant_123:org:department-math",
    issuedCount: 4,
    publicBadgeViewCount: 8,
    verificationViewCount: 3,
    shareClickCount: 1,
    learnerClaimCount: 2,
    walletAcceptCount: 1,
    claimRate: 50,
    shareRate: 25,
  }),
  createComparisonRow({
    groupBy: "orgUnit",
    groupId: "tenant_123:org:department-history",
    issuedCount: 3,
    publicBadgeViewCount: 6,
    verificationViewCount: 2,
    shareClickCount: 1,
    learnerClaimCount: 1,
    walletAcceptCount: 0,
    claimRate: 33.3,
    shareRate: 16.7,
  }),
] as const satisfies readonly TenantReportingComparisonRowRecord[];

export const seededDemoReportingFixture: SeededDemoReportingFixture = {
  tenantId: TENANT_ID,
  routePath: ROUTE_PATH,
  badgeTemplates,
  orgUnits,
  overview: createOverview({
    issued: 18,
    active: 15,
    suspended: 1,
    revoked: 1,
    pendingReview: 1,
    claimRate: 38.9,
    shareRate: 27.8,
  }),
  engagementCounts: createEngagementCounts({
    issuedCount: 18,
    publicBadgeViewCount: 54,
    verificationViewCount: 21,
    shareClickCount: 10,
    learnerClaimCount: 7,
    walletAcceptCount: 6,
    claimRate: 38.9,
    shareRate: 27.8,
  }),
  trends: createTrends({
    series: [
      {
        bucketStart: "2026-03-01",
        issuedCount: 6,
        publicBadgeViewCount: 17,
        verificationViewCount: 6,
        shareClickCount: 3,
        learnerClaimCount: 2,
        walletAcceptCount: 2,
      },
      {
        bucketStart: "2026-03-08",
        issuedCount: 5,
        publicBadgeViewCount: 14,
        verificationViewCount: 5,
        shareClickCount: 3,
        learnerClaimCount: 2,
        walletAcceptCount: 2,
      },
      {
        bucketStart: "2026-03-15",
        issuedCount: 7,
        publicBadgeViewCount: 23,
        verificationViewCount: 10,
        shareClickCount: 4,
        learnerClaimCount: 3,
        walletAcceptCount: 2,
      },
    ],
  }),
  templateComparisons,
  orgUnitComparisons,
  hierarchy: {
    focusOrgUnitId: "tenant_123:org:college-eng",
    level: "department",
    orgUnitLineageIds: [
      "tenant_123:org:institution",
      "tenant_123:org:college-eng",
      "tenant_123:org:department-cs",
      "tenant_123:org:program-cs",
    ],
    rows: hierarchyRows,
  },
  scopedOrgContext: {
    rootOrgUnitId: "tenant_123:org:college-eng",
    orgUnitId: "tenant_123:org:program-cs",
    visibleOrgUnitIds: [
      "tenant_123:org:institution",
      "tenant_123:org:college-eng",
      "tenant_123:org:department-cs",
      "tenant_123:org:department-math",
      "tenant_123:org:program-cs",
    ],
    overview: createOverview({
      issued: 5,
      active: 5,
      suspended: 0,
      revoked: 0,
      pendingReview: 0,
      claimRate: 40,
      shareRate: 20,
      orgUnitId: "tenant_123:org:program-cs",
    }),
    engagementCounts: createEngagementCounts({
      issuedCount: 5,
      publicBadgeViewCount: 14,
      verificationViewCount: 5,
      shareClickCount: 2,
      learnerClaimCount: 2,
      walletAcceptCount: 1,
      claimRate: 40,
      shareRate: 20,
    }),
    trends: createTrends({
      orgUnitId: "tenant_123:org:program-cs",
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
    }),
    templateComparisons: scopedTemplateComparisons,
    orgUnitComparisons: scopedRawOrgUnitComparisons.filter(
      (row) => row.groupId !== "tenant_123:org:department-history",
    ),
    rawOrgUnitComparisons: scopedRawOrgUnitComparisons,
  },
};
