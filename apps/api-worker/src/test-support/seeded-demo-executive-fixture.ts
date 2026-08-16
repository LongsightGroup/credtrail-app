import type {
  GetTenantExecutiveRollupResult,
  TenantMembershipOrgUnitScopeRecord,
  TenantOrgUnitRecord,
  TenantReportingOverviewRecord,
  TenantReportingTrendRecord,
} from "@credtrail/db";

import { createReportingHierarchyPageFilters } from "../reporting/reporting-page-filters";
import {
  buildExecutiveDrilldownPath,
  buildExecutiveDashboardPath,
} from "../executive/executive-dashboard-paths";
import { buildExecutiveKpiCatalog } from "../executive/executive-kpi-catalog";
import type { TenantExecutiveDashboardRecord } from "../executive/executive-rollup-loader";

const GENERATED_AT = "2026-03-22T12:00:00.000Z";
const TENANT_ID = "tenant_123";

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
    createdAt: "2026-03-21T12:00:00.000Z",
    updatedAt: "2026-03-21T12:00:00.000Z",
  };
};

const createScope = (
  overrides: Partial<TenantMembershipOrgUnitScopeRecord>,
): TenantMembershipOrgUnitScopeRecord => {
  return {
    tenantId: TENANT_ID,
    userId: "usr_exec",
    orgUnitId: "tenant_123:org:college-eng",
    role: "issuer",
    createdByUserId: "usr_admin",
    createdAt: "2026-03-21T12:00:00.000Z",
    updatedAt: "2026-03-21T12:00:00.000Z",
    ...overrides,
  };
};

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

const overview: TenantReportingOverviewRecord = {
  tenantId: TENANT_ID,
  filters: {
    issuedFrom: "2025-12-23",
    issuedTo: "2026-03-22",
    badgeTemplateId: null,
    orgUnitId: null,
    state: "active",
  },
  counts: {
    issued: 18,
    active: 15,
    suspended: 2,
    revoked: 1,
    pendingReview: 1,
    claimRate: 44.4,
    shareRate: 27.8,
  },
  generatedAt: GENERATED_AT,
};

const trends: TenantReportingTrendRecord = {
  tenantId: TENANT_ID,
  filters: {
    from: "2025-12-23",
    to: "2026-03-22",
    badgeTemplateId: null,
    orgUnitId: null,
    state: "active",
  },
  bucket: "day",
  series: [
    {
      bucketStart: "2026-03-20",
      issuedCount: 4,
      publicBadgeViewCount: 6,
      verificationViewCount: 3,
      shareClickCount: 2,
      learnerClaimCount: 2,
      walletAcceptCount: 1,
    },
    {
      bucketStart: "2026-03-21",
      issuedCount: 6,
      publicBadgeViewCount: 9,
      verificationViewCount: 5,
      shareClickCount: 3,
      learnerClaimCount: 3,
      walletAcceptCount: 2,
    },
    {
      bucketStart: "2026-03-22",
      issuedCount: 8,
      publicBadgeViewCount: 11,
      verificationViewCount: 6,
      shareClickCount: 4,
      learnerClaimCount: 3,
      walletAcceptCount: 2,
    },
  ],
  generatedAt: GENERATED_AT,
};

const rollups = {
  system: {
    tenantId: TENANT_ID,
    focusOrgUnitId: "tenant_123:org:institution",
    focusDisplayName: "Tenant 123 Institution",
    focusParentOrgUnitId: null,
    focusUnitType: "institution",
    comparisonLevel: "college",
    focusLineageOrgUnitIds: ["tenant_123:org:institution"],
    filters: {
      from: "2025-12-23",
      to: "2026-03-22",
      badgeTemplateId: null,
      orgUnitId: null,
      state: "active",
    },
    rows: [
      {
        level: "college",
        orgUnitId: "tenant_123:org:college-eng",
        displayName: "College of Engineering",
        parentOrgUnitId: "tenant_123:org:institution",
        issuedCount: 12,
        publicBadgeViewCount: 19,
        verificationViewCount: 10,
        shareClickCount: 4,
        learnerClaimCount: 5,
        walletAcceptCount: 3,
        claimRate: 41.7,
        shareRate: 33.3,
      },
      {
        level: "college",
        orgUnitId: "tenant_123:org:college-arts",
        displayName: "College of Arts",
        parentOrgUnitId: "tenant_123:org:institution",
        issuedCount: 6,
        publicBadgeViewCount: 8,
        verificationViewCount: 4,
        shareClickCount: 1,
        learnerClaimCount: 3,
        walletAcceptCount: 1,
        claimRate: 50,
        shareRate: 16.7,
      },
    ],
    generatedAt: GENERATED_AT,
  },
  focused: {
    tenantId: TENANT_ID,
    focusOrgUnitId: "tenant_123:org:college-eng",
    focusDisplayName: "College of Engineering",
    focusParentOrgUnitId: "tenant_123:org:institution",
    focusUnitType: "college",
    comparisonLevel: "department",
    focusLineageOrgUnitIds: ["tenant_123:org:institution", "tenant_123:org:college-eng"],
    filters: {
      from: "2025-12-23",
      to: "2026-03-22",
      badgeTemplateId: "badge_template_science",
      orgUnitId: null,
      state: "active",
    },
    rows: [
      {
        level: "department",
        orgUnitId: "tenant_123:org:department-cs",
        displayName: "Computer Science",
        parentOrgUnitId: "tenant_123:org:college-eng",
        issuedCount: 10,
        publicBadgeViewCount: 16,
        verificationViewCount: 8,
        shareClickCount: 5,
        learnerClaimCount: 4,
        walletAcceptCount: 2,
        claimRate: 40,
        shareRate: 30,
      },
      {
        level: "department",
        orgUnitId: "tenant_123:org:department-math",
        displayName: "Mathematics",
        parentOrgUnitId: "tenant_123:org:college-eng",
        issuedCount: 8,
        publicBadgeViewCount: 10,
        verificationViewCount: 4,
        shareClickCount: 3,
        learnerClaimCount: 4,
        walletAcceptCount: 1,
        claimRate: 50,
        shareRate: 25,
      },
    ],
    generatedAt: GENERATED_AT,
  },
  scoped: {
    tenantId: TENANT_ID,
    focusOrgUnitId: "tenant_123:org:college-eng",
    focusDisplayName: "College of Engineering",
    focusParentOrgUnitId: "tenant_123:org:institution",
    focusUnitType: "college",
    comparisonLevel: "department",
    focusLineageOrgUnitIds: ["tenant_123:org:institution", "tenant_123:org:college-eng"],
    filters: {
      from: "2025-12-23",
      to: "2026-03-22",
      badgeTemplateId: null,
      orgUnitId: null,
      state: null,
    },
    rows: [
      {
        level: "department",
        orgUnitId: "tenant_123:org:department-cs",
        displayName: "Computer Science",
        parentOrgUnitId: "tenant_123:org:college-eng",
        issuedCount: 10,
        publicBadgeViewCount: 16,
        verificationViewCount: 8,
        shareClickCount: 5,
        learnerClaimCount: 4,
        walletAcceptCount: 2,
        claimRate: 40,
        shareRate: 30,
      },
      {
        level: "department",
        orgUnitId: "tenant_123:org:department-math",
        displayName: "Mathematics",
        parentOrgUnitId: "tenant_123:org:college-eng",
        issuedCount: 8,
        publicBadgeViewCount: 10,
        verificationViewCount: 4,
        shareClickCount: 3,
        learnerClaimCount: 4,
        walletAcceptCount: 1,
        claimRate: 50,
        shareRate: 25,
      },
    ],
    generatedAt: GENERATED_AT,
  },
  terminal: {
    tenantId: TENANT_ID,
    focusOrgUnitId: "tenant_123:org:program-cs",
    focusDisplayName: "Computer Science Program",
    focusParentOrgUnitId: "tenant_123:org:department-cs",
    focusUnitType: "program",
    comparisonLevel: "program",
    focusLineageOrgUnitIds: [
      "tenant_123:org:institution",
      "tenant_123:org:college-eng",
      "tenant_123:org:department-cs",
      "tenant_123:org:program-cs",
    ],
    filters: {
      from: "2025-12-23",
      to: "2026-03-22",
      badgeTemplateId: null,
      orgUnitId: null,
      state: null,
    },
    rows: [],
    generatedAt: GENERATED_AT,
  },
} as const satisfies Record<string, GetTenantExecutiveRollupResult>;

const createNavigationLink = (
  input: Pick<
    TenantExecutiveDashboardRecord["navigation"]["current"],
    "kind" | "label" | "focusOrgUnitId" | "comparisonLevel"
  > & {
    pathState: TenantExecutiveDashboardRecord["defaults"]["pathState"];
  },
): TenantExecutiveDashboardRecord["navigation"]["current"] => {
  return {
    kind: input.kind,
    label: input.label,
    focusOrgUnitId: input.focusOrgUnitId,
    comparisonLevel: input.comparisonLevel,
    href: buildExecutiveDrilldownPath(TENANT_ID, input.pathState, {
      focusOrgUnitId: input.focusOrgUnitId,
      comparisonLevel: input.comparisonLevel,
    }),
  };
};

const systemDefaults: TenantExecutiveDashboardRecord["defaults"] = {
  audience: "system",
  window: "last-90-days",
  focusOrgUnitId: "tenant_123:org:institution",
  focusUnitType: "institution",
  comparisonLevel: "college",
  comparisonGroupBy: "orgUnit",
  reportingFilters: {
    issuedFrom: "2025-12-23",
    issuedTo: "2026-03-22",
    badgeTemplateId: undefined,
    orgUnitId: undefined,
    state: "active",
  },
  hierarchyFilters: createReportingHierarchyPageFilters(
    {
      issuedFrom: "2025-12-23",
      issuedTo: "2026-03-22",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      state: "active",
    },
    {
      focusOrgUnitId: "tenant_123:org:institution",
      level: "college",
    },
  ),
  pathState: {
    audience: "system",
    window: "last-90-days",
    state: "active",
    focusOrgUnitId: "tenant_123:org:institution",
    comparisonLevel: "college",
  },
};

const focusedDefaults: TenantExecutiveDashboardRecord["defaults"] = {
  audience: "system",
  window: "last-90-days",
  focusOrgUnitId: "tenant_123:org:college-eng",
  focusUnitType: "college",
  comparisonLevel: "department",
  comparisonGroupBy: "orgUnit",
  reportingFilters: {
    issuedFrom: "2025-12-23",
    issuedTo: "2026-03-22",
    badgeTemplateId: "badge_template_science",
    orgUnitId: undefined,
    state: "active",
  },
  hierarchyFilters: createReportingHierarchyPageFilters(
    {
      issuedFrom: "2025-12-23",
      issuedTo: "2026-03-22",
      badgeTemplateId: "badge_template_science",
      orgUnitId: undefined,
      state: "active",
    },
    {
      focusOrgUnitId: "tenant_123:org:college-eng",
      level: "department",
    },
  ),
  pathState: {
    audience: "system",
    window: "last-90-days",
    badgeTemplateId: "badge_template_science",
    state: "active",
    focusOrgUnitId: "tenant_123:org:college-eng",
    comparisonLevel: "department",
  },
};

const scopedDefaults: TenantExecutiveDashboardRecord["defaults"] = {
  audience: "college",
  window: "last-90-days",
  focusOrgUnitId: "tenant_123:org:college-eng",
  focusUnitType: "college",
  comparisonLevel: "department",
  comparisonGroupBy: "orgUnit",
  reportingFilters: {
    issuedFrom: "2025-12-23",
    issuedTo: "2026-03-22",
    badgeTemplateId: undefined,
    orgUnitId: undefined,
    state: "active",
  },
  hierarchyFilters: createReportingHierarchyPageFilters(
    {
      issuedFrom: "2025-12-23",
      issuedTo: "2026-03-22",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      state: "active",
    },
    {
      focusOrgUnitId: "tenant_123:org:college-eng",
      level: "department",
    },
  ),
  pathState: {
    audience: "college",
    window: "last-90-days",
    state: "active",
    focusOrgUnitId: "tenant_123:org:college-eng",
    comparisonLevel: "department",
  },
};

const systemSlice: TenantExecutiveDashboardRecord = {
  tenantId: TENANT_ID,
  access: {
    tenantId: TENANT_ID,
    membershipRole: "admin",
    visibility: "tenant",
    scopedOrgUnitIds: [],
  },
  defaults: systemDefaults,
  navigation: {
    current: createNavigationLink({
      kind: "drilldown",
      label: "Tenant 123 Institution",
      focusOrgUnitId: "tenant_123:org:institution",
      comparisonLevel: "college",
      pathState: systemDefaults.pathState,
    }),
    breadcrumbs: [
      createNavigationLink({
        kind: "drilldown",
        label: "Tenant 123 Institution",
        focusOrgUnitId: "tenant_123:org:institution",
        comparisonLevel: "college",
        pathState: systemDefaults.pathState,
      }),
    ],
    parent: null,
    back: null,
    drilldowns: [
      createNavigationLink({
        kind: "drilldown",
        label: "College of Engineering",
        focusOrgUnitId: "tenant_123:org:college-eng",
        comparisonLevel: "department",
        pathState: systemDefaults.pathState,
      }),
      createNavigationLink({
        kind: "drilldown",
        label: "College of Arts",
        focusOrgUnitId: "tenant_123:org:college-arts",
        comparisonLevel: "department",
        pathState: systemDefaults.pathState,
      }),
    ],
  },
  orgUnits,
  overview,
  trends,
  kpiCatalog: buildExecutiveKpiCatalog({
    defaults: systemDefaults,
  }),
  rollup: rollups.system,
};

const focusedSlice: TenantExecutiveDashboardRecord = {
  tenantId: TENANT_ID,
  access: {
    tenantId: TENANT_ID,
    membershipRole: "admin",
    visibility: "tenant",
    scopedOrgUnitIds: [],
  },
  defaults: focusedDefaults,
  navigation: {
    current: createNavigationLink({
      kind: "drilldown",
      label: "College of Engineering",
      focusOrgUnitId: "tenant_123:org:college-eng",
      comparisonLevel: "department",
      pathState: focusedDefaults.pathState,
    }),
    breadcrumbs: [
      createNavigationLink({
        kind: "drilldown",
        label: "Tenant 123 Institution",
        focusOrgUnitId: "tenant_123:org:institution",
        comparisonLevel: "college",
        pathState: focusedDefaults.pathState,
      }),
      createNavigationLink({
        kind: "drilldown",
        label: "College of Engineering",
        focusOrgUnitId: "tenant_123:org:college-eng",
        comparisonLevel: "department",
        pathState: focusedDefaults.pathState,
      }),
    ],
    parent: createNavigationLink({
      kind: "drilldown",
      label: "Tenant 123 Institution",
      focusOrgUnitId: "tenant_123:org:institution",
      comparisonLevel: "college",
      pathState: focusedDefaults.pathState,
    }),
    back: createNavigationLink({
      kind: "drilldown",
      label: "Tenant 123 Institution",
      focusOrgUnitId: "tenant_123:org:institution",
      comparisonLevel: "college",
      pathState: focusedDefaults.pathState,
    }),
    drilldowns: [
      createNavigationLink({
        kind: "drilldown",
        label: "Computer Science",
        focusOrgUnitId: "tenant_123:org:department-cs",
        comparisonLevel: "program",
        pathState: focusedDefaults.pathState,
      }),
      createNavigationLink({
        kind: "focus-summary",
        label: "Mathematics",
        focusOrgUnitId: "tenant_123:org:department-math",
        comparisonLevel: "department",
        pathState: focusedDefaults.pathState,
      }),
    ],
  },
  orgUnits,
  overview,
  trends,
  kpiCatalog: buildExecutiveKpiCatalog({
    defaults: focusedDefaults,
  }),
  rollup: rollups.focused,
};

const scopedSlice: TenantExecutiveDashboardRecord = {
  tenantId: TENANT_ID,
  access: {
    tenantId: TENANT_ID,
    membershipRole: "viewer",
    visibility: "scoped",
    scopedOrgUnitIds: ["tenant_123:org:college-eng"],
  },
  defaults: scopedDefaults,
  navigation: {
    current: createNavigationLink({
      kind: "drilldown",
      label: "College of Engineering",
      focusOrgUnitId: "tenant_123:org:college-eng",
      comparisonLevel: "department",
      pathState: scopedDefaults.pathState,
    }),
    breadcrumbs: [
      createNavigationLink({
        kind: "drilldown",
        label: "College of Engineering",
        focusOrgUnitId: "tenant_123:org:college-eng",
        comparisonLevel: "department",
        pathState: scopedDefaults.pathState,
      }),
    ],
    parent: null,
    back: null,
    drilldowns: [
      createNavigationLink({
        kind: "drilldown",
        label: "Computer Science",
        focusOrgUnitId: "tenant_123:org:department-cs",
        comparisonLevel: "program",
        pathState: scopedDefaults.pathState,
      }),
      createNavigationLink({
        kind: "focus-summary",
        label: "Mathematics",
        focusOrgUnitId: "tenant_123:org:department-math",
        comparisonLevel: "department",
        pathState: scopedDefaults.pathState,
      }),
    ],
  },
  orgUnits,
  overview,
  trends,
  kpiCatalog: buildExecutiveKpiCatalog({
    defaults: scopedDefaults,
  }),
  rollup: rollups.scoped,
};

interface SeededDemoExecutiveFixture {
  tenantId: string;
  routeFamily: {
    landing: string;
    focused: string;
    scoped: string;
  };
  orgUnits: readonly TenantOrgUnitRecord[];
  scopes: {
    collegeIssuer: TenantMembershipOrgUnitScopeRecord;
    programViewer: TenantMembershipOrgUnitScopeRecord;
  };
  overview: TenantReportingOverviewRecord;
  trends: TenantReportingTrendRecord;
  rollups: {
    system: GetTenantExecutiveRollupResult;
    focused: GetTenantExecutiveRollupResult;
    scoped: GetTenantExecutiveRollupResult;
    terminal: GetTenantExecutiveRollupResult;
  };
  slices: {
    system: TenantExecutiveDashboardRecord;
    focused: TenantExecutiveDashboardRecord;
    scoped: TenantExecutiveDashboardRecord;
  };
}

export const seededDemoExecutiveFixture: SeededDemoExecutiveFixture = {
  tenantId: TENANT_ID,
  routeFamily: {
    landing: buildExecutiveDashboardPath(TENANT_ID),
    focused: buildExecutiveDashboardPath(TENANT_ID, focusedDefaults.pathState),
    scoped: buildExecutiveDashboardPath(TENANT_ID, scopedDefaults.pathState),
  },
  orgUnits,
  scopes: {
    collegeIssuer: createScope({}),
    programViewer: createScope({
      orgUnitId: "tenant_123:org:program-cs",
      role: "viewer",
    }),
  },
  overview,
  trends,
  rollups: {
    system: rollups.system,
    focused: rollups.focused,
    scoped: rollups.scoped,
    terminal: rollups.terminal,
  },
  slices: {
    system: systemSlice,
    focused: focusedSlice,
    scoped: scopedSlice,
  },
};

type SeededDemoExecutiveSliceName = keyof SeededDemoExecutiveFixture["slices"];
type SeededDemoExecutiveRollupName = keyof SeededDemoExecutiveFixture["rollups"];
type SeededDemoExecutiveScopeName = keyof SeededDemoExecutiveFixture["scopes"];

const cloneValue = <T>(value: T): T => {
  return structuredClone(value);
};

export const createSeededDemoExecutiveDashboardSlice = (
  slice: SeededDemoExecutiveSliceName,
): TenantExecutiveDashboardRecord => {
  return cloneValue(seededDemoExecutiveFixture.slices[slice]);
};

export const createSeededDemoExecutiveRollup = (
  rollup: SeededDemoExecutiveRollupName,
): GetTenantExecutiveRollupResult => {
  return cloneValue(seededDemoExecutiveFixture.rollups[rollup]);
};

export const createSeededDemoExecutiveOrgUnits = (): TenantOrgUnitRecord[] => {
  return cloneValue([...seededDemoExecutiveFixture.orgUnits]);
};

export const createSeededDemoExecutiveScope = (
  scope: SeededDemoExecutiveScopeName,
): TenantMembershipOrgUnitScopeRecord => {
  return cloneValue(seededDemoExecutiveFixture.scopes[scope]);
};
