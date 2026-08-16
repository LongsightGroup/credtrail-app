import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedGetTenantExecutiveRollup,
  mockedGetTenantReportingOverview,
  mockedGetTenantReportingTrends,
  mockedListTenantMembershipOrgUnitScopes,
  mockedListTenantOrgUnits,
} = vi.hoisted(() => {
  return {
    mockedGetTenantExecutiveRollup: vi.fn(),
    mockedGetTenantReportingOverview: vi.fn(),
    mockedGetTenantReportingTrends: vi.fn(),
    mockedListTenantMembershipOrgUnitScopes: vi.fn(),
    mockedListTenantOrgUnits: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    getTenantExecutiveRollup: mockedGetTenantExecutiveRollup,
    getTenantReportingOverview: mockedGetTenantReportingOverview,
    getTenantReportingTrends: mockedGetTenantReportingTrends,
    listTenantMembershipOrgUnitScopes: mockedListTenantMembershipOrgUnitScopes,
    listTenantOrgUnits: mockedListTenantOrgUnits,
  };
});

import {
  getTenantExecutiveRollup,
  getTenantReportingOverview,
  getTenantReportingTrends,
  listTenantMembershipOrgUnitScopes,
  listTenantOrgUnits,
  type SqlDatabase,
} from "@credtrail/db";

import {
  createSeededDemoExecutiveOrgUnits,
  createSeededDemoExecutiveRollup,
  createSeededDemoExecutiveScope,
  seededDemoExecutiveFixture,
} from "../test-support/seeded-demo-executive-fixture";
import { loadTenantExecutiveDashboard } from "./executive-rollup-loader";

const mockedGetTenantExecutiveRollupDb = vi.mocked(getTenantExecutiveRollup);
const mockedGetTenantReportingOverviewDb = vi.mocked(getTenantReportingOverview);
const mockedGetTenantReportingTrendsDb = vi.mocked(getTenantReportingTrends);
const mockedListTenantMembershipOrgUnitScopesDb = vi.mocked(listTenantMembershipOrgUnitScopes);
const mockedListTenantOrgUnitsDb = vi.mocked(listTenantOrgUnits);

const fakeDb = {
  prepare: vi.fn(),
} as unknown as SqlDatabase;

beforeEach(() => {
  mockedListTenantMembershipOrgUnitScopesDb.mockReset();
  mockedListTenantOrgUnitsDb.mockReset();
  mockedGetTenantReportingOverviewDb.mockReset();
  mockedGetTenantReportingTrendsDb.mockReset();
  mockedGetTenantExecutiveRollupDb.mockReset();

  mockedListTenantOrgUnitsDb.mockResolvedValue(createSeededDemoExecutiveOrgUnits());
  mockedGetTenantReportingOverviewDb.mockResolvedValue(seededDemoExecutiveFixture.overview);
  mockedGetTenantReportingTrendsDb.mockResolvedValue(seededDemoExecutiveFixture.trends);
});

describe("loadTenantExecutiveDashboard", () => {
  it("builds a tenant-wide system executive payload from current reporting truth", async () => {
    mockedGetTenantExecutiveRollupDb.mockResolvedValue(createSeededDemoExecutiveRollup("system"));

    const result = await loadTenantExecutiveDashboard({
      db: fakeDb,
      tenantId: "tenant_123",
      userId: "usr_admin",
      membershipRole: "admin",
      query: {},
      today: "2026-03-22",
    });

    expect(result).toMatchObject({
      tenantId: "tenant_123",
      access: {
        visibility: "tenant",
        scopedOrgUnitIds: [],
      },
      defaults: {
        audience: "system",
        focusOrgUnitId: "tenant_123:org:institution",
        comparisonLevel: "college",
      },
      kpiCatalog: {
        audience: "system",
      },
    });
    expect(mockedGetTenantExecutiveRollupDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: "2025-12-23",
      to: "2026-03-22",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      state: undefined,
      focusOrgUnitId: "tenant_123:org:institution",
      comparisonLevel: "college",
      scopedRootOrgUnitIds: undefined,
    });
  });

  it("keeps scoped executive payloads rooted in the visible subtree", async () => {
    mockedListTenantMembershipOrgUnitScopesDb.mockResolvedValue([
      createSeededDemoExecutiveScope("collegeIssuer"),
    ]);
    mockedGetTenantExecutiveRollupDb.mockResolvedValue(createSeededDemoExecutiveRollup("scoped"));

    const result = await loadTenantExecutiveDashboard({
      db: fakeDb,
      tenantId: "tenant_123",
      userId: "usr_exec",
      membershipRole: "issuer",
      query: {},
      today: "2026-03-22",
    });

    expect(result).toMatchObject({
      access: {
        visibility: "scoped",
        scopedOrgUnitIds: ["tenant_123:org:college-eng"],
      },
      defaults: {
        audience: "college",
        focusOrgUnitId: "tenant_123:org:college-eng",
        comparisonLevel: "department",
      },
    });
    expect(mockedGetTenantExecutiveRollupDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      from: "2025-12-23",
      to: "2026-03-22",
      badgeTemplateId: undefined,
      orgUnitId: undefined,
      state: undefined,
      focusOrgUnitId: "tenant_123:org:college-eng",
      comparisonLevel: "department",
      scopedRootOrgUnitIds: ["tenant_123:org:college-eng"],
    });
  });

  it("builds visible breadcrumbs and deeper drilldown targets from the normalized executive slice", async () => {
    mockedListTenantMembershipOrgUnitScopesDb.mockResolvedValue([
      createSeededDemoExecutiveScope("collegeIssuer"),
    ]);
    mockedGetTenantExecutiveRollupDb.mockResolvedValue(createSeededDemoExecutiveRollup("focused"));

    const result = await loadTenantExecutiveDashboard({
      db: fakeDb,
      tenantId: "tenant_123",
      userId: "usr_exec",
      membershipRole: "issuer",
      query: {
        state: "active",
        badgeTemplateId: "badge_template_science",
        focusOrgUnitId: "tenant_123:org:college-arts",
        comparisonLevel: "program",
      },
      today: "2026-03-22",
    });

    expect(result).toMatchObject({
      defaults: {
        focusOrgUnitId: "tenant_123:org:college-eng",
        comparisonLevel: "department",
        pathState: {
          audience: "college",
          window: "last-90-days",
          badgeTemplateId: "badge_template_science",
          state: "active",
          focusOrgUnitId: "tenant_123:org:college-eng",
          comparisonLevel: "department",
        },
      },
      navigation: {
        current: {
          kind: "drilldown",
          focusOrgUnitId: "tenant_123:org:college-eng",
          comparisonLevel: "department",
          href: "/tenants/tenant_123/executive?window=last-90-days&audience=college&badgeTemplateId=badge_template_science&state=active&focusOrgUnitId=tenant_123%3Aorg%3Acollege-eng&comparisonLevel=department",
        },
        breadcrumbs: [
          {
            kind: "drilldown",
            focusOrgUnitId: "tenant_123:org:college-eng",
            comparisonLevel: "department",
          },
        ],
        parent: null,
        back: null,
        drilldowns: [
          {
            kind: "drilldown",
            focusOrgUnitId: "tenant_123:org:department-cs",
            comparisonLevel: "program",
            href: "/tenants/tenant_123/executive?window=last-90-days&audience=college&badgeTemplateId=badge_template_science&state=active&focusOrgUnitId=tenant_123%3Aorg%3Adepartment-cs&comparisonLevel=program",
          },
        ],
      },
    });
  });

  it("keeps terminal slices honest with focus-summary executive modules", async () => {
    mockedListTenantMembershipOrgUnitScopesDb.mockResolvedValue([
      createSeededDemoExecutiveScope("programViewer"),
    ]);
    mockedGetTenantExecutiveRollupDb.mockResolvedValue(createSeededDemoExecutiveRollup("terminal"));

    const result = await loadTenantExecutiveDashboard({
      db: fakeDb,
      tenantId: "tenant_123",
      userId: "usr_exec",
      membershipRole: "viewer",
      query: {},
      today: "2026-03-22",
    });

    expect(result?.defaults).toMatchObject({
      audience: "program",
      focusOrgUnitId: "tenant_123:org:program-cs",
      comparisonLevel: "program",
    });
    expect(result?.kpiCatalog.modules.map((module) => module.id)).toEqual([
      "focus-summary",
      "drilldown",
    ]);
    expect(result?.navigation).toMatchObject({
      current: {
        kind: "focus-summary",
        focusOrgUnitId: "tenant_123:org:program-cs",
        comparisonLevel: "program",
      },
      drilldowns: [],
    });
  });
});
