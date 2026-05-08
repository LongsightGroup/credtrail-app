import {
  getTenantExecutiveRollup,
  getTenantReportingOverview,
  getTenantReportingTrends,
  listTenantOrgUnits,
  type GetTenantExecutiveRollupResult,
  type SqlDatabase,
  type TenantMembershipRole,
  type TenantOrgUnitRecord,
  type TenantReportingOverviewRecord,
  type TenantReportingTrendRecord,
} from "@credtrail/db";
import type { TenantExecutiveDashboardQuery } from "@credtrail/validation";

import {
  resolveTenantExecutiveAccess,
  type TenantExecutiveAccessResult,
} from "../auth/tenant-access";
import {
  toReportingOverviewFilters,
  toReportingTrendFilters,
} from "../reporting/reporting-page-filters";
import { buildExecutiveKpiCatalog, type ExecutiveKpiCatalog } from "./executive-kpi-catalog";
import {
  inferExecutiveDashboardDefaults,
  resolveExecutiveComparisonLevel,
  resolveExecutiveVisibleOrgUnitIds,
  toExecutiveOrgUnitsById,
  type ExecutiveDashboardDefaults,
  type ExecutiveDashboardPathState,
} from "./executive-dashboard-contract";
import { buildExecutiveDrilldownPath } from "./executive-dashboard-paths";

export interface ExecutiveDashboardNavigationLink {
  kind: "drilldown" | "focus-summary";
  label: string;
  focusOrgUnitId: string;
  comparisonLevel: ExecutiveDashboardDefaults["comparisonLevel"];
  href: string;
}

export interface ExecutiveDashboardNavigation {
  current: ExecutiveDashboardNavigationLink;
  breadcrumbs: ExecutiveDashboardNavigationLink[];
  parent: ExecutiveDashboardNavigationLink | null;
  back: ExecutiveDashboardNavigationLink | null;
  drilldowns: ExecutiveDashboardNavigationLink[];
}

export interface TenantExecutiveDashboardRecord {
  tenantId: string;
  access: TenantExecutiveAccessResult;
  defaults: ExecutiveDashboardDefaults;
  navigation: ExecutiveDashboardNavigation;
  orgUnits: readonly TenantOrgUnitRecord[];
  overview: TenantReportingOverviewRecord;
  trends: TenantReportingTrendRecord;
  kpiCatalog: ExecutiveKpiCatalog;
  rollup: GetTenantExecutiveRollupResult;
}

export interface LoadTenantExecutiveDashboardInput {
  db: SqlDatabase;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  query: TenantExecutiveDashboardQuery;
  today?: string | undefined;
}

const todayDateKey = (): string => {
  return new Date().toISOString().slice(0, 10);
};

const buildExecutiveNavigationLink = (input: {
  tenantId: string;
  label: string;
  focusOrgUnitId: string;
  comparisonLevel: ExecutiveDashboardDefaults["comparisonLevel"];
  pathState: ExecutiveDashboardPathState;
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>;
  hasVisibleRows?: boolean | undefined;
}): ExecutiveDashboardNavigationLink => {
  const focusUnitType =
    input.orgUnitsById.get(input.focusOrgUnitId)?.unitType ?? input.comparisonLevel;

  return {
    kind:
      input.hasVisibleRows === false || input.comparisonLevel === focusUnitType
        ? "focus-summary"
        : "drilldown",
    label: input.label,
    focusOrgUnitId: input.focusOrgUnitId,
    comparisonLevel: input.comparisonLevel,
    href: buildExecutiveDrilldownPath(input.tenantId, input.pathState, {
      focusOrgUnitId: input.focusOrgUnitId,
      comparisonLevel: input.comparisonLevel,
    }),
  };
};

const buildExecutiveDashboardNavigation = (input: {
  tenantId: string;
  access: TenantExecutiveAccessResult;
  defaults: ExecutiveDashboardDefaults;
  orgUnits: readonly TenantOrgUnitRecord[];
  rollup: GetTenantExecutiveRollupResult;
}): ExecutiveDashboardNavigation => {
  const orgUnitsById = toExecutiveOrgUnitsById(input.orgUnits);
  const visibleOrgUnitIds = resolveExecutiveVisibleOrgUnitIds({
    visibility: input.access.visibility,
    scopedOrgUnitIds: input.access.scopedOrgUnitIds,
    orgUnitsById,
  });

  const breadcrumbs = input.rollup.focusLineageOrgUnitIds
    .filter((orgUnitId) => visibleOrgUnitIds.has(orgUnitId))
    .map((orgUnitId) => {
      const orgUnit = orgUnitsById.get(orgUnitId);

      if (orgUnit === undefined) {
        return null;
      }

      return buildExecutiveNavigationLink({
        tenantId: input.tenantId,
        label: orgUnit.displayName,
        focusOrgUnitId: orgUnit.id,
        comparisonLevel: resolveExecutiveComparisonLevel({
          focusOrgUnitId: orgUnit.id,
          visibleOrgUnitIds,
          orgUnitsById,
        }),
        pathState: input.defaults.pathState,
        orgUnitsById,
      });
    })
    .filter((link): link is ExecutiveDashboardNavigationLink => link !== null);
  const parent = breadcrumbs.at(-2) ?? null;

  const drilldowns = input.rollup.rows
    .filter((row) => visibleOrgUnitIds.has(row.orgUnitId))
    .map((row) => {
      const comparisonLevel = resolveExecutiveComparisonLevel({
        focusOrgUnitId: row.orgUnitId,
        visibleOrgUnitIds,
        orgUnitsById,
      });

      if (comparisonLevel === row.level) {
        return null;
      }

      return buildExecutiveNavigationLink({
        tenantId: input.tenantId,
        label: row.displayName,
        focusOrgUnitId: row.orgUnitId,
        comparisonLevel,
        pathState: input.defaults.pathState,
        orgUnitsById,
      });
    })
    .filter((link): link is ExecutiveDashboardNavigationLink => link !== null);

  return {
    current: buildExecutiveNavigationLink({
      tenantId: input.tenantId,
      label: input.rollup.focusDisplayName,
      focusOrgUnitId: input.defaults.focusOrgUnitId,
      comparisonLevel: input.defaults.comparisonLevel,
      pathState: input.defaults.pathState,
      orgUnitsById,
      hasVisibleRows: input.rollup.rows.length > 0,
    }),
    breadcrumbs,
    parent,
    back: parent,
    drilldowns,
  };
};

export const loadTenantExecutiveDashboard = async (
  input: LoadTenantExecutiveDashboardInput,
): Promise<TenantExecutiveDashboardRecord | null> => {
  const access = await resolveTenantExecutiveAccess({
    db: input.db,
    tenantId: input.tenantId,
    userId: input.userId,
    membershipRole: input.membershipRole,
  });

  if (access === null) {
    return null;
  }

  const orgUnits = await listTenantOrgUnits(input.db, {
    tenantId: input.tenantId,
    includeInactive: true,
  });

  const defaults = inferExecutiveDashboardDefaults({
    today: input.today ?? todayDateKey(),
    query: input.query,
    visibility: access.visibility,
    scopedOrgUnitIds: access.scopedOrgUnitIds,
    orgUnits,
  });
  const kpiCatalog = buildExecutiveKpiCatalog({
    defaults,
  });
  const overviewFilters = toReportingOverviewFilters(defaults.reportingFilters);
  const trendFilters = toReportingTrendFilters(defaults.reportingFilters);

  const [overview, trends, rollup] = await Promise.all([
    getTenantReportingOverview(input.db, {
      tenantId: input.tenantId,
      ...overviewFilters,
    }),
    getTenantReportingTrends(input.db, {
      tenantId: input.tenantId,
      ...trendFilters,
    }),
    getTenantExecutiveRollup(input.db, {
      tenantId: input.tenantId,
      from: defaults.reportingFilters.issuedFrom,
      to: defaults.reportingFilters.issuedTo,
      badgeTemplateId: defaults.reportingFilters.badgeTemplateId,
      orgUnitId: defaults.reportingFilters.orgUnitId,
      state: defaults.reportingFilters.state,
      focusOrgUnitId: defaults.focusOrgUnitId,
      comparisonLevel: defaults.comparisonLevel,
      scopedRootOrgUnitIds: access.visibility === "scoped" ? access.scopedOrgUnitIds : undefined,
    }),
  ]);
  const navigation = buildExecutiveDashboardNavigation({
    tenantId: input.tenantId,
    access,
    defaults,
    orgUnits,
    rollup,
  });

  return {
    tenantId: input.tenantId,
    access,
    defaults,
    navigation,
    orgUnits,
    overview,
    trends,
    kpiCatalog,
    rollup,
  };
};
