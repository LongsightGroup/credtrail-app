import {
  getTenantReportingEngagementCounts,
  getTenantReportingOverview,
  getTenantReportingTrends,
  listTenantOrgUnits,
  listTenantReportingComparisons,
} from "@credtrail/db";
import type {
  TenantReportingComparisonQuery,
  TenantReportingHierarchyQuery,
  TenantReportingOverviewQuery,
  TenantReportingTrendQuery,
} from "@credtrail/validation";
import type { ReportingRouteAccess } from "../routes/reporting-route-access";
import {
  aggregateHierarchyRows,
  buildOrgUnitMap,
  filterComparisonRowsToScope,
  isOrgUnitWithinRoots,
} from "./reporting-hierarchy";
import { buildReportingMetricEntries } from "./metric-definitions";
import {
  COMPARISON_EXPORT_COLUMNS,
  ENGAGEMENT_EXPORT_COLUMNS,
  HIERARCHY_EXPORT_COLUMNS,
  OVERVIEW_EXPORT_COLUMNS,
  TREND_EXPORT_COLUMNS,
  buildReportingCsvResponse,
} from "./reporting-route-presenters";

export class ReportingServiceError extends Error {
  public readonly status: 400 | 403;

  public constructor(message: string, status: 400 | 403 = 400) {
    super(message);
    this.name = "ReportingServiceError";
    this.status = status;
  }
}

const generatedTimestamp = (): string => new Date().toISOString();

const assertScopedOrgUnit = async (
  access: ReportingRouteAccess,
  orgUnitId: string | undefined,
  requiredError: string,
): Promise<void> => {
  if (access.reportingAccess.visibility !== "scoped") {
    return;
  }

  if (orgUnitId === undefined) {
    throw new ReportingServiceError(requiredError);
  }

  const orgUnits = await listTenantOrgUnits(access.db, {
    tenantId: access.tenantId,
    includeInactive: true,
  });
  const orgUnitsById = buildOrgUnitMap(orgUnits);

  if (!isOrgUnitWithinRoots(orgUnitsById, orgUnitId, access.reportingAccess.scopedOrgUnitIds)) {
    throw new ReportingServiceError("Requested org unit is outside reporting scope", 403);
  }
};

const loadScopedOrgUnitsById = async (access: ReportingRouteAccess) => {
  const orgUnits = await listTenantOrgUnits(access.db, {
    tenantId: access.tenantId,
    includeInactive: true,
  });

  return buildOrgUnitMap(orgUnits);
};

export const loadReportingOverviewPayload = async (
  access: ReportingRouteAccess,
  query: TenantReportingOverviewQuery,
) => {
  await assertScopedOrgUnit(
    access,
    query.orgUnitId,
    "Scoped reporting overview requests require orgUnitId",
  );

  const overview = await getTenantReportingOverview(access.db, {
    tenantId: access.tenantId,
    issuedFrom: query.issuedFrom,
    issuedTo: query.issuedTo,
    badgeTemplateId: query.badgeTemplateId,
    orgUnitId: query.orgUnitId,
    state: query.state,
  });

  return {
    status: "ok",
    tenantId: overview.tenantId,
    filters: overview.filters,
    counts: overview.counts,
    metrics: buildReportingMetricEntries(overview.counts),
    generatedAt: overview.generatedAt,
  };
};

export const buildReportingOverviewCsvResponse = async (
  access: ReportingRouteAccess,
  query: TenantReportingOverviewQuery,
): Promise<Response> => {
  await assertScopedOrgUnit(
    access,
    query.orgUnitId,
    "Scoped reporting overview requests require orgUnitId",
  );

  const overview = await getTenantReportingOverview(access.db, {
    tenantId: access.tenantId,
    issuedFrom: query.issuedFrom,
    issuedTo: query.issuedTo,
    badgeTemplateId: query.badgeTemplateId,
    orgUnitId: query.orgUnitId,
    state: query.state,
  });

  return buildReportingCsvResponse({
    baseName: "Reporting Overview Export",
    generatedAt: overview.generatedAt,
    rows: [
      {
        tenantId: overview.tenantId,
        issuedFrom: overview.filters.issuedFrom,
        issuedTo: overview.filters.issuedTo,
        badgeTemplateId: overview.filters.badgeTemplateId,
        orgUnitId: overview.filters.orgUnitId,
        state: overview.filters.state,
        generatedAt: overview.generatedAt,
        issued: overview.counts.issued,
        active: overview.counts.active,
        suspended: overview.counts.suspended,
        revoked: overview.counts.revoked,
        pendingReview: overview.counts.pendingReview,
      },
    ],
    columns: OVERVIEW_EXPORT_COLUMNS,
  });
};

export const loadReportingEngagementPayload = async (
  access: ReportingRouteAccess,
  query: TenantReportingTrendQuery,
) => {
  await assertScopedOrgUnit(
    access,
    query.orgUnitId,
    "Scoped engagement reporting requests require orgUnitId",
  );

  const engagementCounts = await getTenantReportingEngagementCounts(access.db, {
    tenantId: access.tenantId,
    from: query.from,
    to: query.to,
    badgeTemplateId: query.badgeTemplateId,
    orgUnitId: query.orgUnitId,
    state: query.state,
  });
  const { claimRate, shareRate, ...counts } = engagementCounts;

  return {
    status: "ok",
    tenantId: access.tenantId,
    filters: {
      from: query.from ?? null,
      to: query.to ?? null,
      badgeTemplateId: query.badgeTemplateId ?? null,
      orgUnitId: query.orgUnitId ?? null,
      state: query.state ?? null,
    },
    counts,
    rates: {
      claimRate,
      shareRate,
    },
    generatedAt: generatedTimestamp(),
  };
};

export const buildReportingEngagementCsvResponse = async (
  access: ReportingRouteAccess,
  query: TenantReportingTrendQuery,
): Promise<Response> => {
  await assertScopedOrgUnit(
    access,
    query.orgUnitId,
    "Scoped engagement reporting requests require orgUnitId",
  );

  const engagementCounts = await getTenantReportingEngagementCounts(access.db, {
    tenantId: access.tenantId,
    ...query,
  });
  const generatedAt = generatedTimestamp();

  return buildReportingCsvResponse({
    baseName: "Reporting Engagement Export",
    generatedAt,
    rows: [
      {
        tenantId: access.tenantId,
        from: query.from ?? null,
        to: query.to ?? null,
        badgeTemplateId: query.badgeTemplateId ?? null,
        orgUnitId: query.orgUnitId ?? null,
        state: query.state ?? null,
        generatedAt,
        issuedCount: engagementCounts.issuedCount,
        publicBadgeViewCount: engagementCounts.publicBadgeViewCount,
        verificationViewCount: engagementCounts.verificationViewCount,
        shareClickCount: engagementCounts.shareClickCount,
        learnerClaimCount: engagementCounts.learnerClaimCount,
        walletAcceptCount: engagementCounts.walletAcceptCount,
        claimRate: engagementCounts.claimRate,
        shareRate: engagementCounts.shareRate,
      },
    ],
    columns: ENGAGEMENT_EXPORT_COLUMNS,
  });
};

export const loadReportingTrendsPayload = async (
  access: ReportingRouteAccess,
  query: TenantReportingTrendQuery,
) => {
  await assertScopedOrgUnit(
    access,
    query.orgUnitId,
    "Scoped reporting trend requests require orgUnitId",
  );

  const trends = await getTenantReportingTrends(access.db, {
    tenantId: access.tenantId,
    ...query,
  });

  return {
    status: "ok",
    ...trends,
  };
};

export const buildReportingTrendsCsvResponse = async (
  access: ReportingRouteAccess,
  query: TenantReportingTrendQuery,
): Promise<Response> => {
  await assertScopedOrgUnit(
    access,
    query.orgUnitId,
    "Scoped reporting trend requests require orgUnitId",
  );

  const trends = await getTenantReportingTrends(access.db, {
    tenantId: access.tenantId,
    from: query.from,
    to: query.to,
    badgeTemplateId: query.badgeTemplateId,
    orgUnitId: query.orgUnitId,
    bucket: query.bucket,
  });

  return buildReportingCsvResponse({
    baseName: "Reporting Trends Export",
    generatedAt: trends.generatedAt,
    rows: trends.series.map((row) => {
      return {
        tenantId: trends.tenantId,
        from: trends.filters.from,
        to: trends.filters.to,
        badgeTemplateId: trends.filters.badgeTemplateId,
        orgUnitId: trends.filters.orgUnitId,
        state: trends.filters.state,
        bucket: trends.bucket,
        bucketStart: row.bucketStart,
        issuedCount: row.issuedCount,
        publicBadgeViewCount: row.publicBadgeViewCount,
        verificationViewCount: row.verificationViewCount,
        shareClickCount: row.shareClickCount,
        learnerClaimCount: row.learnerClaimCount,
        walletAcceptCount: row.walletAcceptCount,
      };
    }),
    columns: TREND_EXPORT_COLUMNS,
  });
};

const loadComparisonRows = async (
  access: ReportingRouteAccess,
  query: TenantReportingComparisonQuery,
) => {
  let scopedOrgUnitsById = null;

  if (access.reportingAccess.visibility === "scoped") {
    scopedOrgUnitsById = await loadScopedOrgUnitsById(access);

    if (
      query.orgUnitId !== undefined &&
      !isOrgUnitWithinRoots(
        scopedOrgUnitsById,
        query.orgUnitId,
        access.reportingAccess.scopedOrgUnitIds,
      )
    ) {
      throw new ReportingServiceError("Requested org unit is outside reporting scope", 403);
    }

    if (query.groupBy === "badgeTemplate" && query.orgUnitId === undefined) {
      throw new ReportingServiceError(
        "Scoped badge-template comparison requests require orgUnitId",
      );
    }
  }

  let comparisonRows = await listTenantReportingComparisons(access.db, {
    tenantId: access.tenantId,
    ...query,
  });

  if (
    access.reportingAccess.visibility === "scoped" &&
    query.groupBy === "orgUnit" &&
    scopedOrgUnitsById !== null
  ) {
    comparisonRows = filterComparisonRowsToScope(
      comparisonRows,
      scopedOrgUnitsById,
      access.reportingAccess.scopedOrgUnitIds,
    );
  }

  return comparisonRows;
};

export const loadReportingComparisonPayload = async (
  access: ReportingRouteAccess,
  query: TenantReportingComparisonQuery,
) => {
  const comparisonRows = await loadComparisonRows(access, query);

  return {
    status: "ok",
    tenantId: access.tenantId,
    filters: {
      from: query.from ?? null,
      to: query.to ?? null,
      badgeTemplateId: query.badgeTemplateId ?? null,
      orgUnitId: query.orgUnitId ?? null,
      state: query.state ?? null,
      groupBy: query.groupBy,
    },
    rows: comparisonRows.map((row) => {
      const { groupBy, groupId, claimRate, shareRate, ...counts } = row;

      return {
        groupBy,
        groupId,
        counts,
        rates: {
          claimRate,
          shareRate,
        },
      };
    }),
    generatedAt: generatedTimestamp(),
  };
};

export const buildReportingComparisonCsvResponse = async (
  access: ReportingRouteAccess,
  query: TenantReportingComparisonQuery,
): Promise<Response> => {
  const comparisonRows = await loadComparisonRows(access, query);

  return buildReportingCsvResponse({
    baseName: "Reporting Comparisons Export",
    generatedAt: generatedTimestamp(),
    rows: comparisonRows.map((row) => {
      return {
        tenantId: access.tenantId,
        from: query.from ?? null,
        to: query.to ?? null,
        badgeTemplateId: query.badgeTemplateId ?? null,
        orgUnitId: query.orgUnitId ?? null,
        state: query.state ?? null,
        groupBy: row.groupBy,
        groupId: row.groupId,
        issuedCount: row.issuedCount,
        publicBadgeViewCount: row.publicBadgeViewCount,
        verificationViewCount: row.verificationViewCount,
        shareClickCount: row.shareClickCount,
        learnerClaimCount: row.learnerClaimCount,
        walletAcceptCount: row.walletAcceptCount,
        claimRate: row.claimRate,
        shareRate: row.shareRate,
      };
    }),
    columns: COMPARISON_EXPORT_COLUMNS,
  });
};

const loadHierarchyRows = async (
  access: ReportingRouteAccess,
  query: TenantReportingHierarchyQuery,
) => {
  const orgUnitsById = await loadScopedOrgUnitsById(access);

  if (
    access.reportingAccess.visibility === "scoped" &&
    query.orgUnitId !== undefined &&
    !isOrgUnitWithinRoots(orgUnitsById, query.orgUnitId, access.reportingAccess.scopedOrgUnitIds)
  ) {
    throw new ReportingServiceError("Requested org unit is outside reporting scope", 403);
  }

  if (
    access.reportingAccess.visibility === "scoped" &&
    query.focusOrgUnitId !== undefined &&
    !isOrgUnitWithinRoots(
      orgUnitsById,
      query.focusOrgUnitId,
      access.reportingAccess.scopedOrgUnitIds,
    )
  ) {
    throw new ReportingServiceError("Requested org unit is outside reporting scope", 403);
  }

  const comparisonRows = await listTenantReportingComparisons(access.db, {
    tenantId: access.tenantId,
    from: query.from,
    to: query.to,
    badgeTemplateId: query.badgeTemplateId,
    orgUnitId: query.orgUnitId,
    state: query.state,
    groupBy: "orgUnit",
  });

  try {
    return aggregateHierarchyRows({
      comparisonRows,
      orgUnitsById,
      focusOrgUnitId: query.focusOrgUnitId,
      level: query.level,
      scopedRootOrgUnitIds:
        access.reportingAccess.visibility === "scoped"
          ? access.reportingAccess.scopedOrgUnitIds
          : [],
    });
  } catch (error: unknown) {
    throw new ReportingServiceError(
      error instanceof Error ? error.message : "Invalid reporting hierarchy query",
    );
  }
};

export const loadReportingHierarchyPayload = async (
  access: ReportingRouteAccess,
  query: TenantReportingHierarchyQuery,
) => {
  const rows = await loadHierarchyRows(access, query);

  return {
    status: "ok",
    tenantId: access.tenantId,
    filters: {
      from: query.from ?? null,
      to: query.to ?? null,
      badgeTemplateId: query.badgeTemplateId ?? null,
      orgUnitId: query.orgUnitId ?? null,
      state: query.state ?? null,
      focusOrgUnitId: query.focusOrgUnitId ?? null,
      level: query.level,
    },
    rows,
    generatedAt: generatedTimestamp(),
  };
};

export const buildReportingHierarchyCsvResponse = async (
  access: ReportingRouteAccess,
  query: TenantReportingHierarchyQuery,
): Promise<Response> => {
  const rows = await loadHierarchyRows(access, query);

  return buildReportingCsvResponse({
    baseName: "Reporting Hierarchy Export",
    generatedAt: generatedTimestamp(),
    rows: rows.map((row) => {
      return {
        tenantId: access.tenantId,
        from: query.from ?? null,
        to: query.to ?? null,
        badgeTemplateId: query.badgeTemplateId ?? null,
        orgUnitIdFilter: query.orgUnitId ?? null,
        state: query.state ?? null,
        focusOrgUnitId: query.focusOrgUnitId ?? null,
        level: query.level,
        orgUnitId: row.orgUnitId,
        displayName: row.displayName,
        parentOrgUnitId: row.parentOrgUnitId,
        issuedCount: row.issuedCount,
        publicBadgeViewCount: row.publicBadgeViewCount,
        verificationViewCount: row.verificationViewCount,
        shareClickCount: row.shareClickCount,
        learnerClaimCount: row.learnerClaimCount,
        walletAcceptCount: row.walletAcceptCount,
        claimRate: row.claimRate,
        shareRate: row.shareRate,
      };
    }),
    columns: HIERARCHY_EXPORT_COLUMNS,
  });
};
