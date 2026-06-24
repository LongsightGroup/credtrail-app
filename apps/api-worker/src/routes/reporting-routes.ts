import {
  getTenantReportingEngagementCounts,
  getTenantReportingOverview,
  getTenantReportingTrends,
  listTenantOrgUnits,
  listTenantReportingComparisons,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
  type TenantOrgUnitRecord,
} from "@credtrail/db";
import {
  parseTenantReportingComparisonQuery,
  parseTenantReportingHierarchyQuery,
  parseTenantReportingOverviewQuery,
  parseTenantReportingTrendQuery,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import {
  aggregateHierarchyRows,
  buildOrgUnitMap,
  filterComparisonRowsToScope,
  isOrgUnitWithinRoots,
} from "../reporting/reporting-hierarchy";
import {
  toReportingComparisonFilters,
  toReportingEngagementFilters,
  toReportingHierarchyFilters,
  toReportingTrendFilters,
} from "../reporting/reporting-page-filters";
import { buildReportingMetricEntries } from "../reporting/metric-definitions";
import {
  COMPARISON_EXPORT_COLUMNS,
  ENGAGEMENT_EXPORT_COLUMNS,
  HIERARCHY_EXPORT_COLUMNS,
  OVERVIEW_EXPORT_COLUMNS,
  TREND_EXPORT_COLUMNS,
  buildReportingCsvResponse as buildCsvResponse,
} from "../reporting/reporting-route-presenters";
import { createReportingRouteAccessResolver } from "./reporting-route-access";

interface RegisterReportingRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

export const registerReportingRoutes = (input: RegisterReportingRoutesInput): void => {
  const { app, resolveDatabase, requireTenantRole } = input;
  const requireReportingAccess = createReportingRouteAccessResolver({
    resolveDatabase,
    requireTenantRole,
  });

  app.get("/v1/tenants/:tenantId/reporting/overview", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    let query;

    try {
      query = parseTenantReportingOverviewQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid reporting overview query",
        },
        400,
      );
    }

    if (reportingAccess.reportingAccess.visibility === "scoped") {
      if (query.orgUnitId === undefined) {
        return c.json(
          {
            error: "Scoped reporting overview requests require orgUnitId",
          },
          400,
        );
      }

      const orgUnits = await listTenantOrgUnits(reportingAccess.db, {
        tenantId: reportingAccess.tenantId,
        includeInactive: true,
      });
      const orgUnitsById = buildOrgUnitMap(orgUnits);

      if (
        !isOrgUnitWithinRoots(
          orgUnitsById,
          query.orgUnitId,
          reportingAccess.reportingAccess.scopedOrgUnitIds,
        )
      ) {
        return c.json(
          {
            error: "Requested org unit is outside reporting scope",
          },
          403,
        );
      }
    }

    const overview = await getTenantReportingOverview(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      issuedFrom: query.issuedFrom,
      issuedTo: query.issuedTo,
      badgeTemplateId: query.badgeTemplateId,
      orgUnitId: query.orgUnitId,
      state: query.state,
    });

    return c.json({
      status: "ok",
      tenantId: overview.tenantId,
      filters: overview.filters,
      counts: overview.counts,
      metrics: buildReportingMetricEntries(overview.counts),
      generatedAt: overview.generatedAt,
    });
  });

  app.get("/v1/tenants/:tenantId/reporting/overview/export.csv", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    let query;

    try {
      query = parseTenantReportingOverviewQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid reporting overview query",
        },
        400,
      );
    }

    if (reportingAccess.reportingAccess.visibility === "scoped") {
      if (query.orgUnitId === undefined) {
        return c.json(
          {
            error: "Scoped reporting overview requests require orgUnitId",
          },
          400,
        );
      }

      const orgUnits = await listTenantOrgUnits(reportingAccess.db, {
        tenantId: reportingAccess.tenantId,
        includeInactive: true,
      });
      const orgUnitsById = buildOrgUnitMap(orgUnits);

      if (
        !isOrgUnitWithinRoots(
          orgUnitsById,
          query.orgUnitId,
          reportingAccess.reportingAccess.scopedOrgUnitIds,
        )
      ) {
        return c.json(
          {
            error: "Requested org unit is outside reporting scope",
          },
          403,
        );
      }
    }

    const overview = await getTenantReportingOverview(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      issuedFrom: query.issuedFrom,
      issuedTo: query.issuedTo,
      badgeTemplateId: query.badgeTemplateId,
      orgUnitId: query.orgUnitId,
      state: query.state,
    });

    return buildCsvResponse({
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
  });

  app.get("/v1/tenants/:tenantId/reporting/engagement", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    let query;

    try {
      query = parseTenantReportingTrendQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid engagement reporting query",
        },
        400,
      );
    }

    if (reportingAccess.reportingAccess.visibility === "scoped") {
      if (query.orgUnitId === undefined) {
        return c.json(
          {
            error: "Scoped engagement reporting requests require orgUnitId",
          },
          400,
        );
      }

      const orgUnits = await listTenantOrgUnits(reportingAccess.db, {
        tenantId: reportingAccess.tenantId,
        includeInactive: true,
      });
      const orgUnitsById = buildOrgUnitMap(orgUnits);

      if (
        !isOrgUnitWithinRoots(
          orgUnitsById,
          query.orgUnitId,
          reportingAccess.reportingAccess.scopedOrgUnitIds,
        )
      ) {
        return c.json(
          {
            error: "Requested org unit is outside reporting scope",
          },
          403,
        );
      }
    }

    const engagementCounts = await getTenantReportingEngagementCounts(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      from: query.from,
      to: query.to,
      badgeTemplateId: query.badgeTemplateId,
      orgUnitId: query.orgUnitId,
      state: query.state,
    });
    const { claimRate, shareRate, ...counts } = engagementCounts;

    return c.json({
      status: "ok",
      tenantId: reportingAccess.tenantId,
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
      generatedAt: new Date().toISOString(),
    });
  });

  app.get("/v1/tenants/:tenantId/reporting/engagement/export.csv", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    let pageRangeQuery;

    try {
      pageRangeQuery = parseTenantReportingOverviewQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid engagement reporting query",
        },
        400,
      );
    }

    const query = toReportingEngagementFilters(pageRangeQuery);

    if (reportingAccess.reportingAccess.visibility === "scoped") {
      if (query.orgUnitId === undefined) {
        return c.json(
          {
            error: "Scoped engagement reporting requests require orgUnitId",
          },
          400,
        );
      }

      const orgUnits = await listTenantOrgUnits(reportingAccess.db, {
        tenantId: reportingAccess.tenantId,
        includeInactive: true,
      });
      const orgUnitsById = buildOrgUnitMap(orgUnits);

      if (
        !isOrgUnitWithinRoots(
          orgUnitsById,
          query.orgUnitId,
          reportingAccess.reportingAccess.scopedOrgUnitIds,
        )
      ) {
        return c.json(
          {
            error: "Requested org unit is outside reporting scope",
          },
          403,
        );
      }
    }

    const engagementCounts = await getTenantReportingEngagementCounts(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      ...query,
    });
    const generatedAt = new Date().toISOString();

    return buildCsvResponse({
      baseName: "Reporting Engagement Export",
      generatedAt,
      rows: [
        {
          tenantId: reportingAccess.tenantId,
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
  });

  app.get("/v1/tenants/:tenantId/reporting/trends", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    let query;

    try {
      query = parseTenantReportingTrendQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid reporting trend query",
        },
        400,
      );
    }

    if (reportingAccess.reportingAccess.visibility === "scoped") {
      if (query.orgUnitId === undefined) {
        return c.json(
          {
            error: "Scoped reporting trend requests require orgUnitId",
          },
          400,
        );
      }

      const orgUnits = await listTenantOrgUnits(reportingAccess.db, {
        tenantId: reportingAccess.tenantId,
        includeInactive: true,
      });
      const orgUnitsById = buildOrgUnitMap(orgUnits);

      if (
        !isOrgUnitWithinRoots(
          orgUnitsById,
          query.orgUnitId,
          reportingAccess.reportingAccess.scopedOrgUnitIds,
        )
      ) {
        return c.json(
          {
            error: "Requested org unit is outside reporting scope",
          },
          403,
        );
      }
    }

    const trends = await getTenantReportingTrends(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      ...query,
    });

    return c.json({
      status: "ok",
      ...trends,
    });
  });

  app.get("/v1/tenants/:tenantId/reporting/trends/export.csv", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    let pageRangeQuery;

    try {
      pageRangeQuery = parseTenantReportingOverviewQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid reporting trend query",
        },
        400,
      );
    }

    let query;

    try {
      query = parseTenantReportingTrendQuery({
        ...toReportingTrendFilters(pageRangeQuery),
        bucket: c.req.query("bucket"),
      });
    } catch {
      return c.json(
        {
          error: "Invalid reporting trend query",
        },
        400,
      );
    }

    if (reportingAccess.reportingAccess.visibility === "scoped") {
      if (query.orgUnitId === undefined) {
        return c.json(
          {
            error: "Scoped reporting trend requests require orgUnitId",
          },
          400,
        );
      }

      const orgUnits = await listTenantOrgUnits(reportingAccess.db, {
        tenantId: reportingAccess.tenantId,
        includeInactive: true,
      });
      const orgUnitsById = buildOrgUnitMap(orgUnits);

      if (
        !isOrgUnitWithinRoots(
          orgUnitsById,
          query.orgUnitId,
          reportingAccess.reportingAccess.scopedOrgUnitIds,
        )
      ) {
        return c.json(
          {
            error: "Requested org unit is outside reporting scope",
          },
          403,
        );
      }
    }

    const trends = await getTenantReportingTrends(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      from: query.from,
      to: query.to,
      badgeTemplateId: query.badgeTemplateId,
      orgUnitId: query.orgUnitId,
      bucket: query.bucket,
    });

    return buildCsvResponse({
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
  });

  app.get("/v1/tenants/:tenantId/reporting/comparisons", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    let query;

    try {
      query = parseTenantReportingComparisonQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid reporting comparison query",
        },
        400,
      );
    }

    let scopedOrgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord> | null = null;

    if (reportingAccess.reportingAccess.visibility === "scoped") {
      const orgUnits = await listTenantOrgUnits(reportingAccess.db, {
        tenantId: reportingAccess.tenantId,
        includeInactive: true,
      });
      scopedOrgUnitsById = buildOrgUnitMap(orgUnits);

      if (
        query.orgUnitId !== undefined &&
        !isOrgUnitWithinRoots(
          scopedOrgUnitsById,
          query.orgUnitId,
          reportingAccess.reportingAccess.scopedOrgUnitIds,
        )
      ) {
        return c.json(
          {
            error: "Requested org unit is outside reporting scope",
          },
          403,
        );
      }

      if (query.groupBy === "badgeTemplate" && query.orgUnitId === undefined) {
        return c.json(
          {
            error: "Scoped badge-template comparison requests require orgUnitId",
          },
          400,
        );
      }
    }

    let comparisonRows = await listTenantReportingComparisons(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      ...query,
    });

    if (
      reportingAccess.reportingAccess.visibility === "scoped" &&
      query.groupBy === "orgUnit" &&
      scopedOrgUnitsById !== null
    ) {
      comparisonRows = filterComparisonRowsToScope(
        comparisonRows,
        scopedOrgUnitsById,
        reportingAccess.reportingAccess.scopedOrgUnitIds,
      );
    }

    return c.json({
      status: "ok",
      tenantId: reportingAccess.tenantId,
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
      generatedAt: new Date().toISOString(),
    });
  });

  app.get("/v1/tenants/:tenantId/reporting/comparisons/export.csv", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    let pageRangeQuery;

    try {
      pageRangeQuery = parseTenantReportingOverviewQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid reporting comparison query",
        },
        400,
      );
    }

    let query;

    try {
      query = parseTenantReportingComparisonQuery({
        ...toReportingComparisonFilters(pageRangeQuery, "badgeTemplate"),
        groupBy: c.req.query("groupBy"),
      });
    } catch {
      return c.json(
        {
          error: "Invalid reporting comparison query",
        },
        400,
      );
    }

    let scopedOrgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord> | null = null;

    if (reportingAccess.reportingAccess.visibility === "scoped") {
      const orgUnits = await listTenantOrgUnits(reportingAccess.db, {
        tenantId: reportingAccess.tenantId,
        includeInactive: true,
      });
      scopedOrgUnitsById = buildOrgUnitMap(orgUnits);

      if (
        query.orgUnitId !== undefined &&
        !isOrgUnitWithinRoots(
          scopedOrgUnitsById,
          query.orgUnitId,
          reportingAccess.reportingAccess.scopedOrgUnitIds,
        )
      ) {
        return c.json(
          {
            error: "Requested org unit is outside reporting scope",
          },
          403,
        );
      }

      if (query.groupBy === "badgeTemplate" && query.orgUnitId === undefined) {
        return c.json(
          {
            error: "Scoped badge-template comparison requests require orgUnitId",
          },
          400,
        );
      }
    }

    let comparisonRows = await listTenantReportingComparisons(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      ...query,
    });

    if (
      reportingAccess.reportingAccess.visibility === "scoped" &&
      query.groupBy === "orgUnit" &&
      scopedOrgUnitsById !== null
    ) {
      comparisonRows = filterComparisonRowsToScope(
        comparisonRows,
        scopedOrgUnitsById,
        reportingAccess.reportingAccess.scopedOrgUnitIds,
      );
    }

    return buildCsvResponse({
      baseName: "Reporting Comparisons Export",
      generatedAt: new Date().toISOString(),
      rows: comparisonRows.map((row) => {
        return {
          tenantId: reportingAccess.tenantId,
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
  });

  app.get("/v1/tenants/:tenantId/reporting/hierarchy", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    let query;

    try {
      query = parseTenantReportingHierarchyQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid reporting hierarchy query",
        },
        400,
      );
    }

    const orgUnits = await listTenantOrgUnits(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      includeInactive: true,
    });
    const orgUnitsById = buildOrgUnitMap(orgUnits);

    if (
      reportingAccess.reportingAccess.visibility === "scoped" &&
      query.orgUnitId !== undefined &&
      !isOrgUnitWithinRoots(
        orgUnitsById,
        query.orgUnitId,
        reportingAccess.reportingAccess.scopedOrgUnitIds,
      )
    ) {
      return c.json(
        {
          error: "Requested org unit is outside reporting scope",
        },
        403,
      );
    }

    if (
      reportingAccess.reportingAccess.visibility === "scoped" &&
      query.focusOrgUnitId !== undefined &&
      !isOrgUnitWithinRoots(
        orgUnitsById,
        query.focusOrgUnitId,
        reportingAccess.reportingAccess.scopedOrgUnitIds,
      )
    ) {
      return c.json(
        {
          error: "Requested org unit is outside reporting scope",
        },
        403,
      );
    }

    const comparisonRows = await listTenantReportingComparisons(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      from: query.from,
      to: query.to,
      badgeTemplateId: query.badgeTemplateId,
      orgUnitId: query.orgUnitId,
      state: query.state,
      groupBy: "orgUnit",
    });

    try {
      const rows = aggregateHierarchyRows({
        comparisonRows,
        orgUnitsById,
        focusOrgUnitId: query.focusOrgUnitId,
        level: query.level,
        scopedRootOrgUnitIds:
          reportingAccess.reportingAccess.visibility === "scoped"
            ? reportingAccess.reportingAccess.scopedOrgUnitIds
            : [],
      });

      return c.json({
        status: "ok",
        tenantId: reportingAccess.tenantId,
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
        generatedAt: new Date().toISOString(),
      });
    } catch (error: unknown) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Invalid reporting hierarchy query",
        },
        400,
      );
    }
  });

  app.get("/v1/tenants/:tenantId/reporting/hierarchy/export.csv", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    let pageRangeQuery;

    try {
      pageRangeQuery = parseTenantReportingOverviewQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid reporting hierarchy query",
        },
        400,
      );
    }

    let query;

    try {
      query = parseTenantReportingHierarchyQuery({
        ...toReportingHierarchyFilters({
          ...pageRangeQuery,
          level: c.req.query("level") as never,
          focusOrgUnitId: c.req.query("focusOrgUnitId"),
        }),
        focusOrgUnitId: c.req.query("focusOrgUnitId"),
        level: c.req.query("level"),
      });
    } catch {
      return c.json(
        {
          error: "Invalid reporting hierarchy query",
        },
        400,
      );
    }

    const orgUnits = await listTenantOrgUnits(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      includeInactive: true,
    });
    const orgUnitsById = buildOrgUnitMap(orgUnits);

    if (
      reportingAccess.reportingAccess.visibility === "scoped" &&
      query.orgUnitId !== undefined &&
      !isOrgUnitWithinRoots(
        orgUnitsById,
        query.orgUnitId,
        reportingAccess.reportingAccess.scopedOrgUnitIds,
      )
    ) {
      return c.json(
        {
          error: "Requested org unit is outside reporting scope",
        },
        403,
      );
    }

    if (
      reportingAccess.reportingAccess.visibility === "scoped" &&
      query.focusOrgUnitId !== undefined &&
      !isOrgUnitWithinRoots(
        orgUnitsById,
        query.focusOrgUnitId,
        reportingAccess.reportingAccess.scopedOrgUnitIds,
      )
    ) {
      return c.json(
        {
          error: "Requested org unit is outside reporting scope",
        },
        403,
      );
    }

    const comparisonRows = await listTenantReportingComparisons(reportingAccess.db, {
      tenantId: reportingAccess.tenantId,
      from: query.from,
      to: query.to,
      badgeTemplateId: query.badgeTemplateId,
      orgUnitId: query.orgUnitId,
      state: query.state,
      groupBy: "orgUnit",
    });

    try {
      const rows = aggregateHierarchyRows({
        comparisonRows,
        orgUnitsById,
        focusOrgUnitId: query.focusOrgUnitId,
        level: query.level,
        scopedRootOrgUnitIds:
          reportingAccess.reportingAccess.visibility === "scoped"
            ? reportingAccess.reportingAccess.scopedOrgUnitIds
            : [],
      });

      return buildCsvResponse({
        baseName: "Reporting Hierarchy Export",
        generatedAt: new Date().toISOString(),
        rows: rows.map((row) => {
          return {
            tenantId: reportingAccess.tenantId,
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
    } catch (error: unknown) {
      return c.json(
        {
          error: error instanceof Error ? error.message : "Invalid reporting hierarchy query",
        },
        400,
      );
    }
  });
};
