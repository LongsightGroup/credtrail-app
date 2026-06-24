import type { SessionRecord, SqlDatabase, TenantMembershipRole } from "@credtrail/db";
import {
  parseTenantReportingComparisonQuery,
  parseTenantReportingHierarchyQuery,
  parseTenantReportingOverviewQuery,
  parseTenantReportingTrendQuery,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import {
  buildReportingComparisonCsvResponse,
  buildReportingEngagementCsvResponse,
  buildReportingHierarchyCsvResponse,
  buildReportingOverviewCsvResponse,
  buildReportingTrendsCsvResponse,
  loadReportingComparisonPayload,
  loadReportingEngagementPayload,
  loadReportingHierarchyPayload,
  loadReportingOverviewPayload,
  loadReportingTrendsPayload,
  ReportingServiceError,
} from "../reporting/reporting-service";
import {
  toReportingComparisonFilters,
  toReportingEngagementFilters,
  toReportingHierarchyFilters,
  toReportingTrendFilters,
} from "../reporting/reporting-page-filters";
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

const reportingServiceErrorResponse = (
  c: AppContext,
  error: unknown,
  fallbackMessage: string,
): Response => {
  if (error instanceof ReportingServiceError) {
    return c.json(
      {
        error: error.message,
      },
      error.status,
    );
  }

  return c.json(
    {
      error: fallbackMessage,
    },
    400,
  );
};

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

    try {
      const query = parseTenantReportingOverviewQuery(c.req.query());
      return c.json(await loadReportingOverviewPayload(reportingAccess, query));
    } catch (error: unknown) {
      return reportingServiceErrorResponse(c, error, "Invalid reporting overview query");
    }
  });

  app.get("/v1/tenants/:tenantId/reporting/overview/export.csv", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    try {
      const query = parseTenantReportingOverviewQuery(c.req.query());
      return await buildReportingOverviewCsvResponse(reportingAccess, query);
    } catch (error: unknown) {
      return reportingServiceErrorResponse(c, error, "Invalid reporting overview query");
    }
  });

  app.get("/v1/tenants/:tenantId/reporting/engagement", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    try {
      const query = parseTenantReportingTrendQuery(c.req.query());
      return c.json(await loadReportingEngagementPayload(reportingAccess, query));
    } catch (error: unknown) {
      return reportingServiceErrorResponse(c, error, "Invalid engagement reporting query");
    }
  });

  app.get("/v1/tenants/:tenantId/reporting/engagement/export.csv", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    try {
      const pageRangeQuery = parseTenantReportingOverviewQuery(c.req.query());
      const query = parseTenantReportingTrendQuery(toReportingEngagementFilters(pageRangeQuery));
      return await buildReportingEngagementCsvResponse(reportingAccess, query);
    } catch (error: unknown) {
      return reportingServiceErrorResponse(c, error, "Invalid engagement reporting query");
    }
  });

  app.get("/v1/tenants/:tenantId/reporting/trends", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    try {
      const query = parseTenantReportingTrendQuery(c.req.query());
      return c.json(await loadReportingTrendsPayload(reportingAccess, query));
    } catch (error: unknown) {
      return reportingServiceErrorResponse(c, error, "Invalid reporting trend query");
    }
  });

  app.get("/v1/tenants/:tenantId/reporting/trends/export.csv", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    try {
      const pageRangeQuery = parseTenantReportingOverviewQuery(c.req.query());
      const query = parseTenantReportingTrendQuery({
        ...toReportingTrendFilters(pageRangeQuery),
        bucket: c.req.query("bucket"),
      });
      return await buildReportingTrendsCsvResponse(reportingAccess, query);
    } catch (error: unknown) {
      return reportingServiceErrorResponse(c, error, "Invalid reporting trend query");
    }
  });

  app.get("/v1/tenants/:tenantId/reporting/comparisons", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    try {
      const query = parseTenantReportingComparisonQuery(c.req.query());
      return c.json(await loadReportingComparisonPayload(reportingAccess, query));
    } catch (error: unknown) {
      return reportingServiceErrorResponse(c, error, "Invalid reporting comparison query");
    }
  });

  app.get("/v1/tenants/:tenantId/reporting/comparisons/export.csv", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    try {
      const pageRangeQuery = parseTenantReportingOverviewQuery(c.req.query());
      const query = parseTenantReportingComparisonQuery({
        ...toReportingComparisonFilters(pageRangeQuery, "badgeTemplate"),
        groupBy: c.req.query("groupBy"),
      });
      return await buildReportingComparisonCsvResponse(reportingAccess, query);
    } catch (error: unknown) {
      return reportingServiceErrorResponse(c, error, "Invalid reporting comparison query");
    }
  });

  app.get("/v1/tenants/:tenantId/reporting/hierarchy", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    try {
      const query = parseTenantReportingHierarchyQuery(c.req.query());
      return c.json(await loadReportingHierarchyPayload(reportingAccess, query));
    } catch (error: unknown) {
      return reportingServiceErrorResponse(c, error, "Invalid reporting hierarchy query");
    }
  });

  app.get("/v1/tenants/:tenantId/reporting/hierarchy/export.csv", async (c) => {
    const reportingAccess = await requireReportingAccess(c);

    if (reportingAccess instanceof Response) {
      return reportingAccess;
    }

    try {
      const pageRangeQuery = parseTenantReportingOverviewQuery(c.req.query());
      const query = parseTenantReportingHierarchyQuery({
        ...toReportingHierarchyFilters({
          ...pageRangeQuery,
          level: c.req.query("level") as never,
          focusOrgUnitId: c.req.query("focusOrgUnitId"),
        }),
        focusOrgUnitId: c.req.query("focusOrgUnitId"),
        level: c.req.query("level"),
      });
      return await buildReportingHierarchyCsvResponse(reportingAccess, query);
    } catch (error: unknown) {
      return reportingServiceErrorResponse(c, error, "Invalid reporting hierarchy query");
    }
  });
};
