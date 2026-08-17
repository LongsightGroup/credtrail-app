import type { Hono } from "hono";
import {
  institutionAdminReportingExplorePage,
  institutionAdminReportingPage,
  institutionAdminReportingReportsPage,
  institutionAdminReportingTrendsPage,
} from "../admin/institution-admin/page";
import type { AppContext, AppEnv } from "../app/types";
import type { InstitutionAdminReportingView } from "../admin/institution-admin/page-types";
import type { AppPage } from "../ui/render-page";

type InstitutionAdminPageData = Parameters<typeof institutionAdminReportingPage>[0];

interface RegisterTenantAdminReportingPageRoutesInput {
  app: Hono<AppEnv>;
  renderReportingWorkspace: (
    c: AppContext,
    tenantId: string,
    pagePath: string,
    view: InstitutionAdminReportingView,
    renderPage: (pageData: InstitutionAdminPageData) => AppPage,
  ) => Promise<Response>;
}

export const registerTenantAdminReportingPageRoutes = (
  input: RegisterTenantAdminReportingPageRoutesInput,
): void => {
  const { app, renderReportingWorkspace } = input;

  app.get("/tenants/:tenantId/admin/reporting", async (c) => {
    const tenantId = c.req.param("tenantId");
    return renderReportingWorkspace(
      c,
      tenantId,
      `/tenants/${encodeURIComponent(tenantId)}/admin/reporting`,
      "reporting",
      institutionAdminReportingPage,
    );
  });

  app.get("/tenants/:tenantId/admin/reporting/explore", async (c) => {
    const tenantId = c.req.param("tenantId");
    return renderReportingWorkspace(
      c,
      tenantId,
      `/tenants/${encodeURIComponent(tenantId)}/admin/reporting/explore`,
      "reportingExplore",
      institutionAdminReportingExplorePage,
    );
  });

  app.get("/tenants/:tenantId/admin/reporting/trends", async (c) => {
    const tenantId = c.req.param("tenantId");
    return renderReportingWorkspace(
      c,
      tenantId,
      `/tenants/${encodeURIComponent(tenantId)}/admin/reporting/trends`,
      "reportingTrends",
      institutionAdminReportingTrendsPage,
    );
  });

  app.get("/tenants/:tenantId/admin/reporting/reports", async (c) => {
    const tenantId = c.req.param("tenantId");
    return renderReportingWorkspace(
      c,
      tenantId,
      `/tenants/${encodeURIComponent(tenantId)}/admin/reporting/reports`,
      "reportingReports",
      institutionAdminReportingReportsPage,
    );
  });
};
