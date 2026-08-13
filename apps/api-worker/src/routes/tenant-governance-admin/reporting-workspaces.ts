import { parseTenantReportingOverviewQuery } from "@credtrail/validation";
import { renderAppPage, type AppPage } from "../../ui/render-page";
import type { AppContext } from "../../app";
import { buildLocalTwoFactorPath } from "../../auth/break-glass-policy";
import { applySmartReportingDefaults } from "../../reporting/reporting-defaults";
import type { InstitutionAdminPageData } from "../institution-admin-page-data-loader";
import { reportingAccessRequiredPage } from "../tenant-governance-shared-pages";
import type { RegisterTenantGovernanceRoutesInput } from "../tenant-governance-routes.types";
import type { TenantGovernanceAdminAuth } from "./auth";
import type { TenantGovernanceAdminPageDataLoaders } from "./page-data";

export const createTenantGovernanceReportingAdminWorkspaces = (input: {
  requireTenantRole: RegisterTenantGovernanceRoutesInput["requireTenantRole"];
  ISSUER_ROLES: RegisterTenantGovernanceRoutesInput["ISSUER_ROLES"];
  redirectToTenantLogin: TenantGovernanceAdminAuth["redirectToTenantLogin"];
  loadReportingPageData: TenantGovernanceAdminPageDataLoaders["loadReportingPageData"];
}) => {
  const { requireTenantRole, ISSUER_ROLES, redirectToTenantLogin, loadReportingPageData } = input;

  const renderReportingWorkspace = async (
    c: AppContext,
    tenantId: string,
    pagePath: string,
    renderPage: (pageData: InstitutionAdminPageData) => AppPage,
  ): Promise<Response> => {
    const roleCheck = await requireTenantRole(c, tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(c, tenantId, pagePath);
      }

      if (roleCheck.status === 423) {
        return c.redirect(
          buildLocalTwoFactorPath({
            tenantId,
            nextPath: pagePath,
            setup: true,
            reason: "break_glass_mfa_setup_pending",
          }),
          302,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return renderAppPage(c, reportingAccessRequiredPage(tenantId), 403);
      }

      return roleCheck;
    }

    let reportingQuery: ReturnType<typeof parseTenantReportingOverviewQuery>;

    try {
      reportingQuery = applySmartReportingDefaults({
        query: parseTenantReportingOverviewQuery(c.req.query()),
      });
    } catch {
      return c.json(
        {
          error: "Invalid reporting overview query",
        },
        400,
      );
    }

    const { session, membershipRole } = roleCheck;
    const pageData = await loadReportingPageData({
      c,
      tenantId,
      sessionUserId: session.userId,
      membershipRole,
      issuedFrom: reportingQuery.issuedFrom,
      issuedTo: reportingQuery.issuedTo,
      badgeTemplateId: reportingQuery.badgeTemplateId,
      orgUnitId: reportingQuery.orgUnitId,
      state: reportingQuery.state,
    });

    if (pageData instanceof Response) {
      return pageData;
    }

    c.header("Cache-Control", "no-store");

    return renderAppPage(c, renderPage(pageData));
  };

  return { renderReportingWorkspace };
};
