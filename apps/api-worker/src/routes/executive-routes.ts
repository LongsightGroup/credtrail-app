import type { TenantMembershipRole } from "@credtrail/db";
import { parseTenantExecutiveDashboardQuery, parseTenantPathParams } from "@credtrail/validation";
import type { Hono } from "hono";

import type { AppContext, AppEnv } from "../app/types";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import {
  renderExecutiveDashboardPage,
  renderExecutiveUnavailablePage,
  renderInvalidExecutiveDashboardRequestPage,
} from "../executive/executive-dashboard-page";
import {
  loadTenantExecutiveDashboard,
  type TenantExecutiveDashboardRecord,
} from "../executive/executive-rollup-loader";
import { renderAppPage } from "../ui/render-page";

interface RegisterExecutiveRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  TENANT_MEMBER_ROLES: readonly TenantMembershipRole[];
}

export const registerExecutiveRoutes = (input: RegisterExecutiveRoutesInput): void => {
  const { app, resolveDatabase, requireTenantRole, TENANT_MEMBER_ROLES } = input;

  const loadExecutiveDashboardFromRequest = async (
    c: AppContext,
  ): Promise<
    | {
        tenantId: string;
        membershipRole: TenantMembershipRole;
        dashboard: TenantExecutiveDashboardRecord | null;
      }
    | Response
  > => {
    const { tenantId } = parseTenantPathParams(c.req.param());
    const tenantAccess = await requireTenantRole(c, tenantId, TENANT_MEMBER_ROLES);

    if (tenantAccess instanceof Response) {
      return tenantAccess;
    }

    let query;

    try {
      query = parseTenantExecutiveDashboardQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid executive dashboard query",
        },
        400,
      );
    }

    const dashboard = await loadTenantExecutiveDashboard({
      db: resolveDatabase(c.env),
      tenantId,
      userId: tenantAccess.principal.userId,
      membershipRole: tenantAccess.membershipRole,
      query,
    });

    return {
      tenantId,
      membershipRole: tenantAccess.membershipRole,
      dashboard,
    };
  };

  app.get("/v1/tenants/:tenantId/executive", async (c) => {
    const result = await loadExecutiveDashboardFromRequest(c);

    if (result instanceof Response) {
      return result;
    }

    if (result.dashboard === null) {
      return c.json(
        {
          error: "Executive dashboard access is unavailable for this tenant scope",
        },
        403,
      );
    }

    return c.json({
      status: "ok",
      dashboard: result.dashboard,
    });
  });

  app.get("/tenants/:tenantId/executive", async (c) => {
    const result = await loadExecutiveDashboardFromRequest(c);

    if (result instanceof Response) {
      if (result.status !== 400) {
        return result;
      }

      return renderAppPage(c, renderInvalidExecutiveDashboardRequestPage(), 400);
    }

    if (result.dashboard === null) {
      return renderAppPage(c, renderExecutiveUnavailablePage(), 403);
    }

    return renderAppPage(c, renderExecutiveDashboardPage(result.dashboard));
  });
};
