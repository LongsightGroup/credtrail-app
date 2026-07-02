import type { SqlDatabase } from "@credtrail/db";
import { parseTenantPathParams } from "@credtrail/validation";
import type { AppContext } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import { ISSUER_ROLES, resolveTenantReportingAccess } from "../auth/tenant-access";

type ReportingAccess = NonNullable<Awaited<ReturnType<typeof resolveTenantReportingAccess>>>;

export interface ReportingRouteAccess {
  tenantId: string;
  db: SqlDatabase;
  reportingAccess: ReportingAccess;
}

export interface ReportingRouteAccessDeps {
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
}

export const createReportingRouteAccessResolver = (deps: ReportingRouteAccessDeps) => {
  return async (c: AppContext): Promise<ReportingRouteAccess | Response> => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await deps.requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = deps.resolveDatabase(c.env);
    const reportingAccess = await resolveTenantReportingAccess({
      db,
      tenantId: pathParams.tenantId,
      userId: roleCheck.session.userId,
      membershipRole: roleCheck.membershipRole,
    });

    if (reportingAccess === null) {
      return c.json(
        {
          error: "Insufficient role for reporting",
        },
        403,
      );
    }

    return {
      tenantId: pathParams.tenantId,
      db,
      reportingAccess,
    };
  };
};
