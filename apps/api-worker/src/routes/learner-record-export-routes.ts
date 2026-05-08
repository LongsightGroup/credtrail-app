import type { SqlDatabase, TenantMembershipRole } from "@credtrail/db";
import {
  parseLearnerRecordExportPathParams,
  parseLearnerRecordExportQuery,
  parseLearnerRecordStandardsMappingQuery,
} from "@credtrail/validation";
import type { Hono } from "hono";

import type { AppBindings, AppContext, AppEnv } from "../app";
import {
  buildLearnerRecordStandardsMappingResponse,
  loadLearnerRecordExportBundle,
  serializeLearnerRecordExport,
} from "../learner-record/learner-record-export";

interface RegisterLearnerRecordExportRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  ADMIN_ROLES: readonly TenantMembershipRole[];
}

export const registerLearnerRecordExportRoutes = (
  input: RegisterLearnerRecordExportRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, ADMIN_ROLES } = input;

  app.get("/v1/tenants/:tenantId/learner-records/:learnerProfileId/export", async (c) => {
    let pathParams;
    let query;

    try {
      pathParams = parseLearnerRecordExportPathParams(c.req.param());
      query = parseLearnerRecordExportQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid learner-record export request",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const bundle = await loadLearnerRecordExportBundle(resolveDatabase(c.env), pathParams);

    if (bundle === null) {
      return c.json(
        {
          error: "Learner profile not found",
        },
        404,
      );
    }

    c.header("Cache-Control", "no-store");

    return c.json(serializeLearnerRecordExport(bundle, query.profile));
  });

  app.get(
    "/v1/tenants/:tenantId/learner-records/:learnerProfileId/standards-mapping",
    async (c) => {
      let pathParams;
      let query;

      try {
        pathParams = parseLearnerRecordExportPathParams(c.req.param());
        query = parseLearnerRecordStandardsMappingQuery(c.req.query());
      } catch {
        return c.json(
          {
            error: "Invalid learner-record standards mapping request",
          },
          400,
        );
      }

      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const bundle = await loadLearnerRecordExportBundle(resolveDatabase(c.env), pathParams);

      if (bundle === null) {
        return c.json(
          {
            error: "Learner profile not found",
          },
          404,
        );
      }

      c.header("Cache-Control", "no-store");

      return c.json(buildLearnerRecordStandardsMappingResponse(bundle, query.profile));
    },
  );
};
