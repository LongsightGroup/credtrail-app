import {
  findBadgeTemplateById,
  setBadgeTemplateArchivedState,
  type SqlDatabase,
  type TenantMembershipOrgUnitScopeRole,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseBadgeTemplateImageRevisionPathParams,
  parseBadgeTemplatePathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import {
  badgeTemplateListPageUrl,
  parseBadgeTemplateListPageQuery,
} from "../admin/badge-template-admin-helpers";
import { restoreBadgeTemplateImageRevision } from "../badges/badge-template-image-revision-restore";

interface RegisterBadgeTemplateListAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requireScopedOrgUnitPermission: (
    c: AppContext,
    input: {
      db: SqlDatabase;
      tenantId: string;
      userId: string;
      membershipRole: TenantMembershipRole;
      orgUnitId: string;
      requiredRole: TenantMembershipOrgUnitScopeRole;
      allowWhenNoScopes?: boolean;
    },
  ) => Promise<Response | null>;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        session: { userId: string };
        membershipRole: TenantMembershipRole;
      }
  >;
}

const buildTemplateListPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/rules/templates`;
};

const redirectToTemplateList = (
  c: AppContext,
  tenantId: string,
  listPageQuery: ReturnType<typeof parseBadgeTemplateListPageQuery>,
  extra?: Record<string, string>,
): Response => {
  const location = badgeTemplateListPageUrl(buildTemplateListPath(tenantId), listPageQuery, extra);

  return c.redirect(location, 303);
};

export const registerBadgeTemplateListAdminRoutes = (
  input: RegisterBadgeTemplateListAdminRoutesInput,
): void => {
  const { app, resolveDatabase, requireScopedOrgUnitPermission, resolveInstitutionAdminAdminRole } =
    input;

  const runArchiveAction = async (
    c: AppContext,
    pathParams: ReturnType<typeof parseBadgeTemplatePathParams>,
    archive: boolean,
    listPageQuery: ReturnType<typeof parseBadgeTemplateListPageQuery>,
  ): Promise<Response> => {
    const listPath = buildTemplateListPath(pathParams.tenantId);
    const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, listPath);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const db = resolveDatabase(c.env);
    const template = await findBadgeTemplateById(
      db,
      pathParams.tenantId,
      pathParams.badgeTemplateId,
    );

    if (template === null) {
      return redirectToTemplateList(c, pathParams.tenantId, listPageQuery, {
        listError: "Badge template not found",
      });
    }

    const scopeCheck = await requireScopedOrgUnitPermission(c, {
      db,
      tenantId: pathParams.tenantId,
      userId: session.userId,
      membershipRole,
      orgUnitId: template.ownerOrgUnitId,
      requiredRole: "issuer",
      allowWhenNoScopes: true,
    });

    if (scopeCheck !== null) {
      return scopeCheck;
    }

    const updatedTemplate = await setBadgeTemplateArchivedState(db, {
      tenantId: pathParams.tenantId,
      id: pathParams.badgeTemplateId,
      isArchived: archive,
    });

    if (updatedTemplate === null) {
      return redirectToTemplateList(c, pathParams.tenantId, listPageQuery, {
        listError: "Badge template not found",
      });
    }

    return redirectToTemplateList(c, pathParams.tenantId, listPageQuery, {
      listNotice: archive ? "Badge template archived." : "Badge template restored.",
    });
  };

  app.post("/tenants/:tenantId/admin/rules/templates/:badgeTemplateId/archive", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const listPageQuery = parseBadgeTemplateListPageQuery(c.req.query());

    return runArchiveAction(c, pathParams, true, listPageQuery);
  });

  app.post("/tenants/:tenantId/admin/rules/templates/:badgeTemplateId/unarchive", async (c) => {
    const pathParams = parseBadgeTemplatePathParams(c.req.param());
    const listPageQuery = parseBadgeTemplateListPageQuery(c.req.query());

    return runArchiveAction(c, pathParams, false, listPageQuery);
  });

  app.post(
    "/tenants/:tenantId/admin/rules/templates/:badgeTemplateId/image-revisions/:revisionId/restore",
    async (c) => {
      const pathParams = parseBadgeTemplateImageRevisionPathParams(c.req.param());
      const listPageQuery = parseBadgeTemplateListPageQuery(c.req.query());
      const listPath = buildTemplateListPath(pathParams.tenantId);
      const roleCheck = await resolveInstitutionAdminAdminRole(c, pathParams.tenantId, listPath);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { session, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const template = await findBadgeTemplateById(
        db,
        pathParams.tenantId,
        pathParams.badgeTemplateId,
      );

      if (template === null) {
        return redirectToTemplateList(c, pathParams.tenantId, listPageQuery, {
          listError: "Badge template not found",
        });
      }

      const scopeCheck = await requireScopedOrgUnitPermission(c, {
        db,
        tenantId: pathParams.tenantId,
        userId: session.userId,
        membershipRole,
        orgUnitId: template.ownerOrgUnitId,
        requiredRole: "issuer",
        allowWhenNoScopes: true,
      });

      if (scopeCheck !== null) {
        return scopeCheck;
      }

      const result = await restoreBadgeTemplateImageRevision({
        db,
        tenantId: pathParams.tenantId,
        badgeTemplateId: pathParams.badgeTemplateId,
        revisionId: pathParams.revisionId,
        actorUserId: session.userId,
        membershipRole,
      });

      if ("status" in result) {
        return redirectToTemplateList(c, pathParams.tenantId, listPageQuery, {
          history: "1",
          badgeTemplateId: pathParams.badgeTemplateId,
          listError: result.message,
        });
      }

      const historyUrl = badgeTemplateListPageUrl(
        buildTemplateListPath(pathParams.tenantId),
        listPageQuery,
        {
          badgeTemplateId: pathParams.badgeTemplateId,
          history: "1",
          listNotice: "Badge image restored.",
        },
      );

      return c.redirect(historyUrl, 303);
    },
  );
};
