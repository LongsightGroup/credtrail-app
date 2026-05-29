import {
  retryFailedImportLearnerRecordBatchQueueMessages,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseAdminLearnerRecordReviewQuery,
  parseLearnerRecordImportBatchPathParams,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { institutionAdminLearnerRecordsPage } from "../admin/institution-admin-page";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { AppPage } from "../ui/render-page";
import { renderAppPage } from "../ui/render-page";

type InstitutionAdminPageData = Parameters<typeof institutionAdminLearnerRecordsPage>[0];
type LearnerRecordImportWorkflowInput = Pick<
  NonNullable<InstitutionAdminPageData["learnerRecordImportWorkflow"]>,
  "defaults" | "submission" | "feedback"
>;

interface RegisterTenantLearnerRecordAdminRoutesInput {
  app: Hono<AppEnv>;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  adminRoleRequiredPage: (tenantId: string) => AppPage;
  handleLearnerRecordImportUpload: (input: {
    c: AppContext;
    tenantId: string;
    sessionUserId: string;
    membershipRole: TenantMembershipRole;
    mode: "preview" | "apply";
  }) => Promise<Response>;
  loadLearnerRecordReviewPageData: (input: {
    c: AppContext;
    tenantId: string;
    sessionUserId: string;
    membershipRole: TenantMembershipRole;
    learnerProfileId?: string;
    email?: string;
  }) => Promise<InstitutionAdminPageData | Response>;
  redirectToTenantLogin: (c: AppContext, tenantId: string, nextPath: string) => Response;
  renderLearnerRecordImportWorkspace: (
    c: AppContext,
    tenantId: string,
    sessionUserId: string,
    membershipRole: TenantMembershipRole,
    workflow?: LearnerRecordImportWorkflowInput,
  ) => Promise<Response>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        session: { userId: string };
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
}

export const registerTenantLearnerRecordAdminRoutes = (
  input: RegisterTenantLearnerRecordAdminRoutesInput,
): void => {
  const {
    app,
    ADMIN_ROLES,
    adminRoleRequiredPage,
    handleLearnerRecordImportUpload,
    loadLearnerRecordReviewPageData,
    redirectToTenantLogin,
    renderLearnerRecordImportWorkspace,
    resolveDatabase,
    requireTenantRole,
  } = input;

  app.get("/tenants/:tenantId/admin/operations/learner-record-imports", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(
          c,
          pathParams.tenantId,
          `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/learner-record-imports`,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return renderAppPage(c, adminRoleRequiredPage(pathParams.tenantId), 403);
      }

      return roleCheck;
    }

    return renderLearnerRecordImportWorkspace(
      c,
      pathParams.tenantId,
      roleCheck.session.userId,
      roleCheck.membershipRole,
    );
  });

  app.post("/tenants/:tenantId/admin/operations/learner-record-imports/preview", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(
          c,
          pathParams.tenantId,
          `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/learner-record-imports`,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return renderAppPage(c, adminRoleRequiredPage(pathParams.tenantId), 403);
      }

      return roleCheck;
    }

    return handleLearnerRecordImportUpload({
      c,
      tenantId: pathParams.tenantId,
      sessionUserId: roleCheck.session.userId,
      membershipRole: roleCheck.membershipRole,
      mode: "preview",
    });
  });

  app.post("/tenants/:tenantId/admin/operations/learner-record-imports/apply", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(
          c,
          pathParams.tenantId,
          `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/learner-record-imports`,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return renderAppPage(c, adminRoleRequiredPage(pathParams.tenantId), 403);
      }

      return roleCheck;
    }

    return handleLearnerRecordImportUpload({
      c,
      tenantId: pathParams.tenantId,
      sessionUserId: roleCheck.session.userId,
      membershipRole: roleCheck.membershipRole,
      mode: "apply",
    });
  });

  app.post(
    "/tenants/:tenantId/admin/operations/learner-record-imports/:batchId/retry",
    async (c) => {
      let pathParams;

      try {
        pathParams = parseLearnerRecordImportBatchPathParams(c.req.param());
      } catch {
        return c.json(
          {
            error: "Invalid learner-record import batch path",
          },
          400,
        );
      }

      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

      if (roleCheck instanceof Response) {
        if (roleCheck.status === 401) {
          return redirectToTenantLogin(
            c,
            pathParams.tenantId,
            `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/learner-record-imports`,
          );
        }

        if (roleCheck.status === 403) {
          c.header("Cache-Control", "no-store");
          return renderAppPage(c, adminRoleRequiredPage(pathParams.tenantId), 403);
        }

        return roleCheck;
      }

      const retryResult = await retryFailedImportLearnerRecordBatchQueueMessages(
        resolveDatabase(c.env),
        {
          tenantId: pathParams.tenantId,
          batchId: pathParams.batchId,
        },
      );

      return renderLearnerRecordImportWorkspace(
        c,
        pathParams.tenantId,
        roleCheck.session.userId,
        roleCheck.membershipRole,
        {
          defaults: {
            defaultTrustLevel: "issuer_verified",
            defaultIssuerName: "",
          },
          submission: null,
          feedback:
            retryResult.matched === 0
              ? {
                  tone: "warning",
                  title: "Import batch not found",
                  detail: `Batch ${pathParams.batchId} is not available for retry in this tenant.`,
                }
              : {
                  tone: "success",
                  title: "Failed rows retried",
                  detail: `Retried ${String(retryResult.retried)} failed rows from batch ${pathParams.batchId}.`,
                },
        },
      );
    },
  );

  app.get("/tenants/:tenantId/admin/operations/learner-records", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      if (roleCheck.status === 401) {
        return redirectToTenantLogin(
          c,
          pathParams.tenantId,
          `/tenants/${encodeURIComponent(pathParams.tenantId)}/admin/operations/learner-records`,
        );
      }

      if (roleCheck.status === 403) {
        c.header("Cache-Control", "no-store");
        return renderAppPage(c, adminRoleRequiredPage(pathParams.tenantId), 403);
      }

      return roleCheck;
    }

    let reviewQuery;

    try {
      reviewQuery = parseAdminLearnerRecordReviewQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid learner-record review query",
        },
        400,
      );
    }

    const pageData = await loadLearnerRecordReviewPageData({
      c,
      tenantId: pathParams.tenantId,
      sessionUserId: roleCheck.session.userId,
      membershipRole: roleCheck.membershipRole,
      ...(reviewQuery.learnerProfileId ? { learnerProfileId: reviewQuery.learnerProfileId } : {}),
      ...(reviewQuery.email ? { email: reviewQuery.email } : {}),
    });

    if (pageData instanceof Response) {
      return pageData;
    }

    c.header("Cache-Control", "no-store");
    return renderAppPage(c, institutionAdminLearnerRecordsPage(pageData));
  });
};
