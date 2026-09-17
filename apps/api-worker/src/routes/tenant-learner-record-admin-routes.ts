import { learnerRecordImportRowReportsFromJson } from "../learner-record/learner-record-import-queue";
import { serializeCsv, buildCsvAttachmentHeaders } from "../reporting/csv-export";
import { badgeRecordsReturnHref } from "../admin/learner-record-link";
import {
  retryFailedImportLearnerRecordBatchQueueMessages,
  findActiveLearnerRecordImportPreview,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseAdminLearnerRecordReviewQuery,
  parseLearnerRecordImportBatchPathParams,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { institutionAdminLearnerRecordsPage } from "../admin/institution-admin/page";
import type { AppContext, AppEnv } from "../app/types";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
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
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
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
      roleCheck.principal.userId,
      roleCheck.membershipRole,
    );
  });

  app.get(
    "/tenants/:tenantId/admin/operations/learner-record-imports/:batchId/errors.csv",
    async (c) => {
      c.header("Cache-Control", "no-store");
      let params;
      try {
        params = parseLearnerRecordImportBatchPathParams(c.req.param());
      } catch {
        return c.text("Check the error report link and try again.", 400);
      }
      const authorized = await requireTenantRole(c, params.tenantId, ADMIN_ROLES);
      if (authorized instanceof Response) return authorized;
      const preview = await findActiveLearnerRecordImportPreview(resolveDatabase(c.env), {
        ...params,
        nowIso: new Date().toISOString(),
      });
      if (!preview)
        return c.text(
          "This preview is unavailable or expired. Upload the CSV again to generate its error report.",
          404,
        );
      const reports = learnerRecordImportRowReportsFromJson(preview.reportsJson);
      if (!reports) return c.text("The error report is unavailable. Preview the CSV again.", 422);
      const rows = reports
        .filter((row) => row.status === "invalid" || row.warnings.length > 0)
        .map((row) => ({
          row: row.rowNumber,
          status: row.status,
          learner: row.preview?.learner.email ?? "",
          errors: row.errors.join("; "),
          warnings: row.warnings.join("; "),
          nextStep:
            row.status === "invalid"
              ? "Correct the listed fields in this CSV row, then upload and preview the corrected file."
              : "Check the warnings and inferred values before importing this row.",
        }));
      return c.body(
        serializeCsv({
          rows,
          columns: [
            { key: "row", header: "CSV row" },
            { key: "status", header: "Status" },
            { key: "learner", header: "Learner email" },
            { key: "errors", header: "Errors to correct" },
            { key: "warnings", header: "Warnings to review" },
            { key: "nextStep", header: "Next step" },
          ],
        }),
        200,
        buildCsvAttachmentHeaders("learner-import-errors.csv"),
      );
    },
  );

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
      sessionUserId: roleCheck.principal.userId,
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
      sessionUserId: roleCheck.principal.userId,
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
        roleCheck.principal.userId,
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
      sessionUserId: roleCheck.principal.userId,
      membershipRole: roleCheck.membershipRole,
      ...(reviewQuery.learner ? { learner: reviewQuery.learner } : {}),
    });

    if (pageData instanceof Response) {
      return pageData;
    }

    c.header("Cache-Control", "no-store");
    const returnHref = badgeRecordsReturnHref(pathParams.tenantId, c.req.query("returnTo"));
    return renderAppPage(
      c,
      institutionAdminLearnerRecordsPage({
        ...pageData,
        ...(pageData.learnerRecordReview === undefined
          ? {}
          : { learnerRecordReview: { ...pageData.learnerRecordReview, returnHref } }),
      }),
    );
  });
};
