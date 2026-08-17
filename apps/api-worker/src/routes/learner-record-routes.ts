import {
  createLearnerRecordEntry,
  listImportLearnerRecordBatchQueueMessages,
  listLearnerRecordEntries,
  patchLearnerRecordEntry,
  retryFailedImportLearnerRecordBatchQueueMessages,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  parseCreateLearnerRecordEntryRequest,
  parseLearnerRecordEntryListQuery,
  parseLearnerRecordEntryPathParams,
  parseLearnerRecordImportBatchDefaults,
  parseLearnerRecordImportBatchPathParams,
  parseLearnerRecordImportProgressQuery,
  parseLearnerRecordImportRetryRequest,
  parseLearnerRecordImportUploadQuery,
  parsePatchLearnerRecordEntryRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";

import type { AppEnv } from "../app/types";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import { mapLearnerRecordEntryToCanonicalLearnerRecordItem } from "../learner-record/learner-record-contract";
import { buildLearnerRecordImportTemplateCsv } from "../learner-record/learner-record-import-file";
import { prepareLearnerRecordImportSubmission } from "../learner-record/learner-record-import-preparation";
import { summarizeLearnerRecordImportProgress } from "../learner-record/learner-record-import-progress";
import { enqueueLearnerRecordImportBatch } from "../learner-record/learner-record-import-queue";

interface RegisterLearnerRecordRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  ADMIN_ROLES: readonly TenantMembershipRole[];
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

const getOptionalFormValue = (formData: FormData, name: string): string | undefined => {
  const value = formData.get(name);

  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length === 0 ? undefined : trimmed;
};

export const registerLearnerRecordRoutes = (input: RegisterLearnerRecordRoutesInput): void => {
  const { app, resolveDatabase, requireTenantRole, ADMIN_ROLES, ISSUER_ROLES } = input;

  app.get("/v1/tenants/:tenantId/learner-record-imports/template.csv", async (c) => {
    let pathParams;

    try {
      pathParams = parseTenantPathParams(c.req.param());
    } catch {
      return c.json(
        {
          error: "Invalid learner-record import path",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    c.header("Cache-Control", "no-store");
    c.header("Content-Type", "text/csv; charset=utf-8");
    c.header(
      "Content-Disposition",
      `attachment; filename="${encodeURIComponent(pathParams.tenantId)}-learner-record-import-template.csv"`,
    );

    return c.body(buildLearnerRecordImportTemplateCsv(), 200);
  });

  app.post("/v1/tenants/:tenantId/learner-record-imports/csv", async (c) => {
    let pathParams;
    let query;

    try {
      pathParams = parseTenantPathParams(c.req.param());
      query = parseLearnerRecordImportUploadQuery({
        dryRun: c.req.query("dryRun"),
      });
    } catch {
      return c.json(
        {
          error: "Invalid learner-record import request",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const contentType = c.req.header("content-type")?.toLowerCase() ?? "";

    if (!contentType.includes("multipart/form-data")) {
      return c.json(
        {
          error:
            'Learner-record import requires multipart/form-data with a file field named "file"',
        },
        415,
      );
    }

    const formData = await c.req.formData();
    const upload = formData.get("file");

    if (!(upload instanceof File)) {
      return c.json(
        {
          error: 'Learner-record import file is required in form field "file"',
        },
        400,
      );
    }

    const fileContent = await upload.text();

    if (fileContent.trim().length === 0) {
      return c.json(
        {
          error: "Uploaded learner-record CSV is empty",
        },
        422,
      );
    }

    let defaults;

    try {
      defaults = parseLearnerRecordImportBatchDefaults({
        defaultTrustLevel: getOptionalFormValue(formData, "defaultTrustLevel"),
        defaultIssuerName: getOptionalFormValue(formData, "defaultIssuerName"),
      });
    } catch {
      return c.json(
        {
          error: "Invalid learner-record import defaults",
        },
        400,
      );
    }

    const db = resolveDatabase(c.env);
    let prepared;

    try {
      prepared = await prepareLearnerRecordImportSubmission(db, {
        tenantId: pathParams.tenantId,
        fileName: upload.name,
        content: fileContent,
        defaults,
        requestedAt: new Date().toISOString(),
        requestedByUserId: roleCheck.principal.userId,
      });
    } catch (error: unknown) {
      if (error instanceof Error && error.message.startsWith("Tenant ")) {
        return c.json(
          {
            error: "Tenant not found",
          },
          404,
        );
      }

      return c.json(
        {
          error: error instanceof Error ? error.message : "Invalid learner-record import file",
        },
        422,
      );
    }

    const queuedRows = query.dryRun
      ? 0
      : await enqueueLearnerRecordImportBatch(db, pathParams.tenantId, prepared.queuePayloads);

    const validRows = prepared.reports.filter((report) => report.status === "valid").length;
    const invalidRows = prepared.reports.length - validRows;

    c.header("Cache-Control", "no-store");

    return c.json(
      {
        tenantId: pathParams.tenantId,
        batchId: prepared.batchId,
        fileName: prepared.fileName,
        format: prepared.format,
        dryRun: query.dryRun,
        defaults: prepared.defaults,
        totalRows: prepared.reports.length,
        validRows,
        invalidRows,
        queuedRows,
        rows: prepared.reports,
      },
      200,
    );
  });

  app.get("/v1/tenants/:tenantId/learner-record-imports/progress", async (c) => {
    let pathParams;
    let query;

    try {
      pathParams = parseTenantPathParams(c.req.param());
      query = parseLearnerRecordImportProgressQuery({
        limit: c.req.query("limit"),
      });
    } catch {
      return c.json(
        {
          error: "Invalid learner-record import progress query",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const messages = await listImportLearnerRecordBatchQueueMessages(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      limit: query.limit,
    });
    const progress = summarizeLearnerRecordImportProgress(messages);

    c.header("Cache-Control", "no-store");

    return c.json(
      {
        tenantId: pathParams.tenantId,
        filters: {
          limit: query.limit,
        },
        totals: progress.totals,
        batches: progress.batches,
      },
      200,
    );
  });

  app.post("/v1/tenants/:tenantId/learner-record-imports/:batchId/retry", async (c) => {
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

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    let rawBody: unknown = {};
    const contentType = c.req.header("content-type")?.toLowerCase() ?? "";

    if (contentType.includes("application/json")) {
      const bodyText = await c.req.text();

      if (bodyText.trim().length > 0) {
        try {
          rawBody = JSON.parse(bodyText) as unknown;
        } catch {
          return c.json(
            {
              error: "Invalid learner-record import retry payload",
            },
            400,
          );
        }
      }
    } else if (contentType.length > 0) {
      try {
        rawBody = await c.req.json<unknown>();
      } catch {
        return c.json(
          {
            error: "Invalid learner-record import retry payload",
          },
          400,
        );
      }
    }

    let request;

    try {
      request = parseLearnerRecordImportRetryRequest(rawBody);
    } catch {
      return c.json(
        {
          error: "Invalid learner-record import retry payload",
        },
        400,
      );
    }

    const retryResult = await retryFailedImportLearnerRecordBatchQueueMessages(
      resolveDatabase(c.env),
      {
        tenantId: pathParams.tenantId,
        batchId: pathParams.batchId,
        ...(request.rowNumbers === undefined ? {} : { rowNumbers: request.rowNumbers }),
      },
    );

    if (retryResult.matched === 0) {
      return c.json(
        {
          error: "Learner-record import batch was not found for tenant",
        },
        404,
      );
    }

    const refreshedMessages = await listImportLearnerRecordBatchQueueMessages(
      resolveDatabase(c.env),
      {
        tenantId: pathParams.tenantId,
        limit: 1000,
      },
    );
    const refreshedProgress = summarizeLearnerRecordImportProgress(
      refreshedMessages.filter((message) => message.batchId === pathParams.batchId),
    );
    const batch = refreshedProgress.batches[0] ?? null;

    c.header("Cache-Control", "no-store");

    return c.json(
      {
        tenantId: pathParams.tenantId,
        batchId: pathParams.batchId,
        retry: retryResult,
        batch,
      },
      200,
    );
  });

  app.get("/v1/tenants/:tenantId/learner-record-entries", async (c) => {
    let pathParams;
    let query;

    try {
      pathParams = parseTenantPathParams(c.req.param());
      query = parseLearnerRecordEntryListQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid learner-record query",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const entries = await listLearnerRecordEntries(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      learnerProfileId: query.learnerProfileId,
      ...(query.trustLevel === undefined ? {} : { trustLevel: query.trustLevel }),
      ...(query.status === undefined ? {} : { status: query.status }),
    });

    c.header("Cache-Control", "no-store");

    return c.json({
      tenantId: pathParams.tenantId,
      learnerProfileId: query.learnerProfileId,
      count: entries.length,
      items: entries.map((entry) => mapLearnerRecordEntryToCanonicalLearnerRecordItem(entry)),
    });
  });

  app.post("/v1/tenants/:tenantId/learner-record-entries", async (c) => {
    let pathParams;
    let request;

    try {
      pathParams = parseTenantPathParams(c.req.param());
      request = parseCreateLearnerRecordEntryRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid learner-record payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const created = await createLearnerRecordEntry(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      learnerProfileId: request.learnerProfileId,
      trustLevel: request.trustLevel,
      recordType: request.recordType,
      title: request.title,
      ...(request.description === undefined ? {} : { description: request.description }),
      status: request.status,
      issuerName: request.provenance.issuerName,
      issuerUserId: request.provenance.issuerUserId ?? roleCheck.principal.userId,
      sourceSystem: request.provenance.sourceSystem,
      ...(request.provenance.sourceRecordId === undefined
        ? {}
        : { sourceRecordId: request.provenance.sourceRecordId }),
      issuedAt: request.provenance.issuedAt,
      ...(request.provenance.revisedAt === undefined
        ? {}
        : { revisedAt: request.provenance.revisedAt }),
      ...(request.provenance.revokedAt === undefined
        ? {}
        : { revokedAt: request.provenance.revokedAt }),
      evidenceLinks: request.provenance.evidenceLinks,
      ...(request.details === undefined ? {} : { detailsJson: JSON.stringify(request.details) }),
    });

    c.header("Cache-Control", "no-store");

    return c.json(
      {
        status: "created",
        item: mapLearnerRecordEntryToCanonicalLearnerRecordItem(created),
      },
      201,
    );
  });

  app.patch("/v1/tenants/:tenantId/learner-record-entries/:entryId", async (c) => {
    let pathParams;
    let request;

    try {
      pathParams = parseLearnerRecordEntryPathParams(c.req.param());
      request = parsePatchLearnerRecordEntryRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid learner-record payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const updated = await patchLearnerRecordEntry(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      entryId: pathParams.entryId,
      ...(request.trustLevel === undefined ? {} : { trustLevel: request.trustLevel }),
      ...(request.recordType === undefined ? {} : { recordType: request.recordType }),
      ...(request.title === undefined ? {} : { title: request.title }),
      ...(request.description === undefined ? {} : { description: request.description }),
      ...(request.status === undefined ? {} : { status: request.status }),
      ...(request.provenance === undefined
        ? {}
        : {
            issuerName: request.provenance.issuerName,
            ...(request.provenance.issuerUserId === undefined
              ? {}
              : { issuerUserId: request.provenance.issuerUserId }),
            sourceSystem: request.provenance.sourceSystem,
            ...(request.provenance.sourceRecordId === undefined
              ? {}
              : { sourceRecordId: request.provenance.sourceRecordId }),
            issuedAt: request.provenance.issuedAt,
            ...(request.provenance.revisedAt === undefined
              ? {}
              : { revisedAt: request.provenance.revisedAt }),
            ...(request.provenance.revokedAt === undefined
              ? {}
              : { revokedAt: request.provenance.revokedAt }),
            evidenceLinks: request.provenance.evidenceLinks,
          }),
      ...(request.details === undefined ? {} : { detailsJson: JSON.stringify(request.details) }),
    });

    if (updated === null) {
      return c.json(
        {
          error: "Learner-record entry not found",
        },
        404,
      );
    }

    c.header("Cache-Control", "no-store");

    return c.json({
      status: "updated",
      item: mapLearnerRecordEntryToCanonicalLearnerRecordItem(updated),
    });
  });
};
