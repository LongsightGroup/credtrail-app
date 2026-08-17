import {
  enqueueJobQueueMessage,
  findLearnerProfileByIdentity,
  listBadgeTemplates,
  listImportMigrationBatchQueueMessages,
  retryFailedImportMigrationBatchQueueMessages,
  type ImportMigrationBatchQueueMessageRecord,
  type LearnerIdentityType,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  ob2ImportConversionRequestSchema,
  parseMigrationBatchPathParams,
  parseMigrationBatchRetryRequest,
  parseMigrationBatchUploadQuery,
  parseMigrationProgressQuery,
  parseOb2ImportConversionRequest,
  parseTenantPathParams,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app/types";
import type { RequireTenantRole } from "../app/route-deps";
import {
  MigrationBatchFileParseError,
  parseMigrationBatchUploadFile,
  type MigrationBatchFileFormat,
} from "../migrations/batch-upload";
import { CredlyExportFileParseError, parseCredlyExportFile } from "../migrations/credly-export";
import {
  Ob2ImportError,
  prepareOb2ImportConversion,
  type Ob2ImportConversionResult,
} from "../migrations/ob2-import";
import {
  ParchmentExportFileParseError,
  parseParchmentExportFile,
} from "../migrations/parchment-export";

interface RegisterMigrationRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppContext["env"]) => SqlDatabase;
  requireTenantRole: RequireTenantRole;
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

type MigrationBatchSource = "file_upload" | "credly_export" | "parchment_export";

interface ParsedMigrationUploadFile {
  format: MigrationBatchFileFormat;
  rows: readonly {
    rowNumber: number;
    candidate: Record<string, unknown>;
  }[];
}

interface MigrationFileIngestRoute {
  path: string;
  requestLabel: string;
  queryErrorSubject: string;
  source: MigrationBatchSource;
  includeSourceInResponse: boolean;
  parseFile: (input: {
    fileName: string;
    mimeType: string;
    content: string;
  }) => ParsedMigrationUploadFile;
  parseErrorMessage: (error: unknown) => string | null;
}

const MIGRATION_FILE_INGEST_ROUTES = [
  {
    path: "/v1/tenants/:tenantId/migrations/ob2/batch-upload",
    requestLabel: "Batch upload",
    queryErrorSubject: "batch upload",
    source: "file_upload",
    includeSourceInResponse: false,
    parseFile: parseMigrationBatchUploadFile,
    parseErrorMessage: (error: unknown): string | null =>
      error instanceof MigrationBatchFileParseError ? error.message : null,
  },
  {
    path: "/v1/tenants/:tenantId/migrations/credly/ingest",
    requestLabel: "Credly ingest",
    queryErrorSubject: "credly ingest",
    source: "credly_export",
    includeSourceInResponse: true,
    parseFile: parseCredlyExportFile,
    parseErrorMessage: (error: unknown): string | null =>
      error instanceof CredlyExportFileParseError ? error.message : null,
  },
  {
    path: "/v1/tenants/:tenantId/migrations/parchment/ingest",
    requestLabel: "Parchment ingest",
    queryErrorSubject: "parchment ingest",
    source: "parchment_export",
    includeSourceInResponse: true,
    parseFile: parseParchmentExportFile,
    parseErrorMessage: (error: unknown): string | null =>
      error instanceof ParchmentExportFileParseError ? error.message : null,
  },
] as const satisfies readonly MigrationFileIngestRoute[];

interface DryRunDiffPreview {
  badgeTemplate: {
    operation: "create" | "update";
    existingTemplateId?: string;
    changedFields: string[];
    proposed: Ob2ImportConversionResult["createBadgeTemplateRequest"];
  };
  learnerProfile: {
    operation: "create" | "reuse";
    existingProfileId?: string;
    recipientIdentity: string;
    recipientIdentityType: Ob2ImportConversionResult["manualIssueRequest"]["recipientIdentityType"];
  };
  assertionIssue: {
    operation: "queue_issue";
    recipientIdentity: string;
    recipientIdentityType: Ob2ImportConversionResult["manualIssueRequest"]["recipientIdentityType"];
  };
  summary: {
    creates: number;
    updates: number;
  };
}

interface BatchUploadRowValidationResult {
  rowNumber: number;
  status: "valid" | "invalid";
  errors: string[];
  warnings: string[];
  diffPreview: DryRunDiffPreview | null;
}

interface MigrationBatchProgressSummary {
  batchId: string;
  source: MigrationBatchSource | "unknown";
  fileName: string | null;
  format: string | null;
  totalRows: number;
  pendingRows: number;
  processingRows: number;
  completedRows: number;
  failedRows: number;
  retryableRows: number;
  failedRowNumbers: number[];
  latestError: string | null;
  firstQueuedAt: string;
  lastUpdatedAt: string;
}

const learnerIdentityTypeFromRecipientIdentityType = (
  identityType: Ob2ImportConversionResult["manualIssueRequest"]["recipientIdentityType"],
): LearnerIdentityType => {
  if (identityType === "email") {
    return "email";
  }

  if (identityType === "email_sha256") {
    return "email_sha256";
  }

  if (identityType === "did") {
    return "did";
  }

  return "url";
};

const zodIssueMessages = (
  issues: readonly {
    path: readonly PropertyKey[];
    message: string;
  }[],
): string[] => {
  return issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.map(String).join(".") : "request";
    return `${path}: ${issue.message}`;
  });
};

const dryRunDiffPreview = async (input: {
  db: SqlDatabase;
  tenantId: string;
  conversion: Ob2ImportConversionResult;
}): Promise<DryRunDiffPreview> => {
  const templates = await listBadgeTemplates(input.db, {
    tenantId: input.tenantId,
    includeArchived: true,
  });
  const existingTemplate = templates.find((template) => {
    return template.slug === input.conversion.createBadgeTemplateRequest.slug;
  });
  const changedFields: string[] = [];

  if (existingTemplate !== undefined) {
    if (existingTemplate.title !== input.conversion.createBadgeTemplateRequest.title) {
      changedFields.push("title");
    }

    if (
      (existingTemplate.description ?? undefined) !==
      input.conversion.createBadgeTemplateRequest.description
    ) {
      changedFields.push("description");
    }

    if (
      (existingTemplate.criteriaUri ?? undefined) !==
      input.conversion.createBadgeTemplateRequest.criteriaUri
    ) {
      changedFields.push("criteriaUri");
    }

    if (
      (existingTemplate.imageUri ?? undefined) !==
      input.conversion.createBadgeTemplateRequest.imageUri
    ) {
      changedFields.push("imageUri");
    }
  } else {
    changedFields.push("new_template");
  }

  const learnerIdentityType = learnerIdentityTypeFromRecipientIdentityType(
    input.conversion.manualIssueRequest.recipientIdentityType,
  );
  const existingProfile = await findLearnerProfileByIdentity(input.db, {
    tenantId: input.tenantId,
    identityType: learnerIdentityType,
    identityValue: input.conversion.manualIssueRequest.recipientIdentity,
  });

  const creates = (existingTemplate === undefined ? 1 : 0) + (existingProfile === null ? 1 : 0);
  const updates = existingTemplate === undefined ? 0 : changedFields.length > 0 ? 1 : 0;

  return {
    badgeTemplate: {
      operation: existingTemplate === undefined ? "create" : "update",
      ...(existingTemplate === undefined ? {} : { existingTemplateId: existingTemplate.id }),
      changedFields,
      proposed: input.conversion.createBadgeTemplateRequest,
    },
    learnerProfile: {
      operation: existingProfile === null ? "create" : "reuse",
      ...(existingProfile === null ? {} : { existingProfileId: existingProfile.id }),
      recipientIdentity: input.conversion.manualIssueRequest.recipientIdentity,
      recipientIdentityType: input.conversion.manualIssueRequest.recipientIdentityType,
    },
    assertionIssue: {
      operation: "queue_issue",
      recipientIdentity: input.conversion.manualIssueRequest.recipientIdentity,
      recipientIdentityType: input.conversion.manualIssueRequest.recipientIdentityType,
    },
    summary: {
      creates,
      updates,
    },
  };
};

const runBatchRowValidation = async (input: {
  db: SqlDatabase;
  tenantId: string;
  dryRun: boolean;
  source: MigrationBatchSource;
  fileName: string;
  format: MigrationBatchFileFormat;
  batchId: string;
  rows: readonly {
    rowNumber: number;
    candidate: Record<string, unknown>;
  }[];
}): Promise<{
  reports: BatchUploadRowValidationResult[];
  queuedRows: number;
}> => {
  const reports: BatchUploadRowValidationResult[] = [];
  let queuedRows = 0;

  for (const row of input.rows) {
    const parsedRequest = ob2ImportConversionRequestSchema.safeParse(row.candidate);

    if (!parsedRequest.success) {
      reports.push({
        rowNumber: row.rowNumber,
        status: "invalid",
        errors: zodIssueMessages(parsedRequest.error.issues),
        warnings: [],
        diffPreview: null,
      });
      continue;
    }

    const request = parsedRequest.data;
    let conversionResult;

    try {
      conversionResult = await prepareOb2ImportConversion({
        ...(request.ob2Assertion === undefined ? {} : { ob2Assertion: request.ob2Assertion }),
        ...(request.ob2BadgeClass === undefined ? {} : { ob2BadgeClass: request.ob2BadgeClass }),
        ...(request.ob2Issuer === undefined ? {} : { ob2Issuer: request.ob2Issuer }),
        ...(request.bakedBadgeImage === undefined
          ? {}
          : { bakedBadgeImage: request.bakedBadgeImage }),
      });
    } catch (error: unknown) {
      if (error instanceof Ob2ImportError) {
        reports.push({
          rowNumber: row.rowNumber,
          status: "invalid",
          errors: [error.message],
          warnings: [],
          diffPreview: null,
        });
        continue;
      }

      throw error;
    }

    if (conversionResult.conversion === null) {
      reports.push({
        rowNumber: row.rowNumber,
        status: "invalid",
        errors: ["Conversion could not be completed from supplied payload"],
        warnings: conversionResult.warnings,
        diffPreview: null,
      });
      continue;
    }

    if (!input.dryRun) {
      await enqueueJobQueueMessage(input.db, {
        tenantId: input.tenantId,
        jobType: "import_migration_batch",
        payload: {
          source: input.source,
          batchId: input.batchId,
          rowNumber: row.rowNumber,
          fileName: input.fileName,
          format: input.format,
          request,
          conversion: conversionResult.conversion,
        },
        idempotencyKey: `migration-batch:${input.batchId}:${String(row.rowNumber)}`,
      });
      queuedRows += 1;
    }

    reports.push({
      rowNumber: row.rowNumber,
      status: "valid",
      errors: [],
      warnings: conversionResult.warnings,
      diffPreview: input.dryRun
        ? await dryRunDiffPreview({
            db: input.db,
            tenantId: input.tenantId,
            conversion: conversionResult.conversion,
          })
        : null,
    });
  }

  return {
    reports,
    queuedRows,
  };
};

const registerMigrationFileIngestRoutes = (input: RegisterMigrationRoutesInput): void => {
  for (const route of MIGRATION_FILE_INGEST_ROUTES) {
    input.app.post(route.path, async (c) => {
      const pathParams = parseTenantPathParams(c.req.param());
      const roleCheck = await input.requireTenantRole(
        c,
        pathParams.tenantId,
        input.ISSUER_ROLES,
      );

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      let query;

      try {
        query = parseMigrationBatchUploadQuery({
          dryRun: c.req.query("dryRun"),
        });
      } catch {
        return c.json(
          {
            error: `Invalid ${route.queryErrorSubject} query parameters`,
          },
          400,
        );
      }

      const contentType = c.req.header("content-type")?.toLowerCase() ?? "";

      if (!contentType.includes("multipart/form-data")) {
        return c.json(
          {
            error: `${route.requestLabel} requires multipart/form-data with a file field named "file"`,
          },
          415,
        );
      }

      const formData = await c.req.formData();
      const upload = formData.get("file");

      if (!(upload instanceof File)) {
        return c.json(
          {
            error: `${route.requestLabel} file is required in form field "file"`,
          },
          400,
        );
      }

      const fileContent = await upload.text();

      if (fileContent.trim().length === 0) {
        return c.json(
          {
            error: "Uploaded file is empty",
          },
          422,
        );
      }

      let parsedFile;

      try {
        parsedFile = route.parseFile({
          fileName: upload.name,
          mimeType: upload.type,
          content: fileContent,
        });
      } catch (error: unknown) {
        const message = route.parseErrorMessage(error);

        if (message !== null) {
          return c.json(
            {
              error: message,
            },
            422,
          );
        }

        throw error;
      }

      const batchId = crypto.randomUUID();
      const { reports, queuedRows } = await runBatchRowValidation({
        db: input.resolveDatabase(c.env),
        tenantId: pathParams.tenantId,
        dryRun: query.dryRun,
        source: route.source,
        fileName: upload.name,
        format: parsedFile.format,
        batchId,
        rows: parsedFile.rows,
      });
      const validRows = reports.filter((report) => report.status === "valid").length;

      return c.json(
        {
          tenantId: pathParams.tenantId,
          batchId,
          fileName: upload.name,
          format: parsedFile.format,
          dryRun: query.dryRun,
          ...(route.includeSourceInResponse ? { source: route.source } : {}),
          totalRows: reports.length,
          validRows,
          invalidRows: reports.length - validRows,
          queuedRows,
          rows: reports,
        },
        200,
      );
    });
  }
};

const summarizeMigrationBatchProgress = (
  messages: readonly ImportMigrationBatchQueueMessageRecord[],
): {
  totals: {
    messages: number;
    batches: number;
    pendingRows: number;
    processingRows: number;
    completedRows: number;
    failedRows: number;
  };
  batches: MigrationBatchProgressSummary[];
} => {
  const summaries = new Map<string, MigrationBatchProgressSummary>();

  for (const message of messages) {
    const key = `${message.source}:${message.batchId}`;
    const existing = summaries.get(key);
    const summary =
      existing ??
      ({
        batchId: message.batchId,
        source: message.source,
        fileName: message.fileName,
        format: message.format,
        totalRows: 0,
        pendingRows: 0,
        processingRows: 0,
        completedRows: 0,
        failedRows: 0,
        retryableRows: 0,
        failedRowNumbers: [],
        latestError: null,
        firstQueuedAt: message.createdAt,
        lastUpdatedAt: message.updatedAt,
      } satisfies MigrationBatchProgressSummary);
    summary.totalRows += 1;

    if (summary.fileName === null && message.fileName !== null) {
      summary.fileName = message.fileName;
    }

    if (summary.format === null && message.format !== null) {
      summary.format = message.format;
    }

    if (message.createdAt < summary.firstQueuedAt) {
      summary.firstQueuedAt = message.createdAt;
    }

    if (message.updatedAt > summary.lastUpdatedAt) {
      summary.lastUpdatedAt = message.updatedAt;
    }

    if (message.lastError !== null && message.lastError.trim().length > 0) {
      summary.latestError = message.lastError;
    }

    if (message.status === "pending") {
      summary.pendingRows += 1;
    } else if (message.status === "processing") {
      summary.processingRows += 1;
    } else if (message.status === "completed") {
      summary.completedRows += 1;
    } else {
      summary.failedRows += 1;
      summary.retryableRows += 1;

      if (message.rowNumber !== null) {
        summary.failedRowNumbers.push(message.rowNumber);
      }
    }

    if (existing === undefined) {
      summaries.set(key, summary);
    }
  }

  const batches = Array.from(summaries.values())
    .map((summary) => {
      summary.failedRowNumbers.sort((left, right) => left - right);

      return {
        ...summary,
        failedRowNumbers: summary.failedRowNumbers.slice(0, 50),
      };
    })
    .sort((left, right) => {
      return right.lastUpdatedAt.localeCompare(left.lastUpdatedAt);
    });
  const totals = batches.reduce(
    (accumulator, summary) => {
      accumulator.messages += summary.totalRows;
      accumulator.pendingRows += summary.pendingRows;
      accumulator.processingRows += summary.processingRows;
      accumulator.completedRows += summary.completedRows;
      accumulator.failedRows += summary.failedRows;
      return accumulator;
    },
    {
      messages: 0,
      batches: batches.length,
      pendingRows: 0,
      processingRows: 0,
      completedRows: 0,
      failedRows: 0,
    },
  );

  return {
    totals,
    batches,
  };
};

export const registerMigrationRoutes = (input: RegisterMigrationRoutesInput): void => {
  const { app, resolveDatabase, requireTenantRole, ISSUER_ROLES } = input;

  app.post("/v1/tenants/:tenantId/migrations/ob2/convert", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    let request;

    try {
      request = parseOb2ImportConversionRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid OB2 import conversion request payload",
        },
        400,
      );
    }

    try {
      const result = await prepareOb2ImportConversion({
        ...(request.ob2Assertion === undefined ? {} : { ob2Assertion: request.ob2Assertion }),
        ...(request.ob2BadgeClass === undefined ? {} : { ob2BadgeClass: request.ob2BadgeClass }),
        ...(request.ob2Issuer === undefined ? {} : { ob2Issuer: request.ob2Issuer }),
        ...(request.bakedBadgeImage === undefined
          ? {}
          : { bakedBadgeImage: request.bakedBadgeImage }),
      });
      return c.json(
        {
          tenantId: pathParams.tenantId,
          ...result,
        },
        200,
      );
    } catch (error: unknown) {
      if (error instanceof Ob2ImportError) {
        return c.json(
          {
            error: error.message,
          },
          422,
        );
      }

      throw error;
    }
  });

  app.post("/v1/tenants/:tenantId/migrations/ob2/dry-run", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const rawBody = await c.req.json<unknown>();
    const parsedRequest = ob2ImportConversionRequestSchema.safeParse(rawBody);

    if (!parsedRequest.success) {
      return c.json(
        {
          tenantId: pathParams.tenantId,
          status: "invalid",
          validationReport: {
            errors: zodIssueMessages(parsedRequest.error.issues),
            warnings: [],
            diffPreview: null,
          },
        },
        200,
      );
    }
    const request = parsedRequest.data;

    try {
      const result = await prepareOb2ImportConversion({
        ...(request.ob2Assertion === undefined ? {} : { ob2Assertion: request.ob2Assertion }),
        ...(request.ob2BadgeClass === undefined ? {} : { ob2BadgeClass: request.ob2BadgeClass }),
        ...(request.ob2Issuer === undefined ? {} : { ob2Issuer: request.ob2Issuer }),
        ...(request.bakedBadgeImage === undefined
          ? {}
          : { bakedBadgeImage: request.bakedBadgeImage }),
      });
      const diffPreview =
        result.conversion === null
          ? null
          : await dryRunDiffPreview({
              db: resolveDatabase(c.env),
              tenantId: pathParams.tenantId,
              conversion: result.conversion,
            });

      return c.json(
        {
          tenantId: pathParams.tenantId,
          status: result.conversion === null ? "invalid" : "valid",
          validationReport: {
            errors:
              result.conversion === null
                ? ["Conversion could not be completed from supplied payload"]
                : [],
            warnings: result.warnings,
            ...(result.extractedFromBakedBadge === undefined
              ? {}
              : { extractedFromBakedBadge: result.extractedFromBakedBadge }),
            diffPreview,
          },
        },
        200,
      );
    } catch (error: unknown) {
      if (error instanceof Ob2ImportError) {
        return c.json(
          {
            tenantId: pathParams.tenantId,
            status: "invalid",
            validationReport: {
              errors: [error.message],
              warnings: [],
              diffPreview: null,
            },
          },
          200,
        );
      }

      throw error;
    }
  });

  registerMigrationFileIngestRoutes(input);

  app.get("/v1/tenants/:tenantId/migrations/progress", async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    let query;

    try {
      query = parseMigrationProgressQuery({
        source: c.req.query("source"),
        limit: c.req.query("limit"),
      });
    } catch {
      return c.json(
        {
          error: "Invalid migration progress query parameters",
        },
        400,
      );
    }

    const messages = await listImportMigrationBatchQueueMessages(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ...(query.source === "all" ? {} : { source: query.source }),
      limit: query.limit,
    });
    const progress = summarizeMigrationBatchProgress(messages);

    return c.json(
      {
        tenantId: pathParams.tenantId,
        filters: {
          source: query.source,
          limit: query.limit,
        },
        totals: progress.totals,
        batches: progress.batches,
      },
      200,
    );
  });

  app.post("/v1/tenants/:tenantId/migrations/batches/:batchId/retry", async (c) => {
    const pathParams = parseMigrationBatchPathParams(c.req.param());
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
              error: "Invalid retry request payload",
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
            error: "Invalid retry request payload",
          },
          400,
        );
      }
    }

    let request;

    try {
      request = parseMigrationBatchRetryRequest(rawBody);
    } catch {
      return c.json(
        {
          error: "Invalid retry request payload",
        },
        400,
      );
    }

    const retryResult = await retryFailedImportMigrationBatchQueueMessages(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      batchId: pathParams.batchId,
      ...(request.source === undefined ? {} : { source: request.source }),
      ...(request.rowNumbers === undefined ? {} : { rowNumbers: request.rowNumbers }),
    });

    if (retryResult.matched === 0) {
      return c.json(
        {
          error: "Migration batch was not found for tenant",
        },
        404,
      );
    }

    const refreshedMessages = await listImportMigrationBatchQueueMessages(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ...(request.source === undefined ? {} : { source: request.source }),
      limit: 1000,
    });
    const refreshedProgress = summarizeMigrationBatchProgress(
      refreshedMessages.filter((message) => {
        return message.batchId === pathParams.batchId;
      }),
    );
    const batchSummary = refreshedProgress.batches[0] ?? null;

    return c.json(
      {
        tenantId: pathParams.tenantId,
        batchId: pathParams.batchId,
        retry: retryResult,
        batch: batchSummary,
      },
      200,
    );
  });
};
