import {
  enqueueJobQueueMessage,
  findLearnerProfileByIdentity,
  listBadgeTemplates,
  type LearnerIdentityType,
  type SessionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from '@credtrail/db';
import type { Hono } from 'hono';
import {
  ob2ImportConversionRequestSchema,
  parseMigrationBatchUploadQuery,
  parseOb2ImportConversionRequest,
  parseTenantPathParams,
} from '@credtrail/validation';
import type { AppContext, AppEnv } from '../app';
import {
  type Ob2ImportConversionResult,
  Ob2ImportError,
  prepareOb2ImportConversion,
} from '../migrations/ob2-import';
import {
  MigrationBatchFileParseError,
  parseMigrationBatchUploadFile,
  type MigrationBatchFileFormat,
} from '../migrations/batch-upload';

interface RegisterMigrationRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppContext['env']) => SqlDatabase;
  requireTenantRole: (
    c: AppContext,
    tenantId: string,
    allowedRoles: readonly TenantMembershipRole[],
  ) => Promise<
    | {
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
    | Response
  >;
  ISSUER_ROLES: readonly TenantMembershipRole[];
}

interface DryRunDiffPreview {
  badgeTemplate: {
    operation: 'create' | 'update';
    existingTemplateId?: string;
    changedFields: string[];
    proposed: Ob2ImportConversionResult['createBadgeTemplateRequest'];
  };
  learnerProfile: {
    operation: 'create' | 'reuse';
    existingProfileId?: string;
    recipientIdentity: string;
    recipientIdentityType: Ob2ImportConversionResult['manualIssueRequest']['recipientIdentityType'];
  };
  assertionIssue: {
    operation: 'queue_issue';
    recipientIdentity: string;
    recipientIdentityType: Ob2ImportConversionResult['manualIssueRequest']['recipientIdentityType'];
  };
  summary: {
    creates: number;
    updates: number;
  };
}

interface BatchUploadRowValidationResult {
  rowNumber: number;
  status: 'valid' | 'invalid';
  errors: string[];
  warnings: string[];
  diffPreview: DryRunDiffPreview | null;
}

const learnerIdentityTypeFromRecipientIdentityType = (
  identityType: Ob2ImportConversionResult['manualIssueRequest']['recipientIdentityType'],
): LearnerIdentityType => {
  if (identityType === 'email') {
    return 'email';
  }

  if (identityType === 'email_sha256') {
    return 'email_sha256';
  }

  if (identityType === 'did') {
    return 'did';
  }

  return 'url';
};

const zodIssueMessages = (
  issues: readonly {
    path: (string | number)[];
    message: string;
  }[],
): string[] => {
  return issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join('.') : 'request';
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
      changedFields.push('title');
    }

    if (
      (existingTemplate.description ?? undefined) !==
      input.conversion.createBadgeTemplateRequest.description
    ) {
      changedFields.push('description');
    }

    if (
      (existingTemplate.criteriaUri ?? undefined) !==
      input.conversion.createBadgeTemplateRequest.criteriaUri
    ) {
      changedFields.push('criteriaUri');
    }

    if ((existingTemplate.imageUri ?? undefined) !== input.conversion.createBadgeTemplateRequest.imageUri) {
      changedFields.push('imageUri');
    }
  } else {
    changedFields.push('new_template');
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
      operation: existingTemplate === undefined ? 'create' : 'update',
      ...(existingTemplate === undefined ? {} : { existingTemplateId: existingTemplate.id }),
      changedFields,
      proposed: input.conversion.createBadgeTemplateRequest,
    },
    learnerProfile: {
      operation: existingProfile === null ? 'create' : 'reuse',
      ...(existingProfile === null ? {} : { existingProfileId: existingProfile.id }),
      recipientIdentity: input.conversion.manualIssueRequest.recipientIdentity,
      recipientIdentityType: input.conversion.manualIssueRequest.recipientIdentityType,
    },
    assertionIssue: {
      operation: 'queue_issue',
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
  fileName: string;
  format: MigrationBatchFileFormat;
  batchId: string;
  rows: {
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
        status: 'invalid',
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
          status: 'invalid',
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
        status: 'invalid',
        errors: ['Conversion could not be completed from supplied payload'],
        warnings: conversionResult.warnings,
        diffPreview: null,
      });
      continue;
    }

    if (!input.dryRun) {
      await enqueueJobQueueMessage(input.db, {
        tenantId: input.tenantId,
        jobType: 'import_migration_batch',
        payload: {
          source: 'file_upload',
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
      status: 'valid',
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

export const registerMigrationRoutes = (input: RegisterMigrationRoutesInput): void => {
  const { app, resolveDatabase, requireTenantRole, ISSUER_ROLES } = input;

  app.post('/v1/tenants/:tenantId/migrations/ob2/convert', async (c) => {
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
          error: 'Invalid OB2 import conversion request payload',
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

  app.post('/v1/tenants/:tenantId/migrations/ob2/dry-run', async (c) => {
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
          status: 'invalid',
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
          status: result.conversion === null ? 'invalid' : 'valid',
          validationReport: {
            errors:
              result.conversion === null
                ? ['Conversion could not be completed from supplied payload']
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
            status: 'invalid',
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

  app.post('/v1/tenants/:tenantId/migrations/ob2/batch-upload', async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    let query;

    try {
      query = parseMigrationBatchUploadQuery({
        dryRun: c.req.query('dryRun'),
      });
    } catch {
      return c.json(
        {
          error: 'Invalid batch upload query parameters',
        },
        400,
      );
    }

    const contentType = c.req.header('content-type')?.toLowerCase() ?? '';

    if (!contentType.includes('multipart/form-data')) {
      return c.json(
        {
          error: 'Batch upload requires multipart/form-data with a file field named "file"',
        },
        415,
      );
    }

    const formData = await c.req.formData();
    const upload = formData.get('file');

    if (!(upload instanceof File)) {
      return c.json(
        {
          error: 'Batch upload file is required in form field "file"',
        },
        400,
      );
    }

    const fileContent = await upload.text();

    if (fileContent.trim().length === 0) {
      return c.json(
        {
          error: 'Uploaded file is empty',
        },
        422,
      );
    }

    let parsedFile;

    try {
      parsedFile = parseMigrationBatchUploadFile({
        fileName: upload.name,
        mimeType: upload.type,
        content: fileContent,
      });
    } catch (error: unknown) {
      if (error instanceof MigrationBatchFileParseError) {
        return c.json(
          {
            error: error.message,
          },
          422,
        );
      }

      throw error;
    }

    const batchId = crypto.randomUUID();
    const db = resolveDatabase(c.env);
    const { reports, queuedRows } = await runBatchRowValidation({
      db,
      tenantId: pathParams.tenantId,
      dryRun: query.dryRun,
      fileName: upload.name,
      format: parsedFile.format,
      batchId,
      rows: parsedFile.rows,
    });
    const validRows = reports.filter((report) => report.status === 'valid').length;
    const invalidRows = reports.length - validRows;

    return c.json(
      {
        tenantId: pathParams.tenantId,
        batchId,
        fileName: upload.name,
        format: parsedFile.format,
        dryRun: query.dryRun,
        totalRows: reports.length,
        validRows,
        invalidRows,
        queuedRows,
        rows: reports,
      },
      200,
    );
  });
};
