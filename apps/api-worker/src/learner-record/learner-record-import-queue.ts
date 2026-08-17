import {
  applyLearnerRecordImport,
  enqueueJobQueueMessagesOnce,
  findActiveLearnerRecordImportPreview,
  markLearnerRecordImportPreviewQueued,
  runSqlTransaction,
  type LearnerRecordImportPreviewRecord,
  type SqlDatabase,
} from "@credtrail/db";
import {
  learnerRecordImportBatchDefaultsSchema,
  learnerRecordImportQueuePayloadSchema,
  learnerRecordImportRowReportSchema,
  type LearnerRecordImportBatchDefaults,
  type LearnerRecordImportQueuePayload,
  type LearnerRecordImportRowReport,
} from "@credtrail/validation";

/** Outcome of claiming and queueing a reviewed learner-record import preview. */
export type QueueReviewedLearnerRecordImportPreviewResult =
  | { readonly status: "missing" }
  | {
      readonly status: "invalid_preview";
      readonly defaults: LearnerRecordImportBatchDefaults | null;
    }
  | {
      readonly status: "already_queued";
      readonly preview: LearnerRecordImportPreviewRecord;
      readonly defaults: LearnerRecordImportBatchDefaults;
      readonly reports: readonly LearnerRecordImportRowReport[];
    }
  | {
      readonly status: "queued";
      readonly preview: LearnerRecordImportPreviewRecord;
      readonly defaults: LearnerRecordImportBatchDefaults;
      readonly reports: readonly LearnerRecordImportRowReport[];
      readonly queuedRows: number;
    };

const enqueueLearnerRecordImportBatchWithinTransaction = async (
  db: SqlDatabase,
  tenantId: string,
  queuePayloads: readonly LearnerRecordImportQueuePayload[],
  nowIso: string,
): Promise<number> => {
  return enqueueJobQueueMessagesOnce(db, {
    nowIso,
    messages: queuePayloads.map((payload) => ({
      tenantId,
      jobType: "import_learner_record_batch",
      payload,
      idempotencyKey: `learner-record-import:${payload.batchId}:${String(payload.rowNumber)}`,
    })),
  });
};

/** Enqueues every valid row in a prepared learner-record import batch. */
export const enqueueLearnerRecordImportBatch = async (
  db: SqlDatabase,
  tenantId: string,
  queuePayloads: readonly LearnerRecordImportQueuePayload[],
): Promise<number> => {
  const nowIso = new Date().toISOString();
  return runSqlTransaction(db, (transaction) =>
    enqueueLearnerRecordImportBatchWithinTransaction(transaction, tenantId, queuePayloads, nowIso),
  );
};

const learnerRecordImportBatchDefaultsFromJson = (
  defaultsJson: string,
): LearnerRecordImportBatchDefaults | null => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(defaultsJson) as unknown;
  } catch {
    return null;
  }

  const result = learnerRecordImportBatchDefaultsSchema.safeParse(parsed);
  return result.success ? result.data : null;
};

/** Claims a reviewed preview and enqueues its validated row payloads once. */
export const queueReviewedLearnerRecordImportPreview = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly batchId: string;
    readonly queuedAt: string;
  },
): Promise<QueueReviewedLearnerRecordImportPreviewResult> => {
  const preview = await findActiveLearnerRecordImportPreview(db, {
    tenantId: input.tenantId,
    batchId: input.batchId,
    nowIso: input.queuedAt,
  });

  if (preview === null) {
    return { status: "missing" };
  }

  const defaults = learnerRecordImportBatchDefaultsFromJson(preview.defaultsJson);

  if (defaults === null) {
    return {
      status: "invalid_preview",
      defaults: null,
    };
  }

  const queuePayloads = learnerRecordImportQueuePayloadsFromJson(preview.queuePayloadsJson);
  const reports = learnerRecordImportRowReportsFromJson(preview.reportsJson);

  if (queuePayloads === null || reports === null) {
    return {
      status: "invalid_preview",
      defaults,
    };
  }

  const queueResult = await runSqlTransaction(db, async (transaction) => {
    const claimed = await markLearnerRecordImportPreviewQueued(transaction, {
      tenantId: input.tenantId,
      batchId: preview.batchId,
      queuedAt: input.queuedAt,
    });

    if (!claimed) {
      return null;
    }

    return enqueueLearnerRecordImportBatchWithinTransaction(
      transaction,
      input.tenantId,
      queuePayloads,
      input.queuedAt,
    );
  });

  if (queueResult === null) {
    return {
      status: "already_queued",
      preview,
      defaults,
      reports,
    };
  }

  return {
    status: "queued",
    preview,
    defaults,
    reports,
    queuedRows: queueResult,
  };
};

/** Parses stored queue payload JSON through the current validation schema. */
export const learnerRecordImportQueuePayloadsFromJson = (
  payloadJson: string,
): LearnerRecordImportQueuePayload[] | null => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(payloadJson);
  } catch {
    return null;
  }

  const result = learnerRecordImportQueuePayloadSchema.array().safeParse(parsed);
  return result.success ? result.data : null;
};

/** Parses stored row-report JSON through the current validation schema. */
export const learnerRecordImportRowReportsFromJson = (
  reportsJson: string,
): LearnerRecordImportRowReport[] | null => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(reportsJson);
  } catch {
    return null;
  }

  const result = learnerRecordImportRowReportSchema.array().safeParse(parsed);
  return result.success ? result.data : null;
};

const buildImportDetailsJson = (payload: LearnerRecordImportQueuePayload): string | undefined => {
  const details: Record<string, unknown> = {};

  if (payload.row.smartContext.pathwayLabel !== null) {
    details.pathwayHint = payload.row.smartContext.pathwayLabel;
  }

  if (
    payload.row.smartContext.orgUnitId !== null ||
    payload.row.smartContext.badgeTemplateId !== null
  ) {
    details.importContext = {
      ...(payload.row.smartContext.orgUnitId === null
        ? {}
        : { orgUnitId: payload.row.smartContext.orgUnitId }),
      ...(payload.row.smartContext.badgeTemplateId === null
        ? {}
        : { badgeTemplateId: payload.row.smartContext.badgeTemplateId }),
      inferredFrom: payload.row.smartContext.inferredFrom,
    };
  }

  return Object.keys(details).length === 0 ? undefined : JSON.stringify(details);
};

/** Applies one validated queue payload to the learner-record store. */
export const applyLearnerRecordImportQueuePayload = async (
  db: SqlDatabase,
  tenantId: string,
  payload: LearnerRecordImportQueuePayload,
): Promise<{
  readonly learnerProfileId: string;
  readonly learnerRecordEntryId: string;
}> => {
  const detailsJson = buildImportDetailsJson(payload);
  const result = await applyLearnerRecordImport(db, {
    tenantId,
    batchId: payload.batchId,
    rowNumber: payload.rowNumber,
    learnerEmail: payload.row.learnerEmail,
    ...(payload.row.learnerDisplayName === null
      ? {}
      : { learnerDisplayName: payload.row.learnerDisplayName }),
    entry: {
      trustLevel: payload.row.effectiveTrustLevel,
      recordType: payload.row.recordType,
      title: payload.row.title,
      ...(payload.row.description === null ? {} : { description: payload.row.description }),
      issuerName: payload.row.effectiveIssuerName,
      ...(payload.requestedByUserId === undefined
        ? {}
        : { issuerUserId: payload.requestedByUserId }),
      sourceSystem: "csv_import",
      ...(payload.row.sourceRecordId === null
        ? {}
        : { sourceRecordId: payload.row.sourceRecordId }),
      issuedAt: payload.row.issuedAt,
      evidenceLinks: payload.row.evidenceLinks,
      ...(detailsJson === undefined ? {} : { detailsJson }),
    },
    context: {
      ...(payload.row.smartContext.orgUnitId === null
        ? {}
        : { orgUnitId: payload.row.smartContext.orgUnitId }),
      ...(payload.row.smartContext.badgeTemplateId === null
        ? {}
        : { badgeTemplateId: payload.row.smartContext.badgeTemplateId }),
      ...(payload.row.smartContext.pathwayLabel === null
        ? {}
        : { pathwayLabel: payload.row.smartContext.pathwayLabel }),
      inferredFrom: payload.row.smartContext.inferredFrom,
    },
  });

  return {
    learnerProfileId: result.learnerProfileId,
    learnerRecordEntryId: result.learnerRecordEntryId,
  };
};
