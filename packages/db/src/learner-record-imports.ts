import type { SqlDatabase } from "./tenant-scope";

export type LearnerRecordImportContextInferenceSource =
  | "row"
  | "badge_template"
  | "org_unit"
  | "none";

export interface LearnerRecordImportContextRecord {
  entryId: string;
  tenantId: string;
  orgUnitId: string | null;
  badgeTemplateId: string | null;
  pathwayLabel: string | null;
  inferredFromJson: string;
  createdAt: string;
  updatedAt: string;
}

export interface LearnerRecordImportPreviewRecord {
  tenantId: string;
  batchId: string;
  fileName: string;
  format: "csv";
  defaultsJson: string;
  reportsJson: string;
  queuePayloadsJson: string;
  createdByUserId: string | null;
  createdAt: string;
  expiresAt: string;
  queuedAt: string | null;
}

export interface CreateLearnerRecordImportContextInput {
  tenantId: string;
  entryId: string;
  orgUnitId?: string | null | undefined;
  badgeTemplateId?: string | null | undefined;
  pathwayLabel?: string | null | undefined;
  inferredFrom: readonly LearnerRecordImportContextInferenceSource[];
}

export interface CreateLearnerRecordImportPreviewInput {
  tenantId: string;
  batchId: string;
  fileName: string;
  format: "csv";
  defaultsJson: string;
  reportsJson: string;
  queuePayloadsJson: string;
  createdByUserId?: string | null | undefined;
  createdAt: string;
  expiresAt: string;
}

export interface FindActiveLearnerRecordImportPreviewInput {
  tenantId: string;
  batchId: string;
  nowIso: string;
}

export interface MarkLearnerRecordImportPreviewQueuedInput {
  tenantId: string;
  batchId: string;
  queuedAt: string;
}

interface LearnerRecordImportContextRow {
  entryId: string;
  tenantId: string;
  orgUnitId: string | null;
  badgeTemplateId: string | null;
  pathwayLabel: string | null;
  inferredFromJson: string;
  createdAt: string;
  updatedAt: string;
}

interface LearnerRecordImportPreviewRow {
  tenantId: string;
  batchId: string;
  fileName: string;
  format: "csv";
  defaultsJson: string;
  reportsJson: string;
  queuePayloadsJson: string;
  createdByUserId: string | null;
  createdAt: string;
  expiresAt: string;
  queuedAt: string | null;
}

const normalizeOptionalLearnerRecordText = (value: string | null | undefined): string | null => {
  if (value === undefined || value === null) {
    return null;
  }

  const normalized = value.trim();
  return normalized.length === 0 ? null : normalized;
};

const normalizeLearnerRecordImportInferredFromJson = (
  inferredFrom: readonly LearnerRecordImportContextInferenceSource[],
): string => {
  const normalized = Array.from(new Set(inferredFrom));

  if (normalized.length === 0) {
    throw new Error("Learner-record import context must include at least one inference source");
  }

  for (const entry of normalized) {
    if (entry !== "row" && entry !== "badge_template" && entry !== "org_unit" && entry !== "none") {
      throw new Error("Unsupported learner-record import inference source");
    }
  }

  return JSON.stringify(normalized);
};

const mapLearnerRecordImportContextRow = (
  row: LearnerRecordImportContextRow,
): LearnerRecordImportContextRecord => {
  return {
    entryId: row.entryId,
    tenantId: row.tenantId,
    orgUnitId: row.orgUnitId,
    badgeTemplateId: row.badgeTemplateId,
    pathwayLabel: row.pathwayLabel,
    inferredFromJson: row.inferredFromJson,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLearnerRecordImportPreviewRow = (
  row: LearnerRecordImportPreviewRow,
): LearnerRecordImportPreviewRecord => {
  return {
    tenantId: row.tenantId,
    batchId: row.batchId,
    fileName: row.fileName,
    format: row.format,
    defaultsJson: row.defaultsJson,
    reportsJson: row.reportsJson,
    queuePayloadsJson: row.queuePayloadsJson,
    createdByUserId: row.createdByUserId,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
    queuedAt: row.queuedAt,
  };
};

export const findLearnerRecordImportContextByEntryId = async (
  db: SqlDatabase,
  tenantId: string,
  entryId: string,
): Promise<LearnerRecordImportContextRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        entry_id AS entryId,
        tenant_id AS tenantId,
        org_unit_id AS orgUnitId,
        badge_template_id AS badgeTemplateId,
        pathway_label AS pathwayLabel,
        inferred_from_json AS inferredFromJson,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM learner_record_import_context
      WHERE tenant_id = ?
        AND entry_id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, entryId)
    .first<LearnerRecordImportContextRow>();

  return row === null ? null : mapLearnerRecordImportContextRow(row);
};

export const createLearnerRecordImportContext = async (
  db: SqlDatabase,
  input: CreateLearnerRecordImportContextInput,
): Promise<LearnerRecordImportContextRecord> => {
  const nowIso = new Date().toISOString();
  const orgUnitId = input.orgUnitId ?? null;
  const badgeTemplateId = input.badgeTemplateId ?? null;
  const pathwayLabel = normalizeOptionalLearnerRecordText(input.pathwayLabel);
  const inferredFromJson = normalizeLearnerRecordImportInferredFromJson(input.inferredFrom);

  await db
    .prepare(
      `
      INSERT INTO learner_record_import_context (
        entry_id,
        tenant_id,
        org_unit_id,
        badge_template_id,
        pathway_label,
        inferred_from_json,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(entry_id) DO UPDATE SET
        tenant_id = excluded.tenant_id,
        org_unit_id = excluded.org_unit_id,
        badge_template_id = excluded.badge_template_id,
        pathway_label = excluded.pathway_label,
        inferred_from_json = excluded.inferred_from_json,
        updated_at = excluded.updated_at
    `,
    )
    .bind(
      input.entryId,
      input.tenantId,
      orgUnitId,
      badgeTemplateId,
      pathwayLabel,
      inferredFromJson,
      nowIso,
      nowIso,
    )
    .run();

  const context = await findLearnerRecordImportContextByEntryId(db, input.tenantId, input.entryId);

  if (context === null) {
    throw new Error(`Failed to create learner-record import context for entry "${input.entryId}"`);
  }

  return context;
};

export const createLearnerRecordImportPreview = async (
  db: SqlDatabase,
  input: CreateLearnerRecordImportPreviewInput,
): Promise<LearnerRecordImportPreviewRecord> => {
  await db
    .prepare(
      `
      INSERT INTO learner_record_import_previews (
        tenant_id,
        batch_id,
        file_name,
        format,
        defaults_json,
        reports_json,
        queue_payloads_json,
        created_by_user_id,
        created_at,
        expires_at,
        queued_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
      ON CONFLICT(tenant_id, batch_id) DO UPDATE SET
        file_name = excluded.file_name,
        format = excluded.format,
        defaults_json = excluded.defaults_json,
        reports_json = excluded.reports_json,
        queue_payloads_json = excluded.queue_payloads_json,
        created_by_user_id = excluded.created_by_user_id,
        created_at = excluded.created_at,
        expires_at = excluded.expires_at,
        queued_at = NULL
    `,
    )
    .bind(
      input.tenantId,
      input.batchId,
      input.fileName,
      input.format,
      input.defaultsJson,
      input.reportsJson,
      input.queuePayloadsJson,
      input.createdByUserId ?? null,
      input.createdAt,
      input.expiresAt,
    )
    .run();

  const preview = await findActiveLearnerRecordImportPreview(db, {
    tenantId: input.tenantId,
    batchId: input.batchId,
    nowIso: input.createdAt,
  });

  if (preview === null) {
    throw new Error(`Unable to create learner-record import preview "${input.batchId}"`);
  }

  return preview;
};

export const findActiveLearnerRecordImportPreview = async (
  db: SqlDatabase,
  input: FindActiveLearnerRecordImportPreviewInput,
): Promise<LearnerRecordImportPreviewRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        tenant_id AS tenantId,
        batch_id AS batchId,
        file_name AS fileName,
        format,
        defaults_json AS defaultsJson,
        reports_json AS reportsJson,
        queue_payloads_json AS queuePayloadsJson,
        created_by_user_id AS createdByUserId,
        created_at AS createdAt,
        expires_at AS expiresAt,
        queued_at AS queuedAt
      FROM learner_record_import_previews
      WHERE tenant_id = ?
        AND batch_id = ?
        AND queued_at IS NULL
        AND expires_at > ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.batchId, input.nowIso)
    .first<LearnerRecordImportPreviewRow>();

  return row === null ? null : mapLearnerRecordImportPreviewRow(row);
};

export const markLearnerRecordImportPreviewQueued = async (
  db: SqlDatabase,
  input: MarkLearnerRecordImportPreviewQueuedInput,
): Promise<boolean> => {
  const row = await db
    .prepare(
      `
      UPDATE learner_record_import_previews
      SET queued_at = ?
      WHERE tenant_id = ?
        AND batch_id = ?
        AND queued_at IS NULL
        AND expires_at > ?
      RETURNING batch_id AS batchId
    `,
    )
    .bind(input.queuedAt, input.tenantId, input.batchId, input.queuedAt)
    .first<{ batchId: string }>();

  return row !== null;
};
