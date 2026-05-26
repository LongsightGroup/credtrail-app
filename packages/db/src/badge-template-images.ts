import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export type BadgeTemplateImageRevisionSource =
  | "manual_update"
  | "upload"
  | "ai_generated"
  | "restore";

export interface BadgeTemplateImageRevisionRecord {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  previousImageUri: string | null;
  newImageUri: string | null;
  sourceType: BadgeTemplateImageRevisionSource;
  promptText: string | null;
  provider: string | null;
  model: string | null;
  metadataJson: string | null;
  createdByUserId: string | null;
  createdAt: string;
}

export interface CreateBadgeTemplateImageRevisionInput {
  tenantId: string;
  badgeTemplateId: string;
  previousImageUri: string | null;
  newImageUri: string | null;
  sourceType: BadgeTemplateImageRevisionSource;
  promptText?: string | null | undefined;
  provider?: string | null | undefined;
  model?: string | null | undefined;
  metadataJson?: string | null | undefined;
  createdByUserId?: string | null | undefined;
}

export interface ListBadgeTemplateImageRevisionsInput {
  tenantId: string;
  badgeTemplateId: string;
  limit?: number | undefined;
}

export interface BadgeTemplateImageRevisionCountRecord {
  badgeTemplateId: string;
  revisionCount: number;
}

export type BadgeTemplateImageGenerationStatus = "queued" | "processing" | "succeeded" | "failed";

export interface BadgeTemplateImageGenerationRecord {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  status: BadgeTemplateImageGenerationStatus;
  promptText: string;
  stylePreset: string;
  promptNotes: string | null;
  accentColor: string | null;
  resultImageUri: string | null;
  errorMessage: string | null;
  requestedByUserId: string | null;
  queuedJobId: string | null;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
}

export interface CreateBadgeTemplateImageGenerationInput {
  tenantId: string;
  badgeTemplateId: string;
  promptText: string;
  stylePreset: string;
  promptNotes?: string | null | undefined;
  accentColor?: string | null | undefined;
  requestedByUserId?: string | null | undefined;
}

export interface UpdateBadgeTemplateImageGenerationInput {
  tenantId: string;
  id: string;
  status?: BadgeTemplateImageGenerationStatus | undefined;
  resultImageUri?: string | null | undefined;
  errorMessage?: string | null | undefined;
  queuedJobId?: string | null | undefined;
  completedAt?: string | null | undefined;
}

interface BadgeTemplateImageRevisionRow {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  previousImageUri: string | null;
  newImageUri: string | null;
  sourceType: BadgeTemplateImageRevisionSource;
  promptText: string | null;
  provider: string | null;
  model: string | null;
  metadataJson: string | null;
  createdByUserId: string | null;
  createdAt: string;
}

interface BadgeTemplateImageGenerationRow {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  status: BadgeTemplateImageGenerationStatus;
  promptText: string;
  stylePreset: string;
  promptNotes: string | null;
  accentColor: string | null;
  resultImageUri: string | null;
  errorMessage: string | null;
  requestedByUserId: string | null;
  queuedJobId: string | null;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
}

const mapBadgeTemplateImageRevisionRow = (
  row: BadgeTemplateImageRevisionRow,
): BadgeTemplateImageRevisionRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    previousImageUri: row.previousImageUri,
    newImageUri: row.newImageUri,
    sourceType: row.sourceType,
    promptText: row.promptText,
    provider: row.provider,
    model: row.model,
    metadataJson: row.metadataJson,
    createdByUserId: row.createdByUserId,
    createdAt: row.createdAt,
  };
};

const mapBadgeTemplateImageGenerationRow = (
  row: BadgeTemplateImageGenerationRow,
): BadgeTemplateImageGenerationRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    status: row.status,
    promptText: row.promptText,
    stylePreset: row.stylePreset,
    promptNotes: row.promptNotes,
    accentColor: row.accentColor,
    resultImageUri: row.resultImageUri,
    errorMessage: row.errorMessage,
    requestedByUserId: row.requestedByUserId,
    queuedJobId: row.queuedJobId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    completedAt: row.completedAt,
  };
};

export const createBadgeTemplateImageRevision = async (
  db: SqlDatabase,
  input: CreateBadgeTemplateImageRevisionInput,
): Promise<BadgeTemplateImageRevisionRecord> => {
  const id = createPrefixedId("btir");
  const nowIso = new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_template_image_revisions (
          id,
          tenant_id,
          badge_template_id,
          previous_image_uri,
          new_image_uri,
          source_type,
          prompt_text,
          provider,
          model,
          metadata_json,
          created_by_user_id,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.badgeTemplateId,
        input.previousImageUri,
        input.newImageUri,
        input.sourceType,
        input.promptText ?? null,
        input.provider ?? null,
        input.model ?? null,
        input.metadataJson ?? null,
        input.createdByUserId ?? null,
        nowIso,
      )
      .run();

  await insertStatement();

  const revision = await findBadgeTemplateImageRevisionById(
    db,
    input.tenantId,
    input.badgeTemplateId,
    id,
  );

  if (revision === null) {
    throw new Error(`Unable to load badge template image revision ${id} after insert`);
  }

  return revision;
};

export const listBadgeTemplateImageRevisions = async (
  db: SqlDatabase,
  input: ListBadgeTemplateImageRevisionsInput,
): Promise<BadgeTemplateImageRevisionRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 25, 100));
  const listStatement = (): Promise<SqlQueryResult<BadgeTemplateImageRevisionRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          previous_image_uri AS previousImageUri,
          new_image_uri AS newImageUri,
          source_type AS sourceType,
          prompt_text AS promptText,
          provider,
          model,
          metadata_json AS metadataJson,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt
        FROM badge_template_image_revisions
        WHERE tenant_id = ?
          AND badge_template_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.badgeTemplateId, queryLimit)
      .all<BadgeTemplateImageRevisionRow>();

  let result: SqlQueryResult<BadgeTemplateImageRevisionRow>;

  result = await listStatement();

  return result.results.map((row) => mapBadgeTemplateImageRevisionRow(row));
};

export const listBadgeTemplateImageRevisionCountsByTenant = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<BadgeTemplateImageRevisionCountRecord[]> => {
  const listStatement = (): Promise<
    SqlQueryResult<{
      badgeTemplateId: string;
      revisionCount: number;
    }>
  > =>
    db
      .prepare(
        `
        SELECT
          badge_template_id AS badgeTemplateId,
          COUNT(*) AS revisionCount
        FROM badge_template_image_revisions
        WHERE tenant_id = ?
        GROUP BY badge_template_id
      `,
      )
      .bind(tenantId)
      .all<{
        badgeTemplateId: string;
        revisionCount: number;
      }>();

  let result: SqlQueryResult<{
    badgeTemplateId: string;
    revisionCount: number;
  }>;

  result = await listStatement();

  return result.results.map((row) => ({
    badgeTemplateId: row.badgeTemplateId,
    revisionCount: Number(row.revisionCount),
  }));
};

export const countBadgeTemplateImageRevisions = async (
  db: SqlDatabase,
  tenantId: string,
  badgeTemplateId: string,
): Promise<number> => {
  const countStatement = (): Promise<{ revisionCount: number } | null> =>
    db
      .prepare(
        `
        SELECT COUNT(*) AS revisionCount
        FROM badge_template_image_revisions
        WHERE tenant_id = ?
          AND badge_template_id = ?
      `,
      )
      .bind(tenantId, badgeTemplateId)
      .first<{ revisionCount: number }>();

  let row: { revisionCount: number } | null;

  row = await countStatement();

  return row === null ? 0 : Number(row.revisionCount);
};

export const findBadgeTemplateImageRevisionById = async (
  db: SqlDatabase,
  tenantId: string,
  badgeTemplateId: string,
  revisionId: string,
): Promise<BadgeTemplateImageRevisionRecord | null> => {
  const findStatement = (): Promise<BadgeTemplateImageRevisionRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          previous_image_uri AS previousImageUri,
          new_image_uri AS newImageUri,
          source_type AS sourceType,
          prompt_text AS promptText,
          provider,
          model,
          metadata_json AS metadataJson,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt
        FROM badge_template_image_revisions
        WHERE tenant_id = ?
          AND badge_template_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, badgeTemplateId, revisionId)
      .first<BadgeTemplateImageRevisionRow>();

  let row: BadgeTemplateImageRevisionRow | null;

  row = await findStatement();

  return row === null ? null : mapBadgeTemplateImageRevisionRow(row);
};

export const createBadgeTemplateImageGeneration = async (
  db: SqlDatabase,
  input: CreateBadgeTemplateImageGenerationInput,
): Promise<BadgeTemplateImageGenerationRecord> => {
  const id = createPrefixedId("btig");
  const nowIso = new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_template_image_generations (
          id,
          tenant_id,
          badge_template_id,
          status,
          prompt_text,
          style_preset,
          prompt_notes,
          accent_color,
          result_image_uri,
          error_message,
          requested_by_user_id,
          queued_job_id,
          created_at,
          updated_at,
          completed_at
        )
        VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, NULL, NULL, ?, NULL, ?, ?, NULL)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.badgeTemplateId,
        input.promptText,
        input.stylePreset,
        input.promptNotes ?? null,
        input.accentColor ?? null,
        input.requestedByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  await insertStatement();

  const generation = await findBadgeTemplateImageGenerationById(db, input.tenantId, id);

  if (generation === null) {
    throw new Error(`Unable to load badge template image generation ${id} after insert`);
  }

  return generation;
};

export const updateBadgeTemplateImageGeneration = async (
  db: SqlDatabase,
  input: UpdateBadgeTemplateImageGenerationInput,
): Promise<BadgeTemplateImageGenerationRecord | null> => {
  const setClauses: string[] = [];
  const params: (string | null)[] = [];

  if (input.status !== undefined) {
    setClauses.push("status = ?");
    params.push(input.status);
  }

  if (input.resultImageUri !== undefined) {
    setClauses.push("result_image_uri = ?");
    params.push(input.resultImageUri);
  }

  if (input.errorMessage !== undefined) {
    setClauses.push("error_message = ?");
    params.push(input.errorMessage);
  }

  if (input.queuedJobId !== undefined) {
    setClauses.push("queued_job_id = ?");
    params.push(input.queuedJobId);
  }

  if (input.completedAt !== undefined) {
    setClauses.push("completed_at = ?");
    params.push(input.completedAt);
  }

  if (setClauses.length === 0) {
    throw new Error("No badge template image generation fields were provided for update");
  }

  const updatedAt = new Date().toISOString();
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_template_image_generations
        SET ${setClauses.join(", ")},
            updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
      `,
      )
      .bind(...params, updatedAt, input.tenantId, input.id)
      .run();

  await updateStatement();

  return findBadgeTemplateImageGenerationById(db, input.tenantId, input.id);
};

export const findBadgeTemplateImageGenerationById = async (
  db: SqlDatabase,
  tenantId: string,
  generationId: string,
): Promise<BadgeTemplateImageGenerationRecord | null> => {
  const findStatement = (): Promise<BadgeTemplateImageGenerationRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          status,
          prompt_text AS promptText,
          style_preset AS stylePreset,
          prompt_notes AS promptNotes,
          accent_color AS accentColor,
          result_image_uri AS resultImageUri,
          error_message AS errorMessage,
          requested_by_user_id AS requestedByUserId,
          queued_job_id AS queuedJobId,
          created_at AS createdAt,
          updated_at AS updatedAt,
          completed_at AS completedAt
        FROM badge_template_image_generations
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, generationId)
      .first<BadgeTemplateImageGenerationRow>();

  let row: BadgeTemplateImageGenerationRow | null;

  row = await findStatement();

  return row === null ? null : mapBadgeTemplateImageGenerationRow(row);
};
