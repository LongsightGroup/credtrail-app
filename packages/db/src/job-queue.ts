import { addSecondsToIso, createPrefixedId } from "./shared-helpers";
import type { SqlDatabase } from "./tenant-scope";

type LearnerRecordTrustLevel = "issuer_verified" | "learner_supplemental";

export type JobQueueMessageType =
  | "issue_badge"
  | "revoke_badge"
  | "rebuild_verification_cache"
  | "import_migration_batch"
  | "import_learner_record_batch"
  | "generate_badge_template_image"
  | "process_badge_rule_lifecycle"
  | "process_end_of_term_badge_rule";

export type JobQueueMessageStatus = "pending" | "processing" | "completed" | "failed";

export interface JobQueueMessageRecord {
  id: string;
  tenantId: string;
  jobType: JobQueueMessageType;
  payloadJson: string;
  idempotencyKey: string;
  attemptCount: number;
  maxAttempts: number;
  availableAt: string;
  leasedUntil: string | null;
  leaseToken: string | null;
  lastError: string | null;
  completedAt: string | null;
  failedAt: string | null;
  status: JobQueueMessageStatus;
  createdAt: string;
  updatedAt: string;
}

export interface EnqueueJobQueueMessageInput {
  tenantId: string;
  jobType: JobQueueMessageType;
  payload: unknown;
  idempotencyKey: string;
  maxAttempts?: number | undefined;
}

export interface EnqueueJobQueueMessageOnceInput extends EnqueueJobQueueMessageInput {
  nowIso?: string | undefined;
}

export interface LeaseJobQueueMessagesInput {
  limit: number;
  leaseSeconds: number;
  nowIso: string;
}

export interface CompleteJobQueueMessageInput {
  id: string;
  leaseToken: string;
  nowIso: string;
}

export interface FailJobQueueMessageInput {
  id: string;
  leaseToken: string;
  nowIso: string;
  error: string;
  retryDelaySeconds: number;
}

export type MigrationBatchSource = "file_upload" | "credly_export" | "parchment_export" | "unknown";

export interface ImportMigrationBatchQueueMessageRecord extends JobQueueMessageRecord {
  source: MigrationBatchSource;
  batchId: string;
  rowNumber: number | null;
  fileName: string | null;
  format: string | null;
}

export interface ImportLearnerRecordBatchQueueMessageRecord extends JobQueueMessageRecord {
  batchId: string;
  rowNumber: number | null;
  fileName: string | null;
  format: string | null;
  defaultTrustLevel: LearnerRecordTrustLevel | null;
}

export interface ListImportMigrationBatchQueueMessagesInput {
  tenantId: string;
  source?: Exclude<MigrationBatchSource, "unknown"> | undefined;
  limit?: number | undefined;
}

export interface RetryFailedImportMigrationBatchQueueMessagesInput {
  tenantId: string;
  batchId: string;
  source?: Exclude<MigrationBatchSource, "unknown"> | undefined;
  rowNumbers?: readonly number[] | undefined;
  nowIso?: string | undefined;
}

export interface RetryFailedImportMigrationBatchQueueMessagesResult {
  matched: number;
  retried: number;
  skippedNotFailed: number;
}

export interface ListImportLearnerRecordBatchQueueMessagesInput {
  tenantId: string;
  limit?: number | undefined;
}

export interface RetryFailedImportLearnerRecordBatchQueueMessagesInput {
  tenantId: string;
  batchId: string;
  rowNumbers?: readonly number[] | undefined;
  nowIso?: string | undefined;
}

export interface RetryFailedImportLearnerRecordBatchQueueMessagesResult {
  matched: number;
  retried: number;
  skippedNotFailed: number;
}

interface JobQueueMessageRow {
  id: string;
  tenantId: string;
  jobType: JobQueueMessageType;
  payloadJson: string;
  idempotencyKey: string;
  attemptCount: number;
  maxAttempts: number;
  availableAt: string;
  leasedUntil: string | null;
  leaseToken: string | null;
  lastError: string | null;
  completedAt: string | null;
  failedAt: string | null;
  status: JobQueueMessageStatus;
  createdAt: string;
  updatedAt: string;
}

const serializeQueuePayload = (payload: unknown): string => {
  if (payload === undefined) {
    throw new Error("Queue payload is not JSON serializable");
  }

  return JSON.stringify(payload);
};

const mapJobQueueMessageRow = (row: JobQueueMessageRow): JobQueueMessageRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    jobType: row.jobType,
    payloadJson: row.payloadJson,
    idempotencyKey: row.idempotencyKey,
    attemptCount: row.attemptCount,
    maxAttempts: row.maxAttempts,
    availableAt: row.availableAt,
    leasedUntil: row.leasedUntil,
    leaseToken: row.leaseToken,
    lastError: row.lastError,
    completedAt: row.completedAt,
    failedAt: row.failedAt,
    status: row.status,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const migrationBatchPayloadFromJson = (
  payloadJson: string,
): {
  source: MigrationBatchSource;
  batchId: string;
  rowNumber: number | null;
  fileName: string | null;
  format: string | null;
} | null => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(payloadJson) as unknown;
  } catch {
    return null;
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }

  const payload = parsed as Record<string, unknown>;
  const rawBatchId = payload.batchId;

  if (typeof rawBatchId !== "string") {
    return null;
  }

  const batchId = rawBatchId.trim();

  if (batchId.length === 0) {
    return null;
  }

  const source =
    payload.source === "file_upload" ||
    payload.source === "credly_export" ||
    payload.source === "parchment_export"
      ? payload.source
      : "unknown";
  const rowNumberRaw = payload.rowNumber;
  const rowNumber =
    typeof rowNumberRaw === "number" && Number.isInteger(rowNumberRaw) && rowNumberRaw > 0
      ? rowNumberRaw
      : null;
  const fileName =
    typeof payload.fileName === "string" && payload.fileName.trim().length > 0
      ? payload.fileName.trim()
      : null;
  const format =
    typeof payload.format === "string" && payload.format.trim().length > 0
      ? payload.format.trim()
      : null;

  return {
    source,
    batchId,
    rowNumber,
    fileName,
    format,
  };
};

const learnerRecordImportBatchPayloadFromJson = (
  payloadJson: string,
): {
  batchId: string;
  rowNumber: number | null;
  fileName: string | null;
  format: string | null;
  defaultTrustLevel: LearnerRecordTrustLevel | null;
} | null => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(payloadJson) as unknown;
  } catch {
    return null;
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }

  const payload = parsed as Record<string, unknown>;
  const rawBatchId = payload.batchId;

  if (typeof rawBatchId !== "string") {
    return null;
  }

  const batchId = rawBatchId.trim();

  if (batchId.length === 0) {
    return null;
  }

  const rowNumberRaw = payload.rowNumber;
  const rowNumber =
    typeof rowNumberRaw === "number" && Number.isInteger(rowNumberRaw) && rowNumberRaw > 0
      ? rowNumberRaw
      : null;
  const fileName =
    typeof payload.fileName === "string" && payload.fileName.trim().length > 0
      ? payload.fileName.trim()
      : null;
  const format =
    typeof payload.format === "string" && payload.format.trim().length > 0
      ? payload.format.trim()
      : null;

  let defaultTrustLevel: LearnerRecordTrustLevel | null = null;

  if (
    payload.row !== null &&
    typeof payload.row === "object" &&
    !Array.isArray(payload.row) &&
    (payload.row as Record<string, unknown>).effectiveTrustLevel !== undefined
  ) {
    const effectiveTrustLevel = (payload.row as Record<string, unknown>).effectiveTrustLevel;

    if (
      effectiveTrustLevel === "issuer_verified" ||
      effectiveTrustLevel === "learner_supplemental"
    ) {
      defaultTrustLevel = effectiveTrustLevel;
    }
  }

  return {
    batchId,
    rowNumber,
    fileName,
    format,
    defaultTrustLevel,
  };
};

export const enqueueJobQueueMessage = async (
  db: SqlDatabase,
  input: EnqueueJobQueueMessageInput,
): Promise<JobQueueMessageRecord> => {
  const messageId = createPrefixedId("job");
  const nowIso = new Date().toISOString();
  const payloadJson = serializeQueuePayload(input.payload);
  const maxAttempts = input.maxAttempts ?? 8;

  await db
    .prepare(
      `
      INSERT INTO job_queue_messages (
        id,
        tenant_id,
        job_type,
        payload_json,
        idempotency_key,
        attempt_count,
        max_attempts,
        available_at,
        leased_until,
        lease_token,
        last_error,
        completed_at,
        failed_at,
        status,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL, NULL, NULL, NULL, 'pending', ?, ?)
    `,
    )
    .bind(
      messageId,
      input.tenantId,
      input.jobType,
      payloadJson,
      input.idempotencyKey,
      maxAttempts,
      nowIso,
      nowIso,
      nowIso,
    )
    .run();

  return {
    id: messageId,
    tenantId: input.tenantId,
    jobType: input.jobType,
    payloadJson,
    idempotencyKey: input.idempotencyKey,
    attemptCount: 0,
    maxAttempts,
    availableAt: nowIso,
    leasedUntil: null,
    leaseToken: null,
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: "pending",
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

export const enqueueJobQueueMessageOnce = async (
  db: SqlDatabase,
  input: EnqueueJobQueueMessageOnceInput,
): Promise<boolean> => {
  const messageId = createPrefixedId("job");
  const nowIso = input.nowIso ?? new Date().toISOString();
  const payloadJson = serializeQueuePayload(input.payload);
  const maxAttempts = input.maxAttempts ?? 8;
  const row = await db
    .prepare(
      `
      INSERT INTO job_queue_messages (
        id,
        tenant_id,
        job_type,
        payload_json,
        idempotency_key,
        attempt_count,
        max_attempts,
        available_at,
        leased_until,
        lease_token,
        last_error,
        completed_at,
        failed_at,
        status,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL, NULL, NULL, NULL, 'pending', ?, ?)
      ON CONFLICT(tenant_id, job_type, idempotency_key) DO NOTHING
      RETURNING id
    `,
    )
    .bind(
      messageId,
      input.tenantId,
      input.jobType,
      payloadJson,
      input.idempotencyKey,
      maxAttempts,
      nowIso,
      nowIso,
      nowIso,
    )
    .first<{ id: string }>();

  return row !== null;
};

export const leaseJobQueueMessages = async (
  db: SqlDatabase,
  input: LeaseJobQueueMessagesInput,
): Promise<JobQueueMessageRecord[]> => {
  const leaseToken = createPrefixedId("lease");
  const leaseExpiresAt = addSecondsToIso(input.nowIso, input.leaseSeconds);
  const candidateResult = await db
    .prepare(
      `
      SELECT id
      FROM job_queue_messages
      WHERE status IN ('pending', 'processing')
        AND available_at <= ?
        AND (leased_until IS NULL OR leased_until <= ?)
        AND attempt_count < max_attempts
      ORDER BY created_at ASC
      LIMIT ?
    `,
    )
    .bind(input.nowIso, input.nowIso, input.limit)
    .all<{ id: string }>();

  for (const candidate of candidateResult.results) {
    await db
      .prepare(
        `
        UPDATE job_queue_messages
        SET status = 'processing',
            attempt_count = attempt_count + 1,
            leased_until = ?,
            lease_token = ?,
            updated_at = ?
        WHERE id = ?
          AND available_at <= ?
          AND (leased_until IS NULL OR leased_until <= ?)
          AND attempt_count < max_attempts
      `,
      )
      .bind(leaseExpiresAt, leaseToken, input.nowIso, candidate.id, input.nowIso, input.nowIso)
      .run();
  }

  const leasedResult = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        job_type AS jobType,
        payload_json AS payloadJson,
        idempotency_key AS idempotencyKey,
        attempt_count AS attemptCount,
        max_attempts AS maxAttempts,
        available_at AS availableAt,
        leased_until AS leasedUntil,
        lease_token AS leaseToken,
        last_error AS lastError,
        completed_at AS completedAt,
        failed_at AS failedAt,
        status,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM job_queue_messages
      WHERE lease_token = ?
      ORDER BY created_at ASC
    `,
    )
    .bind(leaseToken)
    .all<JobQueueMessageRow>();

  return leasedResult.results.map((row) => mapJobQueueMessageRow(row));
};

export const completeJobQueueMessage = async (
  db: SqlDatabase,
  input: CompleteJobQueueMessageInput,
): Promise<void> => {
  await db
    .prepare(
      `
      UPDATE job_queue_messages
      SET status = 'completed',
          leased_until = NULL,
          lease_token = NULL,
          last_error = NULL,
          completed_at = ?,
          updated_at = ?
      WHERE id = ?
        AND lease_token = ?
    `,
    )
    .bind(input.nowIso, input.nowIso, input.id, input.leaseToken)
    .run();
};

export const failJobQueueMessage = async (
  db: SqlDatabase,
  input: FailJobQueueMessageInput,
): Promise<JobQueueMessageStatus | null> => {
  const retryAt = addSecondsToIso(input.nowIso, input.retryDelaySeconds);

  await db
    .prepare(
      `
      UPDATE job_queue_messages
      SET status = CASE WHEN attempt_count >= max_attempts THEN 'failed' ELSE 'pending' END,
          available_at = CASE WHEN attempt_count >= max_attempts THEN available_at ELSE ? END,
          leased_until = NULL,
          lease_token = NULL,
          last_error = ?,
          failed_at = CASE WHEN attempt_count >= max_attempts THEN ? ELSE NULL END,
          updated_at = ?
      WHERE id = ?
        AND lease_token = ?
    `,
    )
    .bind(retryAt, input.error, input.nowIso, input.nowIso, input.id, input.leaseToken)
    .run();

  const row = await db
    .prepare(
      `
      SELECT
        status,
        lease_token AS leaseToken
      FROM job_queue_messages
      WHERE id = ?
    `,
    )
    .bind(input.id)
    .first<{ status: JobQueueMessageStatus; leaseToken: string | null }>();

  if (row?.leaseToken !== null) {
    return null;
  }

  return row.status;
};

export const listImportMigrationBatchQueueMessages = async (
  db: SqlDatabase,
  input: ListImportMigrationBatchQueueMessagesInput,
): Promise<ImportMigrationBatchQueueMessageRecord[]> => {
  const limit = input.limit ?? 200;
  const boundedLimit = Math.max(1, Math.min(limit, 1000));
  const result = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        job_type AS jobType,
        payload_json AS payloadJson,
        idempotency_key AS idempotencyKey,
        attempt_count AS attemptCount,
        max_attempts AS maxAttempts,
        available_at AS availableAt,
        leased_until AS leasedUntil,
        lease_token AS leaseToken,
        last_error AS lastError,
        completed_at AS completedAt,
        failed_at AS failedAt,
        status,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM job_queue_messages
      WHERE tenant_id = ?
        AND job_type = 'import_migration_batch'
      ORDER BY created_at DESC
      LIMIT ?
    `,
    )
    .bind(input.tenantId, boundedLimit)
    .all<JobQueueMessageRow>();
  const parsedMessages: ImportMigrationBatchQueueMessageRecord[] = [];

  for (const row of result.results) {
    const payload = migrationBatchPayloadFromJson(row.payloadJson);

    if (payload === null) {
      continue;
    }

    if (input.source !== undefined && payload.source !== input.source) {
      continue;
    }

    parsedMessages.push({
      ...mapJobQueueMessageRow(row),
      source: payload.source,
      batchId: payload.batchId,
      rowNumber: payload.rowNumber,
      fileName: payload.fileName,
      format: payload.format,
    });
  }

  return parsedMessages;
};

export const retryFailedImportMigrationBatchQueueMessages = async (
  db: SqlDatabase,
  input: RetryFailedImportMigrationBatchQueueMessagesInput,
): Promise<RetryFailedImportMigrationBatchQueueMessagesResult> => {
  const nowIso = input.nowIso ?? new Date().toISOString();
  const rowNumberFilter = input.rowNumbers === undefined ? null : new Set<number>(input.rowNumbers);
  const candidateRows = await listImportMigrationBatchQueueMessages(db, {
    tenantId: input.tenantId,
    ...(input.source === undefined ? {} : { source: input.source }),
    limit: 1000,
  });
  let matched = 0;
  let retried = 0;
  let skippedNotFailed = 0;

  for (const row of candidateRows) {
    if (row.batchId !== input.batchId) {
      continue;
    }

    if (
      rowNumberFilter !== null &&
      (row.rowNumber === null || !rowNumberFilter.has(row.rowNumber))
    ) {
      continue;
    }

    matched += 1;

    if (row.status !== "failed") {
      skippedNotFailed += 1;
      continue;
    }

    await db
      .prepare(
        `
        UPDATE job_queue_messages
        SET status = 'pending',
            attempt_count = 0,
            available_at = ?,
            leased_until = NULL,
            lease_token = NULL,
            last_error = NULL,
            failed_at = NULL,
            updated_at = ?
        WHERE id = ?
          AND tenant_id = ?
          AND job_type = 'import_migration_batch'
      `,
      )
      .bind(nowIso, nowIso, row.id, input.tenantId)
      .run();
    retried += 1;
  }

  return {
    matched,
    retried,
    skippedNotFailed,
  };
};

export const listImportLearnerRecordBatchQueueMessages = async (
  db: SqlDatabase,
  input: ListImportLearnerRecordBatchQueueMessagesInput,
): Promise<ImportLearnerRecordBatchQueueMessageRecord[]> => {
  const limit = input.limit ?? 200;
  const boundedLimit = Math.max(1, Math.min(limit, 1000));
  const result = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        job_type AS jobType,
        payload_json AS payloadJson,
        idempotency_key AS idempotencyKey,
        attempt_count AS attemptCount,
        max_attempts AS maxAttempts,
        available_at AS availableAt,
        leased_until AS leasedUntil,
        lease_token AS leaseToken,
        last_error AS lastError,
        completed_at AS completedAt,
        failed_at AS failedAt,
        status,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM job_queue_messages
      WHERE tenant_id = ?
        AND job_type = 'import_learner_record_batch'
      ORDER BY created_at DESC
      LIMIT ?
    `,
    )
    .bind(input.tenantId, boundedLimit)
    .all<JobQueueMessageRow>();
  const parsedMessages: ImportLearnerRecordBatchQueueMessageRecord[] = [];

  for (const row of result.results) {
    const payload = learnerRecordImportBatchPayloadFromJson(row.payloadJson);

    if (payload === null) {
      continue;
    }

    parsedMessages.push({
      ...mapJobQueueMessageRow(row),
      batchId: payload.batchId,
      rowNumber: payload.rowNumber,
      fileName: payload.fileName,
      format: payload.format,
      defaultTrustLevel: payload.defaultTrustLevel,
    });
  }

  return parsedMessages;
};

export const retryFailedImportLearnerRecordBatchQueueMessages = async (
  db: SqlDatabase,
  input: RetryFailedImportLearnerRecordBatchQueueMessagesInput,
): Promise<RetryFailedImportLearnerRecordBatchQueueMessagesResult> => {
  const nowIso = input.nowIso ?? new Date().toISOString();
  const rowNumberFilter = input.rowNumbers === undefined ? null : new Set<number>(input.rowNumbers);
  const candidateRows = await listImportLearnerRecordBatchQueueMessages(db, {
    tenantId: input.tenantId,
    limit: 1000,
  });
  let matched = 0;
  let retried = 0;
  let skippedNotFailed = 0;

  for (const row of candidateRows) {
    if (row.batchId !== input.batchId) {
      continue;
    }

    if (
      rowNumberFilter !== null &&
      (row.rowNumber === null || !rowNumberFilter.has(row.rowNumber))
    ) {
      continue;
    }

    matched += 1;

    if (row.status !== "failed") {
      skippedNotFailed += 1;
      continue;
    }

    await db
      .prepare(
        `
        UPDATE job_queue_messages
        SET status = 'pending',
            attempt_count = 0,
            available_at = ?,
            leased_until = NULL,
            lease_token = NULL,
            last_error = NULL,
            failed_at = NULL,
            updated_at = ?
        WHERE id = ?
          AND tenant_id = ?
          AND job_type = 'import_learner_record_batch'
      `,
      )
      .bind(nowIso, nowIso, row.id, input.tenantId)
      .run();
    retried += 1;
  }

  return {
    matched,
    retried,
    skippedNotFailed,
  };
};
