import type {
  EnqueueJobQueueMessageOnceInput,
  EnqueueJobQueueMessagesOnceInput,
} from "./job-queue.js";
import { serializeQueuePayload } from "./job-queue-payload.js";
import { createPrefixedId } from "./shared-helpers.js";
import type { SqlDatabase } from "./tenant-scope.js";

/** Inserts a bounded batch of queue messages while preserving each idempotency identity. */
export const enqueueJobQueueMessagesOnce = async (
  db: SqlDatabase,
  input: EnqueueJobQueueMessagesOnceInput,
): Promise<number> => {
  let insertedCount = 0;

  for (let offset = 0; offset < input.messages.length; offset += 100) {
    const messageChunk = input.messages.slice(offset, offset + 100);

    if (messageChunk.length === 0) {
      continue;
    }

    const valuesSql = messageChunk
      .map(() => "(?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL, NULL, NULL, NULL, 'pending', ?, ?)")
      .join(", ");
    const bindings = messageChunk.flatMap((message) => [
      createPrefixedId("job"),
      message.tenantId,
      message.jobType,
      serializeQueuePayload(message.payload),
      message.idempotencyKey,
      message.maxAttempts ?? 8,
      input.nowIso,
      input.nowIso,
      input.nowIso,
    ]);
    const result = await db
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
        VALUES ${valuesSql}
        ON CONFLICT(tenant_id, job_type, idempotency_key) DO NOTHING
        RETURNING id
      `,
      )
      .bind(...bindings)
      .all<{ id: string }>();

    insertedCount += result.results.length;
  }

  return insertedCount;
};

/** Inserts a queue message once, or atomically revives the matching terminal failure. */
export const enqueueOrRetryFailedJobQueueMessage = async (
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
      ON CONFLICT(tenant_id, job_type, idempotency_key) DO UPDATE SET
        payload_json = excluded.payload_json,
        attempt_count = 0,
        max_attempts = excluded.max_attempts,
        available_at = excluded.available_at,
        leased_until = NULL,
        lease_token = NULL,
        last_error = NULL,
        completed_at = NULL,
        failed_at = NULL,
        status = 'pending',
        updated_at = excluded.updated_at
      WHERE job_queue_messages.status = 'failed'
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
