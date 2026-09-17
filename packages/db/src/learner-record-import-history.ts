import { z } from "zod";
import type { SqlDatabase } from "./tenant-scope";

const count = z.coerce.number().int().nonnegative();
const batchSchema = z.object({
  batchId: z.string(),
  fileName: z.string().nullable(),
  totalRows: count,
  pendingRows: count,
  processingRows: count,
  completedRows: count,
  failedRows: count,
  firstQueuedAt: z.string(),
  lastUpdatedAt: z.string(),
});
/** Complete counts for a recently updated import batch. */
export type LearnerRecordImportHistoryBatch = z.infer<typeof batchSchema>;

/** Aggregates all rows before limiting the history to 20 batches. */
export const listLearnerRecordImportHistory = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<LearnerRecordImportHistoryBatch[]> => {
  const result = await db
    .prepare(`
    WITH imports AS (
      SELECT *, CASE WHEN payload_json IS JSON OBJECT THEN payload_json::jsonb ELSE '{}'::jsonb END AS payload
      FROM job_queue_messages WHERE tenant_id = ? AND job_type = 'import_learner_record_batch'
    )
    SELECT payload->>'batchId' AS "batchId", MAX(payload->>'fileName') AS "fileName",
      COUNT(*) AS "totalRows",
      COUNT(*) FILTER (WHERE status = 'pending') AS "pendingRows",
      COUNT(*) FILTER (WHERE status = 'processing') AS "processingRows",
      COUNT(*) FILTER (WHERE status = 'completed') AS "completedRows",
      COUNT(*) FILTER (WHERE status = 'failed') AS "failedRows",
      MIN(created_at) AS "firstQueuedAt", MAX(updated_at) AS "lastUpdatedAt"
    FROM imports WHERE payload->>'batchId' IS NOT NULL GROUP BY payload->>'batchId'
    ORDER BY MAX(updated_at) DESC, payload->>'batchId' DESC LIMIT 20
  `)
    .bind(tenantId)
    .all<unknown>();
  return batchSchema.array().parse(result.results);
};

const learnerSchema = z.object({
  profileId: z.string(),
  displayName: z.string().nullable(),
  email: z.string().nullable(),
  records: count,
});
/** One learner whose import rows were successfully persisted. */
export type ImportedLearner = z.infer<typeof learnerSchema>;

/** Pages distinct learners from actual import applications, never from queued intentions. */
export const listImportedLearners = async (
  db: SqlDatabase,
  input: { tenantId: string; batchId: string; after?: string | undefined },
): Promise<ImportedLearner[]> => {
  const result = await db
    .prepare(`
    SELECT p.id AS "profileId", p.display_name AS "displayName",
      (SELECT identity_value FROM learner_identities i WHERE i.tenant_id = p.tenant_id
        AND i.learner_profile_id = p.id AND i.identity_type = 'email'
        ORDER BY i.is_primary DESC, i.id LIMIT 1) AS email,
      COUNT(*) AS records
    FROM learner_record_import_applications a
    JOIN learner_profiles p ON p.id = a.learner_profile_id AND p.tenant_id = a.tenant_id
    WHERE a.tenant_id = ? AND a.batch_id = ? AND a.applied_at IS NOT NULL
      AND a.learner_record_entry_id IS NOT NULL AND (CAST(? AS TEXT) IS NULL OR p.id > ?)
    GROUP BY p.id, p.tenant_id, p.display_name ORDER BY p.id LIMIT 51
  `)
    .bind(input.tenantId, input.batchId, input.after ?? null, input.after ?? null)
    .all<unknown>();
  return learnerSchema.array().parse(result.results);
};
