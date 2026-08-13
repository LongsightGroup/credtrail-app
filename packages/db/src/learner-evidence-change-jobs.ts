import { enqueueJobQueueMessageOnce } from "./job-queue.js";
import type { SqlDatabase } from "./tenant-scope.js";

/** Evidence mutations that can change governed learner-pathway progress. */
export type LearnerEvidenceChangeTrigger =
  | "assertion_issued"
  | "assertion_revoked"
  | "learner_record_created"
  | "learner_record_revised";

/** Atomically records durable learner-pathway projection work for an evidence mutation. */
export const enqueueLearnerEvidenceChange = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly learnerProfileId: string;
    readonly trigger: LearnerEvidenceChangeTrigger;
    readonly evidenceEventId: string;
    readonly requestedAt: string;
  },
): Promise<boolean> => {
  return enqueueJobQueueMessageOnce(db, {
    tenantId: input.tenantId,
    jobType: "process_learner_evidence_change",
    payload: {
      learnerProfileId: input.learnerProfileId,
      trigger: input.trigger,
      requestedAt: input.requestedAt,
    },
    idempotencyKey: `${input.trigger}:${input.evidenceEventId}`,
    nowIso: input.requestedAt,
  });
};
