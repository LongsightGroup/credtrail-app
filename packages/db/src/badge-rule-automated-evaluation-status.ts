import {
  automatedBadgeRuleCommandIdempotencyKey,
  parseBadgeIssuanceRuleDefinitionJson,
  resolveAutomatedBadgeRuleIssuanceTiming,
  type ProcessAutomatedBadgeRuleQueueJob,
} from "@credtrail/validation";
import { findBadgeIssuanceRuleById } from "./badge-issuance-rule-reads.js";
import { findBadgeIssuanceRuleVersionById } from "./badge-issuance-rule-version-reads.js";
import { enqueueOrRetryFailedJobQueueMessageReturningId } from "./job-queue-enqueue.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

export type AutomatedBadgeRuleEvaluationStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "retrying"
  | "failed"
  | "noop";

export type AutomatedBadgeRuleEvaluationTrigger = "activation" | "hourly" | "expiry" | "manual";

export type AutomatedBadgeRuleEvaluationReasonTag =
  | "rule_or_version_not_found"
  | "instructor_confirmation_required"
  | "rule_version_inactive"
  | "rule_version_changed"
  | "learner_evaluation_unavailable";

export type AutomatedBadgeRuleEvaluationFailureTag =
  | "invalid_command"
  | "provider_unavailable"
  | "processing_error";

export interface AutomatedBadgeRuleEvaluationCounts {
  readonly candidateLearnerCount: number;
  readonly matchedLearnerCount: number;
  readonly issueJobsEnqueued: number;
  readonly learnersMissingEmail: number;
  readonly learnersAlreadyIssued: number;
  readonly learnersUnavailable: number;
  readonly learnerIdentityConflicts: number;
}

export interface AutomatedBadgeRuleEvaluationStatusRecord {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly commandId: string;
  readonly triggerKind: AutomatedBadgeRuleEvaluationTrigger;
  readonly status: AutomatedBadgeRuleEvaluationStatus;
  readonly queuedAt: string;
  readonly startedAt: string | null;
  readonly completedAt: string | null;
  readonly candidateLearnerCount: number | null;
  readonly matchedLearnerCount: number | null;
  readonly issueJobsEnqueued: number | null;
  readonly learnersMissingEmail: number | null;
  readonly learnersAlreadyIssued: number | null;
  readonly learnersUnavailable: number | null;
  readonly learnerIdentityConflicts: number | null;
  readonly reasonTag: AutomatedBadgeRuleEvaluationReasonTag | null;
  readonly failureTag: AutomatedBadgeRuleEvaluationFailureTag | null;
  readonly updatedAt: string;
}

interface AutomatedBadgeRuleEvaluationStatusRow extends AutomatedBadgeRuleEvaluationStatusRecord {}

const statusProjection = `
  tenant_id AS tenantId,
  rule_id AS ruleId,
  version_id AS versionId,
  command_id AS commandId,
  trigger_kind AS triggerKind,
  status,
  queued_at AS queuedAt,
  started_at AS startedAt,
  completed_at AS completedAt,
  candidate_learner_count AS candidateLearnerCount,
  matched_learner_count AS matchedLearnerCount,
  issue_jobs_enqueued AS issueJobsEnqueued,
  learners_missing_email AS learnersMissingEmail,
  learners_already_issued AS learnersAlreadyIssued,
  learners_unavailable AS learnersUnavailable,
  learner_identity_conflicts AS learnerIdentityConflicts,
  reason_tag AS reasonTag,
  failure_tag AS failureTag,
  updated_at AS updatedAt
`;

/** Reads the safe latest automated-evaluation outcome for one governed version. */
export const findAutomatedBadgeRuleEvaluationStatus = async (
  db: SqlDatabase,
  input: { readonly tenantId: string; readonly ruleId: string; readonly versionId: string },
): Promise<AutomatedBadgeRuleEvaluationStatusRecord | null> => {
  return db
    .prepare(
      `
      SELECT ${statusProjection}
      FROM badge_rule_automated_evaluation_status
      WHERE tenant_id = ?
        AND rule_id = ?
        AND version_id = ?
    `,
    )
    .bind(input.tenantId, input.ruleId, input.versionId)
    .first<AutomatedBadgeRuleEvaluationStatusRow>();
};

export type EnqueueAutomatedBadgeRuleEvaluationResult =
  | { readonly status: "queued"; readonly commandId: string }
  | { readonly status: "duplicate" };

/**
 * Enqueues and projects a command using the caller's transaction. Callers must
 * wrap this operation when atomicity with surrounding state matters.
 */
export const enqueueAutomatedBadgeRuleEvaluation = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly versionId: string;
    readonly payload: ProcessAutomatedBadgeRuleQueueJob["payload"];
    readonly idempotencyKey: string;
    readonly triggerKind: AutomatedBadgeRuleEvaluationTrigger;
    readonly queuedAt: string;
  },
): Promise<EnqueueAutomatedBadgeRuleEvaluationResult> => {
  const commandId = await enqueueOrRetryFailedJobQueueMessageReturningId(db, {
    tenantId: input.tenantId,
    jobType: "process_automated_badge_rule",
    payload: input.payload,
    idempotencyKey: input.idempotencyKey,
    nowIso: input.queuedAt,
  });

  if (commandId === null) {
    return { status: "duplicate" };
  }

  await db
    .prepare(
      `
      INSERT INTO badge_rule_automated_evaluation_status (
        tenant_id,
        rule_id,
        version_id,
        command_id,
        trigger_kind,
        status,
        queued_at,
        started_at,
        completed_at,
        candidate_learner_count,
        matched_learner_count,
        issue_jobs_enqueued,
        learners_missing_email,
        learners_already_issued,
        learners_unavailable,
        learner_identity_conflicts,
        reason_tag,
        failure_tag,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, 'queued', ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?)
      ON CONFLICT(tenant_id, version_id) DO UPDATE SET
        rule_id = excluded.rule_id,
        command_id = excluded.command_id,
        trigger_kind = excluded.trigger_kind,
        status = 'queued',
        queued_at = excluded.queued_at,
        started_at = NULL,
        completed_at = NULL,
        candidate_learner_count = NULL,
        matched_learner_count = NULL,
        issue_jobs_enqueued = NULL,
        learners_missing_email = NULL,
        learners_already_issued = NULL,
        learners_unavailable = NULL,
        learner_identity_conflicts = NULL,
        reason_tag = NULL,
        failure_tag = NULL,
        updated_at = excluded.updated_at
      WHERE excluded.queued_at >= badge_rule_automated_evaluation_status.queued_at
    `,
    )
    .bind(
      input.tenantId,
      input.ruleId,
      input.versionId,
      commandId,
      input.triggerKind,
      input.queuedAt,
      input.queuedAt,
    )
    .run();

  return { status: "queued", commandId };
};

/** Creates one authorized, retry-safe manual evaluation command. */
export const requestManualAutomatedBadgeRuleEvaluation = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly versionId: string;
    readonly requestId: string;
    readonly requestedAt: string;
  },
): Promise<"queued" | "duplicate" | "not_eligible"> => {
  return runSqlTransaction(db, async (transactionDb) => {
    const rule = await findBadgeIssuanceRuleById(transactionDb, input.tenantId, input.ruleId);
    const version = await findBadgeIssuanceRuleVersionById(transactionDb, input);

    if (
      rule === null ||
      version === null ||
      rule.activeVersionId !== version.id ||
      version.status !== "active" ||
      resolveAutomatedBadgeRuleIssuanceTiming(
        parseBadgeIssuanceRuleDefinitionJson(version.ruleJson),
      ) !== "immediate"
    ) {
      return "not_eligible";
    }

    const result = await enqueueAutomatedBadgeRuleEvaluation(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
      payload: {
        ruleId: input.ruleId,
        versionId: input.versionId,
        scheduledFor: input.requestedAt,
      },
      idempotencyKey: automatedBadgeRuleCommandIdempotencyKey({
        versionId: input.versionId,
        command: { kind: "manual", requestId: input.requestId },
      }),
      triggerKind: "manual",
      queuedAt: input.requestedAt,
    });

    return result.status;
  });
};

/** Marks a correlated command as actively evaluating. */
export const markAutomatedBadgeRuleEvaluationRunning = async (
  db: SqlDatabase,
  input: { readonly tenantId: string; readonly commandId: string; readonly startedAt: string },
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      UPDATE badge_rule_automated_evaluation_status
      SET
        status = 'running',
        started_at = ?,
        completed_at = NULL,
        candidate_learner_count = NULL,
        matched_learner_count = NULL,
        issue_jobs_enqueued = NULL,
        learners_missing_email = NULL,
        learners_already_issued = NULL,
        learners_unavailable = NULL,
        learner_identity_conflicts = NULL,
        reason_tag = NULL,
        failure_tag = NULL,
        updated_at = ?
      WHERE tenant_id = ?
        AND command_id = ?
        AND status IN ('queued', 'running', 'retrying')
    `,
    )
    .bind(input.startedAt, input.startedAt, input.tenantId, input.commandId)
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};

const bindCounts = (counts: AutomatedBadgeRuleEvaluationCounts): readonly number[] => [
  counts.candidateLearnerCount,
  counts.matchedLearnerCount,
  counts.issueJobsEnqueued,
  counts.learnersMissingEmail,
  counts.learnersAlreadyIssued,
  counts.learnersUnavailable,
  counts.learnerIdentityConflicts,
];

/** Records a successful, correlated evaluation with safe aggregate counts. */
export const markAutomatedBadgeRuleEvaluationSucceeded = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly commandId: string;
    readonly completedAt: string;
    readonly counts: AutomatedBadgeRuleEvaluationCounts;
  },
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      UPDATE badge_rule_automated_evaluation_status
      SET
        status = 'succeeded',
        completed_at = ?,
        candidate_learner_count = ?,
        matched_learner_count = ?,
        issue_jobs_enqueued = ?,
        learners_missing_email = ?,
        learners_already_issued = ?,
        learners_unavailable = ?,
        learner_identity_conflicts = ?,
        reason_tag = NULL,
        failure_tag = NULL,
        updated_at = ?
      WHERE tenant_id = ?
        AND command_id = ?
        AND status = 'running'
    `,
    )
    .bind(
      input.completedAt,
      ...bindCounts(input.counts),
      input.completedAt,
      input.tenantId,
      input.commandId,
    )
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};

/** Records a safe no-op reason for the current command. */
export const markAutomatedBadgeRuleEvaluationNoop = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly commandId: string;
    readonly completedAt: string;
    readonly reasonTag: AutomatedBadgeRuleEvaluationReasonTag;
  },
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      UPDATE badge_rule_automated_evaluation_status
      SET
        status = 'noop',
        completed_at = ?,
        reason_tag = ?,
        failure_tag = NULL,
        updated_at = ?
      WHERE tenant_id = ?
        AND command_id = ?
        AND status = 'running'
    `,
    )
    .bind(input.completedAt, input.reasonTag, input.completedAt, input.tenantId, input.commandId)
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};

/** Records an evaluation-level retry with safe aggregate counts. */
export const markAutomatedBadgeRuleEvaluationRetrying = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly commandId: string;
    readonly attemptedAt: string;
    readonly reasonTag: AutomatedBadgeRuleEvaluationReasonTag;
    readonly counts: AutomatedBadgeRuleEvaluationCounts;
  },
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      UPDATE badge_rule_automated_evaluation_status
      SET
        status = 'retrying',
        completed_at = NULL,
        candidate_learner_count = ?,
        matched_learner_count = ?,
        issue_jobs_enqueued = ?,
        learners_missing_email = ?,
        learners_already_issued = ?,
        learners_unavailable = ?,
        learner_identity_conflicts = ?,
        reason_tag = ?,
        failure_tag = NULL,
        updated_at = ?
      WHERE tenant_id = ?
        AND command_id = ?
        AND status = 'running'
    `,
    )
    .bind(
      ...bindCounts(input.counts),
      input.reasonTag,
      input.attemptedAt,
      input.tenantId,
      input.commandId,
    )
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};

/** Projects queue retry/failure without persisting raw exception text. */
export const markAutomatedBadgeRuleEvaluationQueueFailure = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly commandId: string;
    readonly failedAt: string;
    readonly terminal: boolean;
    readonly failureTag: AutomatedBadgeRuleEvaluationFailureTag;
  },
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      UPDATE badge_rule_automated_evaluation_status
      SET
        status = ?,
        completed_at = ?,
        failure_tag = CASE WHEN reason_tag IS NULL OR ? THEN ? ELSE failure_tag END,
        updated_at = ?
      WHERE tenant_id = ?
        AND command_id = ?
        AND status IN ('queued', 'running', 'retrying')
    `,
    )
    .bind(
      input.terminal ? "failed" : "retrying",
      input.terminal ? input.failedAt : null,
      input.terminal,
      input.failureTag,
      input.failedAt,
      input.tenantId,
      input.commandId,
    )
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};
