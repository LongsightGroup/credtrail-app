import { createAuditLog } from "./audit-logs.js";
import {
  insertBadgeIssuanceRuleApprovalEvent,
  lockBadgeIssuanceRuleForTransition,
  lockBadgeIssuanceRuleVersionForTransition,
} from "./badge-issuance-rule-approval-storage.js";
import {
  findBadgeIssuanceRuleVersionById,
  listBadgeIssuanceRuleVersionApprovalSteps,
} from "./badge-issuance-rule-reads.js";
import { actorCanDecideApprovalStep } from "./badge-rule-approval-authorization.js";
import type {
  DecideBadgeIssuanceRuleVersionInput,
  DecideBadgeIssuanceRuleVersionResult,
} from "./badge-issuance-rule-types.js";
import { enqueueJobQueueMessageOnce } from "./job-queue.js";
import { runSqlTransaction, type SqlDatabase, type SqlRunResult } from "./tenant-scope.js";

const decisionNotificationIdempotencyKey = (input: {
  readonly versionId: string;
  readonly occurredAt: string;
}): string => `approval-decision:${input.versionId}:${input.occurredAt}`;

const recordDecisionEffects = async (
  db: SqlDatabase,
  input: DecideBadgeIssuanceRuleVersionInput,
  result: Extract<DecideBadgeIssuanceRuleVersionResult, { readonly status: "decided" }>,
): Promise<void> => {
  await createAuditLog(db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    action: "badge_rule.version_approval_decided",
    targetType: "badge_rule_version",
    targetId: result.version.id,
    metadata: {
      role: input.actorRole,
      ruleId: input.ruleId,
      versionNumber: result.version.versionNumber,
      decision: input.decision,
      comment: input.comment ?? null,
      status: result.version.status,
    },
  });

  await enqueueJobQueueMessageOnce(db, {
    tenantId: input.tenantId,
    jobType: "send_badge_rule_approval_notification",
    idempotencyKey: decisionNotificationIdempotencyKey({
      versionId: result.version.id,
      occurredAt: result.version.updatedAt,
    }),
    payload: {
      notificationType: "approval_decision",
      ruleId: input.ruleId,
      versionId: result.version.id,
      decision: input.decision,
      comment: input.comment ?? null,
      nextStepNumber: result.nextStepNumber,
    },
  });
};

/** Decides a badge-rule approval and records audit and notification effects atomically. */
export const decideBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: DecideBadgeIssuanceRuleVersionInput,
): Promise<DecideBadgeIssuanceRuleVersionResult> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();

  return runSqlTransaction(db, async (transactionDb) => {
    const rule = await lockBadgeIssuanceRuleForTransition(transactionDb, input);

    if (rule === null) {
      return { status: "not_found" };
    }

    const currentVersion = await lockBadgeIssuanceRuleVersionForTransition(transactionDb, input);

    if (currentVersion === null) {
      return { status: "not_found" };
    }

    if (currentVersion.status !== "pending_approval") {
      return { status: "not_pending" };
    }

    if (
      currentVersion.createdByUserId === input.actorUserId ||
      currentVersion.submittedByUserId === input.actorUserId
    ) {
      return { status: "separation_of_duties" };
    }

    if (input.decision === "changes_requested" && (input.comment ?? "").trim().length === 0) {
      return { status: "comment_required" };
    }

    const steps = await listBadgeIssuanceRuleVersionApprovalSteps(transactionDb, input);
    const currentStep = steps.find((step) => step.status === "pending");

    if (currentStep === undefined) {
      return { status: "no_pending_step" };
    }

    if (
      !(await actorCanDecideApprovalStep(transactionDb, {
        tenantId: input.tenantId,
        actorUserId: input.actorUserId,
        actorRole: input.actorRole,
        step: currentStep,
      }))
    ) {
      return {
        status: "forbidden",
        step: {
          targetType: currentStep.targetType,
          requiredRole: currentStep.requiredRole,
        },
      };
    }

    const nextStep = steps.find((step) => step.stepNumber > currentStep.stepNumber);
    const markCurrentStep = (
      status: "approved" | "rejected" | "changes_requested",
    ): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
            UPDATE badge_issuance_rule_approval_steps
            SET
              status = ?,
              decided_by_user_id = ?,
              decided_at = ?,
              decision_comment = ?,
              updated_at = ?
            WHERE tenant_id = ?
              AND version_id = ?
              AND step_number = ?
              AND status = 'pending'
          `,
        )
        .bind(
          status,
          input.actorUserId,
          occurredAt,
          input.comment ?? null,
          occurredAt,
          input.tenantId,
          input.versionId,
          currentStep.stepNumber,
        )
        .run();
    const markNextStepPending = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
            UPDATE badge_issuance_rule_approval_steps
            SET
              status = 'pending',
              updated_at = ?
            WHERE tenant_id = ?
              AND version_id = ?
              AND step_number = ?
              AND status = 'queued'
          `,
        )
        .bind(occurredAt, input.tenantId, input.versionId, nextStep?.stepNumber ?? null)
        .run();
    const updateVersionPending = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
            UPDATE badge_issuance_rule_versions
            SET
              status = 'pending_approval',
              updated_at = ?
            WHERE tenant_id = ?
              AND rule_id = ?
              AND id = ?
              AND status = 'pending_approval'
          `,
        )
        .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
        .run();
    const updateVersionApproved = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
            UPDATE badge_issuance_rule_versions
            SET
              status = 'approved',
              approved_by_user_id = ?,
              approved_at = ?,
              updated_at = ?
            WHERE tenant_id = ?
              AND rule_id = ?
              AND id = ?
              AND status = 'pending_approval'
          `,
        )
        .bind(
          input.actorUserId,
          occurredAt,
          occurredAt,
          input.tenantId,
          input.ruleId,
          input.versionId,
        )
        .run();
    const updateVersionRejected = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
            UPDATE badge_issuance_rule_versions
            SET
              status = 'rejected',
              approved_by_user_id = NULL,
              approved_at = NULL,
              updated_at = ?
            WHERE tenant_id = ?
              AND rule_id = ?
              AND id = ?
              AND status = 'pending_approval'
          `,
        )
        .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
        .run();
    const updateVersionChangesRequested = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
            UPDATE badge_issuance_rule_versions
            SET
              status = 'draft',
              approved_by_user_id = NULL,
              approved_at = NULL,
              updated_at = ?
            WHERE tenant_id = ?
              AND rule_id = ?
              AND id = ?
              AND status = 'pending_approval'
          `,
        )
        .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
        .run();

    if (input.decision === "rejected") {
      const markedStep = await markCurrentStep("rejected");
      const updatedVersion = await updateVersionRejected();

      if (
        (markedStep.meta.rowsWritten ?? 0) === 0 ||
        (updatedVersion.meta.rowsWritten ?? 0) === 0
      ) {
        return { status: "stale" };
      }
    } else if (input.decision === "changes_requested") {
      const markedStep = await markCurrentStep("changes_requested");
      const updatedVersion = await updateVersionChangesRequested();

      if (
        (markedStep.meta.rowsWritten ?? 0) === 0 ||
        (updatedVersion.meta.rowsWritten ?? 0) === 0
      ) {
        return { status: "stale" };
      }
    } else {
      const markedStep = await markCurrentStep("approved");

      if ((markedStep.meta.rowsWritten ?? 0) === 0) {
        return { status: "stale" };
      }

      if (nextStep === undefined) {
        const updatedVersion = await updateVersionApproved();

        if ((updatedVersion.meta.rowsWritten ?? 0) === 0) {
          return { status: "stale" };
        }
      } else {
        const markedNextStep = await markNextStepPending();
        const updatedVersion = await updateVersionPending();

        if (
          (markedNextStep.meta.rowsWritten ?? 0) === 0 ||
          (updatedVersion.meta.rowsWritten ?? 0) === 0
        ) {
          return { status: "stale" };
        }
      }
    }

    await insertBadgeIssuanceRuleApprovalEvent(transactionDb, {
      tenantId: input.tenantId,
      versionId: input.versionId,
      stepNumber: currentStep.stepNumber,
      action: input.decision,
      actorUserId: input.actorUserId,
      actorRole: input.actorRole,
      comment: input.comment ?? null,
      occurredAt,
    });

    const decidedVersion = await findBadgeIssuanceRuleVersionById(transactionDb, input);

    if (decidedVersion === null) {
      return { status: "stale" };
    }

    const result = {
      status: "decided",
      version: decidedVersion,
      decidedStepNumber: currentStep.stepNumber,
      nextStepNumber: input.decision === "approved" ? (nextStep?.stepNumber ?? null) : null,
    } as const;

    await recordDecisionEffects(transactionDb, input, result);
    return result;
  });
};
