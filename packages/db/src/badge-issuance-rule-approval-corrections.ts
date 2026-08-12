import { createAuditLog } from "./audit-logs.js";
import { canReopenApprovedBadgeIssuanceRuleVersion } from "./badge-rule-approval-authorization.js";
import {
  deleteBadgeIssuanceRuleApprovalSteps,
  insertBadgeIssuanceRuleApprovalEvent,
  lockBadgeIssuanceRuleForTransition,
  lockBadgeIssuanceRuleVersionForTransition,
} from "./badge-issuance-rule-approval-storage.js";
import { findBadgeIssuanceRuleVersionById } from "./badge-issuance-rule-version-reads.js";
import type {
  ReopenApprovedBadgeIssuanceRuleVersionInput,
  ReopenApprovedBadgeIssuanceRuleVersionResult,
  WithdrawBadgeIssuanceRuleVersionSubmissionInput,
  WithdrawBadgeIssuanceRuleVersionSubmissionResult,
} from "./badge-issuance-rule-types.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

/** Returns the actor's pending submission to draft while preserving immutable approval history. */
export const withdrawBadgeIssuanceRuleVersionSubmission = async (
  db: SqlDatabase,
  input: WithdrawBadgeIssuanceRuleVersionSubmissionInput,
): Promise<WithdrawBadgeIssuanceRuleVersionSubmissionResult> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();

  return runSqlTransaction(db, async (transactionDb) => {
    const rule = await lockBadgeIssuanceRuleForTransition(transactionDb, input);

    if (rule === null) {
      return { status: "not_found" };
    }

    const version = await lockBadgeIssuanceRuleVersionForTransition(transactionDb, input);

    if (version === null) {
      return { status: "not_found" };
    }

    if (version.status !== "pending_approval") {
      return { status: "not_pending" };
    }

    if (version.submittedByUserId !== input.actorUserId) {
      return { status: "forbidden" };
    }

    const updateResult = await transactionDb
      .prepare(
        `
          UPDATE badge_issuance_rule_versions
          SET
            status = 'draft',
            submitted_by_user_id = NULL,
            submitted_at = NULL,
            approved_by_user_id = NULL,
            approved_at = NULL,
            updated_at = ?
          WHERE tenant_id = ?
            AND rule_id = ?
            AND id = ?
            AND status = 'pending_approval'
            AND submitted_by_user_id = ?
        `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId, input.actorUserId)
      .run();

    if ((updateResult.meta.rowsWritten ?? 0) !== 1) {
      return { status: "stale" };
    }

    await deleteBadgeIssuanceRuleApprovalSteps(transactionDb, input);
    await insertBadgeIssuanceRuleApprovalEvent(transactionDb, {
      tenantId: input.tenantId,
      versionId: input.versionId,
      stepNumber: null,
      action: "withdrawn",
      actorUserId: input.actorUserId,
      actorRole: input.actorRole,
      comment: "Submission withdrawn by submitter",
      occurredAt,
    });

    const withdrawnVersion = await findBadgeIssuanceRuleVersionById(transactionDb, input);

    if (withdrawnVersion === null) {
      return { status: "stale" };
    }

    await createAuditLog(transactionDb, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "badge_rule.version_submission_withdrawn",
      targetType: "badge_rule_version",
      targetId: withdrawnVersion.id,
      metadata: {
        role: input.actorRole,
        ruleId: input.ruleId,
        versionNumber: withdrawnVersion.versionNumber,
        status: withdrawnVersion.status,
      },
    });

    return {
      status: "withdrawn",
      version: withdrawnVersion,
    };
  });
};

/** Reopens an approved, inactive version when the final approver or an administrator corrects it. */
export const reopenApprovedBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: ReopenApprovedBadgeIssuanceRuleVersionInput,
): Promise<ReopenApprovedBadgeIssuanceRuleVersionResult> => {
  const comment = input.comment.trim();

  if (comment.length === 0) {
    return { status: "comment_required" };
  }

  const occurredAt = input.occurredAt ?? new Date().toISOString();

  return runSqlTransaction(db, async (transactionDb) => {
    const rule = await lockBadgeIssuanceRuleForTransition(transactionDb, input);

    if (rule === null) {
      return { status: "not_found" };
    }

    const version = await lockBadgeIssuanceRuleVersionForTransition(transactionDb, input);

    if (version === null) {
      return { status: "not_found" };
    }

    if (version.status !== "approved") {
      return { status: "not_approved" };
    }

    if (
      !canReopenApprovedBadgeIssuanceRuleVersion({
        version,
        actorUserId: input.actorUserId,
        actorRole: input.actorRole,
      })
    ) {
      return { status: "forbidden" };
    }

    const updateResult = await transactionDb
      .prepare(
        `
          UPDATE badge_issuance_rule_versions
          SET
            status = 'draft',
            submitted_by_user_id = NULL,
            submitted_at = NULL,
            approved_by_user_id = NULL,
            approved_at = NULL,
            updated_at = ?
          WHERE tenant_id = ?
            AND rule_id = ?
            AND id = ?
            AND status = 'approved'
        `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();

    if ((updateResult.meta.rowsWritten ?? 0) !== 1) {
      return { status: "stale" };
    }

    await deleteBadgeIssuanceRuleApprovalSteps(transactionDb, input);
    await insertBadgeIssuanceRuleApprovalEvent(transactionDb, {
      tenantId: input.tenantId,
      versionId: input.versionId,
      stepNumber: null,
      action: "reopened",
      actorUserId: input.actorUserId,
      actorRole: input.actorRole,
      comment,
      occurredAt,
    });

    const reopenedVersion = await findBadgeIssuanceRuleVersionById(transactionDb, input);

    if (reopenedVersion === null) {
      return { status: "stale" };
    }

    await createAuditLog(transactionDb, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "badge_rule.version_approval_reopened",
      targetType: "badge_rule_version",
      targetId: reopenedVersion.id,
      metadata: {
        role: input.actorRole,
        ruleId: input.ruleId,
        versionNumber: reopenedVersion.versionNumber,
        status: reopenedVersion.status,
        comment,
      },
    });

    return {
      status: "reopened",
      version: reopenedVersion,
    };
  });
};
