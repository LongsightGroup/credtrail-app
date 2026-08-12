import { createAuditLog } from "./audit-logs.js";
import {
  insertBadgeIssuanceRuleApprovalEvent,
  lockBadgeIssuanceRuleForTransition,
  lockBadgeIssuanceRuleVersionForTransition,
  replaceBadgeIssuanceRuleApprovalSteps,
} from "./badge-issuance-rule-approval-storage.js";
import { findBadgeIssuanceRuleVersionById } from "./badge-issuance-rule-version-reads.js";
import { resolveBadgeRuleApprovalPolicy } from "./badge-rule-approval-policies.js";
import type { BadgeRuleApprovalPolicyRecord } from "./badge-rule-approval-policies.js";
import type {
  BadgeIssuanceRuleVersionRecord,
  CreateBadgeIssuanceRuleResult,
  SubmitBadgeIssuanceRuleVersionForApprovalInput,
  SubmitBadgeIssuanceRuleVersionForApprovalResult,
} from "./badge-issuance-rule-types.js";
import { enqueueJobQueueMessageOnce } from "./job-queue.js";
import { runSqlTransaction, type SqlDatabase, type SqlRunResult } from "./tenant-scope.js";
import type { TenantMembershipRole } from "./tenant-memberships.js";

/** A validated approval policy ready to submit one badge-rule version. */
export type BadgeRuleSubmissionPreparation =
  | {
      readonly status: "ready";
      readonly policy: BadgeRuleApprovalPolicyRecord;
    }
  | {
      readonly status: "failed";
      readonly reason: "self_certification_required" | "policy_missing_steps";
    };

/** Resolves and validates the approval policy before an authoring workflow persists a draft. */
export const prepareBadgeRuleSubmission = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly orgUnitId: string;
  },
): Promise<BadgeRuleSubmissionPreparation> => {
  const policy = await resolveBadgeRuleApprovalPolicy(db, input);

  if (policy.approvalRequirement === "never" && !policy.allowSelfCertification) {
    return { status: "failed", reason: "self_certification_required" };
  }

  if (policy.approvalRequirement === "always" && policy.approvalSteps.length === 0) {
    return { status: "failed", reason: "policy_missing_steps" };
  }

  return {
    status: "ready",
    policy,
  };
};

const submissionNotificationIdempotencyKey = (input: {
  readonly versionId: string;
  readonly occurredAt: string;
}): string => `approval-submitted:${input.versionId}:${input.occurredAt}`;

const recordSubmissionEffects = async (
  db: SqlDatabase,
  input: SubmitBadgeIssuanceRuleVersionForApprovalInput,
  result: Extract<
    SubmitBadgeIssuanceRuleVersionForApprovalResult,
    { readonly status: "submitted" }
  >,
): Promise<void> => {
  await createAuditLog(db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    action: "badge_rule.version_submitted_for_approval",
    targetType: "badge_rule_version",
    targetId: result.version.id,
    metadata: {
      role: input.actorRole ?? null,
      ruleId: input.ruleId,
      versionNumber: result.version.versionNumber,
      status: result.version.status,
    },
  });

  if (result.pendingStepNumber === null) {
    return;
  }

  await enqueueJobQueueMessageOnce(db, {
    tenantId: input.tenantId,
    jobType: "send_badge_rule_approval_notification",
    idempotencyKey: submissionNotificationIdempotencyKey({
      versionId: result.version.id,
      occurredAt: result.version.submittedAt ?? result.version.updatedAt,
    }),
    payload: {
      notificationType: "approval_submitted",
      ruleId: input.ruleId,
      versionId: result.version.id,
      targetStepNumber: result.pendingStepNumber,
    },
  });
};

const applySubmission = async (
  db: SqlDatabase,
  input: SubmitBadgeIssuanceRuleVersionForApprovalInput,
  version: BadgeIssuanceRuleVersionRecord,
  policy: BadgeRuleApprovalPolicyRecord,
): Promise<SubmitBadgeIssuanceRuleVersionForApprovalResult> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();

  if (version.status !== "draft" && version.status !== "rejected") {
    return { status: "not_submittable" };
  }

  if (policy.tenantId !== input.tenantId) {
    throw new Error(`Badge rule approval policy does not match rule "${input.ruleId}"`);
  }

  await replaceBadgeIssuanceRuleApprovalSteps(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    approvalSteps: policy.approvalRequirement === "never" ? [] : policy.approvalSteps,
    createdAt: occurredAt,
  });

  if (policy.approvalRequirement === "never") {
    const approvalUpdate = await db
      .prepare(
        `
          UPDATE badge_issuance_rule_versions
          SET
            status = 'approved',
            submitted_by_user_id = ?,
            submitted_at = ?,
            approved_by_user_id = ?,
            approved_at = ?,
            updated_at = ?
          WHERE tenant_id = ?
            AND rule_id = ?
            AND id = ?
            AND status IN ('draft', 'rejected')
        `,
      )
      .bind(
        input.actorUserId ?? null,
        occurredAt,
        input.actorUserId ?? null,
        occurredAt,
        occurredAt,
        input.tenantId,
        input.ruleId,
        input.versionId,
      )
      .run();

    if ((approvalUpdate.meta.rowsWritten ?? 0) !== 1) {
      return { status: "not_submittable" };
    }

    await insertBadgeIssuanceRuleApprovalEvent(db, {
      tenantId: input.tenantId,
      versionId: input.versionId,
      stepNumber: null,
      action: "submitted",
      actorUserId: input.actorUserId ?? null,
      actorRole: input.actorRole ?? null,
      comment: input.comment ?? "Approved by badge rule approval policy",
      occurredAt,
    });

    const submittedVersion = await findBadgeIssuanceRuleVersionById(db, input);

    if (submittedVersion === null) {
      return { status: "not_found" };
    }

    return {
      status: "submitted",
      version: submittedVersion,
      pendingStepNumber: null,
    };
  }

  const submissionUpdate: SqlRunResult = await db
    .prepare(
      `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'pending_approval',
          submitted_by_user_id = ?,
          submitted_at = ?,
          approved_by_user_id = NULL,
          approved_at = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
          AND status IN ('draft', 'rejected')
      `,
    )
    .bind(
      input.actorUserId ?? null,
      occurredAt,
      occurredAt,
      input.tenantId,
      input.ruleId,
      input.versionId,
    )
    .run();

  if ((submissionUpdate.meta.rowsWritten ?? 0) !== 1) {
    return { status: "not_submittable" };
  }

  await insertBadgeIssuanceRuleApprovalEvent(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    stepNumber: 1,
    action: "submitted",
    actorUserId: input.actorUserId ?? null,
    actorRole: input.actorRole ?? null,
    comment: input.comment ?? null,
    occurredAt,
  });

  const submittedVersion = await findBadgeIssuanceRuleVersionById(db, input);

  if (submittedVersion === null) {
    return { status: "not_found" };
  }

  return {
    status: "submitted",
    version: submittedVersion,
    pendingStepNumber: 1,
  };
};

/**
 * Submits a freshly persisted draft inside its caller-owned authoring transaction.
 * This transaction-local primitive is intentionally not exported by the package barrel.
 */
export const submitPreparedBadgeRuleVersionWithinTransaction = async (
  db: SqlDatabase,
  input: {
    readonly draft: CreateBadgeIssuanceRuleResult;
    readonly actorUserId: string;
    readonly actorRole: TenantMembershipRole;
    readonly preparation: Extract<BadgeRuleSubmissionPreparation, { readonly status: "ready" }>;
  },
): Promise<
  Extract<SubmitBadgeIssuanceRuleVersionForApprovalResult, { readonly status: "submitted" }>
> => {
  const rule = await lockBadgeIssuanceRuleForTransition(db, {
    tenantId: input.draft.rule.tenantId,
    ruleId: input.draft.rule.id,
  });
  const version = await lockBadgeIssuanceRuleVersionForTransition(db, {
    tenantId: input.draft.rule.tenantId,
    ruleId: input.draft.rule.id,
    versionId: input.draft.version.id,
  });

  if (rule === null || version === null) {
    throw new Error(`New badge rule version "${input.draft.version.id}" could not be locked`);
  }

  const submissionInput: SubmitBadgeIssuanceRuleVersionForApprovalInput = {
    tenantId: input.draft.rule.tenantId,
    ruleId: input.draft.rule.id,
    versionId: input.draft.version.id,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
  };
  const result = await applySubmission(db, submissionInput, version, input.preparation.policy);

  if (result.status !== "submitted") {
    throw new Error(
      `New badge rule version "${input.draft.version.id}" could not be submitted: ${result.status}`,
    );
  }

  await recordSubmissionEffects(db, submissionInput, result);
  return result;
};

/** Submits a badge-rule version and records audit and notification effects atomically. */
export const submitBadgeIssuanceRuleVersionForApproval = async (
  db: SqlDatabase,
  input: SubmitBadgeIssuanceRuleVersionForApprovalInput,
): Promise<SubmitBadgeIssuanceRuleVersionForApprovalResult> => {
  return runSqlTransaction(db, async (transactionDb) => {
    const rule = await lockBadgeIssuanceRuleForTransition(transactionDb, input);

    if (rule === null) {
      return { status: "not_found" };
    }

    const version = await lockBadgeIssuanceRuleVersionForTransition(transactionDb, input);

    if (version === null) {
      return { status: "not_found" };
    }

    if (version.status !== "draft" && version.status !== "rejected") {
      return { status: "not_submittable" };
    }

    const preparation = await prepareBadgeRuleSubmission(transactionDb, {
      tenantId: input.tenantId,
      orgUnitId: version.snapshot.orgUnitId,
    });

    if (preparation.status === "failed") {
      return { status: preparation.reason };
    }

    const result = await applySubmission(transactionDb, input, version, preparation.policy);

    if (result.status === "submitted") {
      await recordSubmissionEffects(transactionDb, input, result);
    }

    return result;
  });
};
