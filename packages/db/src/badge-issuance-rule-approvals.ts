import { addMonthsToIso, createPrefixedId } from "./shared-helpers";
import { runSqlTransaction, type SqlDatabase, type SqlRunResult } from "./tenant-scope";
import type { TenantMembershipRole } from "./tenant-memberships";
import {
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
  listBadgeIssuanceRuleVersionApprovalSteps,
} from "./badge-issuance-rule-reads.js";
import {
  badgeIssuanceRuleVersionSelectColumns,
  mapBadgeIssuanceRuleVersionRow,
  type BadgeIssuanceRuleVersionRow,
} from "./badge-issuance-rule-version-sql.js";
import { resolveBadgeRuleApprovalPolicy } from "./badge-rule-approval-policies.js";
import { actorCanDecideApprovalStep } from "./badge-rule-approval-authorization.js";
import type { BadgeRuleApprovalPolicyStepRecord } from "./badge-rule-approval-policies.js";
import type {
  ActivateBadgeIssuanceRuleVersionInput,
  BadgeIssuanceRuleApprovalEventAction,
  BadgeIssuanceRuleVersionRecord,
  DecideBadgeIssuanceRuleVersionInput,
  DecideBadgeIssuanceRuleVersionResult,
  SubmitBadgeIssuanceRuleVersionForApprovalInput,
  SubmitBadgeIssuanceRuleVersionForApprovalResult,
} from "./badge-issuance-rule-types.js";

const insertBadgeIssuanceRuleApprovalSteps = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    versionId: string;
    approvalSteps: readonly BadgeRuleApprovalPolicyStepRecord[];
    createdAt: string;
  },
): Promise<void> => {
  const insertSteps = async (): Promise<void> => {
    for (const [index, step] of input.approvalSteps.entries()) {
      await db
        .prepare(
          `
          INSERT INTO badge_issuance_rule_approval_steps (
            id,
            tenant_id,
            version_id,
            step_number,
            target_type,
            required_role,
            target_user_id,
            target_approver_group_id,
            org_unit_id,
            label,
            status,
            decided_by_user_id,
            decided_at,
            decision_comment,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)
        `,
        )
        .bind(
          createPrefixedId("bras"),
          input.tenantId,
          input.versionId,
          index + 1,
          step.targetType,
          step.requiredRole,
          step.targetUserId,
          step.targetApproverGroupId,
          step.orgUnitId,
          step.label,
          index === 0 ? "pending" : "queued",
          input.createdAt,
          input.createdAt,
        )
        .run();
    }
  };

  await insertSteps();
};

const insertBadgeIssuanceRuleApprovalEvent = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    versionId: string;
    stepNumber: number | null;
    action: BadgeIssuanceRuleApprovalEventAction;
    actorUserId: string | null;
    actorRole: TenantMembershipRole | null;
    comment: string | null;
    occurredAt: string;
  },
): Promise<void> => {
  const insertEventStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_approval_events (
          id,
          tenant_id,
          version_id,
          step_number,
          action,
          actor_user_id,
          actor_role,
          comment,
          occurred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        createPrefixedId("brae"),
        input.tenantId,
        input.versionId,
        input.stepNumber,
        input.action,
        input.actorUserId,
        input.actorRole,
        input.comment,
        input.occurredAt,
        input.occurredAt,
      )
      .run();

  await insertEventStatement();
};

const lockBadgeIssuanceRuleVersionForDecision = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    versionId: string;
  },
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${badgeIssuanceRuleVersionSelectColumns()}
      FROM badge_issuance_rule_versions
      WHERE tenant_id = ?
        AND rule_id = ?
        AND id = ?
      FOR UPDATE
    `,
    )
    .bind(input.tenantId, input.ruleId, input.versionId)
    .first<BadgeIssuanceRuleVersionRow>();

  return row === null ? null : mapBadgeIssuanceRuleVersionRow(row);
};

export const submitBadgeIssuanceRuleVersionForApproval = async (
  db: SqlDatabase,
  input: SubmitBadgeIssuanceRuleVersionForApprovalInput,
): Promise<SubmitBadgeIssuanceRuleVersionForApprovalResult> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();

  return runSqlTransaction(db, async (transactionDb) => {
    const version = await findBadgeIssuanceRuleVersionById(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });

    if (version === null) {
      return { status: "not_found" } as const;
    }

    if (version.status !== "draft" && version.status !== "rejected") {
      return { status: "not_submittable" } as const;
    }

    const rule = await findBadgeIssuanceRuleById(transactionDb, input.tenantId, input.ruleId);

    if (rule === null) {
      return { status: "not_found" } as const;
    }

    const policy = await resolveBadgeRuleApprovalPolicy(transactionDb, {
      tenantId: input.tenantId,
      orgUnitId: rule.orgUnitId,
    });

    if (policy.approvalRequirement === "never" && !policy.allowSelfCertification) {
      return { status: "self_certification_required" } as const;
    }

    if (policy.approvalRequirement === "always" && policy.approvalSteps.length === 0) {
      return { status: "policy_missing_steps" } as const;
    }

    const deleteApprovalStepsStatement = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
          DELETE FROM badge_issuance_rule_approval_steps
          WHERE tenant_id = ?
            AND version_id = ?
        `,
        )
        .bind(input.tenantId, input.versionId)
        .run();

    await deleteApprovalStepsStatement();

    if (policy.approvalRequirement === "never") {
      const approveVersionStatement = (): Promise<SqlRunResult> =>
        transactionDb
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

      await approveVersionStatement();
      await insertBadgeIssuanceRuleApprovalEvent(transactionDb, {
        tenantId: input.tenantId,
        versionId: input.versionId,
        stepNumber: null,
        action: "submitted",
        actorUserId: input.actorUserId ?? null,
        actorRole: input.actorRole ?? null,
        comment: input.comment ?? "Approved by badge rule approval policy",
        occurredAt,
      });

      const submittedVersion = await findBadgeIssuanceRuleVersionById(transactionDb, {
        tenantId: input.tenantId,
        ruleId: input.ruleId,
        versionId: input.versionId,
      });

      if (submittedVersion === null) {
        return { status: "not_found" } as const;
      }

      return {
        status: "submitted",
        version: submittedVersion,
        pendingStepNumber: null,
      } as const;
    }

    await insertBadgeIssuanceRuleApprovalSteps(transactionDb, {
      tenantId: input.tenantId,
      versionId: input.versionId,
      approvalSteps: policy.approvalSteps,
      createdAt: occurredAt,
    });

    const submitVersionStatement = (): Promise<SqlRunResult> =>
      transactionDb
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

    await submitVersionStatement();

    await insertBadgeIssuanceRuleApprovalEvent(transactionDb, {
      tenantId: input.tenantId,
      versionId: input.versionId,
      stepNumber: 1,
      action: "submitted",
      actorUserId: input.actorUserId ?? null,
      actorRole: input.actorRole ?? null,
      comment: input.comment ?? null,
      occurredAt,
    });

    const submittedVersion = await findBadgeIssuanceRuleVersionById(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });

    if (submittedVersion === null) {
      return { status: "not_found" } as const;
    }

    return {
      status: "submitted",
      version: submittedVersion,
      pendingStepNumber: 1,
    } as const;
  });
};

export const decideBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: DecideBadgeIssuanceRuleVersionInput,
): Promise<DecideBadgeIssuanceRuleVersionResult> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();

  return runSqlTransaction(db, async (transactionDb) => {
    const currentVersion = await lockBadgeIssuanceRuleVersionForDecision(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });

    if (currentVersion === null) {
      return { status: "not_found" } as const;
    }

    if (currentVersion.status !== "pending_approval") {
      return { status: "not_pending" } as const;
    }

    if (
      currentVersion.createdByUserId === input.actorUserId ||
      currentVersion.submittedByUserId === input.actorUserId
    ) {
      return { status: "separation_of_duties" } as const;
    }

    if (input.decision === "changes_requested" && (input.comment ?? "").trim().length === 0) {
      return { status: "comment_required" } as const;
    }

    const steps = await listBadgeIssuanceRuleVersionApprovalSteps(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });
    const currentStep = steps.find((step) => step.status === "pending");

    if (currentStep === undefined) {
      return { status: "no_pending_step" } as const;
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
      } as const;
    }

    const nextStep = steps.find((step) => step.stepNumber > currentStep.stepNumber);
    const markCurrentStepStatement = (
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
    const markNextStepPendingStatement = (): Promise<SqlRunResult> =>
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
    const updateVersionPendingStatement = (): Promise<SqlRunResult> =>
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
    const updateVersionApprovedStatement = (): Promise<SqlRunResult> =>
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
    const updateVersionRejectedStatement = (): Promise<SqlRunResult> =>
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
    const updateVersionChangesRequestedStatement = (): Promise<SqlRunResult> =>
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
      const markedStep = await markCurrentStepStatement("rejected");
      const updatedVersion = await updateVersionRejectedStatement();

      if (
        (markedStep.meta.rowsWritten ?? 0) === 0 ||
        (updatedVersion.meta.rowsWritten ?? 0) === 0
      ) {
        return { status: "stale" } as const;
      }
    } else if (input.decision === "changes_requested") {
      const markedStep = await markCurrentStepStatement("changes_requested");
      const updatedVersion = await updateVersionChangesRequestedStatement();

      if (
        (markedStep.meta.rowsWritten ?? 0) === 0 ||
        (updatedVersion.meta.rowsWritten ?? 0) === 0
      ) {
        return { status: "stale" } as const;
      }
    } else {
      const markedStep = await markCurrentStepStatement("approved");

      if ((markedStep.meta.rowsWritten ?? 0) === 0) {
        return { status: "stale" } as const;
      }

      if (nextStep === undefined) {
        const updatedVersion = await updateVersionApprovedStatement();

        if ((updatedVersion.meta.rowsWritten ?? 0) === 0) {
          return { status: "stale" } as const;
        }
      } else {
        const markedNextStep = await markNextStepPendingStatement();
        const updatedVersion = await updateVersionPendingStatement();

        if (
          (markedNextStep.meta.rowsWritten ?? 0) === 0 ||
          (updatedVersion.meta.rowsWritten ?? 0) === 0
        ) {
          return { status: "stale" } as const;
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

    const decidedVersion = await findBadgeIssuanceRuleVersionById(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });

    if (decidedVersion === null) {
      return { status: "stale" } as const;
    }

    return {
      status: "decided",
      version: decidedVersion,
      decidedStepNumber: currentStep.stepNumber,
      nextStepNumber: input.decision === "approved" ? (nextStep?.stepNumber ?? null) : null,
    } as const;
  });
};

export const activateBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: ActivateBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const activatedAt = input.activatedAt ?? new Date().toISOString();
  const effectiveStartsAt = input.effectiveStartsAt ?? activatedAt;

  return runSqlTransaction(db, async (transactionDb) => {
    const rule = await findBadgeIssuanceRuleById(transactionDb, input.tenantId, input.ruleId);

    if (rule === null) {
      return null;
    }

    const policy = await resolveBadgeRuleApprovalPolicy(transactionDb, {
      tenantId: input.tenantId,
      orgUnitId: rule.orgUnitId,
    });
    const recertificationDueAt =
      policy.recertificationIntervalMonths === null
        ? null
        : addMonthsToIso(activatedAt, policy.recertificationIntervalMonths);
    const deprecateExistingStatement = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'deprecated',
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND status = 'active'
          AND id <> ?
      `,
        )
        .bind(activatedAt, input.tenantId, input.ruleId, input.versionId)
        .run();
    const activateStatement = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'active',
          activated_by_user_id = ?,
          activated_at = ?,
          effective_starts_at = ?,
          expires_at = ?,
          expired_at = NULL,
          suspended_at = NULL,
          suspended_by_user_id = NULL,
          suspension_reason = NULL,
          recertification_due_at = ?,
          expiry_reminder_sent_at = NULL,
          recertification_reminder_sent_at = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
          AND status = 'approved'
      `,
        )
        .bind(
          input.actorUserId,
          activatedAt,
          effectiveStartsAt,
          input.expiresAt ?? null,
          recertificationDueAt,
          activatedAt,
          input.tenantId,
          input.ruleId,
          input.versionId,
        )
        .run();
    const updateRuleActiveVersionStatement = (): Promise<SqlRunResult> =>
      transactionDb
        .prepare(
          `
        UPDATE badge_issuance_rules
        SET
          active_version_id = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
      `,
        )
        .bind(input.versionId, activatedAt, input.tenantId, input.ruleId)
        .run();

    const activated = await activateStatement();

    if ((activated.meta.rowsWritten ?? 0) === 0) {
      return null;
    }

    await deprecateExistingStatement();
    await updateRuleActiveVersionStatement();

    return findBadgeIssuanceRuleVersionById(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });
  });
};
