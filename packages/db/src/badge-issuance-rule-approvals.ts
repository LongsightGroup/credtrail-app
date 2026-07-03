import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlRunResult } from "./tenant-scope";
import {
  isTenantMembershipRole,
  tenantMembershipRoleSatisfiesMinimumRole,
  type TenantMembershipRole,
} from "./tenant-memberships";
import {
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
  listBadgeIssuanceRuleVersionApprovalSteps,
} from "./badge-issuance-rule-reads.js";
import { resolveBadgeRuleApprovalPolicy } from "./badge-rule-approval-policies.js";
import type {
  ActivateBadgeIssuanceRuleVersionInput,
  BadgeIssuanceRuleApprovalEventAction,
  BadgeIssuanceRuleApprovalStepRecord,
  BadgeIssuanceRuleVersionRecord,
  DecideBadgeIssuanceRuleVersionInput,
  SubmitBadgeIssuanceRuleVersionForApprovalInput,
} from "./badge-issuance-rule-types.js";

const insertBadgeIssuanceRuleApprovalSteps = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    versionId: string;
    approvalSteps: readonly {
      requiredRole: TenantMembershipRole;
      label: string | null;
    }[];
    createdAt: string;
  },
): Promise<void> => {
  const insertSteps = async (): Promise<void> => {
    for (const [index, step] of input.approvalSteps.entries()) {
      const requiredRole: unknown = step.requiredRole;

      if (!isTenantMembershipRole(requiredRole)) {
        throw new Error(
          `Unsupported tenant role in badge rule approval step: ${String(requiredRole)}`,
        );
      }

      await db
        .prepare(
          `
          INSERT INTO badge_issuance_rule_approval_steps (
            id,
            tenant_id,
            version_id,
            step_number,
            required_role,
            label,
            status,
            decided_by_user_id,
            decided_at,
            decision_comment,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, 'queued', NULL, NULL, NULL, ?, ?)
        `,
        )
        .bind(
          createPrefixedId("bras"),
          input.tenantId,
          input.versionId,
          index + 1,
          step.requiredRole,
          step.label,
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

const ensureBadgeIssuanceRuleApprovalStepsInitialized = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    versionId: string;
  },
): Promise<BadgeIssuanceRuleApprovalStepRecord[]> => {
  return listBadgeIssuanceRuleVersionApprovalSteps(db, input);
};

export const submitBadgeIssuanceRuleVersionForApproval = async (
  db: SqlDatabase,
  input: SubmitBadgeIssuanceRuleVersionForApprovalInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const version = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });

  if (version === null) {
    return null;
  }

  if (version.status !== "draft" && version.status !== "rejected") {
    return null;
  }

  const rule = await findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId);

  if (rule === null) {
    return null;
  }

  const policy = await resolveBadgeRuleApprovalPolicy(db, {
    tenantId: input.tenantId,
    orgUnitId: rule.ownerOrgUnitId,
  });
  const deleteApprovalStepsStatement = (): Promise<SqlRunResult> =>
    db
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
      db
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

    await approveVersionStatement();
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

    return findBadgeIssuanceRuleVersionById(db, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });
  }

  await insertBadgeIssuanceRuleApprovalSteps(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    approvalSteps: policy.approvalSteps,
    createdAt: occurredAt,
  });

  const approvalSteps = await ensureBadgeIssuanceRuleApprovalStepsInitialized(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
  const firstStep = approvalSteps[0];

  if (firstStep === undefined) {
    return null;
  }

  const resetApprovalStepsStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_approval_steps
        SET
          status = 'queued',
          decided_by_user_id = NULL,
          decided_at = NULL,
          decision_comment = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND version_id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.versionId)
      .run();
  const activateFirstApprovalStepStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_approval_steps
        SET
          status = 'pending',
          updated_at = ?
        WHERE tenant_id = ?
          AND version_id = ?
          AND step_number = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.versionId, firstStep.stepNumber)
      .run();
  const submitVersionStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'pending_approval',
          approved_by_user_id = NULL,
          approved_at = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();

  await resetApprovalStepsStatement();
  await activateFirstApprovalStepStatement();
  await submitVersionStatement();

  await insertBadgeIssuanceRuleApprovalEvent(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    stepNumber: firstStep.stepNumber,
    action: "submitted",
    actorUserId: input.actorUserId ?? null,
    actorRole: input.actorRole ?? null,
    comment: input.comment ?? null,
    occurredAt,
  });

  return findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
};

export const decideBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: DecideBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const currentVersion = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });

  if (currentVersion?.status !== "pending_approval") {
    return null;
  }

  const steps = await ensureBadgeIssuanceRuleApprovalStepsInitialized(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
  const currentStep = steps.find((step) => step.status === "pending");

  if (currentStep === undefined) {
    return null;
  }

  if (!tenantMembershipRoleSatisfiesMinimumRole(input.actorRole, currentStep.requiredRole)) {
    throw new Error(
      `Role ${input.actorRole} does not satisfy required approval role ${currentStep.requiredRole}`,
    );
  }

  const nextStep = steps.find((step) => step.stepNumber > currentStep.stepNumber);
  const markCurrentStepStatement = (status: "approved" | "rejected"): Promise<SqlRunResult> =>
    db
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
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_approval_steps
        SET
          status = 'pending',
          updated_at = ?
        WHERE tenant_id = ?
          AND version_id = ?
          AND step_number = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.versionId, nextStep?.stepNumber ?? null)
      .run();
  const updateVersionPendingStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'pending_approval',
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();
  const updateVersionApprovedStatement = (): Promise<SqlRunResult> =>
    db
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
    db
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
      `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();

  if (input.decision === "rejected") {
    await markCurrentStepStatement("rejected");
    await updateVersionRejectedStatement();
  } else {
    await markCurrentStepStatement("approved");

    if (nextStep === undefined) {
      await updateVersionApprovedStatement();
    } else {
      await markNextStepPendingStatement();
      await updateVersionPendingStatement();
    }
  }

  await insertBadgeIssuanceRuleApprovalEvent(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    stepNumber: currentStep.stepNumber,
    action: input.decision,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
    comment: input.comment ?? null,
    occurredAt,
  });

  return findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
};

export const activateBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: ActivateBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const activatedAt = input.activatedAt ?? new Date().toISOString();
  const deprecateExistingStatement = (): Promise<SqlRunResult> =>
    db
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
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'active',
          activated_by_user_id = ?,
          activated_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(
        input.actorUserId,
        activatedAt,
        activatedAt,
        input.tenantId,
        input.ruleId,
        input.versionId,
      )
      .run();
  const updateRuleActiveVersionStatement = (): Promise<SqlRunResult> =>
    db
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

  let activated: SqlRunResult;

  await deprecateExistingStatement();
  activated = await activateStatement();
  await updateRuleActiveVersionStatement();

  if ((activated.meta.rowsWritten ?? 0) === 0) {
    return null;
  }

  return findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
};
