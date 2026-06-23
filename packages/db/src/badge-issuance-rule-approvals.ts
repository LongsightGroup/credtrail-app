import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlRunResult } from "./tenant-scope";
import {
  isTenantMembershipRole,
  tenantMembershipRoleSatisfiesMinimumRole,
  type TenantMembershipRole,
} from "./tenant-memberships";
import {
  findBadgeIssuanceRuleVersionById,
  listBadgeIssuanceRuleVersionApprovalSteps,
} from "./badge-issuance-rule-reads.js";
import type {
  ActivateBadgeIssuanceRuleVersionInput,
  BadgeIssuanceRuleApprovalChainStepInput,
  BadgeIssuanceRuleApprovalEventAction,
  BadgeIssuanceRuleApprovalStepRecord,
  BadgeIssuanceRuleVersionRecord,
  DecideBadgeIssuanceRuleVersionInput,
  SubmitBadgeIssuanceRuleVersionForApprovalInput,
} from "./badge-issuance-rule-types.js";

const DEFAULT_BADGE_ISSUANCE_RULE_APPROVAL_CHAIN: readonly BadgeIssuanceRuleApprovalChainStepInput[] =
  [
    {
      requiredRole: "admin",
      label: "Administrative approval",
    },
  ] as const;

export const normalizeBadgeIssuanceRuleApprovalChain = (
  chain: readonly BadgeIssuanceRuleApprovalChainStepInput[] | undefined,
): BadgeIssuanceRuleApprovalChainStepInput[] => {
  const normalizedChain =
    chain === undefined ? [...DEFAULT_BADGE_ISSUANCE_RULE_APPROVAL_CHAIN] : [...chain];

  if (normalizedChain.length === 0) {
    throw new Error("Badge issuance rule approval chain must include at least one step");
  }

  for (const step of normalizedChain) {
    const requiredRole: unknown = step.requiredRole;

    if (!isTenantMembershipRole(requiredRole)) {
      throw new Error(`Unsupported tenant role in approval chain: ${String(requiredRole)}`);
    }
  }

  return normalizedChain;
};

export const insertBadgeIssuanceRuleApprovalSteps = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    versionId: string;
    approvalChain: readonly BadgeIssuanceRuleApprovalChainStepInput[];
    createdAt: string;
  },
): Promise<void> => {
  const insertSteps = async (): Promise<void> => {
    for (const [index, step] of input.approvalChain.entries()) {
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
          step.label ?? null,
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
  const existingSteps = await listBadgeIssuanceRuleVersionApprovalSteps(db, input);

  if (existingSteps.length > 0) {
    return existingSteps;
  }

  const nowIso = new Date().toISOString();
  await insertBadgeIssuanceRuleApprovalSteps(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    approvalChain: DEFAULT_BADGE_ISSUANCE_RULE_APPROVAL_CHAIN,
    createdAt: nowIso,
  });

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
