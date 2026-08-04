import { createPrefixedId } from "./shared-helpers.js";
import type { SqlDatabase, SqlRunResult } from "./tenant-scope.js";
import type { TenantMembershipRole } from "./tenant-memberships.js";
import { findBadgeIssuanceRuleById } from "./badge-issuance-rule-reads.js";
import {
  badgeIssuanceRuleVersionSelectColumns,
  mapBadgeIssuanceRuleVersionRow,
  type BadgeIssuanceRuleVersionRow,
} from "./badge-issuance-rule-version-sql.js";
import type { BadgeRuleApprovalPolicyStepRecord } from "./badge-rule-approval-policies.js";
import type {
  BadgeIssuanceRuleApprovalEventAction,
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
} from "./badge-issuance-rule-types.js";

/** Locks and reloads a badge rule before a lifecycle transition. */
export const lockBadgeIssuanceRuleForTransition = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
  },
): Promise<BadgeIssuanceRuleRecord | null> => {
  const locked = await db
    .prepare(
      `
        SELECT id
        FROM badge_issuance_rules
        WHERE tenant_id = ?
          AND id = ?
        FOR UPDATE
      `,
    )
    .bind(input.tenantId, input.ruleId)
    .first<{ id: string }>();

  if (locked === null) {
    return null;
  }

  const rule = await findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId);

  if (rule === null) {
    throw new Error(`Locked badge issuance rule "${input.ruleId}" could not be reloaded`);
  }

  return rule;
};

/** Locks and parses one badge-rule version before a lifecycle transition. */
export const lockBadgeIssuanceRuleVersionForTransition = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly versionId: string;
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

/** Replaces materialized approval steps with a fresh policy-defined chain. */
export const replaceBadgeIssuanceRuleApprovalSteps = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly versionId: string;
    readonly approvalSteps: readonly BadgeRuleApprovalPolicyStepRecord[];
    readonly createdAt: string;
  },
): Promise<void> => {
  await deleteBadgeIssuanceRuleApprovalSteps(db, input);

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

/** Deletes the materialized approval chain while immutable events retain its history. */
export const deleteBadgeIssuanceRuleApprovalSteps = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly versionId: string;
  },
): Promise<void> => {
  await db
    .prepare(
      `
        DELETE FROM badge_issuance_rule_approval_steps
        WHERE tenant_id = ?
          AND version_id = ?
      `,
    )
    .bind(input.tenantId, input.versionId)
    .run();
};

/** Appends one immutable badge-rule approval history event. */
export const insertBadgeIssuanceRuleApprovalEvent = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly versionId: string;
    readonly stepNumber: number | null;
    readonly action: BadgeIssuanceRuleApprovalEventAction;
    readonly actorUserId: string | null;
    readonly actorRole: TenantMembershipRole | null;
    readonly comment: string | null;
    readonly occurredAt: string;
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
