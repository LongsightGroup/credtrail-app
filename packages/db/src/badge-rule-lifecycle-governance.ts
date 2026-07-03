import { addMonthsToIso } from "./shared-helpers";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope";
import {
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
} from "./badge-issuance-rule-reads.js";
import { resolveBadgeRuleApprovalPolicy } from "./badge-rule-approval-policies.js";
import {
  badgeIssuanceRuleVersionSelectColumns,
  mapBadgeIssuanceRuleVersionRow,
  type BadgeIssuanceRuleVersionRow,
} from "./badge-issuance-rule-version-sql.js";
import type {
  BadgeIssuanceRuleVersionRecord,
  ResumeBadgeIssuanceRuleVersionInput,
  SuspendBadgeIssuanceRuleVersionInput,
  UpdateBadgeIssuanceRuleVersionLifecycleInput,
} from "./badge-issuance-rule-types.js";

export interface BadgeRuleLifecycleDueVersionRecord extends BadgeIssuanceRuleVersionRecord {
  readonly badgeTemplateId: string;
  readonly lmsProviderKind: string;
  readonly lmsConnectionId: string | null;
  readonly orgUnitId: string;
}

interface BadgeRuleLifecycleDueVersionRow extends BadgeIssuanceRuleVersionRow {
  badgeTemplateId: string;
  lmsProviderKind: string;
  lmsConnectionId: string | null;
  orgUnitId: string;
}

const mapDueVersionRow = (
  row: BadgeRuleLifecycleDueVersionRow,
): BadgeRuleLifecycleDueVersionRecord => ({
  ...mapBadgeIssuanceRuleVersionRow(row),
  badgeTemplateId: row.badgeTemplateId,
  lmsProviderKind: row.lmsProviderKind,
  lmsConnectionId: row.lmsConnectionId,
  orgUnitId: row.orgUnitId,
});

export const listBadgeIssuanceRuleVersionsDueForExpiry = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly nowIso: string;
  },
): Promise<BadgeRuleLifecycleDueVersionRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        ${badgeIssuanceRuleVersionSelectColumns("versions")},
        rules.badge_template_id AS badgeTemplateId,
        rules.lms_provider_kind AS lmsProviderKind,
        rules.lms_connection_id AS lmsConnectionId,
        rules.org_unit_id AS orgUnitId
      FROM badge_issuance_rule_versions AS versions
      INNER JOIN badge_issuance_rules AS rules
        ON rules.tenant_id = versions.tenant_id
        AND rules.id = versions.rule_id
      WHERE versions.tenant_id = ?
        AND versions.status = 'active'
        AND versions.expires_at IS NOT NULL
        AND versions.expires_at <= ?
      ORDER BY versions.expires_at ASC
    `,
    )
    .bind(input.tenantId, input.nowIso)
    .all<BadgeRuleLifecycleDueVersionRow>();

  return result.results.map(mapDueVersionRow);
};

export const updateBadgeIssuanceRuleVersionLifecycleWindow = async (
  db: SqlDatabase,
  input: UpdateBadgeIssuanceRuleVersionLifecycleInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const currentVersion = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });

  if (currentVersion === null || currentVersion.status !== "active") {
    return null;
  }

  const effectiveStartsAt = input.effectiveStartsAt ?? currentVersion.effectiveStartsAt ?? null;
  const expiresAt = input.expiresAt ?? currentVersion.expiresAt ?? null;
  const expiresAtChanged =
    input.expiresAt !== undefined && input.expiresAt !== currentVersion.expiresAt;

  return runSqlTransaction(db, async (transactionDb) => {
    const result = await transactionDb
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          effective_starts_at = ?,
          expires_at = ?,
          expiry_reminder_sent_at = CASE
            WHEN ? THEN NULL
            ELSE expiry_reminder_sent_at
          END,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
          AND status = 'active'
      `,
      )
      .bind(
        effectiveStartsAt,
        expiresAt,
        expiresAtChanged,
        occurredAt,
        input.tenantId,
        input.ruleId,
        input.versionId,
      )
      .run();

    if ((result.meta.rowsWritten ?? 0) === 0) {
      return null;
    }

    return findBadgeIssuanceRuleVersionById(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });
  });
};

export const suspendBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: SuspendBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const trimmedReason = input.reason.trim();

  if (trimmedReason.length === 0) {
    throw new Error("Suspension reason is required");
  }

  return runSqlTransaction(db, async (transactionDb) => {
    const result = await transactionDb
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'suspended',
          suspended_at = ?,
          suspended_by_user_id = ?,
          suspension_reason = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
          AND status = 'active'
      `,
      )
      .bind(
        occurredAt,
        input.actorUserId,
        trimmedReason,
        occurredAt,
        input.tenantId,
        input.ruleId,
        input.versionId,
      )
      .run();

    if ((result.meta.rowsWritten ?? 0) === 0) {
      return null;
    }

    return findBadgeIssuanceRuleVersionById(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });
  });
};

export const resumeBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: ResumeBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();

  return runSqlTransaction(db, async (transactionDb) => {
    const result = await transactionDb
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'active',
          suspended_at = NULL,
          suspended_by_user_id = NULL,
          suspension_reason = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
          AND status = 'suspended'
      `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();

    if ((result.meta.rowsWritten ?? 0) === 0) {
      return null;
    }

    return findBadgeIssuanceRuleVersionById(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });
  });
};

export const expireBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    versionId: string;
    occurredAt?: string | undefined;
  },
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();

  return runSqlTransaction(db, async (transactionDb) => {
    const result = await transactionDb
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'expired',
          expired_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
          AND status = 'active'
          AND expires_at IS NOT NULL
          AND expires_at <= ?
      `,
      )
      .bind(occurredAt, occurredAt, input.tenantId, input.ruleId, input.versionId, occurredAt)
      .run();

    if ((result.meta.rowsWritten ?? 0) === 0) {
      return null;
    }

    await transactionDb
      .prepare(
        `
        UPDATE badge_issuance_rules
        SET
          active_version_id = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
          AND active_version_id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();

    return findBadgeIssuanceRuleVersionById(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });
  });
};

export const recertifyBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly versionId: string;
    readonly actorUserId: string;
    readonly occurredAt?: string | undefined;
  },
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();

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
        : addMonthsToIso(occurredAt, policy.recertificationIntervalMonths);

    const result = await transactionDb
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          recertified_at = ?,
          recertification_due_at = ?,
          recertification_reminder_sent_at = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
          AND status = 'active'
      `,
      )
      .bind(
        occurredAt,
        recertificationDueAt,
        occurredAt,
        input.tenantId,
        input.ruleId,
        input.versionId,
      )
      .run();

    if ((result.meta.rowsWritten ?? 0) === 0) {
      return null;
    }

    return findBadgeIssuanceRuleVersionById(transactionDb, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    });
  });
};
