import { addDaysToIso, addMonthsToIso, createPrefixedId } from "./shared-helpers";
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

type DueVersionListKind =
  | "expiry"
  | "expiry_reminder"
  | "recertification"
  | "recertification_reminder";

type DueTimestampColumn = "expires_at" | "recertification_due_at";
type ReminderSentColumn = "expiry_reminder_sent_at" | "recertification_reminder_sent_at";

interface DueVersionListPredicate {
  readonly dueColumn: DueTimestampColumn;
  readonly reminderSentColumn?: ReminderSentColumn | undefined;
  readonly startsAfterNow: boolean;
}

const DUE_VERSION_LIST_PREDICATES: Record<DueVersionListKind, DueVersionListPredicate> = {
  expiry: {
    dueColumn: "expires_at",
    startsAfterNow: false,
  },
  expiry_reminder: {
    dueColumn: "expires_at",
    reminderSentColumn: "expiry_reminder_sent_at",
    startsAfterNow: true,
  },
  recertification: {
    dueColumn: "recertification_due_at",
    startsAfterNow: false,
  },
  recertification_reminder: {
    dueColumn: "recertification_due_at",
    reminderSentColumn: "recertification_reminder_sent_at",
    startsAfterNow: true,
  },
};

type ListDueVersionsInput =
  | {
      readonly tenantId: string;
      readonly nowIso: string;
      readonly kind: "expiry" | "recertification";
    }
  | {
      readonly tenantId: string;
      readonly nowIso: string;
      readonly kind: "expiry_reminder" | "recertification_reminder";
      readonly reminderWindowDays: number;
    };

const listDueVersions = async (
  db: SqlDatabase,
  input: ListDueVersionsInput,
): Promise<BadgeRuleLifecycleDueVersionRecord[]> => {
  const predicate = DUE_VERSION_LIST_PREDICATES[input.kind];
  const whereClauses = [
    "versions.tenant_id = ?",
    "versions.status = 'active'",
    `versions.${predicate.dueColumn} IS NOT NULL`,
  ];
  const bindings: string[] = [input.tenantId];

  if (predicate.startsAfterNow) {
    whereClauses.push(`versions.${predicate.dueColumn} > ?`);
    bindings.push(input.nowIso);
  }

  whereClauses.push(`versions.${predicate.dueColumn} <= ?`);
  bindings.push(
    "reminderWindowDays" in input
      ? addDaysToIso(input.nowIso, input.reminderWindowDays)
      : input.nowIso,
  );

  if (predicate.reminderSentColumn !== undefined) {
    whereClauses.push(`versions.${predicate.reminderSentColumn} IS NULL`);
  }

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
      WHERE ${whereClauses.join("\n        AND ")}
      ORDER BY versions.${predicate.dueColumn} ASC
    `,
    )
    .bind(...bindings)
    .all<BadgeRuleLifecycleDueVersionRow>();

  return result.results.map(mapDueVersionRow);
};

export const listBadgeIssuanceRuleVersionsDueForExpiry = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly nowIso: string;
  },
): Promise<BadgeRuleLifecycleDueVersionRecord[]> => {
  return listDueVersions(db, {
    tenantId: input.tenantId,
    nowIso: input.nowIso,
    kind: "expiry",
  });
};

export const listBadgeIssuanceRuleVersionsDueForExpiryReminder = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly nowIso: string;
    readonly reminderWindowDays: number;
  },
): Promise<BadgeRuleLifecycleDueVersionRecord[]> => {
  return listDueVersions(db, {
    tenantId: input.tenantId,
    nowIso: input.nowIso,
    kind: "expiry_reminder",
    reminderWindowDays: input.reminderWindowDays,
  });
};

export const listBadgeIssuanceRuleVersionsDueForRecertification = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly nowIso: string;
  },
): Promise<BadgeRuleLifecycleDueVersionRecord[]> => {
  return listDueVersions(db, {
    tenantId: input.tenantId,
    nowIso: input.nowIso,
    kind: "recertification",
  });
};

export const listBadgeIssuanceRuleVersionsDueForRecertificationReminder = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly nowIso: string;
    readonly reminderWindowDays: number;
  },
): Promise<BadgeRuleLifecycleDueVersionRecord[]> => {
  return listDueVersions(db, {
    tenantId: input.tenantId,
    nowIso: input.nowIso,
    kind: "recertification_reminder",
    reminderWindowDays: input.reminderWindowDays,
  });
};

export const markBadgeIssuanceRuleVersionExpiryReminderSent = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly versionId: string;
    readonly occurredAt?: string | undefined;
  },
): Promise<boolean> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const result = await db
    .prepare(
      `
      UPDATE badge_issuance_rule_versions
      SET
        expiry_reminder_sent_at = ?,
        updated_at = ?
      WHERE tenant_id = ?
        AND rule_id = ?
        AND id = ?
        AND status = 'active'
        AND expires_at IS NOT NULL
        AND expiry_reminder_sent_at IS NULL
    `,
    )
    .bind(occurredAt, occurredAt, input.tenantId, input.ruleId, input.versionId)
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const markBadgeIssuanceRuleVersionRecertificationReminderSent = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly versionId: string;
    readonly occurredAt?: string | undefined;
  },
): Promise<boolean> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const result = await db
    .prepare(
      `
      UPDATE badge_issuance_rule_versions
      SET
        recertification_reminder_sent_at = ?,
        updated_at = ?
      WHERE tenant_id = ?
        AND rule_id = ?
        AND id = ?
        AND status = 'active'
        AND recertification_due_at IS NOT NULL
        AND recertification_reminder_sent_at IS NULL
    `,
    )
    .bind(occurredAt, occurredAt, input.tenantId, input.ruleId, input.versionId)
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const ensureBadgeRuleRecertificationReview = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly versionId: string;
    readonly dueAt: string;
    readonly requestedAt?: string | undefined;
  },
): Promise<boolean> => {
  const requestedAt = input.requestedAt ?? new Date().toISOString();
  const result = await db
    .prepare(
      `
      INSERT INTO badge_rule_recertification_reviews (
        id,
        tenant_id,
        rule_id,
        version_id,
        status,
        due_at,
        requested_at,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)
      ON CONFLICT (tenant_id, version_id, due_at) DO NOTHING
    `,
    )
    .bind(
      createPrefixedId("brrr"),
      input.tenantId,
      input.ruleId,
      input.versionId,
      input.dueAt,
      requestedAt,
      requestedAt,
      requestedAt,
    )
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const suspendBadgeIssuanceRuleVersionForOverdueRecertification = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly versionId: string;
    readonly recertificationDueAt: string;
    readonly overdueDays: number;
    readonly occurredAt?: string | undefined;
  },
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const overdueCutoffIso = addDaysToIso(input.recertificationDueAt, input.overdueDays);

  if (overdueCutoffIso > occurredAt) {
    return null;
  }

  return runSqlTransaction(db, async (transactionDb) => {
    const result = await transactionDb
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'suspended',
          suspended_at = ?,
          suspended_by_user_id = NULL,
          suspension_reason = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
          AND status = 'active'
          AND recertification_due_at = ?
      `,
      )
      .bind(
        occurredAt,
        "Automatically suspended because rule recertification is overdue.",
        occurredAt,
        input.tenantId,
        input.ruleId,
        input.versionId,
        input.recertificationDueAt,
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
