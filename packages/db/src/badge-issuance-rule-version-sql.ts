import type {
  BadgeIssuanceRuleVersionRecord,
  BadgeIssuanceRuleVersionStatus,
} from "./badge-issuance-rule-types.js";

export interface BadgeIssuanceRuleVersionRow {
  id: string;
  tenantId: string;
  ruleId: string;
  versionNumber: number;
  status: BadgeIssuanceRuleVersionStatus;
  ruleJson: string;
  changeSummary: string | null;
  createdByUserId: string | null;
  submittedByUserId: string | null;
  submittedAt: string | null;
  approvedByUserId: string | null;
  approvedAt: string | null;
  activatedByUserId: string | null;
  activatedAt: string | null;
  effectiveStartsAt: string | null;
  expiresAt: string | null;
  expiredAt: string | null;
  suspendedAt: string | null;
  suspendedByUserId: string | null;
  suspensionReason: string | null;
  recertifiedAt: string | null;
  recertificationDueAt: string | null;
  expiryReminderSentAt: string | null;
  recertificationReminderSentAt: string | null;
  createdAt: string;
  updatedAt: string;
}

const BADGE_ISSUANCE_RULE_VERSION_COLUMN_DEFS: readonly {
  readonly column: string;
  readonly alias: string;
}[] = [
  { column: "id", alias: "id" },
  { column: "tenant_id", alias: "tenantId" },
  { column: "rule_id", alias: "ruleId" },
  { column: "version_number", alias: "versionNumber" },
  { column: "status", alias: "status" },
  { column: "rule_json", alias: "ruleJson" },
  { column: "change_summary", alias: "changeSummary" },
  { column: "created_by_user_id", alias: "createdByUserId" },
  { column: "submitted_by_user_id", alias: "submittedByUserId" },
  { column: "submitted_at", alias: "submittedAt" },
  { column: "approved_by_user_id", alias: "approvedByUserId" },
  { column: "approved_at", alias: "approvedAt" },
  { column: "activated_by_user_id", alias: "activatedByUserId" },
  { column: "activated_at", alias: "activatedAt" },
  { column: "effective_starts_at", alias: "effectiveStartsAt" },
  { column: "expires_at", alias: "expiresAt" },
  { column: "expired_at", alias: "expiredAt" },
  { column: "suspended_at", alias: "suspendedAt" },
  { column: "suspended_by_user_id", alias: "suspendedByUserId" },
  { column: "suspension_reason", alias: "suspensionReason" },
  { column: "recertified_at", alias: "recertifiedAt" },
  { column: "recertification_due_at", alias: "recertificationDueAt" },
  { column: "expiry_reminder_sent_at", alias: "expiryReminderSentAt" },
  { column: "recertification_reminder_sent_at", alias: "recertificationReminderSentAt" },
  { column: "created_at", alias: "createdAt" },
  { column: "updated_at", alias: "updatedAt" },
];

export const badgeIssuanceRuleVersionSelectColumns = (tableAlias?: string): string => {
  return BADGE_ISSUANCE_RULE_VERSION_COLUMN_DEFS.map(({ column, alias }) => {
    const source = tableAlias === undefined ? column : `${tableAlias}.${column}`;

    if (column === alias) {
      return source;
    }

    return `${source} AS ${alias}`;
  }).join(",\n  ");
};

export const BADGE_ISSUANCE_RULE_VERSION_SELECT_COLUMNS = badgeIssuanceRuleVersionSelectColumns();

export const mapBadgeIssuanceRuleVersionRow = (
  row: BadgeIssuanceRuleVersionRow,
): BadgeIssuanceRuleVersionRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    ruleId: row.ruleId,
    versionNumber: row.versionNumber,
    status: row.status,
    ruleJson: row.ruleJson,
    changeSummary: row.changeSummary,
    createdByUserId: row.createdByUserId,
    submittedByUserId: row.submittedByUserId ?? null,
    submittedAt: row.submittedAt ?? null,
    approvedByUserId: row.approvedByUserId,
    approvedAt: row.approvedAt,
    activatedByUserId: row.activatedByUserId,
    activatedAt: row.activatedAt,
    effectiveStartsAt: row.effectiveStartsAt,
    expiresAt: row.expiresAt,
    expiredAt: row.expiredAt,
    suspendedAt: row.suspendedAt,
    suspendedByUserId: row.suspendedByUserId,
    suspensionReason: row.suspensionReason,
    recertifiedAt: row.recertifiedAt,
    recertificationDueAt: row.recertificationDueAt,
    expiryReminderSentAt: row.expiryReminderSentAt,
    recertificationReminderSentAt: row.recertificationReminderSentAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};
