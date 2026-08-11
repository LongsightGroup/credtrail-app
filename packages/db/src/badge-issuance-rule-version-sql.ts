import { badgeIssuanceRuleLmsProviderKindSchema } from "@credtrail/validation";
import { z } from "zod";

import type {
  BadgeIssuanceRuleVersionSnapshot,
  BadgeIssuanceRuleVersionRecord,
  BadgeIssuanceRuleVersionStatus,
} from "./badge-issuance-rule-types.js";

/** Database projection for one persisted badge-rule version. */
export interface BadgeIssuanceRuleVersionRow {
  id: string;
  tenantId: string;
  ruleId: string;
  versionNumber: number;
  status: BadgeIssuanceRuleVersionStatus;
  ruleJson: string;
  snapshotName: string;
  snapshotDescription: string | null;
  snapshotBadgeTemplateId: string;
  snapshotBadgeTemplateTitle: string;
  snapshotBadgeTemplateImageUri: string | null;
  snapshotOrgUnitId: string;
  snapshotOwnerOrgUnitId: string;
  snapshotLmsProviderKind: string;
  snapshotLmsConnectionId: string | null;
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

const requiredStoredSnapshotTextSchema = z.string().refine((value) => value.trim().length > 0, {
  message: "Stored badge-rule snapshot text must not be blank",
});

const badgeIssuanceRuleVersionSnapshotSchema = z.object({
  name: requiredStoredSnapshotTextSchema,
  description: z.string().nullable(),
  badgeTemplateId: requiredStoredSnapshotTextSchema,
  badgeTemplateTitle: requiredStoredSnapshotTextSchema,
  badgeTemplateImageUri: z.string().nullable(),
  orgUnitId: requiredStoredSnapshotTextSchema,
  ownerOrgUnitId: requiredStoredSnapshotTextSchema,
  lmsProviderKind: badgeIssuanceRuleLmsProviderKindSchema,
  lmsConnectionId: z.string().nullable(),
});

const parseBadgeIssuanceRuleVersionSnapshot = (
  row: BadgeIssuanceRuleVersionRow,
): BadgeIssuanceRuleVersionSnapshot => {
  return badgeIssuanceRuleVersionSnapshotSchema.parse({
    name: row.snapshotName,
    description: row.snapshotDescription,
    badgeTemplateId: row.snapshotBadgeTemplateId,
    badgeTemplateTitle: row.snapshotBadgeTemplateTitle,
    badgeTemplateImageUri: row.snapshotBadgeTemplateImageUri,
    orgUnitId: row.snapshotOrgUnitId,
    ownerOrgUnitId: row.snapshotOwnerOrgUnitId,
    lmsProviderKind: row.snapshotLmsProviderKind,
    lmsConnectionId: row.snapshotLmsConnectionId,
  });
};

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
  { column: "snapshot_name", alias: "snapshotName" },
  { column: "snapshot_description", alias: "snapshotDescription" },
  { column: "snapshot_badge_template_id", alias: "snapshotBadgeTemplateId" },
  { column: "snapshot_badge_template_title", alias: "snapshotBadgeTemplateTitle" },
  { column: "snapshot_badge_template_image_uri", alias: "snapshotBadgeTemplateImageUri" },
  { column: "snapshot_org_unit_id", alias: "snapshotOrgUnitId" },
  { column: "snapshot_owner_org_unit_id", alias: "snapshotOwnerOrgUnitId" },
  { column: "snapshot_lms_provider_kind", alias: "snapshotLmsProviderKind" },
  { column: "snapshot_lms_connection_id", alias: "snapshotLmsConnectionId" },
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

/** Build the canonical SQL projection for persisted badge-rule versions. */
export const badgeIssuanceRuleVersionSelectColumns = (tableAlias?: string): string => {
  return BADGE_ISSUANCE_RULE_VERSION_COLUMN_DEFS.map(({ column, alias }) => {
    const source = tableAlias === undefined ? column : `${tableAlias}.${column}`;

    if (column === alias) {
      return source;
    }

    return `${source} AS ${alias}`;
  }).join(",\n  ");
};

/** Canonical unqualified SQL projection for persisted badge-rule versions. */
export const BADGE_ISSUANCE_RULE_VERSION_SELECT_COLUMNS = badgeIssuanceRuleVersionSelectColumns();

/** Parse a database row into a badge-rule version and reject corrupt snapshot state. */
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
    snapshot: parseBadgeIssuanceRuleVersionSnapshot(row),
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
