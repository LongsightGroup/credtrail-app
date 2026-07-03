import type {
  BadgeIssuanceRuleBuilderDraftRecord,
  SaveBadgeIssuanceRuleBuilderDraftInput,
} from "./badge-issuance-rule-types.js";
import type { SqlDatabase } from "./tenant-scope.js";

interface BadgeIssuanceRuleBuilderDraftRow {
  tenantId: string;
  userId: string;
  ruleId: string | null;
  versionId: string | null;
  currentStep: BadgeIssuanceRuleBuilderDraftRecord["currentStep"];
  draftJson: string;
  createdAt: string;
  updatedAt: string;
}

const mapBadgeIssuanceRuleBuilderDraftRow = (
  row: BadgeIssuanceRuleBuilderDraftRow,
): BadgeIssuanceRuleBuilderDraftRecord => {
  return {
    tenantId: row.tenantId,
    userId: row.userId,
    ruleId: row.ruleId,
    versionId: row.versionId,
    currentStep: row.currentStep,
    draftJson: row.draftJson,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const badgeIssuanceRuleBuilderDraftSelectColumns = `
  tenant_id AS tenantId,
  user_id AS userId,
  rule_id AS ruleId,
  version_id AS versionId,
  current_step AS currentStep,
  draft_json AS draftJson,
  created_at AS createdAt,
  updated_at AS updatedAt
`;

export const saveBadgeIssuanceRuleBuilderDraft = async (
  db: SqlDatabase,
  input: SaveBadgeIssuanceRuleBuilderDraftInput,
): Promise<BadgeIssuanceRuleBuilderDraftRecord> => {
  const nowIso = new Date().toISOString();
  const ruleId = input.ruleId ?? null;
  const versionId = input.versionId ?? null;

  const row = await db
    .prepare(
      `
      INSERT INTO badge_issuance_rule_builder_drafts (
        tenant_id,
        user_id,
        rule_id,
        version_id,
        current_step,
        draft_json,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (tenant_id, user_id, rule_id_key)
      DO UPDATE SET
        version_id = excluded.version_id,
        current_step = excluded.current_step,
        draft_json = excluded.draft_json,
        updated_at = excluded.updated_at
      RETURNING
        ${badgeIssuanceRuleBuilderDraftSelectColumns}
    `,
    )
    .bind(
      input.tenantId,
      input.userId,
      ruleId,
      versionId,
      input.currentStep,
      input.draftJson,
      nowIso,
      nowIso,
    )
    .first<BadgeIssuanceRuleBuilderDraftRow>();

  if (row === null) {
    throw new Error(`Unable to save badge rule builder draft for tenant "${input.tenantId}"`);
  }

  return mapBadgeIssuanceRuleBuilderDraftRow(row);
};

export const findBadgeIssuanceRuleBuilderDraft = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    userId: string;
    ruleId?: string | undefined;
  },
): Promise<BadgeIssuanceRuleBuilderDraftRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${badgeIssuanceRuleBuilderDraftSelectColumns}
      FROM badge_issuance_rule_builder_drafts
      WHERE tenant_id = ?
        AND user_id = ?
        AND rule_id_key = COALESCE(?, '__new__')
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.userId, input.ruleId ?? null)
    .first<BadgeIssuanceRuleBuilderDraftRow>();

  return row === null ? null : mapBadgeIssuanceRuleBuilderDraftRow(row);
};

export const deleteBadgeIssuanceRuleBuilderDraft = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    userId: string;
    ruleId?: string | undefined;
  },
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      DELETE FROM badge_issuance_rule_builder_drafts
      WHERE tenant_id = ?
        AND user_id = ?
        AND rule_id_key = COALESCE(?, '__new__')
    `,
    )
    .bind(input.tenantId, input.userId, input.ruleId ?? null)
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};
