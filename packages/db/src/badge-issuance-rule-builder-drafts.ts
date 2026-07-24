import type {
  BadgeIssuanceRuleBuilderDraftRecord,
  SaveBadgeIssuanceRuleBuilderDraftInput,
} from "./badge-issuance-rule-types.js";
import type { SqlDatabase } from "./tenant-scope.js";

interface BadgeIssuanceRuleBuilderDraftRow {
  id: string;
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
    id: row.id,
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
  id,
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
        id,
        tenant_id,
        user_id,
        rule_id,
        version_id,
        current_step,
        draft_json,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (tenant_id, id)
      DO UPDATE SET
        version_id = excluded.version_id,
        current_step = excluded.current_step,
        draft_json = excluded.draft_json,
        updated_at = excluded.updated_at
      WHERE badge_issuance_rule_builder_drafts.user_id = excluded.user_id
        AND badge_issuance_rule_builder_drafts.rule_id IS NOT DISTINCT FROM excluded.rule_id
      RETURNING
        ${badgeIssuanceRuleBuilderDraftSelectColumns}
    `,
    )
    .bind(
      input.id,
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

/** Finds one builder draft owned by a user. */
export const findBadgeIssuanceRuleBuilderDraftById = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly userId: string;
    readonly draftId: string;
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
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.userId, input.draftId)
    .first<BadgeIssuanceRuleBuilderDraftRow>();

  return row === null ? null : mapBadgeIssuanceRuleBuilderDraftRow(row);
};

/** Finds the current user's working draft for a formal rule. */
export const findBadgeIssuanceRuleBuilderDraftForRule = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly userId: string;
    readonly ruleId: string;
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
        AND rule_id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.userId, input.ruleId)
    .first<BadgeIssuanceRuleBuilderDraftRow>();

  return row === null ? null : mapBadgeIssuanceRuleBuilderDraftRow(row);
};

/** Lists unfinished new-rule drafts owned by a user, newest first. */
export const listBadgeIssuanceRuleBuilderDraftsForUser = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly userId: string;
  },
): Promise<readonly BadgeIssuanceRuleBuilderDraftRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        ${badgeIssuanceRuleBuilderDraftSelectColumns}
      FROM badge_issuance_rule_builder_drafts
      WHERE tenant_id = ?
        AND user_id = ?
        AND rule_id IS NULL
      ORDER BY updated_at DESC, id ASC
    `,
    )
    .bind(input.tenantId, input.userId)
    .all<BadgeIssuanceRuleBuilderDraftRow>();

  return result.results.map((row) => mapBadgeIssuanceRuleBuilderDraftRow(row));
};

/** Deletes one unfinished builder draft owned by a user. */
export const deleteBadgeIssuanceRuleBuilderDraftById = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly userId: string;
    readonly draftId: string;
  },
): Promise<BadgeIssuanceRuleBuilderDraftRecord | null> => {
  const row = await db
    .prepare(
      `
      DELETE FROM badge_issuance_rule_builder_drafts
      WHERE tenant_id = ?
        AND user_id = ?
        AND id = ?
        AND rule_id IS NULL
      RETURNING
        ${badgeIssuanceRuleBuilderDraftSelectColumns}
    `,
    )
    .bind(input.tenantId, input.userId, input.draftId)
    .first<BadgeIssuanceRuleBuilderDraftRow>();

  return row === null ? null : mapBadgeIssuanceRuleBuilderDraftRow(row);
};

/** Deletes the current user's working draft for a formal rule. */
export const deleteBadgeIssuanceRuleBuilderDraftForRule = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly userId: string;
    readonly ruleId: string;
  },
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      DELETE FROM badge_issuance_rule_builder_drafts
      WHERE tenant_id = ?
        AND user_id = ?
        AND rule_id = ?
    `,
    )
    .bind(input.tenantId, input.userId, input.ruleId)
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};
