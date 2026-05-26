import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export interface BadgeIssuanceRuleValueListRecord {
  id: string;
  tenantId: string;
  label: string;
  kind: "course_ids" | "badge_template_ids";
  values: string[];
  createdByUserId: string | null;
  archivedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateBadgeIssuanceRuleValueListInput {
  tenantId: string;
  label: string;
  kind: "course_ids" | "badge_template_ids";
  values: readonly string[];
  createdByUserId?: string | undefined;
}

export interface ListBadgeIssuanceRuleValueListsInput {
  tenantId: string;
  kind?: "course_ids" | "badge_template_ids" | undefined;
  includeArchived?: boolean | undefined;
}

interface BadgeIssuanceRuleValueListRow {
  id: string;
  tenantId: string;
  label: string;
  kind: "course_ids" | "badge_template_ids";
  valuesJson: string;
  createdByUserId: string | null;
  archivedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

const mapBadgeIssuanceRuleValueListRow = (
  row: BadgeIssuanceRuleValueListRow,
): BadgeIssuanceRuleValueListRecord => {
  let values: string[] = [];

  try {
    const parsed = JSON.parse(row.valuesJson) as unknown;

    if (Array.isArray(parsed)) {
      values = parsed.filter((entry): entry is string => typeof entry === "string");
    }
  } catch {
    values = [];
  }

  return {
    id: row.id,
    tenantId: row.tenantId,
    label: row.label,
    kind: row.kind,
    values,
    createdByUserId: row.createdByUserId,
    archivedAt: row.archivedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

export const createBadgeIssuanceRuleValueList = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleValueListInput,
): Promise<BadgeIssuanceRuleValueListRecord> => {
  const valueListId = createPrefixedId("brvl");
  const nowIso = new Date().toISOString();
  const normalizedValues = Array.from(
    new Set(input.values.map((entry) => entry.trim()).filter((entry) => entry.length > 0)),
  );
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_value_lists (
          id,
          tenant_id,
          label,
          kind,
          values_json,
          created_by_user_id,
          archived_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)
      `,
      )
      .bind(
        valueListId,
        input.tenantId,
        input.label,
        input.kind,
        JSON.stringify(normalizedValues),
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();
  const lookupStatement = (): Promise<BadgeIssuanceRuleValueListRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          label,
          kind,
          values_json AS valuesJson,
          created_by_user_id AS createdByUserId,
          archived_at AS archivedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM badge_issuance_rule_value_lists
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, valueListId)
      .first<BadgeIssuanceRuleValueListRow>();

  await insertStatement();

  const row = await lookupStatement();

  if (row === null) {
    throw new Error(`Unable to create badge issuance rule value list "${valueListId}"`);
  }

  return mapBadgeIssuanceRuleValueListRow(row);
};

export const listBadgeIssuanceRuleValueLists = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleValueListsInput,
): Promise<BadgeIssuanceRuleValueListRecord[]> => {
  const includeArchived = input.includeArchived ?? false;
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleValueListRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          label,
          kind,
          values_json AS valuesJson,
          created_by_user_id AS createdByUserId,
          archived_at AS archivedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM badge_issuance_rule_value_lists
        WHERE tenant_id = ?
          AND (CAST(? AS TEXT) IS NULL OR kind = ?)
          AND (? = 1 OR archived_at IS NULL)
        ORDER BY created_at DESC, id DESC
      `,
      )
      .bind(input.tenantId, input.kind ?? null, input.kind ?? null, includeArchived ? 1 : 0)
      .all<BadgeIssuanceRuleValueListRow>();

  const result = await listStatement();

  return result.results.map((row) => mapBadgeIssuanceRuleValueListRow(row));
};
