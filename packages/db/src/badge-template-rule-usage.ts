import type { SqlDatabase } from "./tenant-scope.js";

/** One rule whose immutable version history references a badge template. */
export interface BadgeTemplateRuleUsageRecord {
  readonly badgeTemplateId: string;
  readonly ruleId: string;
  readonly ruleName: string;
  readonly versionNumber: number;
  readonly isActiveVersion: boolean;
}

export interface ListBadgeTemplateRuleUsagesInput {
  readonly tenantId: string;
  readonly badgeTemplateIds: readonly string[];
  readonly excludingRuleId?: string | undefined;
}

interface BadgeTemplateRuleUsageRow {
  readonly badgeTemplateId: string;
  readonly ruleId: string;
  readonly ruleName: string;
  readonly versionNumber: number;
  readonly isActiveVersion: boolean;
}

/**
 * Finds every rule whose immutable version history references one of the templates.
 * One representative version is returned per template/rule pair, preferring the active version.
 */
export const listBadgeTemplateRuleUsages = async (
  db: SqlDatabase,
  input: ListBadgeTemplateRuleUsagesInput,
): Promise<readonly BadgeTemplateRuleUsageRecord[]> => {
  const badgeTemplateIds = [...new Set(input.badgeTemplateIds)];

  if (badgeTemplateIds.length === 0) {
    return [];
  }

  const templatePlaceholders = badgeTemplateIds.map(() => "?").join(", ");
  const excludingRuleClause =
    input.excludingRuleId === undefined ? "" : "AND versions.rule_id <> ?";
  const result = await db
    .prepare(
      `
      WITH ranked_usages AS (
        SELECT
          versions.snapshot_badge_template_id AS badgeTemplateId,
          versions.rule_id AS ruleId,
          versions.snapshot_name AS ruleName,
          versions.version_number AS versionNumber,
          COALESCE(rules.active_version_id = versions.id, FALSE) AS isActiveVersion,
          ROW_NUMBER() OVER (
            PARTITION BY versions.snapshot_badge_template_id, versions.rule_id
            ORDER BY
              COALESCE(rules.active_version_id = versions.id, FALSE) DESC,
              versions.version_number DESC,
              versions.id DESC
          ) AS usageRank
        FROM badge_issuance_rule_versions AS versions
        INNER JOIN badge_issuance_rules AS rules
          ON rules.tenant_id = versions.tenant_id
          AND rules.id = versions.rule_id
        WHERE versions.tenant_id = ?
          AND versions.snapshot_badge_template_id IN (${templatePlaceholders})
          ${excludingRuleClause}
      )
      SELECT
        badgeTemplateId,
        ruleId,
        ruleName,
        versionNumber,
        isActiveVersion
      FROM ranked_usages
      WHERE usageRank = 1
      ORDER BY LOWER(ruleName), ruleName, ruleId
    `,
    )
    .bind(
      input.tenantId,
      ...badgeTemplateIds,
      ...(input.excludingRuleId === undefined ? [] : [input.excludingRuleId]),
    )
    .all<BadgeTemplateRuleUsageRow>();

  return result.results.map((row) => ({
    badgeTemplateId: row.badgeTemplateId,
    ruleId: row.ruleId,
    ruleName: row.ruleName,
    versionNumber: row.versionNumber,
    isActiveVersion: row.isActiveVersion,
  }));
};

/** Groups template-use records for presentation without changing policy semantics. */
export const indexBadgeTemplateRuleUsages = (
  usages: readonly BadgeTemplateRuleUsageRecord[],
): ReadonlyMap<string, readonly BadgeTemplateRuleUsageRecord[]> => {
  const indexed = new Map<string, BadgeTemplateRuleUsageRecord[]>();

  for (const usage of usages) {
    const templateUsages = indexed.get(usage.badgeTemplateId) ?? [];
    templateUsages.push(usage);
    indexed.set(usage.badgeTemplateId, templateUsages);
  }

  return indexed;
};
