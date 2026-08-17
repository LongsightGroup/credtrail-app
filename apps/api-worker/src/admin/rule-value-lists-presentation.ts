import {
  listBadgeIssuanceRuleValueLists,
  type BadgeIssuanceRuleValueListRecord,
  type SqlDatabase,
} from "@credtrail/db";

const ADMIN_BADGE_RULE_VALUE_LIST_LIMIT = 100;

export interface RuleValueListBuilderContextEntry {
  id: string;
  label: string;
  kind: "course_ids" | "badge_template_ids";
  values: readonly string[];
}

export const toRuleValueListBuilderContextEntries = (
  valueLists: readonly BadgeIssuanceRuleValueListRecord[],
): RuleValueListBuilderContextEntry[] => {
  return valueLists.map((valueList) => ({
    id: valueList.id,
    label: valueList.label,
    kind: valueList.kind,
    values: valueList.values,
  }));
};

export const loadTenantBadgeRuleValueLists = async (
  db: SqlDatabase,
  tenantId: string,
  options?: {
    kind?: BadgeIssuanceRuleValueListRecord["kind"];
    limit?: number | "none";
  },
): Promise<BadgeIssuanceRuleValueListRecord[]> => {
  const resolvedLimit =
    options?.limit === "none"
      ? undefined
      : options?.limit === undefined
        ? ADMIN_BADGE_RULE_VALUE_LIST_LIMIT
        : options.limit;

  return listBadgeIssuanceRuleValueLists(db, {
    tenantId,
    includeArchived: false,
    ...(resolvedLimit === undefined ? {} : { limit: resolvedLimit }),
    ...(options?.kind === undefined ? {} : { kind: options.kind }),
  });
};
