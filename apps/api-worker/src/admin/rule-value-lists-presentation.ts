import {
  listBadgeIssuanceRuleValueLists,
  type BadgeIssuanceRuleValueListRecord,
  type SqlDatabase,
} from "@credtrail/db";

export const ADMIN_BADGE_RULE_VALUE_LIST_LIMIT = 100;

export interface RuleValueListBuilderContextEntry {
  id: string;
  label: string;
  kind: "course_ids" | "badge_template_ids";
  values: readonly string[];
}

export const formatRuleValueListKind = (kind: BadgeIssuanceRuleValueListRecord["kind"]): string => {
  if (kind === "course_ids") {
    return "LMS courses";
  }

  if (kind === "badge_template_ids") {
    return "Badge template IDs";
  }

  return "Unknown";
};

export const formatRuleValueListValuesSummary = (values: readonly string[]): string => {
  if (values.length === 0) {
    return "No values";
  }

  return values.join(", ");
};

export const parseCommaSeparatedAdminValues = (raw: unknown): string[] => {
  if (typeof raw !== "string") {
    return [];
  }

  return raw
    .split(/[,\n]/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
};

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
