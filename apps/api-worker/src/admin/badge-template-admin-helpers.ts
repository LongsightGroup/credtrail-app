import type { BadgeTemplateRecord } from "@credtrail/db";

export interface BadgeTemplateClientRecord {
  id: string;
  slug: string;
  title: string;
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
  isArchived: boolean;
  updatedAt: string;
}

export interface BadgeTemplateListPageQueryOptions {
  searchQuery: string;
  includeArchived: boolean;
  returnToRuleBuilder: boolean;
}

export const toBadgeTemplateClientRecord = (
  template: BadgeTemplateRecord,
): BadgeTemplateClientRecord => {
  return {
    id: template.id,
    slug: template.slug,
    title: template.title,
    description: template.description,
    criteriaUri: template.criteriaUri,
    imageUri: template.imageUri,
    isArchived: template.isArchived,
    updatedAt: template.updatedAt,
  };
};

export const buildBadgeTemplateListPageQuery = (
  options: BadgeTemplateListPageQueryOptions,
): URLSearchParams => {
  const query = new URLSearchParams();

  if (options.searchQuery.length > 0) {
    query.set("q", options.searchQuery);
  }

  if (options.includeArchived) {
    query.set("includeArchived", "1");
  }

  if (options.returnToRuleBuilder) {
    query.set("returnTo", "rule-builder");
  }

  return query;
};

export const badgeTemplateHistoryHref = (
  rulesTemplatesPath: string,
  badgeTemplateId: string,
  listPageOptions: BadgeTemplateListPageQueryOptions,
): string => {
  const query = buildBadgeTemplateListPageQuery(listPageOptions);
  query.set("badgeTemplateId", badgeTemplateId);
  query.set("history", "1");

  return `${rulesTemplatesPath}?${query.toString()}`;
};

export const badgeTemplateAdminTableRowPath = (
  rulesTemplatesPath: string,
  badgeTemplateId: string,
  listPageOptions: BadgeTemplateListPageQueryOptions,
): string => {
  const query = buildBadgeTemplateListPageQuery(listPageOptions);
  const queryString = query.toString();

  return `${rulesTemplatesPath}/${encodeURIComponent(badgeTemplateId)}/table-row${
    queryString.length > 0 ? `?${queryString}` : ""
  }`;
};

export const parseBadgeTemplateListPageQuery = (query: {
  q?: string;
  includeArchived?: string;
  returnTo?: string;
}): BadgeTemplateListPageQueryOptions => {
  return {
    searchQuery: (query.q ?? "").trim(),
    includeArchived:
      query.includeArchived === "1" || query.includeArchived === "true",
    returnToRuleBuilder: query.returnTo === "rule-builder",
  };
};
