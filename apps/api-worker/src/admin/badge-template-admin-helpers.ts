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

export const buildBadgeTemplateListPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/rules/templates`;
};

export const badgeTemplateAdminEditorHref = (tenantId: string, badgeTemplateId: string): string => {
  return `${buildBadgeTemplateListPath(tenantId)}/${encodeURIComponent(badgeTemplateId)}`;
};

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

const badgeTemplateSlugBaseFromTitle = (title: string): string => {
  return title
    .trim()
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
};

const clampBadgeTemplateSlug = (slug: string, maxLength: number): string => {
  const clipped = slug.slice(0, maxLength).replace(/-+$/g, "");

  return clipped.length >= 2 ? clipped : "";
};

export const deriveUniqueBadgeTemplateSlug = (
  title: string,
  existingTemplates: readonly Pick<BadgeTemplateRecord, "slug">[],
): string => {
  const baseSource = badgeTemplateSlugBaseFromTitle(title);
  const base = clampBadgeTemplateSlug(
    baseSource.length === 1 ? `${baseSource}-badge` : baseSource,
    96,
  );

  if (base.length === 0) {
    return "";
  }

  const existingSlugs = new Set(existingTemplates.map((template) => template.slug));

  if (!existingSlugs.has(base)) {
    return base;
  }

  for (let suffix = 2; suffix < 1000; suffix += 1) {
    const suffixText = `-${String(suffix)}`;
    const candidate = `${clampBadgeTemplateSlug(base, 96 - suffixText.length)}${suffixText}`;

    if (!existingSlugs.has(candidate)) {
      return candidate;
    }
  }

  return `${clampBadgeTemplateSlug(base, 87)}-${Date.now().toString(36).slice(-8)}`;
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

export const badgeTemplateListPageUrl = (
  rulesTemplatesPath: string,
  listPageOptions: BadgeTemplateListPageQueryOptions,
  extra?: Record<string, string>,
): string => {
  const query = buildBadgeTemplateListPageQuery(listPageOptions);

  if (extra !== undefined) {
    for (const [key, value] of Object.entries(extra)) {
      if (value.length > 0) {
        query.set(key, value);
      }
    }
  }

  const queryString = query.toString();

  return queryString.length > 0 ? `${rulesTemplatesPath}?${queryString}` : rulesTemplatesPath;
};

export const parseBadgeTemplateListPageQuery = (query: {
  q?: string;
  includeArchived?: string;
  returnTo?: string;
}): BadgeTemplateListPageQueryOptions => {
  return {
    searchQuery: (query.q ?? "").trim(),
    includeArchived: query.includeArchived === "1" || query.includeArchived === "true",
    returnToRuleBuilder: query.returnTo === "rule-builder",
  };
};
