import {
  parseTenantAssertionListQuery,
  type TenantAssertionListQuery,
} from "@credtrail/validation";

export type IssuedBadgeLifecycleMode = "audit" | "revoke";

export interface IssuedBadgesPageFilterValues {
  recipientQuery: string;
  badgeTemplateId: string;
  state: string;
  limit: number;
}

export const buildIssuedBadgesPagePath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/operations/issued-badges`;
};

export const buildIssuedBadgesPageQuery = (
  filters: IssuedBadgesPageFilterValues,
): URLSearchParams => {
  const query = new URLSearchParams();

  if (filters.recipientQuery.length > 0) {
    query.set("recipientQuery", filters.recipientQuery);
  }

  if (filters.badgeTemplateId.length > 0) {
    query.set("badgeTemplateId", filters.badgeTemplateId);
  }

  if (filters.state.length > 0) {
    query.set("state", filters.state);
  }

  if (filters.limit !== 100) {
    query.set("limit", String(filters.limit));
  }

  return query;
};

export const shouldLoadIssuedBadgesList = (query: {
  recipientQuery?: string;
  badgeTemplateId?: string;
  state?: string;
  limit?: string;
}): boolean => {
  const recipientQuery = (query.recipientQuery ?? "").trim();
  const badgeTemplateId = (query.badgeTemplateId ?? "").trim();
  const state = (query.state ?? "").trim();
  const limitRaw = (query.limit ?? "").trim();
  const hasLimitOverride = limitRaw.length > 0 && limitRaw !== "100";

  return (
    recipientQuery.length > 0 || badgeTemplateId.length > 0 || state.length > 0 || hasLimitOverride
  );
};

export const issuedBadgesAssertionPageUrl = (
  tenantId: string,
  filters: IssuedBadgesPageFilterValues,
  assertionId: string,
  lifecycleMode: IssuedBadgeLifecycleMode,
): string => {
  return issuedBadgesPageUrl(tenantId, filters, {
    lifecycle: assertionId,
    lifecycleMode,
  });
};

export const issuedBadgesPageUrl = (
  tenantId: string,
  filters: IssuedBadgesPageFilterValues,
  extra?: Record<string, string>,
): string => {
  const query = buildIssuedBadgesPageQuery(filters);

  if (extra !== undefined) {
    for (const [key, value] of Object.entries(extra)) {
      if (value.length > 0) {
        query.set(key, value);
      }
    }
  }

  const path = buildIssuedBadgesPagePath(tenantId);
  const queryString = query.toString();

  return queryString.length > 0 ? `${path}?${queryString}` : path;
};

export interface ParsedIssuedBadgesPageQuery {
  filters: IssuedBadgesPageFilterValues;
  listQuery: TenantAssertionListQuery;
  listNotice: string | null;
  listError: string | null;
  lifecycleAssertionId: string | null;
  lifecycleMode: IssuedBadgeLifecycleMode | null;
}

const parseLifecycleMode = (raw: string | undefined): IssuedBadgeLifecycleMode | null => {
  const normalized = (raw ?? "").trim();

  if (normalized === "audit" || normalized === "revoke") {
    return normalized;
  }

  return null;
};

export const parseIssuedBadgesPageQuery = (query: {
  recipientQuery?: string;
  badgeTemplateId?: string;
  state?: string;
  limit?: string;
  listNotice?: string;
  listError?: string;
  lifecycle?: string;
  lifecycleMode?: string;
}): ParsedIssuedBadgesPageQuery => {
  const parsedListQuery: TenantAssertionListQuery = parseTenantAssertionListQuery({
    recipientQuery: query.recipientQuery,
    badgeTemplateId: query.badgeTemplateId,
    state: query.state,
    limit: query.limit,
  });

  const lifecycleRaw = (query.lifecycle ?? "").trim();
  const lifecycleModeRaw = parseLifecycleMode(query.lifecycleMode);
  const lifecycleMode = lifecycleRaw.length > 0 ? (lifecycleModeRaw ?? "audit") : lifecycleModeRaw;

  return {
    filters: {
      recipientQuery: parsedListQuery.recipientQuery ?? "",
      badgeTemplateId: parsedListQuery.badgeTemplateId ?? "",
      state: parsedListQuery.state ?? "",
      limit: parsedListQuery.limit ?? 100,
    },
    listQuery: parsedListQuery,
    listNotice: (query.listNotice ?? "").trim().length > 0 ? (query.listNotice ?? "").trim() : null,
    listError: (query.listError ?? "").trim().length > 0 ? (query.listError ?? "").trim() : null,
    lifecycleAssertionId: lifecycleRaw.length > 0 ? lifecycleRaw : null,
    lifecycleMode,
  };
};

export const safeParseIssuedBadgesPageQuery = (
  query: Parameters<typeof parseIssuedBadgesPageQuery>[0],
): { ok: true; value: ParsedIssuedBadgesPageQuery } | { ok: false } => {
  try {
    return { ok: true, value: parseIssuedBadgesPageQuery(query) };
  } catch {
    return { ok: false };
  }
};

export const issuedBadgesInvalidFiltersError =
  "Invalid search filters. Check state and limit, then try again.";

export const tenantIssuedBadgeAdminRevokePath = (tenantId: string): string => {
  return `${buildIssuedBadgesPagePath(tenantId)}/revoke`;
};
