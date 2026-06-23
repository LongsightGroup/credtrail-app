import {
  parseTenantAssertionListQuery,
  type TenantAssertionListQuery,
} from "@credtrail/validation";
export type IssuedBadgeLifecycleMode = "audit" | "revoke";

export interface IssuedBadgesPageFilterValues {
  issuedFrom: string;
  issuedTo: string;
  recipientQuery: string;
  badgeTemplateId: string;
  orgUnitId: string;
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

  if (filters.issuedFrom.length > 0) {
    query.set("issuedFrom", filters.issuedFrom);
  }

  if (filters.issuedTo.length > 0) {
    query.set("issuedTo", filters.issuedTo);
  }

  if (filters.recipientQuery.length > 0) {
    query.set("recipientQuery", filters.recipientQuery);
  }

  if (filters.badgeTemplateId.length > 0) {
    query.set("badgeTemplateId", filters.badgeTemplateId);
  }

  if (filters.orgUnitId.length > 0) {
    query.set("orgUnitId", filters.orgUnitId);
  }

  if (filters.state.length > 0) {
    query.set("state", filters.state);
  }

  if (filters.limit !== 100) {
    query.set("limit", String(filters.limit));
  }

  return query;
};

const issuedBadgesSearchFieldNames = [
  "issuedFrom",
  "issuedTo",
  "recipientQuery",
  "badgeTemplateId",
  "orgUnitId",
  "state",
  "limit",
] as const;

type IssuedBadgesSearchFieldName = (typeof issuedBadgesSearchFieldNames)[number];

export const shouldLoadIssuedBadgesList = (
  query: Partial<Record<IssuedBadgesSearchFieldName, string | undefined>>,
): boolean => {
  return issuedBadgesSearchFieldNames.some(
    (fieldName) =>
      Object.prototype.hasOwnProperty.call(query, fieldName) && query[fieldName] !== undefined,
  );
};

export const issuedBadgesLedgerExportUrl = (
  tenantId: string,
  filters: IssuedBadgesPageFilterValues,
): string => {
  const query = new URLSearchParams();

  if (filters.issuedFrom.length > 0) {
    query.set("issuedFrom", filters.issuedFrom);
  }

  if (filters.issuedTo.length > 0) {
    query.set("issuedTo", filters.issuedTo);
  }

  if (filters.badgeTemplateId.length > 0) {
    query.set("badgeTemplateId", filters.badgeTemplateId);
  }

  if (filters.orgUnitId.length > 0) {
    query.set("orgUnitId", filters.orgUnitId);
  }

  if (filters.state.length > 0) {
    query.set("state", filters.state);
  }

  if (filters.recipientQuery.length > 0) {
    query.set("recipientQuery", filters.recipientQuery);
  }

  const path = `/v1/tenants/${encodeURIComponent(tenantId)}/assertions/ledger-export.csv`;
  const queryString = query.toString();

  return queryString.length > 0 ? `${path}?${queryString}` : path;
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
  issuedFrom?: string;
  issuedTo?: string;
  recipientQuery?: string;
  badgeTemplateId?: string;
  orgUnitId?: string;
  state?: string;
  limit?: string;
  lifecycle?: string;
  lifecycleMode?: string;
}): ParsedIssuedBadgesPageQuery => {
  const parsedListQuery: TenantAssertionListQuery = parseTenantAssertionListQuery({
    issuedFrom: query.issuedFrom,
    issuedTo: query.issuedTo,
    recipientQuery: query.recipientQuery,
    badgeTemplateId: query.badgeTemplateId,
    orgUnitId: query.orgUnitId,
    state: query.state,
    limit: query.limit,
  });

  const lifecycleRaw = (query.lifecycle ?? "").trim();
  const lifecycleModeRaw = parseLifecycleMode(query.lifecycleMode);
  const lifecycleMode = lifecycleRaw.length > 0 ? (lifecycleModeRaw ?? "audit") : lifecycleModeRaw;

  return {
    filters: {
      issuedFrom: parsedListQuery.issuedFrom ?? "",
      issuedTo: parsedListQuery.issuedTo ?? "",
      recipientQuery: parsedListQuery.recipientQuery ?? "",
      badgeTemplateId: parsedListQuery.badgeTemplateId ?? "",
      orgUnitId: parsedListQuery.orgUnitId ?? "",
      state: parsedListQuery.state ?? "",
      limit: parsedListQuery.limit ?? 100,
    },
    listQuery: parsedListQuery,
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
  "Invalid search filters. Check dates, state, and limit, then try again.";

export const tenantIssuedBadgeAdminRevokePath = (tenantId: string): string => {
  return `${buildIssuedBadgesPagePath(tenantId)}/revoke`;
};
