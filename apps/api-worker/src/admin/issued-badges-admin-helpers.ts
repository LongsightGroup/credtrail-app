import { parseIssuedBadgeCursor, type IssuedBadgeCursor } from "./issued-badge-pagination";
import {
  parseTenantAssertionListQuery,
  type TenantAssertionListQuery,
} from "@credtrail/validation";
export type IssuedBadgeLifecycleMode =
  | "audit"
  | "status"
  | "revoke"
  | "suspend"
  | "restore"
  | "expire";

export interface IssuedBadgesPageFilterValues {
  notificationStatus?: string;
  cursor?: string;
  issuedFrom: string;
  issuedTo: string;
  recipientQuery: string;
  badgeTemplateId: string;
  orgUnitId: string;
  state: string;
  limit: number;
}

const issuedBadgesDefaultLimit = 100;

export const buildIssuedBadgesPagePath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/operations/issued-badges`;
};

const buildAssertionEvidencePagePath = (
  tenantId: string,
  assertionId: string,
  returnFilters?: IssuedBadgesPageFilterValues,
): string => {
  const path = `${buildIssuedBadgesPagePath(tenantId)}/${encodeURIComponent(assertionId)}/evidence`;

  if (returnFilters === undefined) {
    return path;
  }

  const query = buildIssuedBadgesPageQuery(returnFilters);
  const queryString = query.toString();

  return queryString.length > 0 ? `${path}?${queryString}` : path;
};

export const emptyIssuedBadgesPageFilterValues = (): IssuedBadgesPageFilterValues => {
  return {
    notificationStatus: "",
    issuedFrom: "",
    issuedTo: "",
    recipientQuery: "",
    badgeTemplateId: "",
    orgUnitId: "",
    state: "",
    limit: issuedBadgesDefaultLimit,
  };
};

const issuedBadgesTextFilterNames = [
  "issuedFrom",
  "issuedTo",
  "recipientQuery",
  "notificationStatus",
  "badgeTemplateId",
  "orgUnitId",
  "state",
] as const;

type IssuedBadgesTextFilterName = (typeof issuedBadgesTextFilterNames)[number];

const issuedBadgesPageTextFilterNames = issuedBadgesTextFilterNames;

const issuedBadgesLedgerExportTextFilterNames: readonly IssuedBadgesTextFilterName[] = [
  "issuedFrom",
  "issuedTo",
  "badgeTemplateId",
  "orgUnitId",
  "state",
  "recipientQuery",
  "notificationStatus",
];

const appendIssuedBadgesTextFilterParams = (
  query: URLSearchParams,
  filters: IssuedBadgesPageFilterValues,
  fieldNames: readonly IssuedBadgesTextFilterName[],
): void => {
  for (const fieldName of fieldNames) {
    const value = filters[fieldName];

    if (value !== undefined && value.length > 0) {
      query.set(fieldName, value);
    }
  }
};

export const buildIssuedBadgesPageQuery = (
  filters: IssuedBadgesPageFilterValues,
): URLSearchParams => {
  const query = new URLSearchParams();
  appendIssuedBadgesTextFilterParams(query, filters, issuedBadgesPageTextFilterNames);

  if (filters.limit !== issuedBadgesDefaultLimit) {
    query.set("limit", String(filters.limit));
  }

  if (filters.cursor) query.set("cursor", filters.cursor);
  return query;
};

export const issuedBadgesLedgerExportUrl = (
  tenantId: string,
  filters: IssuedBadgesPageFilterValues,
): string => {
  const query = new URLSearchParams();
  appendIssuedBadgesTextFilterParams(query, filters, issuedBadgesLedgerExportTextFilterNames);

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
  if (lifecycleMode === "audit") {
    return buildAssertionEvidencePagePath(tenantId, assertionId, filters);
  }

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
      if (value !== undefined && value.length > 0) {
        query.set(key, value);
      }
    }
  }

  const path = buildIssuedBadgesPagePath(tenantId);
  const queryString = query.toString();

  return queryString.length > 0 ? `${path}?${queryString}` : path;
};

export interface ParsedIssuedBadgesPageQuery {
  cursor: IssuedBadgeCursor | undefined;
  filters: IssuedBadgesPageFilterValues;
  listQuery: TenantAssertionListQuery;
  lifecycleAssertionId: string | null;
  lifecycleMode: IssuedBadgeLifecycleMode | null;
}

const parseLifecycleMode = (raw: string | undefined): IssuedBadgeLifecycleMode | null => {
  const normalized = (raw ?? "").trim();

  if (
    normalized === "audit" ||
    normalized === "status" ||
    normalized === "revoke" ||
    normalized === "suspend" ||
    normalized === "restore" ||
    normalized === "expire"
  ) {
    return normalized;
  }

  return null;
};

export const parseIssuedBadgesPageQuery = (query: {
  notificationStatus?: string;
  cursor?: string;
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
    notificationStatus: query.notificationStatus,
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

  const cursor = parseIssuedBadgeCursor(query.cursor);
  return {
    cursor,
    filters: {
      ...(cursor === undefined ? {} : { cursor: JSON.stringify(cursor) }),
      notificationStatus: parsedListQuery.notificationStatus ?? "",
      issuedFrom: parsedListQuery.issuedFrom ?? "",
      issuedTo: parsedListQuery.issuedTo ?? "",
      recipientQuery: parsedListQuery.recipientQuery ?? "",
      badgeTemplateId: parsedListQuery.badgeTemplateId ?? "",
      orgUnitId: parsedListQuery.orgUnitId ?? "",
      state: parsedListQuery.state ?? "",
      limit: parsedListQuery.limit ?? issuedBadgesDefaultLimit,
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

export const tenantIssuedBadgeAdminStatusPath = (tenantId: string): string => {
  return `${buildIssuedBadgesPagePath(tenantId)}/status`;
};
