import type {
  BadgeIssuanceRuleRegistryCursor,
  BadgeIssuanceRuleRegistrySort,
  BadgeIssuanceRuleRegistrySortDirection,
  BadgeIssuanceRuleVersionStatus,
} from "@credtrail/db";
import {
  parseBadgeRuleRegistryCursorPayload,
  parseBadgeRuleRegistryPageQuery,
} from "@credtrail/validation";

export interface BadgeRuleRegistryPageQuery {
  readonly searchQuery: string;
  readonly latestStatus: BadgeIssuanceRuleVersionStatus | null;
  readonly sort: BadgeIssuanceRuleRegistrySort;
  readonly direction: BadgeIssuanceRuleRegistrySortDirection;
  readonly limit: number;
  readonly cursor?:
    | {
        readonly position: "after" | "before";
        readonly boundary: BadgeIssuanceRuleRegistryCursor;
      }
    | undefined;
}

const encodeBase64Url = (value: string): string => {
  const bytes = new TextEncoder().encode(value);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
};

const decodeBase64Url = (value: string): string => {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const paddingLength = (4 - (normalized.length % 4)) % 4;
  const binary = atob(`${normalized}${"=".repeat(paddingLength)}`);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return new TextDecoder().decode(bytes);
};

const decodeBadgeRuleRegistryCursor = (
  encoded: string,
  expected: {
    readonly sort: BadgeIssuanceRuleRegistrySort;
    readonly direction: BadgeIssuanceRuleRegistrySortDirection;
  },
): BadgeIssuanceRuleRegistryCursor => {
  const payload = parseBadgeRuleRegistryCursorPayload(JSON.parse(decodeBase64Url(encoded)));

  if (payload.sort !== expected.sort || payload.direction !== expected.direction) {
    throw new Error("Badge rule registry cursor does not match the selected sort");
  }

  return {
    value: payload.value,
    ruleId: payload.ruleId,
    totalCount: payload.totalCount,
  };
};

const encodeBadgeRuleRegistryCursor = (
  query: Pick<BadgeRuleRegistryPageQuery, "sort" | "direction">,
  cursor: BadgeIssuanceRuleRegistryCursor,
): string => {
  return encodeBase64Url(
    JSON.stringify({
      sort: query.sort,
      direction: query.direction,
      value: cursor.value,
      ruleId: cursor.ruleId,
      totalCount: cursor.totalCount,
    }),
  );
};

export const safeParseBadgeRuleRegistryPageQuery = (
  input: unknown,
): { readonly ok: true; readonly value: BadgeRuleRegistryPageQuery } | { readonly ok: false } => {
  try {
    const parsed = parseBadgeRuleRegistryPageQuery(input);
    const rawCursor = parsed.after ?? parsed.before;
    const cursor =
      rawCursor === undefined
        ? undefined
        : {
            position: parsed.before === undefined ? ("after" as const) : ("before" as const),
            boundary: decodeBadgeRuleRegistryCursor(rawCursor, {
              sort: parsed.sort,
              direction: parsed.direction,
            }),
          };

    return {
      ok: true,
      value: {
        searchQuery: parsed.q,
        latestStatus: parsed.status ?? null,
        sort: parsed.sort,
        direction: parsed.direction,
        limit: parsed.limit,
        ...(cursor === undefined ? {} : { cursor }),
      },
    };
  } catch {
    return { ok: false };
  }
};

export const buildBadgeRuleRegistryPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/rules`;
};

export const buildBadgeRuleRegistryPageQuery = (
  query: BadgeRuleRegistryPageQuery,
  cursor?: {
    readonly position: "after" | "before";
    readonly boundary: BadgeIssuanceRuleRegistryCursor;
  },
): URLSearchParams => {
  const params = new URLSearchParams();

  if (query.searchQuery.length > 0) {
    params.set("q", query.searchQuery);
  }
  if (query.latestStatus !== null) {
    params.set("status", query.latestStatus);
  }
  if (query.sort !== "updated") {
    params.set("sort", query.sort);
  }
  if (query.direction !== "desc") {
    params.set("direction", query.direction);
  }
  if (query.limit !== 25) {
    params.set("limit", String(query.limit));
  }

  if (cursor !== undefined) {
    params.set(cursor.position, encodeBadgeRuleRegistryCursor(query, cursor.boundary));
  }

  return params;
};

export const badgeRuleRegistryPageUrl = (
  tenantId: string,
  query: BadgeRuleRegistryPageQuery,
  cursor?: Parameters<typeof buildBadgeRuleRegistryPageQuery>[1],
): string => {
  const path = buildBadgeRuleRegistryPath(tenantId);
  const queryString = buildBadgeRuleRegistryPageQuery(query, cursor).toString();

  return queryString.length === 0 ? path : `${path}?${queryString}`;
};

const defaultDirectionForSort = (
  sort: BadgeIssuanceRuleRegistrySort,
): BadgeIssuanceRuleRegistrySortDirection => {
  return sort === "updated" || sort === "current_version" || sort === "latest_version"
    ? "desc"
    : "asc";
};

export const badgeRuleRegistrySortUrl = (
  tenantId: string,
  query: BadgeRuleRegistryPageQuery,
  sort: BadgeIssuanceRuleRegistrySort,
): string => {
  const direction =
    query.sort === sort
      ? query.direction === "asc"
        ? "desc"
        : "asc"
      : defaultDirectionForSort(sort);

  return badgeRuleRegistryPageUrl(tenantId, {
    ...query,
    sort,
    direction,
    cursor: undefined,
  });
};
