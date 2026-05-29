import type { TenantOrgUnitRecord } from "@credtrail/db";

export const formatReportingCount = (value: number): string => {
  return new Intl.NumberFormat("en-US", {
    maximumFractionDigits: 0,
  }).format(value);
};

export const formatReportingRate = (value: number): string => {
  return `${value.toFixed(1)}%`;
};

export const formatReportingDateLabel = (value: string): string => {
  const date = value.includes("T") ? new Date(value) : new Date(`${value}T00:00:00.000Z`);

  if (!Number.isFinite(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  }).format(date);
};

export const formatReportingStateLabel = (value: string | null | undefined): string => {
  if (value === null || value === undefined || value.trim().length === 0) {
    return "All current states";
  }

  switch (value) {
    case "pending_review":
      return "Pending review";
    case "active":
      return "active";
    case "suspended":
      return "suspended";
    case "revoked":
      return "revoked";
    case "expired":
      return "expired";
    default:
      return value;
  }
};

export const REPORTING_HIERARCHY_LEVELS = [
  "institution",
  "college",
  "department",
  "program",
] as const;
export type ReportingHierarchyLevel = (typeof REPORTING_HIERARCHY_LEVELS)[number];

export const REPORTING_HIERARCHY_DEPTH: Record<ReportingHierarchyLevel, number> = {
  institution: 0,
  college: 1,
  department: 2,
  program: 3,
};

export const REPORTING_RATE_MIN_ISSUED = 5;
export const REPORTING_PERFORMER_ROW_LIMIT = 3;

export interface ReportingHierarchyRow {
  orgUnitId: string;
  level: ReportingHierarchyLevel;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
}

export type ReportingPanelState = "rich" | "sparse" | "empty";

export interface ReportingActivityCounts {
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
}

export const isReportingHierarchyLevel = (
  value: TenantOrgUnitRecord["unitType"],
): value is ReportingHierarchyLevel => {
  return REPORTING_HIERARCHY_LEVELS.includes(value as ReportingHierarchyLevel);
};

export const getNextReportingHierarchyLevel = (
  level: ReportingHierarchyLevel,
): ReportingHierarchyLevel | null => {
  const index = REPORTING_HIERARCHY_LEVELS.indexOf(level);

  return index === REPORTING_HIERARCHY_LEVELS.length - 1
    ? null
    : (REPORTING_HIERARCHY_LEVELS[index + 1] ?? null);
};

export const formatReportingHierarchyLevelLabel = (level: ReportingHierarchyLevel): string => {
  switch (level) {
    case "institution":
      return "Institution";
    case "college":
      return "College";
    case "department":
      return "Department";
    case "program":
      return "Program";
  }
};

export const buildReportingHierarchyFocusId = (orgUnitId: string): string => {
  return `reporting-hierarchy-focus-${encodeURIComponent(orgUnitId)}`;
};

export const appendQueryParam = (
  params: URLSearchParams,
  key: string,
  value: string | null | undefined,
): void => {
  const normalizedValue = value?.trim() ?? "";

  if (normalizedValue.length > 0) {
    params.set(key, normalizedValue);
  }
};

export const buildPathWithQuery = (
  path: string,
  queryEntries: ReadonlyArray<readonly [string, string | null | undefined]>,
): string => {
  const params = new URLSearchParams();

  for (const [key, value] of queryEntries) {
    appendQueryParam(params, key, value);
  }

  const query = params.toString();

  return query.length === 0 ? path : `${path}?${query}`;
};
