import {
  buildCsvAttachmentHeaders,
  buildCsvFilename,
  serializeCsv,
  type CsvColumn,
} from "./csv-export";

export type OverviewExportRow = {
  tenantId: string;
  issuedFrom: string | null;
  issuedTo: string | null;
  badgeTemplateId: string | null;
  orgUnitId: string | null;
  state: string | null;
  generatedAt: string;
  issued: number;
  active: number;
  suspended: number;
  revoked: number;
  pendingReview: number;
};

export type EngagementExportRow = {
  tenantId: string;
  from: string | null;
  to: string | null;
  badgeTemplateId: string | null;
  orgUnitId: string | null;
  state: string | null;
  generatedAt: string;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
};

export type TrendExportRow = {
  tenantId: string;
  from: string | null;
  to: string | null;
  badgeTemplateId: string | null;
  orgUnitId: string | null;
  state: string | null;
  bucket: string;
  bucketStart: string;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
};

export type ComparisonExportRow = {
  tenantId: string;
  from: string | null;
  to: string | null;
  badgeTemplateId: string | null;
  orgUnitId: string | null;
  state: string | null;
  groupBy: string;
  groupId: string;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
};

export type HierarchyExportRow = {
  tenantId: string;
  from: string | null;
  to: string | null;
  badgeTemplateId: string | null;
  orgUnitIdFilter: string | null;
  state: string | null;
  focusOrgUnitId: string | null;
  level: string;
  orgUnitId: string;
  displayName: string;
  parentOrgUnitId: string | null;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
};

export const buildReportingCsvResponse = <
  T extends Record<string, string | number | boolean | null | undefined>,
>(input: {
  baseName: string;
  generatedAt: string;
  rows: readonly T[];
  columns: readonly CsvColumn<T>[];
}): Response => {
  const filename = buildCsvFilename(input.baseName, input.generatedAt);
  const csv = serializeCsv({
    rows: input.rows,
    columns: input.columns,
  });

  return new Response(csv, {
    status: 200,
    headers: buildCsvAttachmentHeaders(filename),
  });
};

export const OVERVIEW_EXPORT_COLUMNS: readonly CsvColumn<OverviewExportRow>[] = [
  { key: "tenantId", header: "Tenant ID" },
  { key: "issuedFrom", header: "Issued From" },
  { key: "issuedTo", header: "Issued To" },
  { key: "badgeTemplateId", header: "Badge Template ID" },
  { key: "orgUnitId", header: "Org Unit ID" },
  { key: "state", header: "Lifecycle State" },
  { key: "generatedAt", header: "Generated At" },
  { key: "issued", header: "Issued" },
  { key: "active", header: "Active" },
  { key: "suspended", header: "Suspended" },
  { key: "revoked", header: "Revoked" },
  { key: "pendingReview", header: "Pending Review" },
] as const;

export const ENGAGEMENT_EXPORT_COLUMNS: readonly CsvColumn<EngagementExportRow>[] = [
  { key: "tenantId", header: "Tenant ID" },
  { key: "from", header: "Issued From" },
  { key: "to", header: "Issued To" },
  { key: "badgeTemplateId", header: "Badge Template ID" },
  { key: "orgUnitId", header: "Org Unit ID" },
  { key: "state", header: "Lifecycle State" },
  { key: "generatedAt", header: "Generated At" },
  { key: "issuedCount", header: "Issued Count" },
  { key: "publicBadgeViewCount", header: "Public Badge View Count" },
  { key: "verificationViewCount", header: "Verification View Count" },
  { key: "shareClickCount", header: "Share Click Count" },
  { key: "learnerClaimCount", header: "Learner Claim Count" },
  { key: "walletAcceptCount", header: "Wallet Accept Count" },
  { key: "claimRate", header: "Claim Rate" },
  { key: "shareRate", header: "Share Rate" },
] as const;

export const TREND_EXPORT_COLUMNS: readonly CsvColumn<TrendExportRow>[] = [
  { key: "tenantId", header: "Tenant ID" },
  { key: "from", header: "Issued From" },
  { key: "to", header: "Issued To" },
  { key: "badgeTemplateId", header: "Badge Template ID" },
  { key: "orgUnitId", header: "Org Unit ID" },
  { key: "state", header: "Lifecycle State" },
  { key: "bucket", header: "Bucket" },
  { key: "bucketStart", header: "Bucket Start" },
  { key: "issuedCount", header: "Issued Count" },
  { key: "publicBadgeViewCount", header: "Public Badge View Count" },
  { key: "verificationViewCount", header: "Verification View Count" },
  { key: "shareClickCount", header: "Share Click Count" },
  { key: "learnerClaimCount", header: "Learner Claim Count" },
  { key: "walletAcceptCount", header: "Wallet Accept Count" },
] as const;

export const COMPARISON_EXPORT_COLUMNS: readonly CsvColumn<ComparisonExportRow>[] = [
  { key: "tenantId", header: "Tenant ID" },
  { key: "from", header: "Issued From" },
  { key: "to", header: "Issued To" },
  { key: "badgeTemplateId", header: "Badge Template ID" },
  { key: "orgUnitId", header: "Org Unit ID" },
  { key: "state", header: "Lifecycle State" },
  { key: "groupBy", header: "Group By" },
  { key: "groupId", header: "Group ID" },
  { key: "issuedCount", header: "Issued Count" },
  { key: "publicBadgeViewCount", header: "Public Badge View Count" },
  { key: "verificationViewCount", header: "Verification View Count" },
  { key: "shareClickCount", header: "Share Click Count" },
  { key: "learnerClaimCount", header: "Learner Claim Count" },
  { key: "walletAcceptCount", header: "Wallet Accept Count" },
  { key: "claimRate", header: "Claim Rate" },
  { key: "shareRate", header: "Share Rate" },
] as const;

export const HIERARCHY_EXPORT_COLUMNS: readonly CsvColumn<HierarchyExportRow>[] = [
  { key: "tenantId", header: "Tenant ID" },
  { key: "from", header: "Issued From" },
  { key: "to", header: "Issued To" },
  { key: "badgeTemplateId", header: "Badge Template ID" },
  { key: "orgUnitIdFilter", header: "Org Unit Filter" },
  { key: "state", header: "Lifecycle State" },
  { key: "focusOrgUnitId", header: "Focus Org Unit ID" },
  { key: "level", header: "Level" },
  { key: "orgUnitId", header: "Org Unit ID" },
  { key: "displayName", header: "Display Name" },
  { key: "parentOrgUnitId", header: "Parent Org Unit ID" },
  { key: "issuedCount", header: "Issued Count" },
  { key: "publicBadgeViewCount", header: "Public Badge View Count" },
  { key: "verificationViewCount", header: "Verification View Count" },
  { key: "shareClickCount", header: "Share Click Count" },
  { key: "learnerClaimCount", header: "Learner Claim Count" },
  { key: "walletAcceptCount", header: "Wallet Accept Count" },
  { key: "claimRate", header: "Claim Rate" },
  { key: "shareRate", header: "Share Rate" },
] as const;
