import { findBadgeTemplateById, listBadgeTemplateOwnershipEvents } from "./badge-templates";
import type { BadgeTemplateOwnershipEventRecord } from "./badge-templates";
import { findLearnerProfileByIdentity, listLearnerIdentitiesByProfile } from "./learner-profiles";
import type { RecipientIdentifierInput } from "./learner-profiles";
import {
  insertAssertionRecipientIdentifiers,
  uniqueRecipientIdentifiers,
} from "./assertion-recipient-identifiers";
export { listRecipientIdentifiersForAssertion } from "./assertion-recipient-identifiers";
import { assertValidIsoTimestamp, createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";
import { listTenantOrgUnits } from "./tenant-org-units";
import type { OrgUnitType, TenantOrgUnitRecord } from "./tenant-org-units";
import { findUserById, normalizeEmail } from "./users";

export interface AssertionRecord {
  id: string;
  tenantId: string;
  publicId: string | null;
  learnerProfileId: string | null;
  badgeTemplateId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  vcR2Key: string;
  statusListIndex: number | null;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface LearnerRecordAssertionExportRecord {
  assertionId: string;
  assertionPublicId: string | null;
  tenantId: string;
  learnerProfileId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  badgeCriteriaUri: string | null;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  vcR2Key: string;
  statusListIndex: number | null;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  issuerName: string;
  createdAt: string;
  updatedAt: string;
}

export interface ListLearnerRecordAssertionExportsInput {
  tenantId: string;
  learnerProfileId: string;
}

export type AssertionLifecycleState = "active" | "suspended" | "revoked" | "expired";

export type AssertionLifecycleTransitionSource = "manual" | "automation";

export type AssertionLifecycleReasonCode =
  | "administrative_hold"
  | "policy_violation"
  | "appeal_pending"
  | "appeal_resolved"
  | "credential_expired"
  | "issuer_requested"
  | "other";

export interface AssertionLifecycleEventRecord {
  id: string;
  tenantId: string;
  assertionId: string;
  fromState: AssertionLifecycleState;
  toState: AssertionLifecycleState;
  reasonCode: AssertionLifecycleReasonCode;
  reason: string | null;
  transitionSource: AssertionLifecycleTransitionSource;
  actorUserId: string | null;
  transitionedAt: string;
  createdAt: string;
}

export interface ListAssertionLifecycleEventsInput {
  tenantId: string;
  assertionId: string;
  limit?: number | undefined;
}

export interface ResolveAssertionLifecycleStateResult {
  state: AssertionLifecycleState;
  source: "assertion_revocation" | "lifecycle_event" | "default_active";
  reasonCode: AssertionLifecycleReasonCode | null;
  reason: string | null;
  transitionedAt: string | null;
  revokedAt: string | null;
}

export interface RecordAssertionLifecycleTransitionInput {
  tenantId: string;
  assertionId: string;
  toState: AssertionLifecycleState;
  reasonCode: AssertionLifecycleReasonCode;
  reason?: string | undefined;
  transitionSource: AssertionLifecycleTransitionSource;
  actorUserId?: string | undefined;
  transitionedAt: string;
}

export interface RecordAssertionLifecycleTransitionResult {
  status: "transitioned" | "already_in_state" | "invalid_transition";
  fromState: AssertionLifecycleState;
  toState: AssertionLifecycleState;
  currentState: AssertionLifecycleState;
  event: AssertionLifecycleEventRecord | null;
  message: string | null;
}

export interface LearnerBadgeSummaryRecord {
  assertionId: string;
  assertionPublicId: string | null;
  tenantId: string;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  issuedAt: string;
  revokedAt: string | null;
}

export interface PublicBadgeWallEntryRecord {
  assertionId: string;
  assertionPublicId: string;
  tenantId: string;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  issuedAt: string;
  revokedAt: string | null;
}

export interface CreateAssertionInput {
  id: string;
  tenantId: string;
  publicId?: string | undefined;
  learnerProfileId?: string | undefined;
  badgeTemplateId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  vcR2Key: string;
  statusListIndex: number;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId?: string | undefined;
  recipientIdentifiers?: readonly RecipientIdentifierInput[];
}

export interface AssertionStatusListEntryRecord {
  statusListIndex: number;
  revokedAt: string | null;
}

export interface RecordAssertionRevocationInput {
  tenantId: string;
  assertionId: string;
  revocationId: string;
  reason: string;
  idempotencyKey: string;
  revokedByUserId?: string | undefined;
  revokedAt: string;
}

export interface RecordAssertionRevocationResult {
  status: "revoked" | "already_revoked";
  revokedAt: string;
}

export interface ListLearnerBadgeSummariesInput {
  tenantId: string;
  userId: string;
}

export interface ListTenantAssertionsInput {
  tenantId: string;
  badgeTemplateId?: string | undefined;
  recipientQuery?: string | undefined;
  state?: AssertionLifecycleState | undefined;
  limit?: number | undefined;
}

export interface ListAssertionsByIdempotencyKeysInput {
  tenantId: string;
  idempotencyKeys: readonly string[];
}

export interface AssertionLifecycleStateByAssertionIdRecord extends ResolveAssertionLifecycleStateResult {
  assertionId: string;
}

export interface ListAssertionLifecycleStatesByAssertionIdsInput {
  tenantId: string;
  assertionIds: readonly string[];
}

export type AssertionReportingAttributionSource =
  | "issuance_snapshot"
  | "historical_backfill"
  | "current_owner_fallback";

export interface AssertionReportingAttributionRecord {
  assertionId: string;
  tenantId: string;
  badgeTemplateId: string;
  orgUnitId: string;
  attributionSource: AssertionReportingAttributionSource;
  attributedAt: string;
  createdAt: string;
  updatedAt: string;
}

export const ASSERTION_ENGAGEMENT_EVENT_TYPES = [
  "public_badge_view",
  "verification_view",
  "share_click",
  "learner_claim",
  "wallet_accept",
] as const;

export type AssertionEngagementEventType = (typeof ASSERTION_ENGAGEMENT_EVENT_TYPES)[number];

export type AssertionEngagementActorType = "anonymous" | "learner" | "wallet" | "system";

export interface AssertionEngagementEventRecord {
  id: string;
  tenantId: string;
  assertionId: string;
  eventType: AssertionEngagementEventType;
  actorType: AssertionEngagementActorType;
  channel: string | null;
  occurredAt: string;
  createdAt: string;
}

export interface RecordAssertionEngagementEventInput {
  tenantId: string;
  assertionId: string;
  eventType: AssertionEngagementEventType;
  actorType: AssertionEngagementActorType;
  channel?: string | undefined;
  occurredAt: string;
}

export interface RecordAssertionEngagementEventResult {
  status: "recorded" | "already_recorded";
  event: AssertionEngagementEventRecord;
}

export interface ListAssertionEngagementEventsInput {
  tenantId: string;
  assertionId: string;
  limit?: number | undefined;
}

export type TenantReportingLifecycleFilter = AssertionLifecycleState | "pending_review";

export interface TenantReportingOverviewFilters {
  issuedFrom?: string | undefined;
  issuedTo?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: TenantReportingLifecycleFilter | undefined;
}

export interface GetTenantReportingOverviewInput extends TenantReportingOverviewFilters {
  tenantId: string;
}

export interface TenantReportingOverviewCounts {
  issued: number;
  active: number;
  suspended: number;
  revoked: number;
  pendingReview: number;
  claimRate?: number | undefined;
  shareRate?: number | undefined;
}

export interface TenantReportingOverviewRecord {
  tenantId: string;
  filters: {
    issuedFrom: string | null;
    issuedTo: string | null;
    badgeTemplateId: string | null;
    orgUnitId: string | null;
    state: TenantReportingLifecycleFilter | null;
  };
  counts: TenantReportingOverviewCounts;
  generatedAt: string;
}

export interface TenantReportingEngagementFilters {
  from?: string | undefined;
  to?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: TenantReportingLifecycleFilter | undefined;
}

export interface TenantReportingHierarchyQuery {
  from?: string | undefined;
  to?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: TenantReportingLifecycleFilter | undefined;
  focusOrgUnitId?: string | undefined;
  level: OrgUnitType;
}

export interface TenantReportingHierarchySourceRow {
  assertionId: string;
  badgeTemplateId: string;
  orgUnitId: string;
  issuedAt: string;
  eventType: AssertionEngagementEventType | null;
  occurredAt: string | null;
}

export interface TenantReportingHierarchyOrgUnitRecord {
  id: string;
  unitType: OrgUnitType;
  displayName: string;
  parentOrgUnitId: string | null;
}

export interface TenantReportingHierarchyGroupRecord {
  level: OrgUnitType;
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
}

export interface TenantExecutiveRollupQuery {
  from?: string | undefined;
  to?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: TenantReportingLifecycleFilter | undefined;
  focusOrgUnitId: string;
  comparisonLevel: OrgUnitType;
}

export interface TenantExecutiveRollupRecord {
  focusOrgUnitId: string;
  focusDisplayName: string;
  focusParentOrgUnitId: string | null;
  focusUnitType: OrgUnitType;
  comparisonLevel: OrgUnitType;
  focusLineageOrgUnitIds: string[];
  filters: {
    from: string | null;
    to: string | null;
    badgeTemplateId: string | null;
    orgUnitId: string | null;
    state: TenantReportingLifecycleFilter | null;
  };
  rows: TenantReportingHierarchyGroupRecord[];
}

export interface GetTenantExecutiveRollupInput extends TenantReportingEngagementFilters {
  tenantId: string;
  focusOrgUnitId: string;
  comparisonLevel: OrgUnitType;
  scopedRootOrgUnitIds?: readonly string[] | undefined;
}

export interface GetTenantExecutiveRollupResult extends TenantExecutiveRollupRecord {
  tenantId: string;
  generatedAt: string;
}

export interface GetTenantReportingEngagementCountsInput extends TenantReportingEngagementFilters {
  tenantId: string;
}

export interface TenantReportingEngagementCounts {
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
}

export type TenantReportingTrendBucket = "day";

export interface GetTenantReportingTrendsInput extends TenantReportingEngagementFilters {
  tenantId: string;
  bucket: TenantReportingTrendBucket;
}

export interface TenantReportingTrendBucketRecord {
  bucketStart: string;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
}

export interface TenantReportingTrendRecord {
  tenantId: string;
  filters: {
    from: string | null;
    to: string | null;
    badgeTemplateId: string | null;
    orgUnitId: string | null;
    state: TenantReportingLifecycleFilter | null;
  };
  bucket: TenantReportingTrendBucket;
  series: TenantReportingTrendBucketRecord[];
  generatedAt: string;
}

export type TenantReportingComparisonGroupBy = "badgeTemplate" | "orgUnit";

export interface ListTenantReportingComparisonsInput extends TenantReportingEngagementFilters {
  tenantId: string;
  groupBy: TenantReportingComparisonGroupBy;
}

export interface TenantReportingComparisonRowRecord {
  groupBy: TenantReportingComparisonGroupBy;
  groupId: string;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
}

export interface TenantAssertionSummaryRecord {
  assertionId: string;
  tenantId: string;
  publicId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  state: AssertionLifecycleState;
  source: ResolveAssertionLifecycleStateResult["source"];
  reasonCode: AssertionLifecycleReasonCode | null;
  reason: string | null;
  transitionedAt: string | null;
}

export const SYNCHRONOUS_EXPORT_ROW_LIMIT = 5000;

export interface ListTenantAssertionLedgerExportRowsInput {
  tenantId: string;
  issuedFrom?: string | undefined;
  issuedTo?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: AssertionLifecycleState | undefined;
  recipientQuery?: string | undefined;
}

export interface TenantAssertionLedgerExportRowRecord {
  assertionId: string;
  tenantId: string;
  publicId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  state: AssertionLifecycleState;
  source: ResolveAssertionLifecycleStateResult["source"];
  reasonCode: AssertionLifecycleReasonCode | null;
  reason: string | null;
  transitionedAt: string | null;
  orgUnitId: string;
  orgUnitDisplayName: string;
  attributionSource: AssertionReportingAttributionSource;
  currentInstitutionName: string | null;
  currentCollegeName: string | null;
  currentDepartmentName: string | null;
  currentProgramName: string | null;
}

export type TenantAssertionLedgerExportResult =
  | {
      status: "ok";
      rowLimit: number;
      rows: TenantAssertionLedgerExportRowRecord[];
    }
  | {
      status: "too_large";
      rowLimit: number;
    };

export interface ListPublicBadgeWallEntriesInput {
  tenantId: string;
  badgeTemplateId?: string | undefined;
  limit?: number | undefined;
}

interface AssertionRow {
  id: string;
  tenantId: string;
  publicId: string | null;
  learnerProfileId: string | null;
  badgeTemplateId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  vcR2Key: string;
  statusListIndex: number | null;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface AssertionReportingAttributionRow {
  assertionId: string;
  tenantId: string;
  badgeTemplateId: string;
  orgUnitId: string;
  attributionSource: AssertionReportingAttributionSource;
  attributedAt: string;
  createdAt: string;
  updatedAt: string;
}

interface AssertionEngagementEventRow {
  id: string;
  tenantId: string;
  assertionId: string;
  eventType: AssertionEngagementEventType;
  actorType: AssertionEngagementActorType;
  channel: string | null;
  occurredAt: string;
  createdAt: string;
}

interface TenantReportingOverviewRow {
  assertionId: string;
  issuedAt: string;
  badgeTemplateId: string;
  orgUnitId: string;
  revokedAt: string | null;
  latestToState: AssertionLifecycleState | null;
  latestReasonCode: AssertionLifecycleReasonCode | null;
}

interface TenantReportingEngagementRow {
  assertionId: string;
  badgeTemplateId: string;
  orgUnitId: string;
  issuedAt: string;
  revokedAt: string | null;
  latestToState: AssertionLifecycleState | null;
  latestReasonCode: AssertionLifecycleReasonCode | null;
  eventType: AssertionEngagementEventType | null;
  occurredAt: string | null;
}

interface AssertionLifecycleEventRow {
  id: string;
  tenantId: string;
  assertionId: string;
  fromState: AssertionLifecycleState;
  toState: AssertionLifecycleState;
  reasonCode: AssertionLifecycleReasonCode;
  reason: string | null;
  transitionSource: AssertionLifecycleTransitionSource;
  actorUserId: string | null;
  transitionedAt: string;
  createdAt: string;
}

interface LearnerBadgeSummaryRow {
  assertionId: string;
  assertionPublicId: string | null;
  tenantId: string;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  issuedAt: string;
  revokedAt: string | null;
}

interface LearnerRecordAssertionExportRow {
  assertionId: string;
  assertionPublicId: string | null;
  tenantId: string;
  learnerProfileId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  badgeCriteriaUri: string | null;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  vcR2Key: string;
  statusListIndex: number | null;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  issuerName: string;
  createdAt: string;
  updatedAt: string;
}

interface TenantAssertionSummaryRow {
  assertionId: string;
  tenantId: string;
  publicId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  latestToState: AssertionLifecycleState | null;
  latestReasonCode: AssertionLifecycleReasonCode | null;
  latestReason: string | null;
  latestTransitionedAt: string | null;
}

interface TenantAssertionLedgerExportRow {
  assertionId: string;
  tenantId: string;
  publicId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  latestToState: AssertionLifecycleState | null;
  latestReasonCode: AssertionLifecycleReasonCode | null;
  latestReason: string | null;
  latestTransitionedAt: string | null;
  orgUnitId: string;
  orgUnitDisplayName: string;
  attributionSource: AssertionReportingAttributionSource;
}

interface PublicBadgeWallEntryRow {
  assertionId: string;
  assertionPublicId: string;
  tenantId: string;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  issuedAt: string;
  revokedAt: string | null;
}

const ASSERTION_LIFECYCLE_REASON_CODES = new Set<AssertionLifecycleReasonCode>([
  "administrative_hold",
  "policy_violation",
  "appeal_pending",
  "appeal_resolved",
  "credential_expired",
  "issuer_requested",
  "other",
]);

const ASSERTION_LIFECYCLE_ALLOWED_TRANSITIONS: Record<
  AssertionLifecycleState,
  ReadonlySet<AssertionLifecycleState>
> = {
  active: new Set<AssertionLifecycleState>(["suspended", "revoked", "expired"]),
  suspended: new Set<AssertionLifecycleState>(["active", "revoked", "expired"]),
  expired: new Set<AssertionLifecycleState>(["active", "revoked"]),
  revoked: new Set<AssertionLifecycleState>(),
};

const uniqueNonEmptyStrings = (values: readonly string[]): string[] => {
  return Array.from(
    new Set(values.map((value) => value.trim()).filter((value) => value.length > 0)),
  );
};

const chunkValues = <T>(values: readonly T[], chunkSize: number): T[][] => {
  const chunks: T[][] = [];

  for (let index = 0; index < values.length; index += chunkSize) {
    chunks.push(values.slice(index, index + chunkSize));
  }

  return chunks;
};

const assertionLifecycleStateFromRecords = (input: {
  assertion: AssertionRecord;
  latestEvent: AssertionLifecycleEventRecord | null;
}): ResolveAssertionLifecycleStateResult => {
  if (input.assertion.revokedAt !== null && input.latestEvent?.toState === "revoked") {
    return {
      state: "revoked",
      source: "lifecycle_event",
      reasonCode: input.latestEvent.reasonCode,
      reason: input.latestEvent.reason ?? "credential has been revoked by issuer",
      transitionedAt: input.latestEvent.transitionedAt,
      revokedAt: input.assertion.revokedAt,
    };
  }

  if (input.assertion.revokedAt !== null) {
    return {
      state: "revoked",
      source: "assertion_revocation",
      reasonCode: null,
      reason: "credential has been revoked by issuer",
      transitionedAt: input.assertion.revokedAt,
      revokedAt: input.assertion.revokedAt,
    };
  }

  if (input.latestEvent !== null) {
    return {
      state: input.latestEvent.toState,
      source: "lifecycle_event",
      reasonCode: input.latestEvent.reasonCode,
      reason: input.latestEvent.reason,
      transitionedAt: input.latestEvent.transitionedAt,
      revokedAt: null,
    };
  }

  return {
    state: "active",
    source: "default_active",
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    revokedAt: null,
  };
};

const tenantReportingCountsZero = (): TenantReportingOverviewCounts => {
  return {
    issued: 0,
    active: 0,
    suspended: 0,
    revoked: 0,
    pendingReview: 0,
  };
};

const tenantReportingLifecycleFromRow = (
  row: Pick<TenantReportingOverviewRow, "revokedAt" | "latestToState">,
): AssertionLifecycleState => {
  if (row.revokedAt !== null) {
    return "revoked";
  }

  return row.latestToState ?? "active";
};

export const resolveAssertionReportingAttribution = (input: {
  issuedAt: string;
  currentOwnerOrgUnitId: string;
  ownershipEvents: readonly Pick<
    BadgeTemplateOwnershipEventRecord,
    "toOrgUnitId" | "transferredAt"
  >[];
}): {
  orgUnitId: string;
  attributionSource: AssertionReportingAttributionSource;
  attributedAt: string;
} => {
  const issuedAtMs = Date.parse(input.issuedAt);

  if (!Number.isFinite(issuedAtMs)) {
    throw new Error("issuedAt must be a valid ISO timestamp");
  }

  const matchedEvent = [...input.ownershipEvents]
    .filter((event) => {
      const transferredAtMs = Date.parse(event.transferredAt);
      return Number.isFinite(transferredAtMs) && transferredAtMs <= issuedAtMs;
    })
    .sort((left, right) => right.transferredAt.localeCompare(left.transferredAt))[0];

  if (matchedEvent !== undefined) {
    return {
      orgUnitId: matchedEvent.toOrgUnitId,
      attributionSource: "historical_backfill",
      attributedAt: input.issuedAt,
    };
  }

  return {
    orgUnitId: input.currentOwnerOrgUnitId,
    attributionSource: "current_owner_fallback",
    attributedAt: input.issuedAt,
  };
};

export const summarizeTenantReportingOverviewRows = (
  rows: readonly TenantReportingOverviewRow[],
  stateFilter?: TenantReportingLifecycleFilter,
): TenantReportingOverviewCounts => {
  const filteredRows =
    stateFilter === undefined
      ? rows
      : rows.filter((row) => {
          const lifecycleState = tenantReportingLifecycleFromRow(row);

          if (stateFilter === "pending_review") {
            return lifecycleState === "suspended" && row.latestReasonCode === "appeal_pending";
          }

          return lifecycleState === stateFilter;
        });

  const counts = tenantReportingCountsZero();
  counts.issued = filteredRows.length;

  for (const row of filteredRows) {
    const lifecycleState = tenantReportingLifecycleFromRow(row);

    if (lifecycleState === "active") {
      counts.active += 1;
    } else if (lifecycleState === "suspended") {
      counts.suspended += 1;
    } else if (lifecycleState === "revoked") {
      counts.revoked += 1;
    }

    if (lifecycleState === "suspended" && row.latestReasonCode === "appeal_pending") {
      counts.pendingReview += 1;
    }
  }

  return counts;
};

interface TenantReportingEngagementCountTarget {
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
}

interface TenantReportingEngagementAggregate {
  issuedAssertionIds: Set<string>;
  shareEngagedAssertionIds: Set<string>;
  claimEngagedAssertionIds: Set<string>;
  counts: TenantReportingEngagementCountTarget;
}

const ONE_SHOT_ASSERTION_ENGAGEMENT_EVENT_TYPES = new Set<AssertionEngagementEventType>([
  "learner_claim",
  "wallet_accept",
]);

const tenantReportingEngagementCountsZero = (): TenantReportingEngagementCounts => {
  return {
    issuedCount: 0,
    publicBadgeViewCount: 0,
    verificationViewCount: 0,
    shareClickCount: 0,
    learnerClaimCount: 0,
    walletAcceptCount: 0,
    claimRate: 0,
    shareRate: 0,
  };
};

const tenantReportingTrendBucketZero = (bucketStart: string): TenantReportingTrendBucketRecord => {
  return {
    bucketStart,
    issuedCount: 0,
    publicBadgeViewCount: 0,
    verificationViewCount: 0,
    shareClickCount: 0,
    learnerClaimCount: 0,
    walletAcceptCount: 0,
  };
};

const tenantReportingComparisonRowZero = (
  groupBy: TenantReportingComparisonGroupBy,
  groupId: string,
): TenantReportingComparisonRowRecord => {
  return {
    groupBy,
    groupId,
    issuedCount: 0,
    publicBadgeViewCount: 0,
    verificationViewCount: 0,
    shareClickCount: 0,
    learnerClaimCount: 0,
    walletAcceptCount: 0,
    claimRate: 0,
    shareRate: 0,
  };
};

const ORG_UNIT_HIERARCHY_DEPTH: Record<OrgUnitType, number> = {
  institution: 0,
  college: 1,
  department: 2,
  program: 3,
};

const createTenantReportingEngagementAggregate = (): TenantReportingEngagementAggregate => {
  return {
    issuedAssertionIds: new Set<string>(),
    shareEngagedAssertionIds: new Set<string>(),
    claimEngagedAssertionIds: new Set<string>(),
    counts: {
      publicBadgeViewCount: 0,
      verificationViewCount: 0,
      shareClickCount: 0,
      learnerClaimCount: 0,
      walletAcceptCount: 0,
    },
  };
};

const incrementTenantReportingEngagementCount = (
  target: TenantReportingEngagementCountTarget,
  eventType: AssertionEngagementEventType,
): void => {
  if (eventType === "public_badge_view") {
    target.publicBadgeViewCount += 1;
  } else if (eventType === "verification_view") {
    target.verificationViewCount += 1;
  } else if (eventType === "share_click") {
    target.shareClickCount += 1;
  } else if (eventType === "learner_claim") {
    target.learnerClaimCount += 1;
  } else if (eventType === "wallet_accept") {
    target.walletAcceptCount += 1;
  }
};

const dateKeyFromTimestamp = (value: string): string => {
  const parsed = new Date(value);

  if (!Number.isFinite(parsed.getTime())) {
    throw new Error(`Invalid reporting timestamp: ${value}`);
  }

  return parsed.toISOString().slice(0, 10);
};

const normalizeReportingDateKey = (value: string, boundary: "start" | "end"): string => {
  return normalizeReportingDateBoundary(value, boundary).slice(0, 10);
};

const isTimestampWithinReportingRange = (
  timestamp: string,
  from: string | undefined,
  to: string | undefined,
): boolean => {
  const dateKey = dateKeyFromTimestamp(timestamp);

  if (from !== undefined && dateKey < from) {
    return false;
  }

  if (to !== undefined && dateKey > to) {
    return false;
  }

  return true;
};

const matchesTenantReportingEngagementFilters = (
  row: Pick<
    TenantReportingEngagementRow,
    "badgeTemplateId" | "orgUnitId" | "revokedAt" | "latestToState" | "latestReasonCode"
  >,
  input: Pick<TenantReportingEngagementFilters, "badgeTemplateId" | "orgUnitId" | "state">,
): boolean => {
  if (input.badgeTemplateId !== undefined && row.badgeTemplateId !== input.badgeTemplateId) {
    return false;
  }

  if (input.orgUnitId !== undefined && row.orgUnitId !== input.orgUnitId) {
    return false;
  }

  if (input.state !== undefined) {
    const lifecycleState = tenantReportingLifecycleFromRow(row);

    if (input.state === "pending_review") {
      return lifecycleState === "suspended" && row.latestReasonCode === "appeal_pending";
    }

    if (lifecycleState !== input.state) {
      return false;
    }
  }

  return true;
};

const buildReportingDateSeries = (from: string, to: string): string[] => {
  if (from > to) {
    throw new Error("Reporting trend range must start on or before the end date");
  }

  const bucketKeys: string[] = [];
  const current = new Date(`${from}T00:00:00.000Z`);
  const end = new Date(`${to}T00:00:00.000Z`);

  while (current.getTime() <= end.getTime()) {
    bucketKeys.push(current.toISOString().slice(0, 10));
    current.setUTCDate(current.getUTCDate() + 1);
  }

  return bucketKeys;
};

const resolveTenantReportingTrendRange = (
  rows: readonly TenantReportingEngagementRow[],
  input: Pick<TenantReportingEngagementFilters, "from" | "to">,
): { from: string; to: string } | null => {
  const explicitFrom = input.from?.trim();
  const explicitTo = input.to?.trim();
  const derivedKeys = rows.flatMap((row) => {
    const keys = [dateKeyFromTimestamp(row.issuedAt)];

    if (row.occurredAt !== null) {
      keys.push(dateKeyFromTimestamp(row.occurredAt));
    }

    return keys;
  });

  if (derivedKeys.length === 0 && explicitFrom === undefined && explicitTo === undefined) {
    return null;
  }

  const sortedKeys = [...derivedKeys].sort((left, right) => left.localeCompare(right));

  return {
    from:
      explicitFrom === undefined
        ? (sortedKeys[0] ?? normalizeReportingDateKey(explicitTo!, "start"))
        : normalizeReportingDateKey(explicitFrom, "start"),
    to:
      explicitTo === undefined
        ? (sortedKeys.at(-1) ?? normalizeReportingDateKey(explicitFrom!, "end"))
        : normalizeReportingDateKey(explicitTo, "end"),
  };
};

const applyTenantReportingEngagementEvent = (
  aggregate: TenantReportingEngagementAggregate,
  assertionId: string,
  eventType: AssertionEngagementEventType,
): void => {
  incrementTenantReportingEngagementCount(aggregate.counts, eventType);

  if (eventType === "share_click") {
    aggregate.shareEngagedAssertionIds.add(assertionId);
  }

  if (eventType === "learner_claim" || eventType === "wallet_accept") {
    aggregate.claimEngagedAssertionIds.add(assertionId);
  }
};

const finalizeTenantReportingEngagementCounts = (
  aggregate: TenantReportingEngagementAggregate,
): TenantReportingEngagementCounts => {
  const issuedCount = aggregate.issuedAssertionIds.size;
  const counts = tenantReportingEngagementCountsZero();

  counts.issuedCount = issuedCount;
  counts.publicBadgeViewCount = aggregate.counts.publicBadgeViewCount;
  counts.verificationViewCount = aggregate.counts.verificationViewCount;
  counts.shareClickCount = aggregate.counts.shareClickCount;
  counts.learnerClaimCount = aggregate.counts.learnerClaimCount;
  counts.walletAcceptCount = aggregate.counts.walletAcceptCount;
  counts.shareRate = issuedCount === 0 ? 0 : aggregate.shareEngagedAssertionIds.size / issuedCount;
  counts.claimRate = issuedCount === 0 ? 0 : aggregate.claimEngagedAssertionIds.size / issuedCount;

  return counts;
};

const summarizeTenantReportingEngagementCounts = (
  rows: readonly TenantReportingEngagementRow[],
  input: TenantReportingEngagementFilters,
): TenantReportingEngagementCounts => {
  const aggregate = createTenantReportingEngagementAggregate();

  for (const row of rows) {
    if (!matchesTenantReportingEngagementFilters(row, input)) {
      continue;
    }

    if (!isTimestampWithinReportingRange(row.issuedAt, input.from, input.to)) {
      continue;
    }

    aggregate.issuedAssertionIds.add(row.assertionId);

    if (
      row.eventType !== null &&
      row.occurredAt !== null &&
      isTimestampWithinReportingRange(row.occurredAt, input.from, input.to)
    ) {
      applyTenantReportingEngagementEvent(aggregate, row.assertionId, row.eventType);
    }
  }

  return finalizeTenantReportingEngagementCounts(aggregate);
};

export const summarizeTenantReportingTrendRows = (
  rows: readonly TenantReportingEngagementRow[],
  input: TenantReportingEngagementFilters & { bucket: TenantReportingTrendBucket },
): TenantReportingTrendBucketRecord[] => {
  if (input.bucket !== "day") {
    throw new Error("Unsupported reporting trend bucket");
  }

  const filteredRows = rows.filter((row) => matchesTenantReportingEngagementFilters(row, input));
  const range = resolveTenantReportingTrendRange(filteredRows, input);

  if (range === null) {
    return [];
  }

  const bucketMap = new Map<
    string,
    TenantReportingTrendBucketRecord & { issuedAssertionIds: Set<string> }
  >();

  for (const bucketStart of buildReportingDateSeries(range.from, range.to)) {
    bucketMap.set(bucketStart, {
      ...tenantReportingTrendBucketZero(bucketStart),
      issuedAssertionIds: new Set<string>(),
    });
  }

  for (const row of filteredRows) {
    if (isTimestampWithinReportingRange(row.issuedAt, range.from, range.to)) {
      const issueBucket = bucketMap.get(dateKeyFromTimestamp(row.issuedAt));
      issueBucket?.issuedAssertionIds.add(row.assertionId);
    }

    if (
      row.eventType !== null &&
      row.occurredAt !== null &&
      isTimestampWithinReportingRange(row.occurredAt, range.from, range.to)
    ) {
      const eventBucket = bucketMap.get(dateKeyFromTimestamp(row.occurredAt));

      if (eventBucket !== undefined) {
        incrementTenantReportingEngagementCount(eventBucket, row.eventType);
      }
    }
  }

  return Array.from(bucketMap.values()).map((bucket) => {
    return {
      bucketStart: bucket.bucketStart,
      issuedCount: bucket.issuedAssertionIds.size,
      publicBadgeViewCount: bucket.publicBadgeViewCount,
      verificationViewCount: bucket.verificationViewCount,
      shareClickCount: bucket.shareClickCount,
      learnerClaimCount: bucket.learnerClaimCount,
      walletAcceptCount: bucket.walletAcceptCount,
    };
  });
};

export const summarizeTenantReportingComparisonRows = (
  rows: readonly TenantReportingEngagementRow[],
  input: TenantReportingEngagementFilters & {
    groupBy: TenantReportingComparisonGroupBy;
  },
): TenantReportingComparisonRowRecord[] => {
  const groups = new Map<
    string,
    {
      row: TenantReportingComparisonRowRecord;
      aggregate: TenantReportingEngagementAggregate;
    }
  >();

  for (const row of rows) {
    if (!matchesTenantReportingEngagementFilters(row, input)) {
      continue;
    }

    if (!isTimestampWithinReportingRange(row.issuedAt, input.from, input.to)) {
      continue;
    }

    const groupId = input.groupBy === "badgeTemplate" ? row.badgeTemplateId : row.orgUnitId;
    const group =
      groups.get(groupId) ??
      (() => {
        const created = {
          row: tenantReportingComparisonRowZero(input.groupBy, groupId),
          aggregate: createTenantReportingEngagementAggregate(),
        };
        groups.set(groupId, created);
        return created;
      })();

    group.aggregate.issuedAssertionIds.add(row.assertionId);

    if (
      row.eventType !== null &&
      row.occurredAt !== null &&
      isTimestampWithinReportingRange(row.occurredAt, input.from, input.to)
    ) {
      applyTenantReportingEngagementEvent(group.aggregate, row.assertionId, row.eventType);
    }
  }

  return Array.from(groups.values())
    .map((group) => {
      const counts = finalizeTenantReportingEngagementCounts(group.aggregate);
      return {
        ...group.row,
        issuedCount: counts.issuedCount,
        publicBadgeViewCount: counts.publicBadgeViewCount,
        verificationViewCount: counts.verificationViewCount,
        shareClickCount: counts.shareClickCount,
        learnerClaimCount: counts.learnerClaimCount,
        walletAcceptCount: counts.walletAcceptCount,
        claimRate: counts.claimRate,
        shareRate: counts.shareRate,
      };
    })
    .sort((left, right) => {
      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.groupId.localeCompare(right.groupId);
    });
};

const getReportingHierarchyOrgUnitOrThrow = (
  orgUnitsById: ReadonlyMap<string, TenantReportingHierarchyOrgUnitRecord>,
  orgUnitId: string,
): TenantReportingHierarchyOrgUnitRecord => {
  const orgUnit = orgUnitsById.get(orgUnitId);

  if (orgUnit === undefined) {
    throw new Error(`Org unit ${orgUnitId} is missing from the reporting hierarchy`);
  }

  return orgUnit;
};

const listReportingHierarchyLineage = (
  orgUnitsById: ReadonlyMap<string, TenantReportingHierarchyOrgUnitRecord>,
  orgUnitId: string,
): TenantReportingHierarchyOrgUnitRecord[] => {
  const lineage: TenantReportingHierarchyOrgUnitRecord[] = [];
  const visited = new Set<string>();
  let currentOrgUnitId: string | null = orgUnitId;

  while (currentOrgUnitId !== null) {
    if (visited.has(currentOrgUnitId)) {
      throw new Error(`Detected an org-unit cycle while resolving hierarchy for ${orgUnitId}`);
    }

    visited.add(currentOrgUnitId);

    const orgUnit = getReportingHierarchyOrgUnitOrThrow(orgUnitsById, currentOrgUnitId);
    lineage.push(orgUnit);
    currentOrgUnitId = orgUnit.parentOrgUnitId;
  }

  return lineage;
};

const isReportingHierarchyLineageWithinRoot = (
  lineage: readonly TenantReportingHierarchyOrgUnitRecord[],
  rootOrgUnitId: string,
): boolean => {
  return lineage.some((orgUnit) => orgUnit.id === rootOrgUnitId);
};

export const summarizeTenantReportingHierarchyRows = (input: {
  rows: readonly TenantReportingHierarchySourceRow[];
  orgUnits: readonly TenantReportingHierarchyOrgUnitRecord[];
  query: TenantReportingHierarchyQuery;
  scopedRootOrgUnitIds?: readonly string[] | undefined;
}): TenantReportingHierarchyGroupRecord[] => {
  const orgUnitsById = new Map(
    input.orgUnits.map((orgUnit) => {
      return [orgUnit.id, orgUnit] as const;
    }),
  );
  const focusOrgUnit =
    input.query.focusOrgUnitId === undefined
      ? null
      : getReportingHierarchyOrgUnitOrThrow(orgUnitsById, input.query.focusOrgUnitId);

  if (
    focusOrgUnit !== null &&
    ORG_UNIT_HIERARCHY_DEPTH[focusOrgUnit.unitType] > ORG_UNIT_HIERARCHY_DEPTH[input.query.level]
  ) {
    throw new Error("focusOrgUnitId must be at or above the requested hierarchy level");
  }

  const scopedRootOrgUnitIds = Array.from(new Set(input.scopedRootOrgUnitIds ?? []));
  for (const scopedRootOrgUnitId of scopedRootOrgUnitIds) {
    getReportingHierarchyOrgUnitOrThrow(orgUnitsById, scopedRootOrgUnitId);
  }

  const groups = new Map<
    string,
    {
      orgUnit: TenantReportingHierarchyOrgUnitRecord;
      aggregate: TenantReportingEngagementAggregate;
    }
  >();

  for (const row of input.rows) {
    if (
      input.query.badgeTemplateId !== undefined &&
      row.badgeTemplateId !== input.query.badgeTemplateId
    ) {
      continue;
    }

    if (input.query.orgUnitId !== undefined && row.orgUnitId !== input.query.orgUnitId) {
      continue;
    }

    if (!isTimestampWithinReportingRange(row.issuedAt, input.query.from, input.query.to)) {
      continue;
    }

    const lineage = listReportingHierarchyLineage(orgUnitsById, row.orgUnitId);

    if (focusOrgUnit !== null && !isReportingHierarchyLineageWithinRoot(lineage, focusOrgUnit.id)) {
      continue;
    }

    if (
      scopedRootOrgUnitIds.length > 0 &&
      !scopedRootOrgUnitIds.some((scopedRootOrgUnitId) => {
        return isReportingHierarchyLineageWithinRoot(lineage, scopedRootOrgUnitId);
      })
    ) {
      continue;
    }

    const targetOrgUnit = lineage.find((orgUnit) => orgUnit.unitType === input.query.level);

    if (targetOrgUnit === undefined) {
      continue;
    }

    const group =
      groups.get(targetOrgUnit.id) ??
      (() => {
        const created = {
          orgUnit: targetOrgUnit,
          aggregate: createTenantReportingEngagementAggregate(),
        };
        groups.set(targetOrgUnit.id, created);
        return created;
      })();

    group.aggregate.issuedAssertionIds.add(row.assertionId);

    if (
      row.eventType !== null &&
      row.occurredAt !== null &&
      isTimestampWithinReportingRange(row.occurredAt, input.query.from, input.query.to)
    ) {
      applyTenantReportingEngagementEvent(group.aggregate, row.assertionId, row.eventType);
    }
  }

  return Array.from(groups.values())
    .map((group) => {
      const counts = finalizeTenantReportingEngagementCounts(group.aggregate);
      return {
        level: input.query.level,
        orgUnitId: group.orgUnit.id,
        displayName: group.orgUnit.displayName,
        parentOrgUnitId: group.orgUnit.parentOrgUnitId,
        issuedCount: counts.issuedCount,
        publicBadgeViewCount: counts.publicBadgeViewCount,
        verificationViewCount: counts.verificationViewCount,
        shareClickCount: counts.shareClickCount,
        learnerClaimCount: counts.learnerClaimCount,
        walletAcceptCount: counts.walletAcceptCount,
        claimRate: counts.claimRate,
        shareRate: counts.shareRate,
      };
    })
    .sort((left, right) => {
      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    });
};

export const summarizeTenantExecutiveRollup = (input: {
  rows: readonly TenantReportingHierarchySourceRow[];
  orgUnits: readonly TenantReportingHierarchyOrgUnitRecord[];
  query: TenantExecutiveRollupQuery;
  scopedRootOrgUnitIds?: readonly string[] | undefined;
}): TenantExecutiveRollupRecord => {
  const orgUnitsById = new Map(
    input.orgUnits.map((orgUnit) => {
      return [orgUnit.id, orgUnit] as const;
    }),
  );
  const focusOrgUnit = getReportingHierarchyOrgUnitOrThrow(
    orgUnitsById,
    input.query.focusOrgUnitId,
  );
  const focusLineageOrgUnitIds = listReportingHierarchyLineage(
    orgUnitsById,
    input.query.focusOrgUnitId,
  )
    .map((orgUnit) => orgUnit.id)
    .reverse();

  return {
    focusOrgUnitId: focusOrgUnit.id,
    focusDisplayName: focusOrgUnit.displayName,
    focusParentOrgUnitId: focusOrgUnit.parentOrgUnitId,
    focusUnitType: focusOrgUnit.unitType,
    comparisonLevel: input.query.comparisonLevel,
    focusLineageOrgUnitIds,
    filters: {
      from: input.query.from ?? null,
      to: input.query.to ?? null,
      badgeTemplateId: input.query.badgeTemplateId ?? null,
      orgUnitId: input.query.orgUnitId ?? null,
      state: input.query.state ?? null,
    },
    rows: summarizeTenantReportingHierarchyRows({
      rows: input.rows,
      orgUnits: input.orgUnits,
      query: {
        from: input.query.from,
        to: input.query.to,
        badgeTemplateId: input.query.badgeTemplateId,
        orgUnitId: input.query.orgUnitId,
        state: input.query.state,
        focusOrgUnitId: input.query.focusOrgUnitId,
        level: input.query.comparisonLevel,
      },
      scopedRootOrgUnitIds: input.scopedRootOrgUnitIds,
    }),
  };
};

const resolveAssertionLifecycleProjection = (input: {
  revokedAt: string | null;
  latestToState: AssertionLifecycleState | null;
  latestReasonCode: AssertionLifecycleReasonCode | null;
  latestReason: string | null;
  latestTransitionedAt: string | null;
}): Pick<
  TenantAssertionSummaryRecord,
  "state" | "source" | "reasonCode" | "reason" | "transitionedAt"
> => {
  let state: AssertionLifecycleState = "active";
  let source: ResolveAssertionLifecycleStateResult["source"] = "default_active";
  let reasonCode: AssertionLifecycleReasonCode | null = null;
  let reason: string | null = null;
  let transitionedAt: string | null = null;

  if (input.revokedAt !== null && input.latestToState === "revoked") {
    state = "revoked";
    source = "lifecycle_event";
    reasonCode = input.latestReasonCode;
    reason = input.latestReason ?? "credential has been revoked by issuer";
    transitionedAt = input.latestTransitionedAt ?? input.revokedAt;
  } else if (input.revokedAt !== null) {
    state = "revoked";
    source = "assertion_revocation";
    reason = "credential has been revoked by issuer";
    transitionedAt = input.revokedAt;
  } else if (input.latestToState !== null) {
    state = input.latestToState;
    source = "lifecycle_event";
    reasonCode = input.latestReasonCode;
    reason = input.latestReason;
    transitionedAt = input.latestTransitionedAt;
  }

  return {
    state,
    source,
    reasonCode,
    reason,
    transitionedAt,
  };
};

const buildCurrentOrgUnitLineageNames = (
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
  orgUnitId: string,
): Pick<
  TenantAssertionLedgerExportRowRecord,
  "currentInstitutionName" | "currentCollegeName" | "currentDepartmentName" | "currentProgramName"
> => {
  const lineageNames: Pick<
    TenantAssertionLedgerExportRowRecord,
    "currentInstitutionName" | "currentCollegeName" | "currentDepartmentName" | "currentProgramName"
  > = {
    currentInstitutionName: null,
    currentCollegeName: null,
    currentDepartmentName: null,
    currentProgramName: null,
  };

  const visited = new Set<string>();
  let currentOrgUnitId: string | null = orgUnitId;

  while (currentOrgUnitId !== null) {
    if (visited.has(currentOrgUnitId)) {
      throw new Error(`Detected an org-unit cycle while resolving export lineage for ${orgUnitId}`);
    }

    visited.add(currentOrgUnitId);
    const orgUnit = orgUnitsById.get(currentOrgUnitId);

    if (orgUnit === undefined) {
      return lineageNames;
    }

    if (orgUnit.unitType === "institution") {
      lineageNames.currentInstitutionName = orgUnit.displayName;
    } else if (orgUnit.unitType === "college") {
      lineageNames.currentCollegeName = orgUnit.displayName;
    } else if (orgUnit.unitType === "department") {
      lineageNames.currentDepartmentName = orgUnit.displayName;
    } else if (orgUnit.unitType === "program") {
      lineageNames.currentProgramName = orgUnit.displayName;
    }

    currentOrgUnitId = orgUnit.parentOrgUnitId;
  }

  return lineageNames;
};

const mapAssertionRow = (row: AssertionRow): AssertionRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    publicId: row.publicId,
    learnerProfileId: row.learnerProfileId,
    badgeTemplateId: row.badgeTemplateId,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    vcR2Key: row.vcR2Key,
    statusListIndex: row.statusListIndex,
    idempotencyKey: row.idempotencyKey,
    issuedAt: row.issuedAt,
    issuedByUserId: row.issuedByUserId,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapAssertionReportingAttributionRow = (
  row: AssertionReportingAttributionRow,
): AssertionReportingAttributionRecord => {
  return {
    assertionId: row.assertionId,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    orgUnitId: row.orgUnitId,
    attributionSource: row.attributionSource,
    attributedAt: row.attributedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapAssertionEngagementEventRow = (
  row: AssertionEngagementEventRow,
): AssertionEngagementEventRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    assertionId: row.assertionId,
    eventType: row.eventType,
    actorType: row.actorType,
    channel: row.channel,
    occurredAt: row.occurredAt,
    createdAt: row.createdAt,
  };
};

const mapAssertionLifecycleEventRow = (
  row: AssertionLifecycleEventRow,
): AssertionLifecycleEventRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    assertionId: row.assertionId,
    fromState: row.fromState,
    toState: row.toState,
    reasonCode: row.reasonCode,
    reason: row.reason,
    transitionSource: row.transitionSource,
    actorUserId: row.actorUserId,
    transitionedAt: row.transitionedAt,
    createdAt: row.createdAt,
  };
};

const mapLearnerBadgeSummaryRow = (row: LearnerBadgeSummaryRow): LearnerBadgeSummaryRecord => {
  return {
    assertionId: row.assertionId,
    assertionPublicId: row.assertionPublicId,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: row.badgeTitle,
    badgeDescription: row.badgeDescription,
    issuedAt: row.issuedAt,
    revokedAt: row.revokedAt,
  };
};

const mapLearnerRecordAssertionExportRow = (
  row: LearnerRecordAssertionExportRow,
): LearnerRecordAssertionExportRecord => {
  return {
    assertionId: row.assertionId,
    assertionPublicId: row.assertionPublicId,
    tenantId: row.tenantId,
    learnerProfileId: row.learnerProfileId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: row.badgeTitle,
    badgeDescription: row.badgeDescription,
    badgeCriteriaUri: row.badgeCriteriaUri,
    badgeImageUri: row.badgeImageUri,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    vcR2Key: row.vcR2Key,
    statusListIndex: row.statusListIndex,
    idempotencyKey: row.idempotencyKey,
    issuedAt: row.issuedAt,
    issuedByUserId: row.issuedByUserId,
    revokedAt: row.revokedAt,
    issuerName: row.issuerName,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapTenantAssertionSummaryRow = (
  row: TenantAssertionSummaryRow,
): TenantAssertionSummaryRecord => {
  const lifecycle = resolveAssertionLifecycleProjection({
    revokedAt: row.revokedAt,
    latestToState: row.latestToState,
    latestReasonCode: row.latestReasonCode,
    latestReason: row.latestReason,
    latestTransitionedAt: row.latestTransitionedAt,
  });

  return {
    assertionId: row.assertionId,
    tenantId: row.tenantId,
    publicId: row.publicId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: row.badgeTitle,
    badgeImageUri: row.badgeImageUri,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    issuedAt: row.issuedAt,
    issuedByUserId: row.issuedByUserId,
    revokedAt: row.revokedAt,
    ...lifecycle,
  };
};

const mapTenantAssertionLedgerExportRow = (
  row: TenantAssertionLedgerExportRow,
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
): TenantAssertionLedgerExportRowRecord => {
  const lifecycle = resolveAssertionLifecycleProjection({
    revokedAt: row.revokedAt,
    latestToState: row.latestToState,
    latestReasonCode: row.latestReasonCode,
    latestReason: row.latestReason,
    latestTransitionedAt: row.latestTransitionedAt,
  });

  return {
    assertionId: row.assertionId,
    tenantId: row.tenantId,
    publicId: row.publicId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: row.badgeTitle,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    issuedAt: row.issuedAt,
    issuedByUserId: row.issuedByUserId,
    revokedAt: row.revokedAt,
    orgUnitId: row.orgUnitId,
    orgUnitDisplayName: row.orgUnitDisplayName,
    attributionSource: row.attributionSource,
    ...lifecycle,
    ...buildCurrentOrgUnitLineageNames(orgUnitsById, row.orgUnitId),
  };
};

const mapPublicBadgeWallEntryRow = (row: PublicBadgeWallEntryRow): PublicBadgeWallEntryRecord => {
  return {
    assertionId: row.assertionId,
    assertionPublicId: row.assertionPublicId,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: row.badgeTitle,
    badgeDescription: row.badgeDescription,
    badgeImageUri: row.badgeImageUri,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    issuedAt: row.issuedAt,
    revokedAt: row.revokedAt,
  };
};

export const findAssertionById = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<AssertionRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        public_id AS publicId,
        learner_profile_id AS learnerProfileId,
        badge_template_id AS badgeTemplateId,
        recipient_identity AS recipientIdentity,
        recipient_identity_type AS recipientIdentityType,
        vc_r2_key AS vcR2Key,
        status_list_index AS statusListIndex,
        idempotency_key AS idempotencyKey,
        issued_at AS issuedAt,
        issued_by_user_id AS issuedByUserId,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM assertions
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, assertionId)
    .first<AssertionRow>();

  if (row === null) {
    return null;
  }

  return mapAssertionRow(row);
};

export const findAssertionByIdempotencyKey = async (
  db: SqlDatabase,
  tenantId: string,
  idempotencyKey: string,
): Promise<AssertionRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        public_id AS publicId,
        learner_profile_id AS learnerProfileId,
        badge_template_id AS badgeTemplateId,
        recipient_identity AS recipientIdentity,
        recipient_identity_type AS recipientIdentityType,
        vc_r2_key AS vcR2Key,
        status_list_index AS statusListIndex,
        idempotency_key AS idempotencyKey,
        issued_at AS issuedAt,
        issued_by_user_id AS issuedByUserId,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM assertions
      WHERE tenant_id = ?
        AND idempotency_key = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, idempotencyKey)
    .first<AssertionRow>();

  if (row === null) {
    return null;
  }

  return mapAssertionRow(row);
};

export const listAssertionsByIdempotencyKeys = async (
  db: SqlDatabase,
  input: ListAssertionsByIdempotencyKeysInput,
): Promise<AssertionRecord[]> => {
  const idempotencyKeys = uniqueNonEmptyStrings(input.idempotencyKeys);

  if (idempotencyKeys.length === 0) {
    return [];
  }

  const assertions: AssertionRecord[] = [];

  for (const keyChunk of chunkValues(idempotencyKeys, 400)) {
    const keyPlaceholders = keyChunk.map(() => "?").join(", ");
    const result = await db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          public_id AS publicId,
          learner_profile_id AS learnerProfileId,
          badge_template_id AS badgeTemplateId,
          recipient_identity AS recipientIdentity,
          recipient_identity_type AS recipientIdentityType,
          vc_r2_key AS vcR2Key,
          status_list_index AS statusListIndex,
          idempotency_key AS idempotencyKey,
          issued_at AS issuedAt,
          issued_by_user_id AS issuedByUserId,
          revoked_at AS revokedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM assertions
        WHERE tenant_id = ?
          AND idempotency_key IN (${keyPlaceholders})
      `,
      )
      .bind(input.tenantId, ...keyChunk)
      .all<AssertionRow>();

    assertions.push(...result.results.map((row) => mapAssertionRow(row)));
  }

  return assertions;
};

export const findAssertionByPublicId = async (
  db: SqlDatabase,
  publicId: string,
): Promise<AssertionRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        public_id AS publicId,
        learner_profile_id AS learnerProfileId,
        badge_template_id AS badgeTemplateId,
        recipient_identity AS recipientIdentity,
        recipient_identity_type AS recipientIdentityType,
        vc_r2_key AS vcR2Key,
        status_list_index AS statusListIndex,
        idempotency_key AS idempotencyKey,
        issued_at AS issuedAt,
        issued_by_user_id AS issuedByUserId,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM assertions
      WHERE public_id = ?
      LIMIT 1
    `,
    )
    .bind(publicId)
    .first<AssertionRow>();

  if (row === null) {
    return null;
  }

  return mapAssertionRow(row);
};

const findLatestAssertionLifecycleEvent = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<AssertionLifecycleEventRecord | null> => {
  const latestStatement = (): Promise<AssertionLifecycleEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          from_state AS fromState,
          to_state AS toState,
          reason_code AS reasonCode,
          reason,
          transition_source AS transitionSource,
          actor_user_id AS actorUserId,
          transitioned_at AS transitionedAt,
          created_at AS createdAt
        FROM assertion_lifecycle_events
        WHERE tenant_id = ?
          AND assertion_id = ?
        ORDER BY transitioned_at DESC, created_at DESC, id DESC
        LIMIT 1
      `,
      )
      .bind(tenantId, assertionId)
      .first<AssertionLifecycleEventRow>();

  const row = await latestStatement();

  return row === null ? null : mapAssertionLifecycleEventRow(row);
};

const findAssertionLifecycleEventById = async (
  db: SqlDatabase,
  id: string,
): Promise<AssertionLifecycleEventRecord | null> => {
  const lookupStatement = (): Promise<AssertionLifecycleEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          from_state AS fromState,
          to_state AS toState,
          reason_code AS reasonCode,
          reason,
          transition_source AS transitionSource,
          actor_user_id AS actorUserId,
          transitioned_at AS transitionedAt,
          created_at AS createdAt
        FROM assertion_lifecycle_events
        WHERE id = ?
        LIMIT 1
      `,
      )
      .bind(id)
      .first<AssertionLifecycleEventRow>();

  const row = await lookupStatement();

  return row === null ? null : mapAssertionLifecycleEventRow(row);
};

export const listAssertionLifecycleEvents = async (
  db: SqlDatabase,
  input: ListAssertionLifecycleEventsInput,
): Promise<AssertionLifecycleEventRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 50, 200));
  const listStatement = (): Promise<SqlQueryResult<AssertionLifecycleEventRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          from_state AS fromState,
          to_state AS toState,
          reason_code AS reasonCode,
          reason,
          transition_source AS transitionSource,
          actor_user_id AS actorUserId,
          transitioned_at AS transitionedAt,
          created_at AS createdAt
        FROM assertion_lifecycle_events
        WHERE tenant_id = ?
          AND assertion_id = ?
        ORDER BY transitioned_at DESC, created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.assertionId, queryLimit)
      .all<AssertionLifecycleEventRow>();

  const result = await listStatement();

  return result.results.map((row) => mapAssertionLifecycleEventRow(row));
};

export const resolveAssertionLifecycleState = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<ResolveAssertionLifecycleStateResult | null> => {
  const assertion = await findAssertionById(db, tenantId, assertionId);

  if (assertion === null) {
    return null;
  }

  const latestEvent = await findLatestAssertionLifecycleEvent(db, tenantId, assertionId);
  return assertionLifecycleStateFromRecords({
    assertion,
    latestEvent,
  });
};

export const listAssertionLifecycleStatesByAssertionIds = async (
  db: SqlDatabase,
  input: ListAssertionLifecycleStatesByAssertionIdsInput,
): Promise<AssertionLifecycleStateByAssertionIdRecord[]> => {
  const assertionIds = uniqueNonEmptyStrings(input.assertionIds);

  if (assertionIds.length === 0) {
    return [];
  }

  const states: AssertionLifecycleStateByAssertionIdRecord[] = [];

  for (const assertionIdChunk of chunkValues(assertionIds, 400)) {
    const assertionIdPlaceholders = assertionIdChunk.map(() => "?").join(", ");
    const result = await db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode,
          lifecycle.reason AS latestReason,
          lifecycle.transitioned_at AS latestTransitionedAt
        FROM assertions
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        WHERE assertions.tenant_id = ?
          AND assertions.id IN (${assertionIdPlaceholders})
      `,
      )
      .bind(input.tenantId, ...assertionIdChunk)
      .all<{
        assertionId: string;
        revokedAt: string | null;
        latestToState: AssertionLifecycleState | null;
        latestReasonCode: AssertionLifecycleReasonCode | null;
        latestReason: string | null;
        latestTransitionedAt: string | null;
      }>();

    states.push(
      ...result.results.map((row) => {
        const lifecycle = resolveAssertionLifecycleProjection({
          revokedAt: row.revokedAt,
          latestToState: row.latestToState,
          latestReasonCode: row.latestReasonCode,
          latestReason: row.latestReason,
          latestTransitionedAt: row.latestTransitionedAt,
        });

        return {
          assertionId: row.assertionId,
          ...lifecycle,
          revokedAt: row.revokedAt,
        };
      }),
    );
  }

  return states;
};

export const recordAssertionLifecycleTransition = async (
  db: SqlDatabase,
  input: RecordAssertionLifecycleTransitionInput,
): Promise<RecordAssertionLifecycleTransitionResult> => {
  const transitionedAtMs = Date.parse(input.transitionedAt);

  if (!Number.isFinite(transitionedAtMs)) {
    throw new Error("transitionedAt must be a valid ISO timestamp");
  }

  if (!ASSERTION_LIFECYCLE_REASON_CODES.has(input.reasonCode)) {
    throw new Error(`Unsupported assertion lifecycle reason code: ${input.reasonCode}`);
  }

  if (input.transitionSource === "manual" && input.actorUserId === undefined) {
    throw new Error("Manual lifecycle transitions require actorUserId");
  }

  if (input.transitionSource === "automation" && input.actorUserId !== undefined) {
    throw new Error("Automated lifecycle transitions must not set actorUserId");
  }

  const assertion = await findAssertionById(db, input.tenantId, input.assertionId);

  if (assertion === null) {
    throw new Error(`Assertion ${input.assertionId} not found for tenant ${input.tenantId}`);
  }

  const latestEvent = await findLatestAssertionLifecycleEvent(
    db,
    input.tenantId,
    input.assertionId,
  );
  const current = assertionLifecycleStateFromRecords({
    assertion,
    latestEvent,
  });

  if (current.state === input.toState) {
    return {
      status: "already_in_state",
      fromState: current.state,
      toState: input.toState,
      currentState: current.state,
      event: null,
      message: `assertion is already in ${current.state} state`,
    };
  }

  const allowedTransitions = ASSERTION_LIFECYCLE_ALLOWED_TRANSITIONS[current.state];

  if (!allowedTransitions.has(input.toState)) {
    return {
      status: "invalid_transition",
      fromState: current.state,
      toState: input.toState,
      currentState: current.state,
      event: null,
      message: `transition from ${current.state} to ${input.toState} is not allowed`,
    };
  }

  const normalizedReason = input.reason?.trim();
  const reason =
    normalizedReason === undefined || normalizedReason.length === 0 ? null : normalizedReason;
  let effectiveTransitionedAt = input.transitionedAt;

  if (input.toState === "revoked") {
    const revocationResult = await recordAssertionRevocation(db, {
      tenantId: input.tenantId,
      assertionId: input.assertionId,
      revocationId: createPrefixedId("rev"),
      reason: reason ?? input.reasonCode,
      idempotencyKey: createPrefixedId("idem"),
      ...(input.actorUserId === undefined ? {} : { revokedByUserId: input.actorUserId }),
      revokedAt: input.transitionedAt,
    });

    if (revocationResult.status === "already_revoked") {
      return {
        status: "already_in_state",
        fromState: current.state,
        toState: input.toState,
        currentState: "revoked",
        event: null,
        message: "assertion is already in revoked state",
      };
    }

    effectiveTransitionedAt = revocationResult.revokedAt;
  }

  const eventId = createPrefixedId("ale");
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO assertion_lifecycle_events (
          id,
          tenant_id,
          assertion_id,
          from_state,
          to_state,
          reason_code,
          reason,
          transition_source,
          actor_user_id,
          transitioned_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        eventId,
        input.tenantId,
        input.assertionId,
        current.state,
        input.toState,
        input.reasonCode,
        reason,
        input.transitionSource,
        input.actorUserId ?? null,
        effectiveTransitionedAt,
        effectiveTransitionedAt,
      )
      .run();

  await insertStatement();

  await db
    .prepare(
      `
      UPDATE assertions
      SET updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(effectiveTransitionedAt, input.tenantId, input.assertionId)
    .run();

  const event = await findAssertionLifecycleEventById(db, eventId);

  if (event === null) {
    throw new Error(`Unable to load assertion lifecycle event ${eventId} after insert`);
  }

  return {
    status: "transitioned",
    fromState: current.state,
    toState: input.toState,
    currentState: input.toState,
    event,
    message: null,
  };
};

export const listLearnerBadgeSummaries = async (
  db: SqlDatabase,
  input: ListLearnerBadgeSummariesInput,
): Promise<LearnerBadgeSummaryRecord[]> => {
  const user = await findUserById(db, input.userId);

  if (user === null) {
    return [];
  }

  const learnerProfile = await findLearnerProfileByIdentity(db, {
    tenantId: input.tenantId,
    identityType: "email",
    identityValue: user.email,
  });

  if (learnerProfile === null) {
    const legacyResult = await db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.public_id AS assertionPublicId,
          assertions.tenant_id AS tenantId,
          assertions.badge_template_id AS badgeTemplateId,
          badge_templates.title AS badgeTitle,
          badge_templates.description AS badgeDescription,
          assertions.issued_at AS issuedAt,
          assertions.revoked_at AS revokedAt
        FROM assertions
        INNER JOIN badge_templates
          ON badge_templates.tenant_id = assertions.tenant_id
          AND badge_templates.id = assertions.badge_template_id
        WHERE assertions.tenant_id = ?
          AND assertions.recipient_identity_type = 'email'
          AND LOWER(assertions.recipient_identity) = ?
        ORDER BY assertions.issued_at DESC
      `,
      )
      .bind(input.tenantId, normalizeEmail(user.email))
      .all<LearnerBadgeSummaryRow>();

    return legacyResult.results.map((row) => mapLearnerBadgeSummaryRow(row));
  }

  const identities = await listLearnerIdentitiesByProfile(db, input.tenantId, learnerProfile.id);
  const emailAliases = new Set<string>();
  emailAliases.add(normalizeEmail(user.email));

  for (const identity of identities) {
    if (identity.identityType === "email") {
      emailAliases.add(normalizeEmail(identity.identityValue));
    }
  }

  const aliasList = Array.from(emailAliases);
  const emailPlaceholders = aliasList.map(() => "?").join(", ");
  const params: unknown[] = [input.tenantId, learnerProfile.id, ...aliasList];
  const result = await db
    .prepare(
      `
      SELECT
        assertions.id AS assertionId,
        assertions.public_id AS assertionPublicId,
        assertions.tenant_id AS tenantId,
        assertions.badge_template_id AS badgeTemplateId,
        badge_templates.title AS badgeTitle,
        badge_templates.description AS badgeDescription,
        assertions.issued_at AS issuedAt,
        assertions.revoked_at AS revokedAt
      FROM assertions
      INNER JOIN badge_templates
        ON badge_templates.tenant_id = assertions.tenant_id
        AND badge_templates.id = assertions.badge_template_id
      WHERE assertions.tenant_id = ?
        AND (
          assertions.learner_profile_id = ?
          OR (
            assertions.recipient_identity_type = 'email'
            AND LOWER(assertions.recipient_identity) IN (${emailPlaceholders})
          )
        )
      ORDER BY assertions.issued_at DESC
    `,
    )
    .bind(...params)
    .all<LearnerBadgeSummaryRow>();

  return result.results.map((row) => mapLearnerBadgeSummaryRow(row));
};

export const listLearnerRecordAssertionExports = async (
  db: SqlDatabase,
  input: ListLearnerRecordAssertionExportsInput,
): Promise<LearnerRecordAssertionExportRecord[]> => {
  const identities = await listLearnerIdentitiesByProfile(
    db,
    input.tenantId,
    input.learnerProfileId,
  );
  const emailAliases = Array.from(
    new Set(
      identities
        .filter((identity) => identity.identityType === "email")
        .map((identity) => normalizeEmail(identity.identityValue)),
    ),
  );
  const emailAliasClause =
    emailAliases.length === 0
      ? ""
      : `
          OR (
            assertions.recipient_identity_type = 'email'
            AND LOWER(assertions.recipient_identity) IN (${emailAliases.map(() => "?").join(", ")})
          )
        `;
  const params: unknown[] = [input.tenantId, input.learnerProfileId, ...emailAliases];
  const result = await db
    .prepare(
      `
      SELECT
        assertions.id AS assertionId,
        assertions.public_id AS assertionPublicId,
        assertions.tenant_id AS tenantId,
        assertions.learner_profile_id AS learnerProfileId,
        assertions.badge_template_id AS badgeTemplateId,
        badge_templates.title AS badgeTitle,
        badge_templates.description AS badgeDescription,
        badge_templates.criteria_uri AS badgeCriteriaUri,
        badge_templates.image_uri AS badgeImageUri,
        assertions.recipient_identity AS recipientIdentity,
        assertions.recipient_identity_type AS recipientIdentityType,
        assertions.vc_r2_key AS vcR2Key,
        assertions.status_list_index AS statusListIndex,
        assertions.idempotency_key AS idempotencyKey,
        assertions.issued_at AS issuedAt,
        assertions.issued_by_user_id AS issuedByUserId,
        assertions.revoked_at AS revokedAt,
        tenants.display_name AS issuerName,
        assertions.created_at AS createdAt,
        assertions.updated_at AS updatedAt
      FROM assertions
      INNER JOIN badge_templates
        ON badge_templates.tenant_id = assertions.tenant_id
        AND badge_templates.id = assertions.badge_template_id
      INNER JOIN tenants
        ON tenants.id = assertions.tenant_id
      WHERE assertions.tenant_id = ?
        AND (
          assertions.learner_profile_id = ?
          ${emailAliasClause}
        )
      ORDER BY assertions.issued_at DESC, assertions.id DESC
    `,
    )
    .bind(...params)
    .all<LearnerRecordAssertionExportRow>();

  return result.results.map((row) => mapLearnerRecordAssertionExportRow(row));
};

export const listTenantAssertions = async (
  db: SqlDatabase,
  input: ListTenantAssertionsInput,
): Promise<TenantAssertionSummaryRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 100, 500));
  const whereClauses = ["assertions.tenant_id = ?"];
  const params: unknown[] = [input.tenantId];

  if (input.badgeTemplateId !== undefined) {
    whereClauses.push("assertions.badge_template_id = ?");
    params.push(input.badgeTemplateId);
  }

  if (input.recipientQuery !== undefined) {
    const normalizedQuery = `%${input.recipientQuery.trim().toLowerCase()}%`;
    whereClauses.push(
      `(
        LOWER(assertions.recipient_identity) LIKE ?
        OR LOWER(assertions.id) LIKE ?
        OR LOWER(COALESCE(assertions.public_id, '')) LIKE ?
      )`,
    );
    params.push(normalizedQuery, normalizedQuery, normalizedQuery);
  }

  if (input.state !== undefined) {
    whereClauses.push(
      `(
        CASE
          WHEN assertions.revoked_at IS NOT NULL THEN 'revoked'
          WHEN lifecycle.to_state IS NOT NULL THEN lifecycle.to_state
          ELSE 'active'
        END
      ) = ?`,
    );
    params.push(input.state);
  }

  const listStatement = (): Promise<SqlQueryResult<TenantAssertionSummaryRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.tenant_id AS tenantId,
          assertions.public_id AS publicId,
          assertions.badge_template_id AS badgeTemplateId,
          badge_templates.title AS badgeTitle,
          badge_templates.image_uri AS badgeImageUri,
          assertions.recipient_identity AS recipientIdentity,
          assertions.recipient_identity_type AS recipientIdentityType,
          assertions.issued_at AS issuedAt,
          assertions.issued_by_user_id AS issuedByUserId,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode,
          lifecycle.reason AS latestReason,
          lifecycle.transitioned_at AS latestTransitionedAt
        FROM assertions
        INNER JOIN badge_templates
          ON badge_templates.tenant_id = assertions.tenant_id
          AND badge_templates.id = assertions.badge_template_id
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at DESC, assertions.id DESC
        LIMIT ?
      `,
      )
      .bind(...params, queryLimit)
      .all<TenantAssertionSummaryRow>();

  const result = await listStatement();

  return result.results.map((row) => mapTenantAssertionSummaryRow(row));
};

export const listTenantAssertionLedgerExportRows = async (
  db: SqlDatabase,
  input: ListTenantAssertionLedgerExportRowsInput,
): Promise<TenantAssertionLedgerExportResult> => {
  await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);

  const whereClauses = ["assertions.tenant_id = ?"];
  const params: unknown[] = [input.tenantId];

  if (input.issuedFrom !== undefined) {
    whereClauses.push("assertions.issued_at >= ?");
    params.push(normalizeReportingDateBoundary(input.issuedFrom, "start"));
  }

  if (input.issuedTo !== undefined) {
    whereClauses.push("assertions.issued_at <= ?");
    params.push(normalizeReportingDateBoundary(input.issuedTo, "end"));
  }

  if (input.badgeTemplateId !== undefined) {
    whereClauses.push("assertions.badge_template_id = ?");
    params.push(input.badgeTemplateId);
  }

  if (input.orgUnitId !== undefined) {
    whereClauses.push("attribution.org_unit_id = ?");
    params.push(input.orgUnitId);
  }

  if (input.recipientQuery !== undefined) {
    const normalizedQuery = `%${input.recipientQuery.trim().toLowerCase()}%`;
    whereClauses.push(
      `(
        LOWER(assertions.recipient_identity) LIKE ?
        OR LOWER(assertions.id) LIKE ?
        OR LOWER(COALESCE(assertions.public_id, '')) LIKE ?
      )`,
    );
    params.push(normalizedQuery, normalizedQuery, normalizedQuery);
  }

  if (input.state !== undefined) {
    whereClauses.push(
      `(
        CASE
          WHEN assertions.revoked_at IS NOT NULL THEN 'revoked'
          WHEN lifecycle.to_state IS NOT NULL THEN lifecycle.to_state
          ELSE 'active'
        END
      ) = ?`,
    );
    params.push(input.state);
  }

  const rowLimit = SYNCHRONOUS_EXPORT_ROW_LIMIT;
  const listStatement = (): Promise<SqlQueryResult<TenantAssertionLedgerExportRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.tenant_id AS tenantId,
          assertions.public_id AS publicId,
          assertions.badge_template_id AS badgeTemplateId,
          badge_templates.title AS badgeTitle,
          assertions.recipient_identity AS recipientIdentity,
          assertions.recipient_identity_type AS recipientIdentityType,
          assertions.issued_at AS issuedAt,
          assertions.issued_by_user_id AS issuedByUserId,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode,
          lifecycle.reason AS latestReason,
          lifecycle.transitioned_at AS latestTransitionedAt,
          attribution.org_unit_id AS orgUnitId,
          COALESCE(org_units.display_name, attribution.org_unit_id) AS orgUnitDisplayName,
          attribution.attribution_source AS attributionSource
        FROM assertions
        INNER JOIN badge_templates
          ON badge_templates.tenant_id = assertions.tenant_id
          AND badge_templates.id = assertions.badge_template_id
        INNER JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        LEFT JOIN tenant_org_units org_units
          ON org_units.tenant_id = assertions.tenant_id
          AND org_units.id = attribution.org_unit_id
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at DESC, assertions.id DESC
        LIMIT ?
      `,
      )
      .bind(...params, rowLimit + 1)
      .all<TenantAssertionLedgerExportRow>();

  const rows = (await listStatement()).results;
  const orgUnits = await listTenantOrgUnits(db, {
    tenantId: input.tenantId,
  });
  const orgUnitsById = new Map(orgUnits.map((orgUnit) => [orgUnit.id, orgUnit] as const));

  if (rows.length > rowLimit) {
    return {
      status: "too_large",
      rowLimit,
    };
  }

  return {
    status: "ok",
    rowLimit,
    rows: rows.map((row) => mapTenantAssertionLedgerExportRow(row, orgUnitsById)),
  };
};

const normalizeReportingDateBoundary = (value: string, boundary: "start" | "end"): string => {
  const trimmed = value.trim();
  const date = trimmed.includes("T")
    ? new Date(trimmed)
    : new Date(`${trimmed}${boundary === "start" ? "T00:00:00.000Z" : "T23:59:59.999Z"}`);

  if (!Number.isFinite(date.getTime())) {
    throw new Error(`Invalid reporting date boundary: ${value}`);
  }

  return date.toISOString();
};

export const findAssertionReportingAttributionByAssertionId = async (
  db: SqlDatabase,
  assertionId: string,
): Promise<AssertionReportingAttributionRecord | null> => {
  const lookupStatement = (): Promise<AssertionReportingAttributionRow | null> =>
    db
      .prepare(
        `
        SELECT
          assertion_id AS assertionId,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          org_unit_id AS orgUnitId,
          attribution_source AS attributionSource,
          attributed_at AS attributedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM assertion_reporting_attributions
        WHERE assertion_id = ?
        LIMIT 1
      `,
      )
      .bind(assertionId)
      .first<AssertionReportingAttributionRow>();

  const row = await lookupStatement();

  return row === null ? null : mapAssertionReportingAttributionRow(row);
};

const upsertAssertionReportingAttribution = async (
  db: SqlDatabase,
  input: {
    assertionId: string;
    tenantId: string;
    badgeTemplateId: string;
    orgUnitId: string;
    attributionSource: AssertionReportingAttributionSource;
    attributedAt: string;
  },
): Promise<AssertionReportingAttributionRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO assertion_reporting_attributions (
          assertion_id,
          tenant_id,
          badge_template_id,
          org_unit_id,
          attribution_source,
          attributed_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (assertion_id)
        DO UPDATE SET
          tenant_id = excluded.tenant_id,
          badge_template_id = excluded.badge_template_id,
          org_unit_id = excluded.org_unit_id,
          attribution_source = excluded.attribution_source,
          attributed_at = excluded.attributed_at,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.assertionId,
        input.tenantId,
        input.badgeTemplateId,
        input.orgUnitId,
        input.attributionSource,
        input.attributedAt,
        nowIso,
        nowIso,
      )
      .run();

  await upsertStatement();

  const attribution = await findAssertionReportingAttributionByAssertionId(db, input.assertionId);

  if (attribution === null) {
    throw new Error(`Unable to load reporting attribution for assertion "${input.assertionId}"`);
  }

  return attribution;
};

const backfillAssertionReportingAttributionsForTenant = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<number> => {
  type MissingAttributionRow = {
    assertionId: string;
    badgeTemplateId: string;
    currentOwnerOrgUnitId: string;
    issuedAt: string;
  };

  const missingStatement = (): Promise<SqlQueryResult<MissingAttributionRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.badge_template_id AS badgeTemplateId,
          badge_templates.owner_org_unit_id AS currentOwnerOrgUnitId,
          assertions.issued_at AS issuedAt
        FROM assertions
        INNER JOIN badge_templates
          ON badge_templates.tenant_id = assertions.tenant_id
          AND badge_templates.id = assertions.badge_template_id
        LEFT JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        WHERE assertions.tenant_id = ?
          AND attribution.assertion_id IS NULL
        ORDER BY assertions.issued_at ASC, assertions.id ASC
      `,
      )
      .bind(tenantId)
      .all<MissingAttributionRow>();

  const missingRows = (await missingStatement()).results;
  const ownershipEventsByTemplateId = new Map<string, BadgeTemplateOwnershipEventRecord[]>();

  for (const badgeTemplateId of new Set(missingRows.map((row) => row.badgeTemplateId))) {
    ownershipEventsByTemplateId.set(
      badgeTemplateId,
      await listBadgeTemplateOwnershipEvents(db, {
        tenantId,
        badgeTemplateId,
      }),
    );
  }

  for (const row of missingRows) {
    const attribution = resolveAssertionReportingAttribution({
      issuedAt: row.issuedAt,
      currentOwnerOrgUnitId: row.currentOwnerOrgUnitId,
      ownershipEvents: ownershipEventsByTemplateId.get(row.badgeTemplateId) ?? [],
    });

    await upsertAssertionReportingAttribution(db, {
      assertionId: row.assertionId,
      tenantId,
      badgeTemplateId: row.badgeTemplateId,
      orgUnitId: attribution.orgUnitId,
      attributionSource: attribution.attributionSource,
      attributedAt: attribution.attributedAt,
    });
  }

  return missingRows.length;
};

const findAssertionEngagementEventById = async (
  db: SqlDatabase,
  id: string,
): Promise<AssertionEngagementEventRecord | null> => {
  const lookupStatement = (): Promise<AssertionEngagementEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          event_type AS eventType,
          actor_type AS actorType,
          channel,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM assertion_engagement_events
        WHERE id = ?
        LIMIT 1
      `,
      )
      .bind(id)
      .first<AssertionEngagementEventRow>();

  const row = await lookupStatement();

  return row === null ? null : mapAssertionEngagementEventRow(row);
};

const findAssertionEngagementEventByType = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
  eventType: AssertionEngagementEventType,
): Promise<AssertionEngagementEventRecord | null> => {
  const lookupStatement = (): Promise<AssertionEngagementEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          event_type AS eventType,
          actor_type AS actorType,
          channel,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM assertion_engagement_events
        WHERE tenant_id = ?
          AND assertion_id = ?
          AND event_type = ?
        ORDER BY occurred_at ASC, created_at ASC, id ASC
        LIMIT 1
      `,
      )
      .bind(tenantId, assertionId, eventType)
      .first<AssertionEngagementEventRow>();

  const row = await lookupStatement();

  return row === null ? null : mapAssertionEngagementEventRow(row);
};

export const listAssertionEngagementEvents = async (
  db: SqlDatabase,
  input: ListAssertionEngagementEventsInput,
): Promise<AssertionEngagementEventRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 50, 200));
  const listStatement = (): Promise<SqlQueryResult<AssertionEngagementEventRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          event_type AS eventType,
          actor_type AS actorType,
          channel,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM assertion_engagement_events
        WHERE tenant_id = ?
          AND assertion_id = ?
        ORDER BY occurred_at DESC, created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.assertionId, queryLimit)
      .all<AssertionEngagementEventRow>();

  const result = await listStatement();

  return result.results.map((row) => mapAssertionEngagementEventRow(row));
};

export const recordAssertionEngagementEvent = async (
  db: SqlDatabase,
  input: RecordAssertionEngagementEventInput,
): Promise<RecordAssertionEngagementEventResult> => {
  const assertion = await findAssertionById(db, input.tenantId, input.assertionId);

  if (assertion === null) {
    throw new Error(`Assertion ${input.assertionId} not found for tenant ${input.tenantId}`);
  }

  const existingAttribution = await findAssertionReportingAttributionByAssertionId(
    db,
    input.assertionId,
  );

  if (existingAttribution === null) {
    await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);
  }

  if (ONE_SHOT_ASSERTION_ENGAGEMENT_EVENT_TYPES.has(input.eventType)) {
    const existingEvent = await findAssertionEngagementEventByType(
      db,
      input.tenantId,
      input.assertionId,
      input.eventType,
    );

    if (existingEvent !== null) {
      return {
        status: "already_recorded",
        event: existingEvent,
      };
    }
  }

  assertValidIsoTimestamp(input.occurredAt, "occurredAt");

  const normalizedChannel = input.channel?.trim();
  const channel =
    normalizedChannel === undefined || normalizedChannel.length === 0 ? null : normalizedChannel;
  const eventId = createPrefixedId("aee");
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO assertion_engagement_events (
          id,
          tenant_id,
          assertion_id,
          event_type,
          actor_type,
          channel,
          occurred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        eventId,
        input.tenantId,
        input.assertionId,
        input.eventType,
        input.actorType,
        channel,
        input.occurredAt,
        input.occurredAt,
      )
      .run();

  await insertStatement();

  const event = await findAssertionEngagementEventById(db, eventId);

  if (event === null) {
    throw new Error(`Unable to load assertion engagement event ${eventId} after insert`);
  }

  return {
    status: "recorded",
    event,
  };
};

const listTenantReportingEngagementRows = async (
  db: SqlDatabase,
  input: GetTenantReportingEngagementCountsInput,
): Promise<TenantReportingEngagementRow[]> => {
  await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);

  const whereClauses = ["assertions.tenant_id = ?"];
  const params: unknown[] = [input.tenantId];

  if (input.from !== undefined) {
    whereClauses.push("assertions.issued_at >= ?");
    params.push(normalizeReportingDateBoundary(input.from, "start"));
  }

  if (input.to !== undefined) {
    whereClauses.push("assertions.issued_at <= ?");
    params.push(normalizeReportingDateBoundary(input.to, "end"));
  }

  if (input.badgeTemplateId !== undefined) {
    whereClauses.push("attribution.badge_template_id = ?");
    params.push(input.badgeTemplateId);
  }

  if (input.orgUnitId !== undefined) {
    whereClauses.push("attribution.org_unit_id = ?");
    params.push(input.orgUnitId);
  }

  const listStatement = (): Promise<SqlQueryResult<TenantReportingEngagementRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          attribution.badge_template_id AS badgeTemplateId,
          attribution.org_unit_id AS orgUnitId,
          assertions.issued_at AS issuedAt,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode,
          events.event_type AS eventType,
          events.occurred_at AS occurredAt
        FROM assertions
        INNER JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        LEFT JOIN assertion_engagement_events events
          ON events.tenant_id = assertions.tenant_id
          AND events.assertion_id = assertions.id
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at ASC, assertions.id ASC, events.occurred_at ASC, events.id ASC
      `,
      )
      .bind(...params)
      .all<TenantReportingEngagementRow>();

  return (await listStatement()).results;
};

export const getTenantReportingEngagementCounts = async (
  db: SqlDatabase,
  input: GetTenantReportingEngagementCountsInput,
): Promise<TenantReportingEngagementCounts> => {
  const rows = await listTenantReportingEngagementRows(db, input);
  return summarizeTenantReportingEngagementCounts(rows, input);
};

export const getTenantReportingTrends = async (
  db: SqlDatabase,
  input: GetTenantReportingTrendsInput,
): Promise<TenantReportingTrendRecord> => {
  const rows = await listTenantReportingEngagementRows(db, input);

  return {
    tenantId: input.tenantId,
    filters: {
      from: input.from ?? null,
      to: input.to ?? null,
      badgeTemplateId: input.badgeTemplateId ?? null,
      orgUnitId: input.orgUnitId ?? null,
      state: input.state ?? null,
    },
    bucket: input.bucket,
    series: summarizeTenantReportingTrendRows(rows, input),
    generatedAt: new Date().toISOString(),
  };
};

export const listTenantReportingComparisons = async (
  db: SqlDatabase,
  input: ListTenantReportingComparisonsInput,
): Promise<TenantReportingComparisonRowRecord[]> => {
  const rows = await listTenantReportingEngagementRows(db, input);
  return summarizeTenantReportingComparisonRows(rows, input);
};

export const getTenantExecutiveRollup = async (
  db: SqlDatabase,
  input: GetTenantExecutiveRollupInput,
): Promise<GetTenantExecutiveRollupResult> => {
  const [rows, orgUnits] = await Promise.all([
    listTenantReportingEngagementRows(db, {
      tenantId: input.tenantId,
      from: input.from,
      to: input.to,
      badgeTemplateId: input.badgeTemplateId,
      orgUnitId: input.orgUnitId,
      state: input.state,
    }),
    listTenantOrgUnits(db, {
      tenantId: input.tenantId,
      includeInactive: true,
    }),
  ]);

  return {
    tenantId: input.tenantId,
    ...summarizeTenantExecutiveRollup({
      rows,
      orgUnits: orgUnits.map((orgUnit) => {
        return {
          id: orgUnit.id,
          unitType: orgUnit.unitType,
          displayName: orgUnit.displayName,
          parentOrgUnitId: orgUnit.parentOrgUnitId,
        };
      }),
      query: {
        from: input.from,
        to: input.to,
        badgeTemplateId: input.badgeTemplateId,
        orgUnitId: input.orgUnitId,
        state: input.state,
        focusOrgUnitId: input.focusOrgUnitId,
        comparisonLevel: input.comparisonLevel,
      },
      scopedRootOrgUnitIds: input.scopedRootOrgUnitIds,
    }),
    generatedAt: new Date().toISOString(),
  };
};

export const getTenantReportingOverview = async (
  db: SqlDatabase,
  input: GetTenantReportingOverviewInput,
): Promise<TenantReportingOverviewRecord> => {
  await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);

  const whereClauses = ["assertions.tenant_id = ?"];
  const params: unknown[] = [input.tenantId];

  if (input.issuedFrom !== undefined) {
    whereClauses.push("assertions.issued_at >= ?");
    params.push(normalizeReportingDateBoundary(input.issuedFrom, "start"));
  }

  if (input.issuedTo !== undefined) {
    whereClauses.push("assertions.issued_at <= ?");
    params.push(normalizeReportingDateBoundary(input.issuedTo, "end"));
  }

  if (input.badgeTemplateId !== undefined) {
    whereClauses.push("assertions.badge_template_id = ?");
    params.push(input.badgeTemplateId);
  }

  if (input.orgUnitId !== undefined) {
    whereClauses.push("attribution.org_unit_id = ?");
    params.push(input.orgUnitId);
  }

  const overviewStatement = (): Promise<SqlQueryResult<TenantReportingOverviewRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.issued_at AS issuedAt,
          assertions.badge_template_id AS badgeTemplateId,
          attribution.org_unit_id AS orgUnitId,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode
        FROM assertions
        INNER JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at DESC, assertions.id DESC
      `,
      )
      .bind(...params)
      .all<TenantReportingOverviewRow>();

  const rows = (await overviewStatement()).results;

  const engagementCounts = await getTenantReportingEngagementCounts(db, {
    tenantId: input.tenantId,
    from: input.issuedFrom,
    to: input.issuedTo,
    badgeTemplateId: input.badgeTemplateId,
    orgUnitId: input.orgUnitId,
    state: input.state,
  });

  return {
    tenantId: input.tenantId,
    filters: {
      issuedFrom: input.issuedFrom ?? null,
      issuedTo: input.issuedTo ?? null,
      badgeTemplateId: input.badgeTemplateId ?? null,
      orgUnitId: input.orgUnitId ?? null,
      state: input.state ?? null,
    },
    counts: {
      ...summarizeTenantReportingOverviewRows(rows, input.state),
      claimRate: engagementCounts.claimRate,
      shareRate: engagementCounts.shareRate,
    },
    generatedAt: new Date().toISOString(),
  };
};

export const listPublicBadgeWallEntries = async (
  db: SqlDatabase,
  input: ListPublicBadgeWallEntriesInput,
): Promise<PublicBadgeWallEntryRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 300, 1000));
  const result =
    input.badgeTemplateId === undefined
      ? await db
          .prepare(
            `
            SELECT
              assertions.id AS assertionId,
              assertions.public_id AS assertionPublicId,
              assertions.tenant_id AS tenantId,
              assertions.badge_template_id AS badgeTemplateId,
              badge_templates.title AS badgeTitle,
              badge_templates.description AS badgeDescription,
              badge_templates.image_uri AS badgeImageUri,
              assertions.recipient_identity AS recipientIdentity,
              assertions.recipient_identity_type AS recipientIdentityType,
              assertions.issued_at AS issuedAt,
              assertions.revoked_at AS revokedAt
            FROM assertions
            INNER JOIN badge_templates
              ON badge_templates.tenant_id = assertions.tenant_id
              AND badge_templates.id = assertions.badge_template_id
            WHERE assertions.tenant_id = ?
              AND assertions.public_id IS NOT NULL
            ORDER BY assertions.issued_at DESC
            LIMIT ?
          `,
          )
          .bind(input.tenantId, queryLimit)
          .all<PublicBadgeWallEntryRow>()
      : await db
          .prepare(
            `
            SELECT
              assertions.id AS assertionId,
              assertions.public_id AS assertionPublicId,
              assertions.tenant_id AS tenantId,
              assertions.badge_template_id AS badgeTemplateId,
              badge_templates.title AS badgeTitle,
              badge_templates.description AS badgeDescription,
              badge_templates.image_uri AS badgeImageUri,
              assertions.recipient_identity AS recipientIdentity,
              assertions.recipient_identity_type AS recipientIdentityType,
              assertions.issued_at AS issuedAt,
              assertions.revoked_at AS revokedAt
            FROM assertions
            INNER JOIN badge_templates
              ON badge_templates.tenant_id = assertions.tenant_id
              AND badge_templates.id = assertions.badge_template_id
            WHERE assertions.tenant_id = ?
              AND assertions.badge_template_id = ?
              AND assertions.public_id IS NOT NULL
            ORDER BY assertions.issued_at DESC
            LIMIT ?
          `,
          )
          .bind(input.tenantId, input.badgeTemplateId, queryLimit)
          .all<PublicBadgeWallEntryRow>();

  return result.results.map((row) => mapPublicBadgeWallEntryRow(row));
};

export const createAssertion = async (
  db: SqlDatabase,
  input: CreateAssertionInput,
): Promise<AssertionRecord> => {
  const nowIso = new Date().toISOString();
  const assertionPublicId = input.publicId ?? crypto.randomUUID();
  const recipientIdentifiers = uniqueRecipientIdentifiers(input.recipientIdentifiers ?? []);

  await db
    .prepare(
      `
      INSERT INTO assertions (
        id,
        tenant_id,
        public_id,
        learner_profile_id,
        badge_template_id,
        recipient_identity,
        recipient_identity_type,
        vc_r2_key,
        status_list_index,
        idempotency_key,
        issued_at,
        issued_by_user_id,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      input.id,
      input.tenantId,
      assertionPublicId,
      input.learnerProfileId ?? null,
      input.badgeTemplateId,
      input.recipientIdentity,
      input.recipientIdentityType,
      input.vcR2Key,
      input.statusListIndex,
      input.idempotencyKey,
      input.issuedAt,
      input.issuedByUserId ?? null,
      nowIso,
      nowIso,
    )
    .run();

  await insertAssertionRecipientIdentifiers(db, input.id, recipientIdentifiers);
  const badgeTemplate = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (badgeTemplate === null) {
    throw new Error(
      `Badge template ${input.badgeTemplateId} not found for tenant ${input.tenantId}`,
    );
  }

  await upsertAssertionReportingAttribution(db, {
    assertionId: input.id,
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    orgUnitId: badgeTemplate.ownerOrgUnitId,
    attributionSource: "issuance_snapshot",
    attributedAt: input.issuedAt,
  });

  return {
    id: input.id,
    tenantId: input.tenantId,
    publicId: assertionPublicId,
    learnerProfileId: input.learnerProfileId ?? null,
    badgeTemplateId: input.badgeTemplateId,
    recipientIdentity: input.recipientIdentity,
    recipientIdentityType: input.recipientIdentityType,
    vcR2Key: input.vcR2Key,
    statusListIndex: input.statusListIndex,
    idempotencyKey: input.idempotencyKey,
    issuedAt: input.issuedAt,
    issuedByUserId: input.issuedByUserId ?? null,
    revokedAt: null,
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

export const nextAssertionStatusListIndex = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<number> => {
  const row = await db
    .prepare(
      `
      SELECT
        COALESCE(MAX(status_list_index), -1) + 1 AS nextStatusListIndex
      FROM assertions
      WHERE tenant_id = ?
    `,
    )
    .bind(tenantId)
    .first<{ nextStatusListIndex: number }>();

  if (row === null) {
    throw new Error(`Unable to allocate status list index for tenant "${tenantId}"`);
  }

  return row.nextStatusListIndex;
};

export const listAssertionStatusListEntries = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<AssertionStatusListEntryRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        status_list_index AS statusListIndex,
        revoked_at AS revokedAt
      FROM assertions
      WHERE tenant_id = ?
        AND status_list_index IS NOT NULL
      ORDER BY status_list_index ASC
    `,
    )
    .bind(tenantId)
    .all<AssertionStatusListEntryRecord>();

  return result.results;
};

export const recordAssertionRevocation = async (
  db: SqlDatabase,
  input: RecordAssertionRevocationInput,
): Promise<RecordAssertionRevocationResult> => {
  const assertion = await findAssertionById(db, input.tenantId, input.assertionId);

  if (assertion === null) {
    throw new Error(`Assertion "${input.assertionId}" not found for tenant "${input.tenantId}"`);
  }

  const effectiveRevokedAt = assertion.revokedAt ?? input.revokedAt;

  if (assertion.revokedAt === null) {
    await db
      .prepare(
        `
        UPDATE assertions
        SET revoked_at = ?,
            updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
          AND revoked_at IS NULL
      `,
      )
      .bind(effectiveRevokedAt, input.revokedAt, input.tenantId, input.assertionId)
      .run();
  }

  await db
    .prepare(
      `
      INSERT INTO revocations (
        id,
        tenant_id,
        assertion_id,
        reason,
        idempotency_key,
        revoked_by_user_id,
        revoked_at,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT DO NOTHING
    `,
    )
    .bind(
      input.revocationId,
      input.tenantId,
      input.assertionId,
      input.reason,
      input.idempotencyKey,
      input.revokedByUserId ?? null,
      effectiveRevokedAt,
      input.revokedAt,
    )
    .run();

  return {
    status: assertion.revokedAt === null ? "revoked" : "already_revoked",
    revokedAt: effectiveRevokedAt,
  };
};
