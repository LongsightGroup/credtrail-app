import type { BadgeAchievementSnapshot } from "@credtrail/validation";
import type { AssertionAchievementSnapshotStatus } from "./assertion-achievement-snapshot.js";
import type { OrgUnitType } from "./tenant-org-units";
import type { RecipientIdentifierInput } from "./learner-profiles";

export interface AssertionRecord {
  id: string;
  tenantId: string;
  publicId: string | null;
  learnerProfileId: string | null;
  badgeTemplateId: string;
  achievementSnapshot: BadgeAchievementSnapshot;
  achievementSnapshotStatus: AssertionAchievementSnapshotStatus;
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
  achievementSnapshot: BadgeAchievementSnapshot;
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

export interface ListTenantAssertionsInput {
  tenantId: string;
  issuedFrom?: string | undefined;
  issuedTo?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  recipientQuery?: string | undefined;
  state?: AssertionLifecycleState | undefined;
  limit?: number | undefined;
}

export interface ListAssertionsByIdempotencyKeysInput {
  tenantId: string;
  idempotencyKeys: readonly string[];
}

export interface ListAssertionsByBadgeTemplatesAndRecipientEmailsInput {
  tenantId: string;
  badgeTemplateIds: readonly string[];
  recipientEmails: readonly string[];
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
