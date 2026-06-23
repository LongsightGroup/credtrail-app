import { findBadgeTemplateById, listBadgeTemplateOwnershipEvents } from "./badge-templates";
import type { BadgeTemplateOwnershipEventRecord } from "./badge-templates";
import {
  assertionBadgeTemplateJoinSql,
  bindLearnerProfileOrEmailAccessParams,
  buildLearnerProfileOrEmailAccessFilter,
} from "./learner-assertion-access-sql";
import { listLearnerIdentitiesByProfile } from "./learner-profiles";
import {
  insertAssertionRecipientIdentifiers,
  uniqueRecipientIdentifiers,
} from "./assertion-recipient-identifiers";
export { listRecipientIdentifiersForAssertion } from "./assertion-recipient-identifiers";
import { assertValidIsoTimestamp, createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";
import { listTenantOrgUnits } from "./tenant-org-units";
import type { TenantOrgUnitRecord } from "./tenant-org-units";
import { normalizeEmail } from "./users";

export type {
  AssertionRecord,
  LearnerRecordAssertionExportRecord,
  ListLearnerRecordAssertionExportsInput,
  AssertionLifecycleState,
  AssertionLifecycleTransitionSource,
  AssertionLifecycleReasonCode,
  AssertionLifecycleEventRecord,
  ListAssertionLifecycleEventsInput,
  ResolveAssertionLifecycleStateResult,
  RecordAssertionLifecycleTransitionInput,
  RecordAssertionLifecycleTransitionResult,
  PublicBadgeWallEntryRecord,
  CreateAssertionInput,
  AssertionStatusListEntryRecord,
  RecordAssertionRevocationInput,
  RecordAssertionRevocationResult,
  ListTenantAssertionsInput,
  ListAssertionsByIdempotencyKeysInput,
  ListAssertionsByBadgeTemplatesAndRecipientEmailsInput,
  AssertionLifecycleStateByAssertionIdRecord,
  ListAssertionLifecycleStatesByAssertionIdsInput,
  AssertionEngagementEventType,
  AssertionEngagementActorType,
  AssertionEngagementEventRecord,
  RecordAssertionEngagementEventInput,
  RecordAssertionEngagementEventResult,
  ListAssertionEngagementEventsInput,
  TenantAssertionSummaryRecord,
  ListTenantAssertionLedgerExportRowsInput,
  TenantAssertionLedgerExportRowRecord,
  TenantAssertionLedgerExportResult,
  ListPublicBadgeWallEntriesInput,
} from "./assertion-types.js";
export {
  ASSERTION_ENGAGEMENT_EVENT_TYPES,
  SYNCHRONOUS_EXPORT_ROW_LIMIT,
} from "./assertion-types.js";
import { SYNCHRONOUS_EXPORT_ROW_LIMIT } from "./assertion-types.js";
import {
  resolveAssertionReportingAttribution,
  summarizeTenantReportingComparisonRows,
  summarizeTenantReportingEngagementCounts,
  summarizeTenantReportingOverviewRows,
  summarizeTenantReportingTrendRows,
  summarizeTenantExecutiveRollup,
} from "./assertion-reporting-summaries.js";
import type {
  AssertionEngagementActorType,
  AssertionEngagementEventRecord,
  AssertionEngagementEventType,
  AssertionLifecycleEventRecord,
  AssertionLifecycleReasonCode,
  AssertionLifecycleState,
  AssertionLifecycleStateByAssertionIdRecord,
  AssertionLifecycleTransitionSource,
  AssertionRecord,
  AssertionReportingAttributionRecord,
  AssertionReportingAttributionSource,
  LearnerRecordAssertionExportRecord,
  ListAssertionLifecycleEventsInput,
  ListAssertionLifecycleStatesByAssertionIdsInput,
  ListAssertionsByBadgeTemplatesAndRecipientEmailsInput,
  ListAssertionsByIdempotencyKeysInput,
  ListLearnerRecordAssertionExportsInput,
  ListTenantAssertionLedgerExportRowsInput,
  ListTenantAssertionsInput,
  PublicBadgeWallEntryRecord,
  RecordAssertionLifecycleTransitionInput,
  RecordAssertionLifecycleTransitionResult,
  ResolveAssertionLifecycleStateResult,
  TenantAssertionLedgerExportResult,
  TenantAssertionLedgerExportRowRecord,
  TenantAssertionSummaryRecord,
  ListAssertionEngagementEventsInput,
  RecordAssertionEngagementEventInput,
  RecordAssertionEngagementEventResult,
  GetTenantReportingEngagementCountsInput,
  TenantReportingEngagementCounts,
  GetTenantReportingTrendsInput,
  TenantReportingTrendRecord,
  ListTenantReportingComparisonsInput,
  TenantReportingComparisonRowRecord,
  GetTenantExecutiveRollupInput,
  GetTenantExecutiveRollupResult,
  GetTenantReportingOverviewInput,
  TenantReportingOverviewRecord,
  ListPublicBadgeWallEntriesInput,
  CreateAssertionInput,
  AssertionStatusListEntryRecord,
  RecordAssertionRevocationInput,
  RecordAssertionRevocationResult,
} from "./assertion-types.js";

const ONE_SHOT_ASSERTION_ENGAGEMENT_EVENT_TYPES = new Set<AssertionEngagementEventType>([
  "learner_claim",
  "wallet_accept",
]);

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

export {
  resolveAssertionReportingAttribution,
  summarizeTenantReportingOverviewRows,
  summarizeTenantReportingTrendRows,
  summarizeTenantReportingComparisonRows,
  summarizeTenantReportingHierarchyRows,
  summarizeTenantExecutiveRollup,
} from "./assertion-reporting-summaries.js";
export type {
  AssertionReportingAttributionSource,
  TenantReportingLifecycleFilter,
  TenantReportingOverviewFilters,
  GetTenantReportingOverviewInput,
  TenantReportingOverviewCounts,
  TenantReportingOverviewRecord,
  TenantReportingEngagementFilters,
  TenantReportingHierarchyQuery,
  TenantReportingHierarchySourceRow,
  TenantReportingHierarchyOrgUnitRecord,
  TenantReportingHierarchyGroupRecord,
  TenantExecutiveRollupQuery,
  TenantExecutiveRollupRecord,
  GetTenantExecutiveRollupInput,
  GetTenantExecutiveRollupResult,
  GetTenantReportingEngagementCountsInput,
  TenantReportingEngagementCounts,
  TenantReportingTrendBucket,
  GetTenantReportingTrendsInput,
  TenantReportingTrendBucketRecord,
  TenantReportingTrendRecord,
  TenantReportingComparisonGroupBy,
  ListTenantReportingComparisonsInput,
  TenantReportingComparisonRowRecord,
} from "./assertion-types.js";

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

export const listAssertionsByBadgeTemplatesAndRecipientEmails = async (
  db: SqlDatabase,
  input: ListAssertionsByBadgeTemplatesAndRecipientEmailsInput,
): Promise<AssertionRecord[]> => {
  const badgeTemplateIds = uniqueNonEmptyStrings(input.badgeTemplateIds);
  const recipientEmails = Array.from(
    new Set(uniqueNonEmptyStrings(input.recipientEmails).map((email) => normalizeEmail(email))),
  );

  if (badgeTemplateIds.length === 0 || recipientEmails.length === 0) {
    return [];
  }

  const assertions: AssertionRecord[] = [];

  for (const badgeTemplateIdChunk of chunkValues(badgeTemplateIds, 100)) {
    for (const recipientEmailChunk of chunkValues(recipientEmails, 100)) {
      const badgeTemplateIdPlaceholders = badgeTemplateIdChunk.map(() => "?").join(", ");
      const recipientEmailPlaceholders = recipientEmailChunk.map(() => "?").join(", ");
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
            AND badge_template_id IN (${badgeTemplateIdPlaceholders})
            AND recipient_identity_type = 'email'
            AND LOWER(recipient_identity) IN (${recipientEmailPlaceholders})
          ORDER BY issued_at DESC, id DESC
        `,
        )
        .bind(input.tenantId, ...badgeTemplateIdChunk, ...recipientEmailChunk)
        .all<AssertionRow>();

      assertions.push(...result.results.map((row) => mapAssertionRow(row)));
    }
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
  const learnerAccessFilter = buildLearnerProfileOrEmailAccessFilter(emailAliases);
  const params: unknown[] = [
    input.tenantId,
    ...bindLearnerProfileOrEmailAccessParams(input.learnerProfileId, emailAliases),
  ];
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
      ${assertionBadgeTemplateJoinSql}
      INNER JOIN tenants
        ON tenants.id = assertions.tenant_id
      WHERE assertions.tenant_id = ?
        AND ${learnerAccessFilter}
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
