import type { TenantOrgUnitRecord } from "./tenant-org-units";
import { resolveStoredAssertionAchievement } from "./assertion-achievement-snapshot.js";
import type {
  AssertionEngagementEventRecord,
  AssertionEngagementEventType,
  AssertionEngagementActorType,
  AssertionLifecycleEventRecord,
  AssertionLifecycleTransitionSource,
  AssertionLifecycleReasonCode,
  AssertionLifecycleState,
  AssertionRecord,
  AssertionReportingAttributionRecord,
  AssertionReportingAttributionSource,
  LearnerRecordAssertionExportRecord,
  PublicBadgeWallEntryRecord,
  ResolveAssertionLifecycleStateResult,
  TenantAssertionLedgerExportRowRecord,
  TenantAssertionSummaryRecord,
} from "./assertion-types.js";

export const ONE_SHOT_ASSERTION_ENGAGEMENT_EVENT_TYPES = new Set<AssertionEngagementEventType>([
  "learner_claim",
  "wallet_accept",
]);

interface AssertionAchievementSnapshotRow {
  badgeTemplateId: string;
  achievementSnapshotJson: string | null;
  achievementSnapshotStatus: string;
}

export interface AssertionRow extends AssertionAchievementSnapshotRow {
  id: string;
  tenantId: string;
  publicId: string | null;
  learnerProfileId: string | null;
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

export interface AssertionReportingAttributionRow {
  assertionId: string;
  tenantId: string;
  badgeTemplateId: string;
  orgUnitId: string;
  attributionSource: AssertionReportingAttributionSource;
  attributedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface AssertionEngagementEventRow {
  id: string;
  tenantId: string;
  assertionId: string;
  eventType: AssertionEngagementEventType;
  actorType: AssertionEngagementActorType;
  channel: string | null;
  occurredAt: string;
  createdAt: string;
}

export interface AssertionLifecycleEventRow {
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

export interface LearnerRecordAssertionExportRow extends AssertionAchievementSnapshotRow {
  assertionId: string;
  assertionPublicId: string | null;
  tenantId: string;
  learnerProfileId: string | null;
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

export interface TenantAssertionSummaryRow extends AssertionAchievementSnapshotRow {
  assertionId: string;
  tenantId: string;
  publicId: string | null;
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

export interface TenantAssertionLedgerExportRow extends AssertionAchievementSnapshotRow {
  assertionId: string;
  tenantId: string;
  publicId: string | null;
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

export interface PublicBadgeWallEntryRow extends AssertionAchievementSnapshotRow {
  assertionId: string;
  assertionPublicId: string;
  tenantId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  issuedAt: string;
  revokedAt: string | null;
}

export const ASSERTION_LIFECYCLE_REASON_CODES = new Set<AssertionLifecycleReasonCode>([
  "administrative_hold",
  "policy_violation",
  "appeal_pending",
  "appeal_resolved",
  "credential_expired",
  "issuer_requested",
  "other",
]);

export const ASSERTION_LIFECYCLE_ALLOWED_TRANSITIONS: Record<
  AssertionLifecycleState,
  ReadonlySet<AssertionLifecycleState>
> = {
  active: new Set<AssertionLifecycleState>(["suspended", "revoked", "expired"]),
  suspended: new Set<AssertionLifecycleState>(["active", "revoked", "expired"]),
  expired: new Set<AssertionLifecycleState>(["active", "revoked"]),
  revoked: new Set<AssertionLifecycleState>(),
};

export const uniqueNonEmptyStrings = (values: readonly string[]): string[] => {
  return Array.from(
    new Set(values.map((value) => value.trim()).filter((value) => value.length > 0)),
  );
};

export const chunkValues = <T>(values: readonly T[], chunkSize: number): T[][] => {
  const chunks: T[][] = [];

  for (let index = 0; index < values.length; index += chunkSize) {
    chunks.push(values.slice(index, index + chunkSize));
  }

  return chunks;
};

export const assertionLifecycleStateFromRecords = (input: {
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

export const resolveAssertionLifecycleProjection = (input: {
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

export const buildCurrentOrgUnitLineageNames = (
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

export const mapAssertionRow = (row: AssertionRow): AssertionRecord => {
  const achievement = resolveStoredAssertionAchievement(row);

  return {
    id: row.id,
    tenantId: row.tenantId,
    publicId: row.publicId,
    learnerProfileId: row.learnerProfileId,
    badgeTemplateId: row.badgeTemplateId,
    achievementSnapshot: achievement.snapshot,
    achievementSnapshotStatus: achievement.status,
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

export const mapAssertionReportingAttributionRow = (
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

export const mapAssertionEngagementEventRow = (
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

export const mapAssertionLifecycleEventRow = (
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

export const mapLearnerRecordAssertionExportRow = (
  row: LearnerRecordAssertionExportRow,
): LearnerRecordAssertionExportRecord => {
  const achievement = resolveStoredAssertionAchievement(row).snapshot;

  return {
    assertionId: row.assertionId,
    assertionPublicId: row.assertionPublicId,
    tenantId: row.tenantId,
    learnerProfileId: row.learnerProfileId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: achievement.title,
    badgeDescription: achievement.description,
    badgeCriteriaUri: achievement.criteriaUri,
    badgeImageUri: achievement.imageUri,
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

export const mapTenantAssertionSummaryRow = (
  row: TenantAssertionSummaryRow,
): TenantAssertionSummaryRecord => {
  const achievement = resolveStoredAssertionAchievement(row).snapshot;
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
    badgeTitle: achievement.title,
    badgeImageUri: achievement.imageUri,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    issuedAt: row.issuedAt,
    issuedByUserId: row.issuedByUserId,
    revokedAt: row.revokedAt,
    ...lifecycle,
  };
};

export const mapTenantAssertionLedgerExportRow = (
  row: TenantAssertionLedgerExportRow,
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
): TenantAssertionLedgerExportRowRecord => {
  const achievement = resolveStoredAssertionAchievement(row).snapshot;
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
    badgeTitle: achievement.title,
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

export const mapPublicBadgeWallEntryRow = (
  row: PublicBadgeWallEntryRow,
): PublicBadgeWallEntryRecord => {
  const achievement = resolveStoredAssertionAchievement(row).snapshot;

  return {
    assertionId: row.assertionId,
    assertionPublicId: row.assertionPublicId,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: achievement.title,
    badgeDescription: achievement.description,
    badgeImageUri: achievement.imageUri,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    issuedAt: row.issuedAt,
    revokedAt: row.revokedAt,
  };
};

export const normalizeReportingDateBoundary = (
  value: string,
  boundary: "start" | "end",
): string => {
  const trimmed = value.trim();
  const date = trimmed.includes("T")
    ? new Date(trimmed)
    : new Date(`${trimmed}${boundary === "start" ? "T00:00:00.000Z" : "T23:59:59.999Z"}`);

  if (!Number.isFinite(date.getTime())) {
    throw new Error(`Invalid reporting date boundary: ${value}`);
  }

  return date.toISOString();
};
