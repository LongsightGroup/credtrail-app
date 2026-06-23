import type { BadgeTemplateOwnershipEventRecord } from "./badge-templates";
import type { OrgUnitType } from "./tenant-org-units";
import type {
  AssertionEngagementEventType,
  AssertionLifecycleReasonCode,
  AssertionLifecycleState,
  AssertionReportingAttributionSource,
  TenantExecutiveRollupQuery,
  TenantExecutiveRollupRecord,
  TenantReportingComparisonGroupBy,
  TenantReportingComparisonRowRecord,
  TenantReportingEngagementCounts,
  TenantReportingHierarchyGroupRecord,
  TenantReportingHierarchyOrgUnitRecord,
  TenantReportingHierarchyQuery,
  TenantReportingHierarchySourceRow,
  TenantReportingLifecycleFilter,
  TenantReportingEngagementFilters,
  TenantReportingOverviewCounts,
  TenantReportingTrendBucket,
  TenantReportingTrendBucketRecord,
} from "./assertion-types.js";

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

export const summarizeTenantReportingEngagementCounts = (
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
