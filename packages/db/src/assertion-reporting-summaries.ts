import { ORG_UNIT_HIERARCHY_DEPTH } from "@credtrail/validation";
import type {
  TenantExecutiveRollupQuery,
  TenantExecutiveRollupRecord,
  TenantReportingComparisonGroupBy,
  TenantReportingHierarchyGroupRecord,
  TenantReportingHierarchyOrgUnitRecord,
} from "./assertion-types.js";

interface TenantReportingHierarchyAggregateRow {
  readonly groupBy: TenantReportingComparisonGroupBy;
  readonly groupId: string;
  readonly issuedCount: number;
  readonly publicBadgeViewCount: number;
  readonly verificationViewCount: number;
  readonly shareClickCount: number;
  readonly learnerClaimCount: number;
  readonly walletAcceptCount: number;
  readonly shareEngagedCount: number;
  readonly claimEngagedCount: number;
}

interface ReportingHierarchyAggregate {
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  shareEngagedCount: number;
  claimEngagedCount: number;
}

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

const createReportingHierarchyAggregate = (): ReportingHierarchyAggregate => ({
  issuedCount: 0,
  publicBadgeViewCount: 0,
  verificationViewCount: 0,
  shareClickCount: 0,
  learnerClaimCount: 0,
  walletAcceptCount: 0,
  shareEngagedCount: 0,
  claimEngagedCount: 0,
});

const addReportingComparison = (
  aggregate: ReportingHierarchyAggregate,
  comparison: TenantReportingHierarchyAggregateRow,
): void => {
  aggregate.issuedCount += comparison.issuedCount;
  aggregate.publicBadgeViewCount += comparison.publicBadgeViewCount;
  aggregate.verificationViewCount += comparison.verificationViewCount;
  aggregate.shareClickCount += comparison.shareClickCount;
  aggregate.learnerClaimCount += comparison.learnerClaimCount;
  aggregate.walletAcceptCount += comparison.walletAcceptCount;
  aggregate.shareEngagedCount += comparison.shareEngagedCount;
  aggregate.claimEngagedCount += comparison.claimEngagedCount;
};

const reportingHierarchyGroupFromAggregate = (input: {
  readonly orgUnit: TenantReportingHierarchyOrgUnitRecord;
  readonly aggregate: ReportingHierarchyAggregate;
}): TenantReportingHierarchyGroupRecord => {
  const { aggregate, orgUnit } = input;

  return {
    level: orgUnit.unitType,
    orgUnitId: orgUnit.id,
    displayName: orgUnit.displayName,
    parentOrgUnitId: orgUnit.parentOrgUnitId,
    issuedCount: aggregate.issuedCount,
    publicBadgeViewCount: aggregate.publicBadgeViewCount,
    verificationViewCount: aggregate.verificationViewCount,
    shareClickCount: aggregate.shareClickCount,
    learnerClaimCount: aggregate.learnerClaimCount,
    walletAcceptCount: aggregate.walletAcceptCount,
    claimRate:
      aggregate.issuedCount === 0 ? 0 : aggregate.claimEngagedCount / aggregate.issuedCount,
    shareRate:
      aggregate.issuedCount === 0 ? 0 : aggregate.shareEngagedCount / aggregate.issuedCount,
  };
};

/** Rolls bounded per-org-unit comparison aggregates into a requested hierarchy level. */
export const summarizeTenantReportingHierarchyRows = (input: {
  readonly comparisonRows: readonly TenantReportingHierarchyAggregateRow[];
  readonly orgUnits: readonly TenantReportingHierarchyOrgUnitRecord[];
  readonly focusOrgUnitId?: string | undefined;
  readonly level: TenantReportingHierarchyOrgUnitRecord["unitType"];
  readonly scopedRootOrgUnitIds?: readonly string[] | undefined;
}): TenantReportingHierarchyGroupRecord[] => {
  const orgUnitsById = new Map(input.orgUnits.map((orgUnit) => [orgUnit.id, orgUnit] as const));
  const focusOrgUnit =
    input.focusOrgUnitId === undefined
      ? null
      : getReportingHierarchyOrgUnitOrThrow(orgUnitsById, input.focusOrgUnitId);

  if (
    focusOrgUnit !== null &&
    ORG_UNIT_HIERARCHY_DEPTH[focusOrgUnit.unitType] > ORG_UNIT_HIERARCHY_DEPTH[input.level]
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
      readonly orgUnit: TenantReportingHierarchyOrgUnitRecord;
      readonly aggregate: ReportingHierarchyAggregate;
    }
  >();

  for (const comparison of input.comparisonRows) {
    if (comparison.groupBy !== "orgUnit") {
      throw new Error("Reporting hierarchy requires org-unit comparison rows");
    }

    const lineage = listReportingHierarchyLineage(orgUnitsById, comparison.groupId);

    if (focusOrgUnit !== null && !isReportingHierarchyLineageWithinRoot(lineage, focusOrgUnit.id)) {
      continue;
    }

    if (
      scopedRootOrgUnitIds.length > 0 &&
      !scopedRootOrgUnitIds.some((rootId) => isReportingHierarchyLineageWithinRoot(lineage, rootId))
    ) {
      continue;
    }

    const targetOrgUnit = lineage.find((orgUnit) => orgUnit.unitType === input.level);

    if (targetOrgUnit === undefined) {
      continue;
    }

    let group = groups.get(targetOrgUnit.id);

    if (group === undefined) {
      group = {
        orgUnit: targetOrgUnit,
        aggregate: createReportingHierarchyAggregate(),
      };
      groups.set(targetOrgUnit.id, group);
    }

    addReportingComparison(group.aggregate, comparison);
  }

  return Array.from(groups.values())
    .map(reportingHierarchyGroupFromAggregate)
    .sort((left, right) => {
      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    });
};

/** Builds executive hierarchy metadata around bounded per-org-unit aggregates. */
export const summarizeTenantExecutiveRollup = (input: {
  readonly comparisonRows: readonly TenantReportingHierarchyAggregateRow[];
  readonly orgUnits: readonly TenantReportingHierarchyOrgUnitRecord[];
  readonly query: TenantExecutiveRollupQuery;
  readonly scopedRootOrgUnitIds?: readonly string[] | undefined;
}): TenantExecutiveRollupRecord => {
  const orgUnitsById = new Map(input.orgUnits.map((orgUnit) => [orgUnit.id, orgUnit] as const));
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
      comparisonRows: input.comparisonRows,
      orgUnits: input.orgUnits,
      focusOrgUnitId: input.query.focusOrgUnitId,
      level: input.query.comparisonLevel,
      scopedRootOrgUnitIds: input.scopedRootOrgUnitIds,
    }),
  };
};
