import type { TenantOrgUnitRecord } from "@credtrail/db";
import { ORG_UNIT_HIERARCHY_DEPTH } from "@credtrail/validation";

export interface ReportingComparisonMetricRow {
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

export interface ReportingHierarchyMetricRow {
  level: TenantOrgUnitRecord["unitType"];
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

export const buildOrgUnitMap = (
  orgUnits: readonly TenantOrgUnitRecord[],
): ReadonlyMap<string, TenantOrgUnitRecord> => {
  return new Map(orgUnits.map((orgUnit) => [orgUnit.id, orgUnit] as const));
};

const isOrgUnitWithinRoot = (
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
  orgUnitId: string,
  rootOrgUnitId: string,
): boolean => {
  const visited = new Set<string>();
  let currentOrgUnitId: string | null = orgUnitId;

  while (currentOrgUnitId !== null) {
    if (currentOrgUnitId === rootOrgUnitId) {
      return true;
    }

    if (visited.has(currentOrgUnitId)) {
      return false;
    }

    visited.add(currentOrgUnitId);
    currentOrgUnitId = orgUnitsById.get(currentOrgUnitId)?.parentOrgUnitId ?? null;
  }

  return false;
};

export const isOrgUnitWithinRoots = (
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
  orgUnitId: string,
  rootOrgUnitIds: readonly string[],
): boolean => {
  return rootOrgUnitIds.some((rootOrgUnitId) =>
    isOrgUnitWithinRoot(orgUnitsById, orgUnitId, rootOrgUnitId),
  );
};

const listOrgUnitLineage = (
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
  orgUnitId: string,
): TenantOrgUnitRecord[] => {
  const lineage: TenantOrgUnitRecord[] = [];
  const visited = new Set<string>();
  let currentOrgUnitId: string | null = orgUnitId;

  while (currentOrgUnitId !== null) {
    if (visited.has(currentOrgUnitId)) {
      throw new Error(`Detected an org-unit cycle while resolving hierarchy for ${orgUnitId}`);
    }

    visited.add(currentOrgUnitId);
    const orgUnit = orgUnitsById.get(currentOrgUnitId);

    if (orgUnit === undefined) {
      throw new Error(`Org unit ${orgUnitId} is missing from the reporting hierarchy`);
    }

    lineage.push(orgUnit);
    currentOrgUnitId = orgUnit.parentOrgUnitId;
  }

  return lineage;
};

export const filterComparisonRowsToScope = <T extends ReportingComparisonMetricRow>(
  comparisonRows: readonly T[],
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
  scopedRootOrgUnitIds: readonly string[],
): T[] => {
  return comparisonRows.filter((row) =>
    isOrgUnitWithinRoots(orgUnitsById, row.groupId, scopedRootOrgUnitIds),
  );
};

export const aggregateHierarchyRows = (input: {
  comparisonRows: readonly ReportingComparisonMetricRow[];
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>;
  focusOrgUnitId?: string | undefined;
  level: TenantOrgUnitRecord["unitType"];
  scopedRootOrgUnitIds: readonly string[];
}): ReportingHierarchyMetricRow[] => {
  const focusOrgUnit =
    input.focusOrgUnitId === undefined
      ? null
      : (input.orgUnitsById.get(input.focusOrgUnitId) ?? null);

  if (input.focusOrgUnitId !== undefined && focusOrgUnit === null) {
    throw new Error(`Org unit ${input.focusOrgUnitId} is missing from the reporting hierarchy`);
  }

  if (
    focusOrgUnit !== null &&
    ORG_UNIT_HIERARCHY_DEPTH[focusOrgUnit.unitType] > ORG_UNIT_HIERARCHY_DEPTH[input.level]
  ) {
    throw new Error("focusOrgUnitId must be at or above the requested hierarchy level");
  }

  const groups = new Map<
    string,
    {
      orgUnit: TenantOrgUnitRecord;
      issuedCount: number;
      publicBadgeViewCount: number;
      verificationViewCount: number;
      shareClickCount: number;
      learnerClaimCount: number;
      walletAcceptCount: number;
      weightedClaimRateTotal: number;
      weightedShareRateTotal: number;
    }
  >();

  for (const row of input.comparisonRows) {
    const lineage = listOrgUnitLineage(input.orgUnitsById, row.groupId);

    if (focusOrgUnit !== null && !lineage.some((orgUnit) => orgUnit.id === focusOrgUnit.id)) {
      continue;
    }

    if (
      input.scopedRootOrgUnitIds.length > 0 &&
      !input.scopedRootOrgUnitIds.some((rootOrgUnitId) =>
        lineage.some((orgUnit) => orgUnit.id === rootOrgUnitId),
      )
    ) {
      continue;
    }

    const targetOrgUnit = lineage.find((orgUnit) => orgUnit.unitType === input.level);

    if (targetOrgUnit === undefined) {
      continue;
    }

    const group =
      groups.get(targetOrgUnit.id) ??
      (() => {
        const created = {
          orgUnit: targetOrgUnit,
          issuedCount: 0,
          publicBadgeViewCount: 0,
          verificationViewCount: 0,
          shareClickCount: 0,
          learnerClaimCount: 0,
          walletAcceptCount: 0,
          weightedClaimRateTotal: 0,
          weightedShareRateTotal: 0,
        };
        groups.set(targetOrgUnit.id, created);
        return created;
      })();

    group.issuedCount += row.issuedCount;
    group.publicBadgeViewCount += row.publicBadgeViewCount;
    group.verificationViewCount += row.verificationViewCount;
    group.shareClickCount += row.shareClickCount;
    group.learnerClaimCount += row.learnerClaimCount;
    group.walletAcceptCount += row.walletAcceptCount;
    group.weightedClaimRateTotal += row.claimRate * row.issuedCount;
    group.weightedShareRateTotal += row.shareRate * row.issuedCount;
  }

  return Array.from(groups.values())
    .map((group) => {
      const issuedCount = group.issuedCount;
      return {
        level: input.level,
        orgUnitId: group.orgUnit.id,
        displayName: group.orgUnit.displayName,
        parentOrgUnitId: group.orgUnit.parentOrgUnitId,
        issuedCount,
        publicBadgeViewCount: group.publicBadgeViewCount,
        verificationViewCount: group.verificationViewCount,
        shareClickCount: group.shareClickCount,
        learnerClaimCount: group.learnerClaimCount,
        walletAcceptCount: group.walletAcceptCount,
        claimRate: issuedCount === 0 ? 0 : group.weightedClaimRateTotal / issuedCount,
        shareRate: issuedCount === 0 ? 0 : group.weightedShareRateTotal / issuedCount,
      };
    })
    .sort((left, right) => {
      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    });
};
