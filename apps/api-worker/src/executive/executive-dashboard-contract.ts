import type { TenantOrgUnitRecord } from "@credtrail/db";
import type {
  ExecutiveDashboardAudience,
  ExecutiveDashboardWindow,
  OrgUnitType,
  TenantExecutiveDashboardQuery,
} from "@credtrail/validation";

import type {
  ReportingHierarchyPageFilters,
  ReportingPageFilters,
} from "../reporting/reporting-page-filters";
import { createReportingHierarchyPageFilters } from "../reporting/reporting-page-filters";

const EXECUTIVE_WINDOW_DAYS: Record<ExecutiveDashboardWindow, number> = {
  "last-30-days": 30,
  "last-90-days": 90,
};

const DEFAULT_EXECUTIVE_WINDOW: ExecutiveDashboardWindow = "last-90-days";

const ORG_UNIT_DEPTH: Record<OrgUnitType, number> = {
  institution: 0,
  college: 1,
  department: 2,
  program: 3,
};

export interface InferExecutiveDashboardDefaultsInput {
  today: string;
  query: TenantExecutiveDashboardQuery;
  visibility: "tenant" | "scoped";
  scopedOrgUnitIds: readonly string[];
  orgUnits: readonly TenantOrgUnitRecord[];
}

export interface ExecutiveDashboardDefaults {
  audience: ExecutiveDashboardAudience;
  window: ExecutiveDashboardWindow | "custom";
  focusOrgUnitId: string;
  focusUnitType: OrgUnitType;
  comparisonLevel: OrgUnitType;
  comparisonGroupBy: "orgUnit";
  reportingFilters: ReportingPageFilters;
  hierarchyFilters: ReportingHierarchyPageFilters;
  pathState: ExecutiveDashboardPathState;
}

export interface ExecutiveDashboardPathState extends Partial<
  Pick<
    TenantExecutiveDashboardQuery,
    | "window"
    | "audience"
    | "issuedFrom"
    | "issuedTo"
    | "badgeTemplateId"
    | "orgUnitId"
    | "state"
    | "focusOrgUnitId"
    | "comparisonLevel"
  >
> {
  audience: ExecutiveDashboardAudience;
  focusOrgUnitId: string;
  comparisonLevel: OrgUnitType;
}

export const toExecutiveOrgUnitsById = (
  orgUnits: readonly TenantOrgUnitRecord[],
): ReadonlyMap<string, TenantOrgUnitRecord> => {
  return new Map(
    orgUnits.filter((orgUnit) => orgUnit.isActive).map((orgUnit) => [orgUnit.id, orgUnit] as const),
  );
};

const subtractUtcDays = (isoDate: string, days: number): string => {
  const date = new Date(`${isoDate}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() - days);
  return date.toISOString().slice(0, 10);
};

const isDescendantOf = (
  orgUnitId: string,
  ancestorOrgUnitId: string,
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
): boolean => {
  let currentOrgUnitId: string | null = orgUnitId;

  while (currentOrgUnitId !== null) {
    if (currentOrgUnitId === ancestorOrgUnitId) {
      return true;
    }

    currentOrgUnitId = orgUnitsById.get(currentOrgUnitId)?.parentOrgUnitId ?? null;
  }

  return false;
};

const getOrgUnitDepth = (
  orgUnitId: string,
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
): number => {
  let depth = 0;
  let currentOrgUnitId = orgUnitsById.get(orgUnitId)?.parentOrgUnitId ?? null;

  while (currentOrgUnitId !== null) {
    depth += 1;
    currentOrgUnitId = orgUnitsById.get(currentOrgUnitId)?.parentOrgUnitId ?? null;
  }

  return depth;
};

const sortOrgUnitIdsByDepthThenId = (
  orgUnitIds: readonly string[],
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
): string[] => {
  return [...orgUnitIds].sort((left, right) => {
    const depthDiff = getOrgUnitDepth(left, orgUnitsById) - getOrgUnitDepth(right, orgUnitsById);

    if (depthDiff !== 0) {
      return depthDiff;
    }

    return left.localeCompare(right);
  });
};

export const resolveExecutiveVisibleOrgUnitIds = (
  input: Pick<InferExecutiveDashboardDefaultsInput, "visibility" | "scopedOrgUnitIds"> & {
    orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>;
  },
): Set<string> => {
  if (input.visibility === "tenant") {
    return new Set(input.orgUnitsById.keys());
  }

  const visibleOrgUnitIds = new Set<string>();

  for (const orgUnitId of input.orgUnitsById.keys()) {
    if (
      input.scopedOrgUnitIds.some((scopedOrgUnitId) =>
        isDescendantOf(orgUnitId, scopedOrgUnitId, input.orgUnitsById),
      )
    ) {
      visibleOrgUnitIds.add(orgUnitId);
    }
  }

  return visibleOrgUnitIds;
};

const resolveDefaultFocusOrgUnitId = (
  input: Pick<InferExecutiveDashboardDefaultsInput, "visibility" | "scopedOrgUnitIds"> & {
    orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>;
  },
): string => {
  if (input.visibility === "tenant") {
    const institutionRoot = [...input.orgUnitsById.values()].find(
      (orgUnit) => orgUnit.unitType === "institution",
    );

    if (institutionRoot !== undefined) {
      return institutionRoot.id;
    }

    const rootIds = [...input.orgUnitsById.values()]
      .filter((orgUnit) => {
        return orgUnit.parentOrgUnitId === null || !input.orgUnitsById.has(orgUnit.parentOrgUnitId);
      })
      .map((orgUnit) => orgUnit.id);

    const [fallbackRootId] = sortOrgUnitIdsByDepthThenId(rootIds, input.orgUnitsById);

    if (fallbackRootId !== undefined) {
      return fallbackRootId;
    }
  }

  const scopedRootIds = sortOrgUnitIdsByDepthThenId(
    input.scopedOrgUnitIds.filter((orgUnitId) => input.orgUnitsById.has(orgUnitId)),
    input.orgUnitsById,
  );
  const [fallbackScopedRootId] = scopedRootIds;

  if (fallbackScopedRootId !== undefined) {
    return fallbackScopedRootId;
  }

  throw new Error("Executive dashboard defaults require at least one visible org unit");
};

const resolveFocusOrgUnitId = (
  input: InferExecutiveDashboardDefaultsInput & {
    orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>;
    visibleOrgUnitIds: ReadonlySet<string>;
  },
): string => {
  if (
    input.query.focusOrgUnitId !== undefined &&
    input.visibleOrgUnitIds.has(input.query.focusOrgUnitId)
  ) {
    return input.query.focusOrgUnitId;
  }

  return resolveDefaultFocusOrgUnitId(input);
};

const resolveWindowFilters = (
  today: string,
  query: TenantExecutiveDashboardQuery,
): Pick<ExecutiveDashboardDefaults, "window" | "reportingFilters"> => {
  if (query.issuedFrom !== undefined || query.issuedTo !== undefined) {
    return {
      window: "custom",
      reportingFilters: {
        issuedFrom: query.issuedFrom,
        issuedTo: query.issuedTo,
        badgeTemplateId: query.badgeTemplateId,
        orgUnitId: query.orgUnitId,
        state: query.state,
      },
    };
  }

  const window = query.window ?? DEFAULT_EXECUTIVE_WINDOW;
  const issuedTo = today;
  const issuedFrom = subtractUtcDays(today, EXECUTIVE_WINDOW_DAYS[window] - 1);

  return {
    window,
    reportingFilters: {
      issuedFrom,
      issuedTo,
      badgeTemplateId: query.badgeTemplateId,
      orgUnitId: query.orgUnitId,
      state: query.state,
    },
  };
};

export const resolveExecutiveComparisonLevel = (input: {
  focusOrgUnitId: string;
  visibleOrgUnitIds: ReadonlySet<string>;
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>;
}): OrgUnitType => {
  const focusOrgUnit = input.orgUnitsById.get(input.focusOrgUnitId);

  if (focusOrgUnit === undefined) {
    throw new Error(`Executive focus org unit ${input.focusOrgUnitId} was not found`);
  }

  const descendantLevels = [...input.visibleOrgUnitIds]
    .filter(
      (orgUnitId) =>
        orgUnitId !== input.focusOrgUnitId &&
        isDescendantOf(orgUnitId, input.focusOrgUnitId, input.orgUnitsById),
    )
    .map((orgUnitId) => input.orgUnitsById.get(orgUnitId)?.unitType)
    .filter((unitType): unitType is OrgUnitType => unitType !== undefined);

  for (const unitType of ["college", "department", "program"] as const) {
    if (
      ORG_UNIT_DEPTH[unitType] > ORG_UNIT_DEPTH[focusOrgUnit.unitType] &&
      descendantLevels.includes(unitType)
    ) {
      return unitType;
    }
  }

  return focusOrgUnit.unitType;
};

const resolveAudience = (input: {
  query: TenantExecutiveDashboardQuery;
  visibility: InferExecutiveDashboardDefaultsInput["visibility"];
  focusOrgUnitId: string;
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>;
}): ExecutiveDashboardAudience => {
  const focusUnitType = input.orgUnitsById.get(input.focusOrgUnitId)?.unitType ?? "institution";

  if (
    input.query.audience !== undefined &&
    input.visibility === "tenant" &&
    focusUnitType === "institution" &&
    (input.query.audience === "system" || input.query.audience === "institution")
  ) {
    return input.query.audience;
  }

  if (input.visibility === "tenant") {
    return "system";
  }

  return focusUnitType;
};

export const inferExecutiveDashboardDefaults = (
  input: InferExecutiveDashboardDefaultsInput,
): ExecutiveDashboardDefaults => {
  const orgUnitsById = toExecutiveOrgUnitsById(input.orgUnits);
  const visibleOrgUnitIds = resolveExecutiveVisibleOrgUnitIds({
    visibility: input.visibility,
    scopedOrgUnitIds: input.scopedOrgUnitIds,
    orgUnitsById,
  });
  const focusOrgUnitId = resolveFocusOrgUnitId({
    ...input,
    orgUnitsById,
    visibleOrgUnitIds,
  });
  const { window, reportingFilters } = resolveWindowFilters(input.today, input.query);
  const comparisonLevel = resolveExecutiveComparisonLevel({
    focusOrgUnitId,
    visibleOrgUnitIds,
    orgUnitsById,
  });
  const focusUnitType = orgUnitsById.get(focusOrgUnitId)?.unitType;

  if (focusUnitType === undefined) {
    throw new Error(`Executive focus org unit ${focusOrgUnitId} was not found`);
  }

  const audience = resolveAudience({
    query: input.query,
    visibility: input.visibility,
    focusOrgUnitId,
    orgUnitsById,
  });
  const hierarchyFilters = createReportingHierarchyPageFilters(reportingFilters, {
    focusOrgUnitId,
    level: comparisonLevel,
  });
  const pathState: ExecutiveDashboardPathState = {
    audience,
    focusOrgUnitId,
    comparisonLevel,
    ...(reportingFilters.badgeTemplateId === undefined
      ? {}
      : {
          badgeTemplateId: reportingFilters.badgeTemplateId,
        }),
    ...(reportingFilters.orgUnitId === undefined
      ? {}
      : {
          orgUnitId: reportingFilters.orgUnitId,
        }),
    ...(reportingFilters.state === undefined
      ? {}
      : {
          state: reportingFilters.state,
        }),
    ...(window === "custom"
      ? {
          issuedFrom: reportingFilters.issuedFrom,
          issuedTo: reportingFilters.issuedTo,
        }
      : {
          window,
        }),
  };

  return {
    audience,
    window,
    focusOrgUnitId,
    focusUnitType,
    comparisonLevel,
    comparisonGroupBy: "orgUnit",
    reportingFilters,
    hierarchyFilters,
    pathState,
  };
};
