import type { OrgUnitType } from "./primitives.js";

export const ORG_UNIT_HIERARCHY_DEPTH: Record<OrgUnitType, number> = {
  institution: 0,
  college: 1,
  department: 2,
  program: 3,
  course: 4,
};

export const ORG_UNIT_LABELS: Record<OrgUnitType, { singular: string; plural: string }> = {
  institution: {
    singular: "institution",
    plural: "institutions",
  },
  college: {
    singular: "college",
    plural: "colleges",
  },
  department: {
    singular: "department",
    plural: "departments",
  },
  program: {
    singular: "program",
    plural: "programs",
  },
  course: {
    singular: "course",
    plural: "courses",
  },
};

export const ALLOWED_PARENT_ORG_UNIT_TYPES: Record<OrgUnitType, readonly OrgUnitType[]> = {
  institution: [],
  college: ["institution"],
  department: ["college"],
  program: ["department"],
  course: ["department", "program"],
};

export const ORG_UNIT_COMPARISON_LEVELS = [
  "college",
  "department",
  "program",
  "course",
] as const satisfies readonly Exclude<OrgUnitType, "institution">[];

export const formatAllowedParentOrgUnitTypes = (unitType: OrgUnitType): string => {
  return ALLOWED_PARENT_ORG_UNIT_TYPES[unitType].join(" or ");
};

export const requiresParentOrgUnit = (unitType: OrgUnitType): boolean => {
  return ALLOWED_PARENT_ORG_UNIT_TYPES[unitType].length > 0;
};

export const isAllowedParentOrgUnitType = (
  unitType: OrgUnitType,
  parentUnitType: OrgUnitType,
): boolean => {
  return ALLOWED_PARENT_ORG_UNIT_TYPES[unitType].includes(parentUnitType);
};

export const orgUnitTypeListSortOrder = (unitType: OrgUnitType): number => {
  return ORG_UNIT_HIERARCHY_DEPTH[unitType] + 1;
};
