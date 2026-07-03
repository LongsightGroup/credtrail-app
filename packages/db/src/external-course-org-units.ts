import {
  createTenantOrgUnit,
  findTenantOrgUnitById,
  findTenantOrgUnitBySlug,
  type TenantOrgUnitRecord,
} from "./tenant-org-units.js";
import { isTenantOrgUnitValidationError } from "./tenant-org-unit-errors.js";
import type { SqlDatabase } from "./tenant-scope";

export type EnsureExternalCourseOrgUnitResult =
  | {
      status: "ok";
      orgUnit: TenantOrgUnitRecord;
    }
  | {
      status: "invalid_parent";
    }
  | {
      status: "slug_conflict";
      orgUnit: TenantOrgUnitRecord;
    };

const externalCourseOrgUnitSlug = (input: {
  readonly externalSystemId: string;
  readonly externalCourseId: string;
}): string => {
  const normalized = `${input.externalSystemId}-${input.externalCourseId}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  const bounded = normalized.length > 0 ? normalized.slice(0, 89).replace(/-+$/g, "") : "course";

  return `course-${bounded}`;
};

export const ensureExternalCourseOrgUnit = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly parentOrgUnitId: string;
    readonly externalSystemId: string;
    readonly externalCourseId: string;
    readonly courseTitle: string;
    readonly createdByUserId: string;
  },
): Promise<EnsureExternalCourseOrgUnitResult> => {
  const parentOrgUnit = await findTenantOrgUnitById(db, input.tenantId, input.parentOrgUnitId);

  if (parentOrgUnit === null || !parentOrgUnit.isActive) {
    return { status: "invalid_parent" };
  }

  const slug = externalCourseOrgUnitSlug({
    externalSystemId: input.externalSystemId,
    externalCourseId: input.externalCourseId,
  });
  const existing = await findTenantOrgUnitBySlug(db, {
    tenantId: input.tenantId,
    slug,
  });

  if (existing !== null) {
    if (
      existing.unitType !== "course" ||
      existing.parentOrgUnitId !== parentOrgUnit.id ||
      !existing.isActive
    ) {
      return { status: "slug_conflict", orgUnit: existing };
    }

    return { status: "ok", orgUnit: existing };
  }

  try {
    const orgUnit = await createTenantOrgUnit(db, {
      tenantId: input.tenantId,
      unitType: "course",
      slug,
      displayName: input.courseTitle,
      parentOrgUnitId: parentOrgUnit.id,
      createdByUserId: input.createdByUserId,
    });

    return { status: "ok", orgUnit };
  } catch (error: unknown) {
    if (isTenantOrgUnitValidationError(error)) {
      return { status: "invalid_parent" };
    }

    throw error;
  }
};
