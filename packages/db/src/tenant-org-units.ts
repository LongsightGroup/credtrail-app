import {
  formatAllowedParentOrgUnitTypes,
  isAllowedParentOrgUnitType,
  orgUnitTypeListSortOrder,
  requiresParentOrgUnit,
} from "@credtrail/validation";
import type { OrgUnitType } from "@credtrail/validation";
import { createPrefixedId } from "./shared-helpers";
import { TenantOrgUnitValidationError } from "./tenant-org-unit-errors.js";
import type { SqlDatabase, SqlQueryResult } from "./tenant-scope";

export type { OrgUnitType };

export interface TenantOrgUnitRecord {
  id: string;
  tenantId: string;
  unitType: OrgUnitType;
  slug: string;
  displayName: string;
  parentOrgUnitId: string | null;
  createdByUserId: string | null;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateTenantOrgUnitInput {
  tenantId: string;
  unitType: OrgUnitType;
  slug: string;
  displayName: string;
  parentOrgUnitId?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface ListTenantOrgUnitsInput {
  tenantId: string;
  includeInactive?: boolean | undefined;
}

interface TenantOrgUnitRow {
  id: string;
  tenantId: string;
  unitType: OrgUnitType;
  slug: string;
  displayName: string;
  parentOrgUnitId: string | null;
  createdByUserId: string | null;
  isActive: number | boolean;
  createdAt: string;
  updatedAt: string;
}

const TENANT_ORG_UNIT_SELECT_COLUMNS = `
  id,
  tenant_id AS tenantId,
  unit_type AS unitType,
  slug,
  display_name AS displayName,
  parent_org_unit_id AS parentOrgUnitId,
  created_by_user_id AS createdByUserId,
  is_active AS isActive,
  created_at AS createdAt,
  updated_at AS updatedAt
`;

export const institutionOrgUnitIdForTenant = (tenantId: string): string => {
  return `${tenantId}:org:institution`;
};

const mapTenantOrgUnitRow = (row: TenantOrgUnitRow): TenantOrgUnitRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    unitType: row.unitType,
    slug: row.slug,
    displayName: row.displayName,
    parentOrgUnitId: row.parentOrgUnitId,
    createdByUserId: row.createdByUserId,
    isActive: row.isActive === 1 || row.isActive === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

export const findTenantOrgUnitById = async (
  db: SqlDatabase,
  tenantId: string,
  orgUnitId: string,
): Promise<TenantOrgUnitRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${TENANT_ORG_UNIT_SELECT_COLUMNS}
      FROM tenant_org_units
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, orgUnitId)
    .first<TenantOrgUnitRow>();

  return row === null ? null : mapTenantOrgUnitRow(row);
};

export const findTenantOrgUnitBySlug = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly slug: string;
  },
): Promise<TenantOrgUnitRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        ${TENANT_ORG_UNIT_SELECT_COLUMNS}
      FROM tenant_org_units
      WHERE tenant_id = ?
        AND slug = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.slug)
    .first<TenantOrgUnitRow>();

  return row === null ? null : mapTenantOrgUnitRow(row);
};

export const ensureInstitutionOrgUnitForTenant = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<string> => {
  const institutionId = institutionOrgUnitIdForTenant(tenantId);
  const nowIso = new Date().toISOString();
  await db
    .prepare(
      `
      INSERT INTO tenant_org_units (
        id,
        tenant_id,
        unit_type,
        slug,
        display_name,
        parent_org_unit_id,
        created_by_user_id,
        is_active,
        created_at,
        updated_at
      )
      VALUES (?, ?, 'institution', 'institution', ?, NULL, NULL, 1, ?, ?)
      ON CONFLICT DO NOTHING
    `,
    )
    .bind(institutionId, tenantId, `${tenantId} Institution`, nowIso, nowIso)
    .run();

  return institutionId;
};

export const createTenantOrgUnit = async (
  db: SqlDatabase,
  input: CreateTenantOrgUnitInput,
): Promise<TenantOrgUnitRecord> => {
  if (!requiresParentOrgUnit(input.unitType) && input.parentOrgUnitId !== undefined) {
    throw new TenantOrgUnitValidationError(
      "parent_not_permitted",
      `Org unit type ${input.unitType} cannot have a parent org unit`,
    );
  }

  if (requiresParentOrgUnit(input.unitType) && input.parentOrgUnitId === undefined) {
    throw new TenantOrgUnitValidationError(
      "parent_required",
      `Org unit type ${input.unitType} requires parent org unit type ${formatAllowedParentOrgUnitTypes(
        input.unitType,
      )}`,
    );
  }

  if (input.parentOrgUnitId !== undefined) {
    const parent = await findTenantOrgUnitById(db, input.tenantId, input.parentOrgUnitId);

    if (parent === null) {
      throw new TenantOrgUnitValidationError(
        "parent_not_found",
        `Parent org unit ${input.parentOrgUnitId} not found for tenant ${input.tenantId}`,
      );
    }

    if (!isAllowedParentOrgUnitType(input.unitType, parent.unitType)) {
      throw new TenantOrgUnitValidationError(
        "parent_type_not_allowed",
        `Org unit type ${input.unitType} requires parent org unit type ${formatAllowedParentOrgUnitTypes(
          input.unitType,
        )}`,
      );
    }

    if (!parent.isActive) {
      throw new TenantOrgUnitValidationError(
        "parent_inactive",
        `Parent org unit ${input.parentOrgUnitId} is inactive for tenant ${input.tenantId}`,
      );
    }
  }

  const id = createPrefixedId("ou");
  const nowIso = new Date().toISOString();
  await db
    .prepare(
      `
      INSERT INTO tenant_org_units (
        id,
        tenant_id,
        unit_type,
        slug,
        display_name,
        parent_org_unit_id,
        created_by_user_id,
        is_active,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.unitType,
      input.slug,
      input.displayName,
      input.parentOrgUnitId ?? null,
      input.createdByUserId ?? null,
      nowIso,
      nowIso,
    )
    .run();

  const orgUnit = await findTenantOrgUnitById(db, input.tenantId, id);

  if (orgUnit === null) {
    throw new Error(`Unable to create org unit ${id} for tenant ${input.tenantId}`);
  }

  return orgUnit;
};

export const listTenantOrgUnits = async (
  db: SqlDatabase,
  input: ListTenantOrgUnitsInput,
): Promise<TenantOrgUnitRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<TenantOrgUnitRow>> =>
    db
      .prepare(
        `
        SELECT
          ${TENANT_ORG_UNIT_SELECT_COLUMNS}
        FROM tenant_org_units
        WHERE tenant_id = ?
          AND (? = 1 OR is_active = 1)
        ORDER BY
          CASE unit_type
            WHEN 'institution' THEN ${orgUnitTypeListSortOrder("institution")}
            WHEN 'college' THEN ${orgUnitTypeListSortOrder("college")}
            WHEN 'department' THEN ${orgUnitTypeListSortOrder("department")}
            WHEN 'program' THEN ${orgUnitTypeListSortOrder("program")}
            WHEN 'course' THEN ${orgUnitTypeListSortOrder("course")}
            ELSE 99
          END,
          display_name ASC,
          created_at ASC
      `,
      )
      .bind(input.tenantId, input.includeInactive === true ? 1 : 0)
      .all<TenantOrgUnitRow>();

  let result = await listStatement();

  if (result.results.length === 0) {
    await ensureInstitutionOrgUnitForTenant(db, input.tenantId);
    result = await listStatement();
  }

  return result.results.map((row) => mapTenantOrgUnitRow(row));
};
