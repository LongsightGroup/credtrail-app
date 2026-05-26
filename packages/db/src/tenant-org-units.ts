import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export type OrgUnitType = "institution" | "college" | "department" | "program";

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

export const isMissingTenantOrgUnitsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_org_units")
  );
};

export const ensureTenantOrgUnitsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_org_units (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        unit_type TEXT NOT NULL CHECK (unit_type IN ('institution', 'college', 'department', 'program')),
        slug TEXT NOT NULL,
        display_name TEXT NOT NULL,
        parent_org_unit_id TEXT,
        created_by_user_id TEXT,
        is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, slug),
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (parent_org_unit_id) REFERENCES tenant_org_units (id) ON DELETE SET NULL,
        FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_tenant_org_units_tenant_type
        ON tenant_org_units (tenant_id, unit_type, is_active)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_tenant_org_units_tenant_parent
        ON tenant_org_units (tenant_id, parent_org_unit_id)
    `,
    )
    .run();
};

export const institutionOrgUnitIdForTenant = (tenantId: string): string => {
  return `${tenantId}:org:institution`;
};

const REQUIRED_PARENT_ORG_UNIT_TYPE: Record<OrgUnitType, OrgUnitType | null> = {
  institution: null,
  college: "institution",
  department: "college",
  program: "department",
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
  const findStatement = (): Promise<TenantOrgUnitRow | null> =>
    db
      .prepare(
        `
        SELECT
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
        FROM tenant_org_units
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, orgUnitId)
      .first<TenantOrgUnitRow>();

  let row: TenantOrgUnitRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingTenantOrgUnitsTableError(error)) {
      throw error;
    }

    await ensureTenantOrgUnitsTable(db);
    row = await findStatement();
  }

  return row === null ? null : mapTenantOrgUnitRow(row);
};

export const ensureInstitutionOrgUnitForTenant = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<string> => {
  const institutionId = institutionOrgUnitIdForTenant(tenantId);
  const nowIso = new Date().toISOString();
  const seedStatement = (): Promise<SqlRunResult> =>
    db
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

  try {
    await seedStatement();
  } catch (error: unknown) {
    if (!isMissingTenantOrgUnitsTableError(error)) {
      throw error;
    }

    await ensureTenantOrgUnitsTable(db);
    await seedStatement();
  }

  return institutionId;
};

export const createTenantOrgUnit = async (
  db: SqlDatabase,
  input: CreateTenantOrgUnitInput,
): Promise<TenantOrgUnitRecord> => {
  const requiredParentType = REQUIRED_PARENT_ORG_UNIT_TYPE[input.unitType];

  if (requiredParentType === null && input.parentOrgUnitId !== undefined) {
    throw new Error(`Org unit type ${input.unitType} cannot have a parent org unit`);
  }

  if (requiredParentType !== null && input.parentOrgUnitId === undefined) {
    throw new Error(
      `Org unit type ${input.unitType} requires parent org unit type ${requiredParentType}`,
    );
  }

  if (input.parentOrgUnitId !== undefined) {
    const parent = await findTenantOrgUnitById(db, input.tenantId, input.parentOrgUnitId);

    if (parent === null) {
      throw new Error(
        `Parent org unit ${input.parentOrgUnitId} not found for tenant ${input.tenantId}`,
      );
    }

    const expectedParentType = requiredParentType ?? "institution";

    if (parent.unitType !== expectedParentType) {
      throw new Error(
        `Org unit type ${input.unitType} requires parent org unit type ${expectedParentType}`,
      );
    }

    if (!parent.isActive) {
      throw new Error(
        `Parent org unit ${input.parentOrgUnitId} is inactive for tenant ${input.tenantId}`,
      );
    }
  }

  const id = createPrefixedId("ou");
  const nowIso = new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
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

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantOrgUnitsTableError(error)) {
      throw error;
    }

    await ensureTenantOrgUnitsTable(db);
    await insertStatement();
  }

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
        FROM tenant_org_units
        WHERE tenant_id = ?
          AND (? = 1 OR is_active = 1)
        ORDER BY
          CASE unit_type
            WHEN 'institution' THEN 1
            WHEN 'college' THEN 2
            WHEN 'department' THEN 3
            WHEN 'program' THEN 4
            ELSE 5
          END,
          display_name ASC,
          created_at ASC
      `,
      )
      .bind(input.tenantId, input.includeInactive === true ? 1 : 0)
      .all<TenantOrgUnitRow>();

  let result: SqlQueryResult<TenantOrgUnitRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingTenantOrgUnitsTableError(error)) {
      throw error;
    }

    await ensureTenantOrgUnitsTable(db);
    await ensureInstitutionOrgUnitForTenant(db, input.tenantId);
    result = await listStatement();
  }

  if (result.results.length === 0) {
    await ensureInstitutionOrgUnitForTenant(db, input.tenantId);
    result = await listStatement();
  }

  return result.results.map((row) => mapTenantOrgUnitRow(row));
};
