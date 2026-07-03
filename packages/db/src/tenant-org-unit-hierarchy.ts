import type { SqlDatabase, SqlQueryResult } from "./tenant-scope";

interface TenantOrgUnitAncestorRow {
  orgUnitId: string;
  depth: number;
}

export const listTenantOrgUnitAncestorIdsFromSelf = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly orgUnitId: string;
  },
): Promise<string[]> => {
  const result: SqlQueryResult<TenantOrgUnitAncestorRow> = await db
    .prepare(
      `
      WITH RECURSIVE org_ancestors AS (
        SELECT id AS orgUnitId, parent_org_unit_id AS parentOrgUnitId, 0 AS depth
        FROM tenant_org_units
        WHERE tenant_id = ?
          AND id = ?

        UNION ALL

        SELECT parent.id AS orgUnitId, parent.parent_org_unit_id AS parentOrgUnitId, org_ancestors.depth + 1
        FROM tenant_org_units AS parent
        INNER JOIN org_ancestors
          ON org_ancestors.parentOrgUnitId = parent.id
        WHERE parent.tenant_id = ?
      )
      SELECT orgUnitId, depth
      FROM org_ancestors
      ORDER BY depth ASC
    `,
    )
    .bind(input.tenantId, input.orgUnitId, input.tenantId)
    .all<TenantOrgUnitAncestorRow>();

  return result.results.map((row) => row.orgUnitId);
};

export const listTenantOrgUnitDescendantIdsFromRoots = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly rootOrgUnitIds: readonly string[];
  },
): Promise<string[]> => {
  if (input.rootOrgUnitIds.length === 0) {
    return [];
  }

  const rootValues = input.rootOrgUnitIds.map(() => "(?)").join(", ");
  const result: SqlQueryResult<{ orgUnitId: string }> = await db
    .prepare(
      `
      WITH RECURSIVE scoped_roots(id) AS (
        VALUES ${rootValues}
      ),
      scoped_descendants AS (
        SELECT org_units.id AS orgUnitId
        FROM tenant_org_units AS org_units
        INNER JOIN scoped_roots
          ON scoped_roots.id = org_units.id
        WHERE org_units.tenant_id = ?

        UNION

        SELECT child.id AS orgUnitId
        FROM tenant_org_units AS child
        INNER JOIN scoped_descendants
          ON child.parent_org_unit_id = scoped_descendants.orgUnitId
        WHERE child.tenant_id = ?
      )
      SELECT orgUnitId
      FROM scoped_descendants
      ORDER BY orgUnitId ASC
    `,
    )
    .bind(...input.rootOrgUnitIds, input.tenantId, input.tenantId)
    .all<{ orgUnitId: string }>();

  return result.results.map((row) => row.orgUnitId);
};

export const isOrgUnitWithinAncestorScope = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly targetOrgUnitId: string;
    readonly scopedOrgUnitId: string;
  },
): Promise<boolean> => {
  const row = await db
    .prepare(
      `
      WITH RECURSIVE org_ancestors AS (
        SELECT id, parent_org_unit_id AS parentOrgUnitId
        FROM tenant_org_units
        WHERE tenant_id = ?
          AND id = ?

        UNION ALL

        SELECT parent.id, parent.parent_org_unit_id AS parentOrgUnitId
        FROM tenant_org_units parent
        INNER JOIN org_ancestors
          ON org_ancestors.parentOrgUnitId = parent.id
        WHERE parent.tenant_id = ?
      )
      SELECT id
      FROM org_ancestors
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.targetOrgUnitId, input.tenantId, input.scopedOrgUnitId)
    .first<{ id: string }>();

  return row !== null;
};
