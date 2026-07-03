import type { SqlDatabase, SqlQueryResult } from "./tenant-scope";
import {
  buildScopedDescendantsCte,
  ORG_ANCESTORS_BASE_CTE,
  ORG_ANCESTORS_WITH_DEPTH_CTE,
} from "./tenant-org-unit-hierarchy-sql.js";

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
      ${ORG_ANCESTORS_WITH_DEPTH_CTE}
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
      ${buildScopedDescendantsCte(rootValues)}
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
      ${ORG_ANCESTORS_BASE_CTE}
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
