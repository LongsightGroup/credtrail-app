import type { SqlDatabase } from "./tenant-scope";
import { ORG_ANCESTORS_BASE_CTE } from "./tenant-org-unit-hierarchy-sql.js";

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
