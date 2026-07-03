export const buildScopedDescendantsCte = (rootValuesSql: string): string => {
  return `
      WITH RECURSIVE scoped_roots(id) AS (
        VALUES ${rootValuesSql}
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
  `;
};

export const ORG_ANCESTORS_WITH_DEPTH_CTE = `
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
`;

export const ORG_ANCESTORS_BASE_CTE = `
      WITH RECURSIVE org_ancestors AS (
        SELECT id, parent_org_unit_id AS parentOrgUnitId, 0 AS depth
        FROM tenant_org_units
        WHERE tenant_id = ?
          AND id = ?

        UNION ALL

        SELECT parent.id, parent.parent_org_unit_id AS parentOrgUnitId, org_ancestors.depth + 1
        FROM tenant_org_units AS parent
        INNER JOIN org_ancestors
          ON org_ancestors.parentOrgUnitId = parent.id
        WHERE parent.tenant_id = ?
      )
`;
