import { findTenantOrgUnitById, type TenantOrgUnitRecord } from "./tenant-org-units.js";
import type { SqlDatabase } from "./tenant-scope";

export const resolveActiveRuleOrgUnit = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly orgUnitId: string;
  },
): Promise<TenantOrgUnitRecord> => {
  const orgUnit = await findTenantOrgUnitById(db, input.tenantId, input.orgUnitId);

  if (orgUnit === null) {
    throw new Error(`Org unit "${input.orgUnitId}" not found for tenant "${input.tenantId}"`);
  }

  if (!orgUnit.isActive) {
    throw new Error(`Org unit "${input.orgUnitId}" is inactive for tenant "${input.tenantId}"`);
  }

  return orgUnit;
};
