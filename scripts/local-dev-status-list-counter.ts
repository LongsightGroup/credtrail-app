import type { SqlDatabase } from "../packages/db/src/tenant-scope";

/** Keep normal issuance beyond the fixed indexes embedded in signed demo credentials. */
export const reserveLocalSeedStatusListRange = async (
  db: SqlDatabase,
  tenantId: string,
  lastSeedIndex: number,
): Promise<void> => {
  await db
    .prepare(`
    INSERT INTO assertion_status_list_counters (tenant_id, next_index)
    VALUES (?, ?)
    ON CONFLICT (tenant_id) DO UPDATE
    SET next_index = GREATEST(assertion_status_list_counters.next_index, EXCLUDED.next_index)
  `)
    .bind(tenantId, lastSeedIndex + 1)
    .run();
};
