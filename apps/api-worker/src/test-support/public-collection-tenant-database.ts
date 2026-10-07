import type { SqlDatabase, SqlPreparedStatement } from "@credtrail/db";

/** Supplies tenant rows through the SQL seam in the existing collection rendering suites. */
export const createPublicCollectionTenantDatabase = (): SqlDatabase => ({
  prepare: (sql) => {
    if (!sql.includes("FROM tenants")) throw new Error("Unexpected collection fixture query");
    let tenantId: unknown;
    const statement: SqlPreparedStatement = {
      bind: (id) => {
        tenantId = id;
        return statement;
      },
      first: async <T>(): Promise<T | null> => {
        if (typeof tenantId !== "string") throw new Error("Missing fixture tenant");
        const row = {
          id: tenantId,
          slug: tenantId,
          displayName: tenantId === "sakai" ? "Sakai Community" : "Example University",
          planTier: "team",
          issuerDomain: "example.edu",
          didWeb: "did:web:example.edu",
          isActive: true,
          createdAt: "2026-01-01T00:00:00.000Z",
          updatedAt: "2026-01-01T00:00:00.000Z",
        };
        // SAFETY: This SQL-boundary fixture returns the raw projection selected by findTenantById.
        return row as T;
      },
      all: async () => {
        throw new Error("Unexpected fixture list query");
      },
      run: async () => {
        throw new Error("Unexpected fixture write");
      },
    };
    return statement;
  },
});
