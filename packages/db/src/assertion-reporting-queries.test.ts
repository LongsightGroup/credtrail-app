import { describe, expect, it } from "vitest";

import { getTenantReportingEngagementCounts } from "./assertion-reporting-queries";
import type {
  SqlDatabase,
  SqlPreparedStatement,
  SqlQueryResult,
  SqlRunResult,
} from "./tenant-scope";

const successfulRun = (): SqlRunResult => ({
  success: true,
  meta: {},
});

const createAggregateDatabase = (row: unknown): SqlDatabase => {
  const statement: SqlPreparedStatement = {
    bind: () => statement,
    async first<T>(): Promise<T | null> {
      // SAFETY: This boundary fake intentionally supplies an untrusted database row to the
      // production parser; callers choose T through the same SqlDatabase seam used in production.
      return row as T;
    },
    async all<T>(): Promise<SqlQueryResult<T>> {
      return { ...successfulRun(), results: [] };
    },
    run: async () => successfulRun(),
  };

  return {
    prepare: () => statement,
  };
};

describe("assertion reporting query boundaries", () => {
  it("rejects null SQL counts instead of coercing them to zero", async () => {
    const db = createAggregateDatabase({
      issuedCount: 1,
      activeCount: 1,
      suspendedCount: 0,
      revokedCount: 0,
      pendingReviewCount: 0,
      publicBadgeViewCount: null,
      verificationViewCount: 0,
      shareClickCount: 0,
      learnerClaimCount: 0,
      walletAcceptCount: 0,
      shareEngagedCount: 0,
      claimEngagedCount: 0,
    });

    await expect(getTenantReportingEngagementCounts(db, { tenantId: "tenant-1" })).rejects.toThrow(
      "Reporting query returned an invalid public badge view count",
    );
  });
});
