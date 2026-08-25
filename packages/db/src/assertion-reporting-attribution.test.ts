import { describe, expect, it } from "vitest";

import {
  findAssertionReportingAttributionByAssertionId,
  upsertAssertionReportingAttribution,
} from "./assertion-reporting-attribution";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

interface RecordedStatement {
  readonly sql: string;
  params: readonly unknown[];
}

const successfulRun = (): SqlRunResult => {
  return {
    success: true,
    meta: { rowsWritten: 0 },
  };
};

const createRecordingDatabase = (): {
  readonly db: SqlDatabase;
  readonly statements: readonly RecordedStatement[];
} => {
  const statements: RecordedStatement[] = [];
  const db: SqlDatabase = {
    prepare(sql) {
      const recorded: RecordedStatement = { sql, params: [] };
      statements.push(recorded);

      return {
        bind(...params) {
          recorded.params = params;
          return this;
        },
        async first<T>(): Promise<T | null> {
          return null;
        },
        async all<T>(): Promise<SqlQueryResult<T>> {
          return { ...successfulRun(), results: [] };
        },
        async run(): Promise<SqlRunResult> {
          return successfulRun();
        },
      };
    },
  };

  return { db, statements };
};

describe("assertion reporting attribution tenant scope", () => {
  it("binds the tenant to assertion attribution lookups", async () => {
    const recording = createRecordingDatabase();

    await expect(
      findAssertionReportingAttributionByAssertionId(recording.db, "tenant-a", "assertion-1"),
    ).resolves.toBeNull();

    expect(recording.statements).toHaveLength(1);
    expect(recording.statements[0]?.sql).toContain("AND tenant_id = ?");
    expect(recording.statements[0]?.params).toEqual(["assertion-1", "tenant-a"]);
  });

  it("does not transfer tenant ownership during an attribution conflict", async () => {
    const recording = createRecordingDatabase();

    await expect(
      upsertAssertionReportingAttribution(recording.db, {
        assertionId: "assertion-1",
        tenantId: "tenant-b",
        badgeTemplateId: "badge-1",
        orgUnitId: "org-1",
        attributionSource: "issuance_snapshot",
        attributedAt: "2026-08-25T12:00:00.000Z",
      }),
    ).rejects.toThrow("Unable to load reporting attribution");

    expect(recording.statements).toHaveLength(2);
    const upsertSql = recording.statements[0]?.sql ?? "";
    expect(upsertSql).not.toMatch(/DO UPDATE SET\s+tenant_id\s*=/u);
    expect(upsertSql).toContain(
      "WHERE assertion_reporting_attributions.tenant_id = excluded.tenant_id",
    );
    expect(recording.statements[1]?.params).toEqual(["assertion-1", "tenant-b"]);
  });
});
