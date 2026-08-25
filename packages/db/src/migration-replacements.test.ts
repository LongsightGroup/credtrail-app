import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  LMS_PROVIDER_NARROWING_MIGRATION,
  LMS_PROVIDER_NARROWING_REPAIR,
  REPORTING_ATTRIBUTION_BACKFILL_MIGRATION,
  REPORTING_ATTRIBUTION_BACKFILL_REPAIR,
  verifyMigrationRepairHistory,
  type KnownMigrationRepair,
} from "../scripts/migration-replacements.mjs";

const knownRepairs = [
  {
    blockedVersion: REPORTING_ATTRIBUTION_BACKFILL_MIGRATION,
    repair: {
      fileName: REPORTING_ATTRIBUTION_BACKFILL_REPAIR,
      checksum: "1".repeat(64),
    },
  },
  {
    blockedVersion: LMS_PROVIDER_NARROWING_MIGRATION,
    repair: {
      fileName: LMS_PROVIDER_NARROWING_REPAIR,
      checksum: "2".repeat(64),
    },
  },
] satisfies readonly KnownMigrationRepair[];

describe("verifyMigrationRepairHistory", () => {
  it("accepts every known committed repair audit row", () => {
    expect(() =>
      verifyMigrationRepairHistory(
        knownRepairs.map(({ blockedVersion, repair }) => ({
          repair_version: repair.fileName,
          blocked_version: blockedVersion,
          repair_checksum: repair.checksum,
        })),
        knownRepairs,
      ),
    ).not.toThrow();
  });

  it("rejects a changed repair checksum", () => {
    expect(() =>
      verifyMigrationRepairHistory(
        [
          {
            repair_version: LMS_PROVIDER_NARROWING_REPAIR,
            blocked_version: LMS_PROVIDER_NARROWING_MIGRATION,
            repair_checksum: "0".repeat(64),
          },
        ],
        knownRepairs,
      ),
    ).toThrow(`Applied migration repair ${LMS_PROVIDER_NARROWING_REPAIR} does not match source`);
  });

  it("rejects repair history without a committed artifact", () => {
    expect(() =>
      verifyMigrationRepairHistory(
        [
          {
            repair_version: "0080_unknown_repair.sql",
            blocked_version: "0080_unknown_migration.sql",
            repair_checksum: "3".repeat(64),
          },
        ],
        knownRepairs,
      ),
    ).toThrow("Applied migration repair 0080_unknown_repair.sql is not a known artifact");
  });
});

describe("committed migration replacements", () => {
  it("bounds the reporting attribution backfill by assertion ID", () => {
    const sql = readFileSync(
      new URL(
        "../migration-repairs/0077_batch_assertion_reporting_attributions.sql",
        import.meta.url,
      ),
      "utf8",
    );

    expect(sql).toContain("batch_size CONSTANT INTEGER := 10000");
    expect(sql).toContain("assertions.id > batch_after_id");
    expect(sql).toContain("assertions.id <= batch_through_id");
    expect(sql).toContain("ON CONFLICT (assertion_id) DO NOTHING");
  });

  it("detaches 0078 dependents before adding checks for separate validation", () => {
    const repairSql = readFileSync(
      new URL(
        "../migration-repairs/0078_detach_dependents_and_narrow_lms_providers.sql",
        import.meta.url,
      ),
      "utf8",
    );
    const validationSql = readFileSync(
      new URL(
        "../migrations/0079_validate_badge_rule_lms_provider_constraints.sql",
        import.meta.url,
      ),
      "utf8",
    );

    expect(repairSql).toContain("DELETE FROM assertion_issuance_provenance");
    expect(repairSql).toContain("UPDATE lti_resource_link_placements");
    expect(repairSql.indexOf("DELETE FROM assertion_issuance_provenance")).toBeLessThan(
      repairSql.indexOf("DELETE FROM badge_issuance_rules"),
    );
    expect(repairSql.indexOf("UPDATE lti_resource_link_placements")).toBeLessThan(
      repairSql.indexOf("DELETE FROM badge_issuance_rules"),
    );
    expect(repairSql.match(/NOT VALID/g)).toHaveLength(3);
    expect(repairSql).not.toContain("VALIDATE CONSTRAINT");
    expect(validationSql.match(/VALIDATE CONSTRAINT/g)).toHaveLength(3);
  });
});
