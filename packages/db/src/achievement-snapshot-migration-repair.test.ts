import { describe, expect, it } from "vitest";

import {
  ACHIEVEMENT_SNAPSHOT_MIGRATION,
  ACHIEVEMENT_SNAPSHOT_REPAIR,
  verifyAchievementSnapshotMigrationRepairHistory,
} from "../scripts/achievement-snapshot-migration-repair.mjs";

const repair = {
  fileName: ACHIEVEMENT_SNAPSHOT_REPAIR,
  checksum: "d0ec36a6b745087844f93726329d16ad297aeaa67d0176a9559f59d589fb4017",
};

describe("verifyAchievementSnapshotMigrationRepairHistory", () => {
  it("accepts the committed repair audit row", () => {
    expect(() =>
      verifyAchievementSnapshotMigrationRepairHistory(
        [
          {
            repair_version: ACHIEVEMENT_SNAPSHOT_REPAIR,
            blocked_version: ACHIEVEMENT_SNAPSHOT_MIGRATION,
            repair_checksum: repair.checksum,
          },
        ],
        repair,
      ),
    ).not.toThrow();
  });

  it("rejects changed repair history", () => {
    expect(() =>
      verifyAchievementSnapshotMigrationRepairHistory(
        [
          {
            repair_version: ACHIEVEMENT_SNAPSHOT_REPAIR,
            blocked_version: ACHIEVEMENT_SNAPSHOT_MIGRATION,
            repair_checksum: "0".repeat(64),
          },
        ],
        repair,
      ),
    ).toThrow("Applied achievement snapshot migration repair does not match source");
  });
});
