import { expect, it } from "vitest";
import { reserveAssertionStatusListIndex } from "../packages/db/src/assertion-writes";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
} from "../packages/db/src/postgres-test-support";
import { reserveLocalSeedStatusListRange } from "./local-dev-status-list-counter";

describeDbIntegration("local demo status-list reservations", () => {
  it("skips the fixed demo range and never rewinds the allocator on reseeding", async () => {
    const fixture = await createTestTenantFixture();
    try {
      await reserveLocalSeedStatusListRange(fixture.db, fixture.tenantId, 7);
      const indexes = await Promise.all(
        Array.from({ length: 16 }, () =>
          reserveAssertionStatusListIndex(fixture.db, fixture.tenantId),
        ),
      );
      expect(indexes.sort((a, b) => a - b)).toEqual(
        Array.from({ length: 16 }, (_, index) => index + 8),
      );
      await reserveLocalSeedStatusListRange(fixture.db, fixture.tenantId, 7);
      expect(await reserveAssertionStatusListIndex(fixture.db, fixture.tenantId)).toBe(24);
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });
});
