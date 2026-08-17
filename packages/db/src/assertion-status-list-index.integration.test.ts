import { expect, it } from "vitest";
import { reserveAssertionStatusListIndex } from "./assertion-writes";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
} from "./postgres-test-support";

describeDbIntegration("assertion status-list index reservation with Postgres", () => {
  it("returns distinct sequential indexes under concurrent reservation", async () => {
    const fixture = await createTestTenantFixture();

    try {
      const indexes = await Promise.all(
        Array.from({ length: 32 }, () =>
          reserveAssertionStatusListIndex(fixture.db, fixture.tenantId),
        ),
      );

      expect([...indexes].sort((left, right) => left - right)).toEqual(
        Array.from({ length: 32 }, (_, index) => index),
      );
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });

  it("maintains independent counters for each tenant", async () => {
    const firstFixture = await createTestTenantFixture();
    const secondFixture = await createTestTenantFixture();

    try {
      const [firstTenantIndex, nextFirstTenantIndex, secondTenantIndex] = await Promise.all([
        reserveAssertionStatusListIndex(firstFixture.db, firstFixture.tenantId),
        reserveAssertionStatusListIndex(firstFixture.db, firstFixture.tenantId),
        reserveAssertionStatusListIndex(secondFixture.db, secondFixture.tenantId),
      ]);

      expect([firstTenantIndex, nextFirstTenantIndex].sort((left, right) => left - right)).toEqual([
        0, 1,
      ]);
      expect(secondTenantIndex).toBe(0);
    } finally {
      await cleanupTestResources(firstFixture.db, {
        tenantIds: [firstFixture.tenantId, secondFixture.tenantId],
      });
    }
  });
});
