import { expect, it } from "vitest";
import { enqueueOrReplayJobQueueMessage } from "./job-queue";
import {
  cleanupTestResources,
  countRows,
  createTestTenantFixture,
  describeDbIntegration,
  uniqueTestId,
} from "./postgres-test-support";

describeDbIntegration("queue command idempotency", () => {
  it("returns the original immutable command when an idempotency key is replayed", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Queue Replay University" });
    const idempotencyKey = uniqueTestId("queue-replay");

    try {
      const first = await enqueueOrReplayJobQueueMessage(fixture.db, {
        tenantId: fixture.tenantId,
        jobType: "issue_badge",
        idempotencyKey,
        payload: {
          assertionId: "assertion_original",
          snapshot: { title: "Original badge" },
        },
      });
      const replay = await enqueueOrReplayJobQueueMessage(fixture.db, {
        tenantId: fixture.tenantId,
        jobType: "issue_badge",
        idempotencyKey,
        payload: {
          assertionId: "assertion_reallocated",
          snapshot: { title: "Changed badge" },
        },
      });

      expect(replay).toEqual(first);
      expect(JSON.parse(replay.payloadJson)).toEqual({
        assertionId: "assertion_original",
        snapshot: { title: "Original badge" },
      });
      await expect(
        countRows(fixture.db, "job_queue_messages", "tenant_id = ?", [fixture.tenantId]),
      ).resolves.toBe(1);
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });

  it("atomically returns one immutable command to concurrent callers", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Concurrent Queue University" });
    const idempotencyKey = uniqueTestId("queue-concurrent-replay");

    try {
      const [first, second] = await Promise.all([
        enqueueOrReplayJobQueueMessage(fixture.db, {
          tenantId: fixture.tenantId,
          jobType: "issue_badge",
          idempotencyKey,
          payload: {
            assertionId: "assertion_first",
            snapshot: { title: "First badge" },
          },
        }),
        enqueueOrReplayJobQueueMessage(fixture.db, {
          tenantId: fixture.tenantId,
          jobType: "issue_badge",
          idempotencyKey,
          payload: {
            assertionId: "assertion_second",
            snapshot: { title: "Second badge" },
          },
        }),
      ]);

      expect(second).toEqual(first);
      expect(["assertion_first", "assertion_second"]).toContain(
        JSON.parse(first.payloadJson).assertionId,
      );
      await expect(
        countRows(fixture.db, "job_queue_messages", "tenant_id = ?", [fixture.tenantId]),
      ).resolves.toBe(1);
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });
});
