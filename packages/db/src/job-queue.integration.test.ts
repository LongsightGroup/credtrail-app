import { expect, it } from "vitest";
import { enqueueOrReplayJobQueueMessage, failJobQueueMessage } from "./job-queue";
import {
  cleanupTestResources,
  countRows,
  createTestTenantFixture,
  describeDbIntegration,
  uniqueTestId,
} from "./postgres-test-support";

describeDbIntegration("queue command idempotency", () => {
  it.each(["allowed", "never"] as const)("persists the failure retry policy: %s", async (retry) => {
    const fixture = await createTestTenantFixture();
    const nowIso = "2099-01-01T00:00:00.000Z";
    const leaseToken = uniqueTestId("lease");
    try {
      const message = await enqueueOrReplayJobQueueMessage(fixture.db, {
        tenantId: fixture.tenantId,
        jobType: "issue_badge",
        idempotencyKey: uniqueTestId("expiry-failure"),
        payload: {},
        maxAttempts: 8,
      });
      await fixture.db
        .prepare(
          "UPDATE job_queue_messages SET status = 'processing', attempt_count = 1, lease_token = ?, leased_until = ? WHERE id = ?",
        )
        .bind(leaseToken, nowIso, message.id)
        .run();
      // A stale worker cannot finalize a newer lease, even for a permanent failure.
      expect(
        await failJobQueueMessage(fixture.db, {
          id: message.id,
          leaseToken: "stale-lease",
          nowIso,
          error: "Expired before issuance",
          retryDelaySeconds: 30,
          retry,
        }),
      ).toBeNull();
      expect(
        await failJobQueueMessage(fixture.db, {
          id: message.id,
          leaseToken,
          nowIso,
          error: "Expired before issuance",
          retryDelaySeconds: 30,
          retry,
        }),
      ).toBe(retry === "never" ? "failed" : "pending");
      expect(
        await fixture.db
          .prepare(
            "SELECT failed_at AS failedAt, available_at AS availableAt, lease_token AS leaseToken FROM job_queue_messages WHERE id = ?",
          )
          .bind(message.id)
          .first(),
      ).toEqual({
        failedAt: retry === "never" ? nowIso : null,
        availableAt: retry === "never" ? message.availableAt : "2099-01-01T00:00:30.000Z",
        leaseToken: null,
      });
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });

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
