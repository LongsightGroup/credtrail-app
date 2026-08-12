import { Hono } from "hono";
import { expect, it } from "vitest";
import {
  cleanupTestResources,
  countRows,
  createTestTenantFixture,
  describeDbIntegration,
  uniqueTestId,
} from "../../../packages/db/src/postgres-test-support";
import type { AppBindings, AppEnv } from "./app";
import { createPostgresQueueIngressStore } from "./queue/ingress-store";
import { processQueueInputWithDefaults, readJsonBodyOrEmptyObject } from "./queue/processing";
import { registerQueueRoutes } from "./routes/queue-routes";
import { createBadgeTemplateArtworkBucket } from "./test-support/badge-template-artwork-bucket";

interface QueuedRevokeResponse {
  readonly status: "queued";
  readonly jobType: "revoke_badge";
  readonly assertionId: string;
  readonly revocationId: string;
  readonly idempotencyKey: string;
}

const createEnv = (): AppBindings => ({
  APP_ENV: "test",
  BADGE_OBJECTS: createBadgeTemplateArtworkBucket(),
  JOB_PROCESSOR_TOKEN: "processor-secret",
  PLATFORM_DOMAIN: "credtrail.test",
  PUBLIC_APP_ORIGIN: "https://credtrail.test",
});

describeDbIntegration("queue ingress HTTP idempotency", () => {
  it("returns one persisted command to concurrent requests", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Queue Ingress University" });
    const idempotencyKey = uniqueTestId("queue-http-concurrent");
    const assertionId = `${fixture.tenantId}:assertion_123`;
    const app = new Hono<AppEnv>();

    registerQueueRoutes({
      app,
      resolveQueueIngressStore: () => createPostgresQueueIngressStore(fixture.db),
      sha256Hex: () => Promise.resolve("unused"),
      readJsonBodyOrEmptyObject,
      processQueuedJobs: () =>
        Promise.resolve({
          leased: 0,
          processed: 0,
          succeeded: 0,
          retried: 0,
          deadLettered: 0,
          failedToFinalize: 0,
        }),
      processQueueInputWithDefaults,
    });

    const request = async (): Promise<Response> =>
      app.request(
        "/v1/revoke",
        {
          method: "POST",
          headers: {
            authorization: "Bearer processor-secret",
            "content-type": "application/json",
          },
          body: JSON.stringify({
            tenantId: fixture.tenantId,
            assertionId,
            reason: "Concurrent idempotency test",
            requestedByUserId: "usr_test",
            idempotencyKey,
          }),
        },
        createEnv(),
      );

    try {
      const [firstResponse, secondResponse] = await Promise.all([request(), request()]);
      const [firstBody, secondBody] = await Promise.all([
        firstResponse.json<QueuedRevokeResponse>(),
        secondResponse.json<QueuedRevokeResponse>(),
      ]);

      expect(firstResponse.status).toBe(202);
      expect(secondResponse.status).toBe(202);
      expect(secondBody).toEqual(firstBody);
      expect(firstBody).toMatchObject({
        status: "queued",
        jobType: "revoke_badge",
        assertionId,
        idempotencyKey,
      });
      await expect(
        countRows(fixture.db, "job_queue_messages", "tenant_id = ?", [fixture.tenantId]),
      ).resolves.toBe(1);
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });
});
