import { expect, it } from "vitest";
import {
  badgeAchievementSnapshotFromTemplate,
  enqueueOrReplayJobQueueMessage,
  findAssertionById,
  findBadgeTemplateById,
} from "@credtrail/db";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
} from "../../../../packages/db/src/postgres-test-support";
import { createIssueBadgeForTenant } from "../badges/direct-issue";
import { HttpErrorResponse } from "../http/http-error-response";
import { createBadgeTemplateArtworkBucket } from "../test-support/badge-template-artwork-bucket";
import { observabilityContext } from "../app/observability";
import type { AppBindings } from "../app/types";
import { issueBadgeQueueJobFromRequest } from "./job-builders";
import { createProcessQueuedJobs, processQueueInputWithDefaults } from "./processing";

describeDbIntegration("expiry while waiting for queued issuance", () => {
  it("fails once without signing a credential or scheduling another attempt", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    try {
      const template = await findBadgeTemplateById(
        fixture.db,
        fixture.tenantId,
        fixture.badgeTemplateId,
      );
      if (template === null) throw new Error("Missing fixture template");
      const { assertionId, job } = issueBadgeQueueJobFromRequest({
        tenantId: fixture.tenantId,
        achievementSource: {
          kind: "template_snapshot",
          snapshot: badgeAchievementSnapshotFromTemplate(template),
          provenance: { source: "programmatic" },
        },
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
        idempotencyKey: "expiry-before-delivery",
        validUntil: "2020-01-01T00:00:00.000Z",
      });
      const message = await enqueueOrReplayJobQueueMessage(fixture.db, {
        tenantId: job.tenantId,
        jobType: job.jobType,
        idempotencyKey: job.idempotencyKey,
        payload: { ...job.payload, requestedAt: "2019-12-31T00:00:00.000Z" },
      });
      const env: AppBindings = {
        APP_ENV: "test",
        PLATFORM_DOMAIN: "credtrail.test",
        PUBLIC_APP_ORIGIN: "https://credtrail.org",
        BADGE_OBJECTS: createBadgeTemplateArtworkBucket(),
      };
      type Context = { env: AppBindings; req: { url: string } };
      const issueBadge = createIssueBadgeForTenant<Context, AppBindings>({
        resolveDatabase: () => fixture.db,
        observabilityContext,
        HttpErrorResponseClass: HttpErrorResponse,
        publicBadgePathForAssertion: (assertion) => `/badges/${assertion.publicId}`,
        sendIssuanceEmailNotification: async () => {
          throw new Error("Expired award reached email");
        },
        signCredentialForDid: async () => {
          throw new Error("Expired award reached signing");
        },
      });
      const process = createProcessQueuedJobs<AppBindings, Context>({
        resolveDatabase: () => fixture.db,
        observabilityContext,
        issueBadgeForTenant: issueBadge,
        processMigrationBatchJob: async () => undefined,
        processBadgeTemplateImageGenerationJob: async () => undefined,
        processBadgeRuleLifecycleJob: async () => undefined,
        processAutomatedBadgeRuleJob: async () => undefined,
        processBadgeRuleApprovalNotificationJob: async () => undefined,
      });
      const context = { env, req: { url: "https://credtrail.org/v1/jobs/process" } };
      const config = processQueueInputWithDefaults({});
      expect(await process(context, config)).toMatchObject({
        deadLettered: 1,
        retried: 0,
        succeeded: 0,
      });
      expect(
        await fixture.db
          .prepare(
            "SELECT status, attempt_count AS attemptCount, failed_at AS failedAt FROM job_queue_messages WHERE id = ?",
          )
          .bind(message.id)
          .first(),
      ).toMatchObject({
        status: "failed",
        attemptCount: 1,
        failedAt: expect.any(String),
      });
      expect(await findAssertionById(fixture.db, fixture.tenantId, assertionId)).toBeNull();
      expect(await process(context, config)).toMatchObject({ leased: 0, processed: 0 });
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});
