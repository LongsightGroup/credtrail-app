import {
  createTenantApiKey,
  badgeAchievementSnapshotFromTemplate,
  findAssertionById,
  findBadgeTemplateById,
  findTenantById,
  type AssertionRecord,
} from "@credtrail/db";
import {
  generateTenantDidSigningMaterial,
  signCredentialWithDataIntegrityProof,
  type ImmutableCredentialStore,
} from "@credtrail/core-domain";
import { programmaticAcceptedSchema, programmaticOperationSchema } from "@credtrail/validation";
import { registerProgrammaticReadRoutes } from "../routes/programmatic-read-routes";
import { Hono } from "hono";
import { afterEach, expect, it } from "vitest";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createTestPostgresDatabase,
  describeDbIntegration,
  requireTestDatabaseUrl,
} from "../../../../packages/db/src/postgres-test-support";
import type { AppBindings, AppEnv } from "../app/types";
import { observabilityContext } from "../app/observability";
import { resolveDatabase } from "../app/database";
import { createIssueBadgeForTenant, isIssueBadgeHttpError } from "../badges/direct-issue";
import { HttpErrorResponse } from "../http/http-error-response";
import { createPostgresQueueIngressStore } from "./ingress-store";
import {
  createProcessQueuedJobs,
  processQueueInputWithDefaults,
  readJsonBodyOrEmptyObject,
} from "./processing";
import { registerQueueRoutes } from "../routes/queue-routes";
import { sha256Hex } from "../utils/crypto";

import { createRecordingEmailBinding } from "../test-support/recording-email";
import { sendIssuanceEmailNotification } from "../notifications/send-issuance-email";

type IssuanceContext = { env: AppBindings; req: { url: string } };
const tenantIds: string[] = [];
const userIds: string[] = [];
afterEach(async () => {
  if (tenantIds.length)
    await cleanupTestResources(createTestPostgresDatabase(), { tenantIds, userIds });
  tenantIds.length = 0;
  userIds.length = 0;
});

describeDbIntegration("durable queued issuance identity", () => {
  it("preserves API reservation through Postgres, immutable object storage, retries and replay", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();
    tenantIds.push(fixture.tenantId);
    userIds.push(fixture.userId);
    const db = fixture.db;
    const objects = new Map<string, string>();
    let writes = 0;
    await db
      .prepare("UPDATE badge_templates SET description = ? WHERE id = ?")
      .bind("Completed the community workshop.", fixture.badgeTemplateId)
      .run();
    const template = await findBadgeTemplateById(db, fixture.tenantId, fixture.badgeTemplateId);
    const tenant = await findTenantById(db, fixture.tenantId);
    if (template === null || tenant === null) throw new Error("Missing fixture");
    const store: ImmutableCredentialStore = {
      head: async (key) => (objects.has(key) ? { key } : null),
      get: async (key) => {
        const value = objects.get(key);
        return value === undefined ? null : { size: value.length, text: async () => value };
      },
      put: async (key, value) => {
        if (objects.has(key)) return null;
        objects.set(key, value);
        writes++;
        return { key, etag: "test", version: "test", size: value.length, uploaded: new Date() };
      },
      delete: async (key) => {
        objects.delete(key);
      },
    };
    // Seed artwork through the same immutable store contract used by issuance checks.
    objects.set(
      `tenants/${fixture.tenantId}/badge-template-images/${fixture.badgeTemplateId}/asset_test.json`,
      JSON.stringify({
        version: 1,
        mimeType: "image/png",
        byteSize: 8,
        base64Data: "iVBORw0KGgo=",
        uploadedAt: "2026-10-03T00:00:00Z",
        originalFilename: "test.png",
      }),
    );
    const material = await generateTenantDidSigningMaterial({ did: tenant.didWeb });
    const { emailBinding, messages } = createRecordingEmailBinding();
    const env: AppBindings = {
      APP_ENV: "production",
      RUNTIME: "node",
      DATABASE_URL: requireTestDatabaseUrl(),
      PLATFORM_DOMAIN: "badges.example.edu",
      PUBLIC_APP_ORIGIN: "https://badges.example.edu",
      BADGE_OBJECTS: store,
      JOB_PROCESSOR_TOKEN: "test-processor",
      ISSUANCE_EMAIL_NOTIFICATIONS_ENABLED: "true",
      EMAIL: emailBinding,
    };
    const issue = createIssueBadgeForTenant<IssuanceContext, AppBindings>({
      resolveDatabase: () => db,
      observabilityContext,
      HttpErrorResponseClass: HttpErrorResponse,
      publicBadgePathForAssertion: (assertion: AssertionRecord) => `/badges/${assertion.publicId}`,
      sendIssuanceEmailNotification,
      signCredentialForDid: async (input) => ({
        status: "ok",
        keyId: material.keyId,
        verificationMethod: `${tenant.didWeb}#${material.keyId}`,
        credential: await signCredentialWithDataIntegrityProof({
          credential: input.credential,
          privateJwk: material.privateJwk,
          verificationMethod: `${tenant.didWeb}#${material.keyId}`,
          ...(input.createdAt === undefined ? {} : { createdAt: input.createdAt }),
        }),
      }),
    });
    const process = createProcessQueuedJobs<AppBindings, IssuanceContext>({
      resolveDatabase: () => db,
      observabilityContext,
      issueBadgeForTenant: issue,
      processMigrationBatchJob: async () => undefined,
      processBadgeTemplateImageGenerationJob: async () => undefined,
      processBadgeRuleLifecycleJob: async () => undefined,
      processAutomatedBadgeRuleJob: async () => undefined,
      processBadgeRuleApprovalNotificationJob: async () => undefined,
    });
    const app = new Hono<AppEnv>();
    registerQueueRoutes({
      app,
      resolveQueueIngressStore: () => createPostgresQueueIngressStore(db),
      sha256Hex,
      readJsonBodyOrEmptyObject,
      processQueuedJobs: process,
      processQueueInputWithDefaults,
    });
    registerProgrammaticReadRoutes({
      app,
      resolveDatabase: () => db,
      resolveQueueIngressStore: () => createPostgresQueueIngressStore(db),
      sha256Hex,
    });
    const token = `ctak_${crypto.randomUUID()}`;
    await createTenantApiKey(db, {
      tenantId: fixture.tenantId,
      label: "Queue test",
      keyPrefix: token.slice(0, 13),
      keyHash: await sha256Hex(token),
      scopesJson: '["queue.issue","operations.read"]',
      createdByUserId: fixture.userId,
    });
    const enqueue = async (): Promise<Response> =>
      app.request(
        "https://badges.example.edu/v1/programmatic/issue",
        {
          method: "POST",
          headers: { "content-type": "application/json", "x-api-key": token },
          body: JSON.stringify({
            tenantId: fixture.tenantId,
            badgeTemplateId: fixture.badgeTemplateId,
            recipientIdentity: "learner@example.edu",
            recipientIdentityType: "email",
            idempotencyKey: "queue-identity-test",
          }),
        },
        env,
      );
    const response = await enqueue();
    expect(response.status).toBe(202);
    const envelope = programmaticAcceptedSchema.parse(await response.json());
    const pending = await app.request(envelope.statusUrl, { headers: { "x-api-key": token } }, env);
    expect(programmaticOperationSchema.parse(await pending.json()).status).toBe("pending");
    const processed = await app.request(
      "https://badges.example.edu/v1/jobs/process",
      { method: "POST", headers: { authorization: "Bearer test-processor" } },
      env,
    );
    expect(processed.status).toBe(200);
    expect(await processed.json()).toMatchObject({ succeeded: 1 });
    const assertion = await findAssertionById(db, fixture.tenantId, envelope.assertionId);
    expect(assertion?.id).toBe(envelope.assertionId);
    if (assertion === null) throw new Error("Queued assertion missing");
    const completed = await app.request(
      envelope.statusUrl,
      { headers: { "x-api-key": token } },
      env,
    );
    expect(programmaticOperationSchema.parse(await completed.json())).toMatchObject({
      status: "completed",
      assertionId: assertion.id,
      result: { badgeUrl: `https://badges.example.edu/badges/${assertion.publicId}` },
    });
    const value = objects.get(assertion.vcR2Key);
    expect(value).toBeDefined();
    expect(value === undefined ? undefined : JSON.parse(value)).toMatchObject({
      id: `urn:credtrail:assertion:${encodeURIComponent(envelope.assertionId)}`,
    });
    expect(assertion.vcR2Key).toContain(encodeURIComponent(envelope.assertionId));
    expect(writes).toBe(1);
    expect(messages).toHaveLength(1);
    expect(messages[0]?.html).toContain(assertion.achievementSnapshot.imageUri);
    expect(messages[0]?.text).toContain(assertion.achievementSnapshot.description);
    expect(messages[0]?.text).toContain(`/badges/${assertion.publicId}/download.pdf`);
    const replay = await enqueue();
    expect(await replay.json()).toMatchObject(envelope);
    expect(
      await (
        await app.request(
          "https://badges.example.edu/v1/jobs/process",
          { method: "POST", headers: { authorization: "Bearer test-processor" } },
          env,
        )
      ).json(),
    ).toMatchObject({ succeeded: 1 });
    expect(
      await db
        .prepare("SELECT COUNT(*)::int AS count FROM assertions WHERE tenant_id = ?")
        .bind(fixture.tenantId)
        .first(),
    ).toEqual({ count: 1 });
    const context = { env, req: { url: "https://badges.example.edu" } };
    const request = {
      achievementSource: {
        kind: "template_snapshot" as const,
        snapshot: badgeAchievementSnapshotFromTemplate(template),
        provenance: { source: "programmatic" as const },
      },
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email" as const,
      idempotencyKey: "queue-identity-test",
      reservedAssertionId: envelope.assertionId,
    };
    expect((await issue(context, fixture.tenantId, request)).status).toBe("already_issued");
    expect(writes).toBe(1);
    for (const reservation of ["malformed", `other:${crypto.randomUUID()}`]) {
      await expect(
        issue(context, fixture.tenantId, { ...request, reservedAssertionId: reservation }),
      ).rejects.toSatisfy(
        (error: unknown) => isIssueBadgeHttpError(error) && error.statusCode === 400,
      );
    }
    await expect(
      issue(context, fixture.tenantId, {
        ...request,
        reservedAssertionId: `${fixture.tenantId}:${crypto.randomUUID()}`,
      }),
    ).rejects.toSatisfy(
      (error: unknown) => isIssueBadgeHttpError(error) && error.statusCode === 409,
    );
    expect(writes).toBe(1);
    expect(await resolveDatabase(env).prepare("SELECT 1 AS healthy").first()).toEqual({
      healthy: 1,
    });
  });
});
