import type {
  BadgeTemplateRecord,
  EnqueueJobQueueMessageInput,
  FindActiveTenantApiKeyByHashInput,
  JobQueueMessageRecord,
  TenantApiKeyRecord,
} from "@credtrail/db";
import { Hono } from "hono";
import type { AppEnv } from "../app";
import type { QueueIngressStore } from "../queue/ingress-store";
import { processQueueInputWithDefaults, readJsonBodyOrEmptyObject } from "../queue/processing";
import { registerQueueRoutes } from "../routes/queue-routes";
import { createBadgeTemplateArtworkBucket } from "./badge-template-artwork-bucket";

export const sampleQueueIngressBadgeTemplate: BadgeTemplateRecord = {
  id: "badge_template_001",
  tenantId: "tenant_123",
  slug: "typescript-foundations",
  title: "TypeScript Foundations",
  description: "Awarded for completing TypeScript fundamentals.",
  criteriaUri: "https://example.edu/criteria/typescript-foundations",
  imageUri:
    "https://credtrail.test/badges/assets/tenant_123/badge_template_001/asset_typescript",
  trustedCredentialMetadataJson: null,
  createdByUserId: "usr_issuer",
  ownerOrgUnitId: "tenant_123:org:institution",
  governanceMetadataJson: null,
  isArchived: false,
  createdAt: "2026-02-10T15:00:00.000Z",
  updatedAt: "2026-02-10T15:00:00.000Z",
};

/** Recording persistence adapter used by queue-ingress route tests. */
export class RecordingQueueIngressStore implements QueueIngressStore {
  readonly enqueuedInputs: EnqueueJobQueueMessageInput[] = [];
  readonly idempotencyLookups: Array<{
    readonly tenantId: string;
    readonly jobType: JobQueueMessageRecord["jobType"];
    readonly idempotencyKey: string;
  }> = [];
  readonly apiKeyLookups: FindActiveTenantApiKeyByHashInput[] = [];
  readonly badgeTemplateLookups: Array<{
    readonly tenantId: string;
    readonly badgeTemplateId: string;
  }> = [];
  readonly touchedApiKeys: Array<{ readonly apiKeyId: string; readonly lastUsedAt: string }> = [];
  badgeTemplate: BadgeTemplateRecord | null = sampleQueueIngressBadgeTemplate;
  activeApiKey: TenantApiKeyRecord | null = null;
  existingMessage: JobQueueMessageRecord | null = null;
  nextEnqueueMessage: JobQueueMessageRecord | null = null;

  reset(): void {
    this.enqueuedInputs.length = 0;
    this.idempotencyLookups.length = 0;
    this.apiKeyLookups.length = 0;
    this.badgeTemplateLookups.length = 0;
    this.touchedApiKeys.length = 0;
    this.badgeTemplate = sampleQueueIngressBadgeTemplate;
    this.activeApiKey = null;
    this.existingMessage = null;
    this.nextEnqueueMessage = null;
  }

  findByIdempotencyKey(input: {
    readonly tenantId: string;
    readonly jobType: JobQueueMessageRecord["jobType"];
    readonly idempotencyKey: string;
  }): Promise<JobQueueMessageRecord | null> {
    this.idempotencyLookups.push(input);
    return Promise.resolve(this.existingMessage);
  }

  enqueueOrReplay(input: EnqueueJobQueueMessageInput): Promise<JobQueueMessageRecord> {
    this.enqueuedInputs.push(input);

    if (this.nextEnqueueMessage !== null) {
      return Promise.resolve(this.nextEnqueueMessage);
    }

    const nowIso = "2026-08-12T12:00:00.000Z";
    return Promise.resolve({
      id: "job_queued",
      tenantId: input.tenantId,
      jobType: input.jobType,
      payloadJson: JSON.stringify(input.payload),
      idempotencyKey: input.idempotencyKey,
      attemptCount: 0,
      maxAttempts: input.maxAttempts ?? 8,
      availableAt: nowIso,
      leasedUntil: null,
      leaseToken: null,
      lastError: null,
      completedAt: null,
      failedAt: null,
      status: "pending",
      createdAt: nowIso,
      updatedAt: nowIso,
    });
  }

  findBadgeTemplateById(
    tenantId: string,
    badgeTemplateId: string,
  ): Promise<BadgeTemplateRecord | null> {
    this.badgeTemplateLookups.push({ tenantId, badgeTemplateId });
    return Promise.resolve(this.badgeTemplate);
  }

  findActiveApiKeyByHash(
    input: FindActiveTenantApiKeyByHashInput,
  ): Promise<TenantApiKeyRecord | null> {
    this.apiKeyLookups.push(input);
    return Promise.resolve(this.activeApiKey);
  }

  touchApiKeyLastUsedAt(apiKeyId: string, lastUsedAt: string): Promise<void> {
    this.touchedApiKeys.push({ apiKeyId, lastUsedAt });
    return Promise.resolve();
  }
}

/** Builds an isolated queue-ingress route app and its observable persistence fake. */
export const createQueueIngressTestHarness = (): {
  readonly app: Hono<AppEnv>;
  readonly store: RecordingQueueIngressStore;
} => {
  const store = new RecordingQueueIngressStore();
  const app = new Hono<AppEnv>();

  registerQueueRoutes({
    app,
    resolveQueueIngressStore: () => store,
    sha256Hex: () => Promise.resolve("hash_123"),
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

  return { app, store };
};

/** Returns the default bindings used by queue-ingress route tests. */
export const createQueueIngressTestEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  PUBLIC_APP_ORIGIN: string;
  JOB_PROCESSOR_TOKEN?: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: createBadgeTemplateArtworkBucket(),
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

/** Returns the canonical API-key fixture for programmatic queue-ingress tests. */
export const sampleQueueIngressApiKey = (
  overrides: Partial<TenantApiKeyRecord> = {},
): TenantApiKeyRecord => {
  return {
    id: "tak_123",
    tenantId: "tenant_123",
    label: "Integration key",
    keyPrefix: "ctak_abc12345",
    keyHash: "hash_123",
    scopesJson: '["queue.issue","queue.revoke"]',
    createdByUserId: "usr_admin",
    expiresAt: null,
    lastUsedAt: null,
    revokedAt: null,
    createdAt: "2026-02-14T15:00:00.000Z",
    updatedAt: "2026-02-14T15:00:00.000Z",
    ...overrides,
  };
};

/** Returns a persisted issuance fixture used to test idempotent replay. */
export const sampleQueuedIssueMessage = (): JobQueueMessageRecord => {
  const nowIso = "2026-08-12T12:00:00.000Z";
  return {
    id: "job_original",
    tenantId: "tenant_123",
    jobType: "issue_badge",
    payloadJson: JSON.stringify({
      assertionId: "assertion_original",
      achievementSource: {
        kind: "template_snapshot",
        snapshot: {
          badgeTemplateId: sampleQueueIngressBadgeTemplate.id,
          title: sampleQueueIngressBadgeTemplate.title,
          description: sampleQueueIngressBadgeTemplate.description,
          criteriaUri: sampleQueueIngressBadgeTemplate.criteriaUri,
          imageUri: sampleQueueIngressBadgeTemplate.imageUri,
          trustedCredentialMetadataJson:
            sampleQueueIngressBadgeTemplate.trustedCredentialMetadataJson,
        },
        provenance: { source: "programmatic" },
      },
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
      requestedAt: nowIso,
      requestedByUserId: "usr_admin",
    }),
    idempotencyKey: "idem_programmatic_issue_123",
    attemptCount: 0,
    maxAttempts: 8,
    availableAt: nowIso,
    leasedUntil: null,
    leaseToken: null,
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: "pending",
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};
