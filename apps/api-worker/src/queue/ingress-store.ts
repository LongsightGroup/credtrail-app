import {
  enqueueOrReplayJobQueueMessage,
  findActiveTenantApiKeyByHash,
  findBadgeTemplateById,
  findJobQueueMessageByIdempotencyKey,
  touchTenantApiKeyLastUsedAt,
  type BadgeTemplateRecord,
  type EnqueueJobQueueMessageInput,
  type FindActiveTenantApiKeyByHashInput,
  type JobQueueMessageRecord,
  type SqlDatabase,
  type TenantApiKeyRecord,
} from "@credtrail/db";

/** Persistence required to create and replay queue commands. */
export interface QueueIngressCommandStore {
  findByIdempotencyKey(input: {
    readonly tenantId: string;
    readonly jobType: JobQueueMessageRecord["jobType"];
    readonly idempotencyKey: string;
  }): Promise<JobQueueMessageRecord | null>;
  enqueueOrReplay(input: EnqueueJobQueueMessageInput): Promise<JobQueueMessageRecord>;
  findBadgeTemplateById(
    tenantId: string,
    badgeTemplateId: string,
  ): Promise<BadgeTemplateRecord | null>;
}

/** Persistence required to authorize a programmatic queue command. */
export interface QueueIngressAuthorizationStore {
  findActiveApiKeyByHash(input: FindActiveTenantApiKeyByHashInput): Promise<TenantApiKeyRecord | null>;
  touchApiKeyLastUsedAt(apiKeyId: string, lastUsedAt: string): Promise<void>;
}

/** Complete persistence boundary used by queue-ingress HTTP routes. */
export type QueueIngressStore = QueueIngressCommandStore & QueueIngressAuthorizationStore;

/** Binds queue-ingress persistence to one Postgres request context. */
export const createPostgresQueueIngressStore = (db: SqlDatabase): QueueIngressStore => {
  return {
    findByIdempotencyKey: (input) => findJobQueueMessageByIdempotencyKey(db, input),
    enqueueOrReplay: (input) => enqueueOrReplayJobQueueMessage(db, input),
    findBadgeTemplateById: (tenantId, badgeTemplateId) =>
      findBadgeTemplateById(db, tenantId, badgeTemplateId),
    findActiveApiKeyByHash: (input) => findActiveTenantApiKeyByHash(db, input),
    touchApiKeyLastUsedAt: (apiKeyId, lastUsedAt) =>
      touchTenantApiKeyLastUsedAt(db, apiKeyId, lastUsedAt),
  };
};
