import { logInfo, type ObservabilityContext } from "@credtrail/core-domain";
import {
  createAuditLog,
  deleteFailedJobQueueMessageByIdentity,
  enqueueJobQueueMessageOnce,
  expireBadgeIssuanceRuleVersion,
  listActiveTenants,
  listBadgeIssuanceRuleVersionsDueForExpiry,
  type SqlDatabase,
} from "@credtrail/db";
import { resolveRuleDefinition } from "../rules/badge-rule-definition-resolver";

export interface BadgeRuleLifecycleProcessingResult {
  readonly tenantsScanned: number;
  readonly lifecycleJobsEnqueued: number;
  readonly dueVersionsProcessed: number;
  readonly endOfTermJobsEnqueued: number;
  readonly expiredVersions: number;
}

export interface ProcessBadgeRuleLifecycleInput {
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly nowIso: string;
  readonly observability: ObservabilityContext;
}

const lifecycleScheduleBucketFromIso = (isoTimestamp: string): string => isoTimestamp.slice(0, 13);

const ruleUsesEndOfTermIssuance = (ruleJson: string): boolean => {
  return resolveRuleDefinition(ruleJson).options?.issuanceTiming === "end_of_term";
};

const endOfTermIdempotencyKey = (input: {
  readonly ruleId: string;
  readonly versionId: string;
  readonly expiresAt: string | null;
  readonly nowIso: string;
}): string => `end-of-term:${input.ruleId}:${input.versionId}:${input.expiresAt ?? input.nowIso}`;

export const enqueueBadgeRuleLifecycleJobsForActiveTenants = async (input: {
  readonly db: SqlDatabase;
  readonly nowIso: string;
}): Promise<{ readonly tenantsScanned: number; readonly lifecycleJobsEnqueued: number }> => {
  const tenants = await listActiveTenants(input.db);
  let lifecycleJobsEnqueued = 0;
  const scheduleBucket = lifecycleScheduleBucketFromIso(input.nowIso);

  for (const tenant of tenants) {
    const inserted = await enqueueJobQueueMessageOnce(input.db, {
      tenantId: tenant.id,
      jobType: "process_badge_rule_lifecycle",
      payload: {
        scheduledFor: input.nowIso,
      },
      idempotencyKey: `badge-rule-lifecycle:${scheduleBucket}`,
      nowIso: input.nowIso,
    });

    if (inserted) {
      lifecycleJobsEnqueued += 1;
    }
  }

  return {
    tenantsScanned: tenants.length,
    lifecycleJobsEnqueued,
  };
};

export const processBadgeRuleLifecycleForTenant = async (
  input: ProcessBadgeRuleLifecycleInput,
): Promise<
  Omit<BadgeRuleLifecycleProcessingResult, "tenantsScanned" | "lifecycleJobsEnqueued">
> => {
  const dueVersions = await listBadgeIssuanceRuleVersionsDueForExpiry(input.db, {
    tenantId: input.tenantId,
    nowIso: input.nowIso,
  });
  let endOfTermJobsEnqueued = 0;
  let expiredVersions = 0;

  for (const version of dueVersions) {
    const usesEndOfTermIssuance = ruleUsesEndOfTermIssuance(version.ruleJson);

    if (usesEndOfTermIssuance) {
      const idempotencyKey = endOfTermIdempotencyKey({
        ruleId: version.ruleId,
        versionId: version.id,
        expiresAt: version.expiresAt,
        nowIso: input.nowIso,
      });

      await deleteFailedJobQueueMessageByIdentity(input.db, {
        tenantId: input.tenantId,
        jobType: "process_end_of_term_badge_rule",
        idempotencyKey,
      });

      const inserted = await enqueueJobQueueMessageOnce(input.db, {
        tenantId: input.tenantId,
        jobType: "process_end_of_term_badge_rule",
        payload: {
          ruleId: version.ruleId,
          versionId: version.id,
          badgeTemplateId: version.badgeTemplateId,
          scheduledFor: input.nowIso,
        },
        idempotencyKey,
        nowIso: input.nowIso,
      });

      if (inserted) {
        endOfTermJobsEnqueued += 1;
      }

      continue;
    }

    const expired = await expireBadgeIssuanceRuleVersion(input.db, {
      tenantId: input.tenantId,
      ruleId: version.ruleId,
      versionId: version.id,
      occurredAt: input.nowIso,
    });

    if (expired !== null) {
      expiredVersions += 1;
      await createAuditLog(input.db, {
        tenantId: input.tenantId,
        action: "badge_rule.version_expired",
        targetType: "badge_rule_version",
        targetId: version.id,
        metadata: {
          ruleId: version.ruleId,
          expiresAt: version.expiresAt,
        },
        occurredAt: input.nowIso,
      });
    }
  }

  logInfo(input.observability, "badge_rule_lifecycle_processed", {
    tenantId: input.tenantId,
    dueVersionsProcessed: dueVersions.length,
    endOfTermJobsEnqueued,
    expiredVersions,
  });

  return {
    dueVersionsProcessed: dueVersions.length,
    endOfTermJobsEnqueued,
    expiredVersions,
  };
};
