import { logError, logInfo, type ObservabilityContext } from "@credtrail/core-domain";
import {
  completeJobQueueMessage,
  createAuditLog,
  failJobQueueMessage,
  leaseJobQueueMessages,
  recordAssertionRevocation,
  type SqlDatabase,
} from "@credtrail/db";
import {
  parseQueueJob,
  type GenerateBadgeTemplateImageQueueJob,
  type ProcessAutomatedBadgeRuleQueueJob,
  type ProcessBadgeRuleLifecycleQueueJob,
  type ProcessQueueRequest,
  type QueueJob,
  type SendBadgeRuleApprovalNotificationQueueJob,
} from "@credtrail/validation";
import { applyLearnerRecordImportQueuePayload } from "../learner-record/learner-record-import";
import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";

const DEFAULT_JOB_PROCESS_LIMIT = 10;
const DEFAULT_JOB_PROCESS_LEASE_SECONDS = 300;
const DEFAULT_JOB_PROCESS_RETRY_DELAY_SECONDS = 30;

export interface ProcessQueueRunResult {
  leased: number;
  processed: number;
  succeeded: number;
  retried: number;
  deadLettered: number;
  failedToFinalize: number;
}

export interface ProcessQueueConfig {
  limit: number;
  leaseSeconds: number;
  retryDelaySeconds: number;
}

interface RequestBodyContext {
  req: {
    header: (name: string) => string | undefined;
    json: <T>() => Promise<T>;
  };
}

export const readJsonBodyOrEmptyObject = async (c: RequestBodyContext): Promise<unknown> => {
  const contentLengthHeader = c.req.header("content-length");

  if (contentLengthHeader === undefined || contentLengthHeader === "0") {
    return {};
  }

  return c.req.json<unknown>();
};

export const processQueueInputWithDefaults = (input: ProcessQueueRequest): ProcessQueueConfig => {
  return {
    limit: input.limit ?? DEFAULT_JOB_PROCESS_LIMIT,
    leaseSeconds: input.leaseSeconds ?? DEFAULT_JOB_PROCESS_LEASE_SECONDS,
    retryDelaySeconds: input.retryDelaySeconds ?? DEFAULT_JOB_PROCESS_RETRY_DELAY_SECONDS,
  };
};

interface QueueMessageEnvelope {
  tenantId: string;
  jobType: QueueJob["jobType"];
  payloadJson: string;
  idempotencyKey: string;
}

const queueJobFromMessage = (message: QueueMessageEnvelope): QueueJob => {
  let payload: unknown;

  try {
    payload = JSON.parse(message.payloadJson) as unknown;
  } catch {
    throw new Error(`Invalid queue payload JSON for message type "${message.jobType}"`);
  }

  return parseQueueJob({
    jobType: message.jobType,
    tenantId: message.tenantId,
    payload,
    idempotencyKey: message.idempotencyKey,
  });
};

interface ProcessQueuedJobsDependencies<TBindings, TContext extends { env: TBindings }> {
  resolveDatabase: (bindings: TBindings) => SqlDatabase;
  observabilityContext: (bindings: TBindings) => ObservabilityContext;
  issueBadgeForTenant: (
    context: TContext,
    tenantId: string,
    request: DirectIssueBadgeRequest,
    issuedByUserId?: string,
    options?: {
      recipientDisplayName?: string;
      issuerImageUri?: string;
    },
  ) => Promise<unknown>;
  processBadgeTemplateImageGenerationJob: (
    context: TContext,
    tenantId: string,
    payload: GenerateBadgeTemplateImageQueueJob["payload"],
  ) => Promise<void>;
  processBadgeRuleLifecycleJob: (
    context: TContext,
    tenantId: string,
    payload: ProcessBadgeRuleLifecycleQueueJob["payload"],
  ) => Promise<void>;
  processAutomatedBadgeRuleJob: (
    context: TContext,
    tenantId: string,
    payload: ProcessAutomatedBadgeRuleQueueJob["payload"],
  ) => Promise<void>;
  processBadgeRuleApprovalNotificationJob: (
    context: TContext,
    tenantId: string,
    payload: SendBadgeRuleApprovalNotificationQueueJob["payload"],
  ) => Promise<void>;
}

const processQueuedJob = async <TBindings, TContext extends { env: TBindings }>(
  c: TContext,
  job: QueueJob,
  dependencies: ProcessQueuedJobsDependencies<TBindings, TContext>,
): Promise<void> => {
  switch (job.jobType) {
    case "issue_badge":
      await dependencies.issueBadgeForTenant(
        c,
        job.tenantId,
        {
          badgeTemplateId: job.payload.badgeTemplateId,
          recipientIdentity: job.payload.recipientIdentity,
          recipientIdentityType: job.payload.recipientIdentityType,
          recipientIdentifiers: job.payload.recipientIdentifiers,
          ...(job.payload.recipientDisplayName === undefined
            ? {}
            : { recipientDisplayName: job.payload.recipientDisplayName }),
          ...(job.payload.issuerImageUri === undefined
            ? {}
            : { issuerImageUri: job.payload.issuerImageUri }),
          idempotencyKey: job.idempotencyKey,
          issuanceProvenance: job.payload.issuanceProvenance,
          ...(job.payload.lmsLearnerIdentity === undefined
            ? {}
            : { lmsLearnerIdentity: job.payload.lmsLearnerIdentity }),
        },
        job.payload.requestedByUserId,
      );
      return;
    case "revoke_badge": {
      const revocationResult = await recordAssertionRevocation(
        dependencies.resolveDatabase(c.env),
        {
          tenantId: job.tenantId,
          assertionId: job.payload.assertionId,
          revocationId: job.payload.revocationId,
          reason: job.payload.reason,
          idempotencyKey: job.idempotencyKey,
          revokedByUserId: job.payload.requestedByUserId,
          revokedAt: new Date().toISOString(),
        },
      );
      await createAuditLog(dependencies.resolveDatabase(c.env), {
        tenantId: job.tenantId,
        ...(job.payload.requestedByUserId === undefined
          ? {}
          : {
              actorUserId: job.payload.requestedByUserId,
            }),
        action: "assertion.revoked",
        targetType: "assertion",
        targetId: job.payload.assertionId,
        metadata: {
          revocationId: job.payload.revocationId,
          reason: job.payload.reason,
          status: revocationResult.status,
          revokedAt: revocationResult.revokedAt,
        },
      });
      return;
    }
    case "rebuild_verification_cache":
    case "import_migration_batch":
      logInfo(dependencies.observabilityContext(c.env), "queue_job_received", {
        jobType: job.jobType,
        tenantId: job.tenantId,
        idempotencyKey: job.idempotencyKey,
      });
      return;
    case "import_learner_record_batch":
      await applyLearnerRecordImportQueuePayload(
        dependencies.resolveDatabase(c.env),
        job.tenantId,
        {
          batchId: job.payload.batchId,
          rowNumber: job.payload.rowNumber,
          fileName: job.payload.fileName,
          format: job.payload.format,
          requestedAt: job.payload.requestedAt,
          ...(job.payload.requestedByUserId === undefined
            ? {}
            : { requestedByUserId: job.payload.requestedByUserId }),
          row: job.payload.row,
        },
      );
      return;
    case "generate_badge_template_image":
      await dependencies.processBadgeTemplateImageGenerationJob(c, job.tenantId, job.payload);
      return;
    case "process_badge_rule_lifecycle":
      await dependencies.processBadgeRuleLifecycleJob(c, job.tenantId, job.payload);
      return;
    case "process_automated_badge_rule":
      await dependencies.processAutomatedBadgeRuleJob(c, job.tenantId, job.payload);
      return;
    case "send_badge_rule_approval_notification":
      await dependencies.processBadgeRuleApprovalNotificationJob(c, job.tenantId, job.payload);
      return;
  }
};

export const createProcessQueuedJobs = <TBindings, TContext extends { env: TBindings }>(
  dependencies: ProcessQueuedJobsDependencies<TBindings, TContext>,
): ((c: TContext, requestInput: ProcessQueueConfig) => Promise<ProcessQueueRunResult>) => {
  return async (c, requestInput): Promise<ProcessQueueRunResult> => {
    const nowIso = new Date().toISOString();
    const leasedMessages = await leaseJobQueueMessages(dependencies.resolveDatabase(c.env), {
      limit: requestInput.limit,
      leaseSeconds: requestInput.leaseSeconds,
      nowIso,
    });
    const result: ProcessQueueRunResult = {
      leased: leasedMessages.length,
      processed: 0,
      succeeded: 0,
      retried: 0,
      deadLettered: 0,
      failedToFinalize: 0,
    };

    for (const leasedMessage of leasedMessages) {
      const leaseToken = leasedMessage.leaseToken;

      if (leaseToken === null) {
        result.failedToFinalize += 1;
        continue;
      }

      try {
        const job = queueJobFromMessage(leasedMessage);
        await processQueuedJob(c, job, dependencies);
        await completeJobQueueMessage(dependencies.resolveDatabase(c.env), {
          id: leasedMessage.id,
          leaseToken,
          nowIso: new Date().toISOString(),
        });

        result.processed += 1;
        result.succeeded += 1;
      } catch (error: unknown) {
        const detail = error instanceof Error ? error.message : "Unknown queue processing error";

        logError(dependencies.observabilityContext(c.env), "queue_job_failed", {
          messageId: leasedMessage.id,
          jobType: leasedMessage.jobType,
          tenantId: leasedMessage.tenantId,
          detail,
        });

        const status = await failJobQueueMessage(dependencies.resolveDatabase(c.env), {
          id: leasedMessage.id,
          leaseToken,
          nowIso: new Date().toISOString(),
          error: detail,
          retryDelaySeconds: requestInput.retryDelaySeconds,
        });

        result.processed += 1;

        if (status === "failed") {
          result.deadLettered += 1;
        } else if (status === "pending") {
          result.retried += 1;
        } else {
          result.failedToFinalize += 1;
        }
      }
    }

    return result;
  };
};
