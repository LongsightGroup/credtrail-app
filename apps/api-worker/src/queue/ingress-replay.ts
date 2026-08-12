import type { JobQueueMessageRecord } from "@credtrail/db";
import {
  parseQueueJob,
  type IssueBadgeQueueJob,
  type IssueBadgeRequest,
  type RevokeBadgeQueueJob,
  type RevokeBadgeRequest,
} from "@credtrail/validation";

type QueueIngressReplayResult<Envelope> =
  | { readonly status: "matched"; readonly envelope: Envelope }
  | { readonly status: "conflict" };

interface IssueBadgeQueueEnvelope {
  readonly assertionId: string;
  readonly job: IssueBadgeQueueJob;
}

interface RevokeBadgeQueueEnvelope {
  readonly revocationId: string;
  readonly job: RevokeBadgeQueueJob;
}

const parsePersistedQueueJob = (message: JobQueueMessageRecord) => {
  let payload: unknown;

  try {
    payload = JSON.parse(message.payloadJson) as unknown;
  } catch {
    throw new Error(`Persisted queue message "${message.id}" contains invalid JSON`);
  }

  return parseQueueJob({
    tenantId: message.tenantId,
    jobType: message.jobType,
    payload,
    idempotencyKey: message.idempotencyKey,
  });
};

const sameJsonValue = (left: unknown, right: unknown): boolean => {
  return JSON.stringify(left) === JSON.stringify(right);
};

/** Reconstructs the original issue response only when the idempotency key names this request. */
export const replayIssueBadgeQueueMessage = (input: {
  readonly message: JobQueueMessageRecord;
  readonly request: IssueBadgeRequest;
  readonly requestedByUserId?: string | undefined;
}): QueueIngressReplayResult<IssueBadgeQueueEnvelope> => {
  const job = parsePersistedQueueJob(input.message);

  if (job.jobType !== "issue_badge" || job.payload.achievementSource.kind !== "template_snapshot") {
    return { status: "conflict" };
  }

  const expectedIdentity = {
    badgeTemplateId: input.request.badgeTemplateId,
    recipientIdentity: input.request.recipientIdentity,
    recipientIdentityType: input.request.recipientIdentityType,
    recipientIdentifiers: input.request.recipientIdentifiers ?? null,
    recipientDisplayName: input.request.recipientDisplayName ?? null,
    issuerImageUri: input.request.issuerImageUri ?? null,
    requestedByUserId: input.requestedByUserId ?? input.request.requestedByUserId ?? null,
  };
  const persistedIdentity = {
    badgeTemplateId: job.payload.achievementSource.snapshot.badgeTemplateId,
    recipientIdentity: job.payload.recipientIdentity,
    recipientIdentityType: job.payload.recipientIdentityType,
    recipientIdentifiers: job.payload.recipientIdentifiers ?? null,
    recipientDisplayName: job.payload.recipientDisplayName ?? null,
    issuerImageUri: job.payload.issuerImageUri ?? null,
    requestedByUserId: job.payload.requestedByUserId ?? null,
  };

  if (!sameJsonValue(expectedIdentity, persistedIdentity)) {
    return { status: "conflict" };
  }

  return {
    status: "matched",
    envelope: {
      assertionId: job.payload.assertionId,
      job,
    },
  };
};

/** Reconstructs the original revocation response only when the idempotency key names this request. */
export const replayRevokeBadgeQueueMessage = (input: {
  readonly message: JobQueueMessageRecord;
  readonly request: RevokeBadgeRequest;
  readonly requestedByUserId?: string | undefined;
}): QueueIngressReplayResult<RevokeBadgeQueueEnvelope> => {
  const job = parsePersistedQueueJob(input.message);

  if (job.jobType !== "revoke_badge") {
    return { status: "conflict" };
  }

  const expectedIdentity = {
    assertionId: input.request.assertionId,
    reason: input.request.reason,
    requestedByUserId: input.requestedByUserId ?? input.request.requestedByUserId ?? null,
  };
  const persistedIdentity = {
    assertionId: job.payload.assertionId,
    reason: job.payload.reason,
    requestedByUserId: job.payload.requestedByUserId ?? null,
  };

  if (!sameJsonValue(expectedIdentity, persistedIdentity)) {
    return { status: "conflict" };
  }

  return {
    status: "matched",
    envelope: {
      revocationId: job.payload.revocationId,
      job,
    },
  };
};
