import { createTenantScopedId } from "@credtrail/core-domain";
import type {
  IssuanceAchievementSource,
  IssueBadgeQueueJob,
  IssueBadgeRequest,
  RevokeBadgeQueueJob,
  RevokeBadgeRequest,
} from "@credtrail/validation";

type IssueBadgeQueueRequestBase = Omit<IssueBadgeRequest, "badgeTemplateId"> & {
  readonly lmsLearnerIdentity?: {
    readonly connectionId: string;
    readonly learnerId: string;
  };
};

type IssueBadgeQueueRequest = IssueBadgeQueueRequestBase & {
  readonly achievementSource: IssuanceAchievementSource;
};

export const issueBadgeQueueJobFromRequest = (
  request: IssueBadgeQueueRequest,
): { assertionId: string; job: IssueBadgeQueueJob } => {
  const assertionId = createTenantScopedId(request.tenantId);
  const idempotencyKey = request.idempotencyKey ?? crypto.randomUUID();
  const job: IssueBadgeQueueJob = {
    jobType: "issue_badge",
    tenantId: request.tenantId,
    payload: {
      assertionId,
      achievementSource: request.achievementSource,
      recipientIdentity: request.recipientIdentity,
      recipientIdentityType: request.recipientIdentityType,
      ...(request.recipientIdentifiers === undefined
        ? {}
        : {
            recipientIdentifiers: request.recipientIdentifiers,
          }),
      ...(request.recipientDisplayName === undefined
        ? {}
        : {
            recipientDisplayName: request.recipientDisplayName,
          }),
      ...(request.issuerImageUri === undefined
        ? {}
        : {
            issuerImageUri: request.issuerImageUri,
          }),
      requestedAt: new Date().toISOString(),
      ...(request.requestedByUserId === undefined
        ? {}
        : {
            requestedByUserId: request.requestedByUserId,
          }),
      ...(request.lmsLearnerIdentity === undefined
        ? {}
        : { lmsLearnerIdentity: request.lmsLearnerIdentity }),
    },
    idempotencyKey,
  };

  return {
    assertionId,
    job,
  };
};

export const revokeBadgeQueueJobFromRequest = (
  request: RevokeBadgeRequest,
): { revocationId: string; job: RevokeBadgeQueueJob } => {
  const revocationId = createTenantScopedId(request.tenantId);
  const idempotencyKey = request.idempotencyKey ?? crypto.randomUUID();

  const job: RevokeBadgeQueueJob = {
    jobType: "revoke_badge",
    tenantId: request.tenantId,
    payload: {
      revocationId,
      assertionId: request.assertionId,
      reason: request.reason,
      requestedAt: new Date().toISOString(),
      ...(request.requestedByUserId === undefined
        ? {}
        : {
            requestedByUserId: request.requestedByUserId,
          }),
    },
    idempotencyKey,
  };

  return {
    revocationId,
    job,
  };
};
