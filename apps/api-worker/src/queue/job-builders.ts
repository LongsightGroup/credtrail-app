import { createTenantScopedId } from '@credtrail/core-domain';
import type {
  IssueBadgeQueueJob,
  IssueBadgeRequest,
  RevokeBadgeQueueJob,
  RevokeBadgeRequest,
} from '@credtrail/validation';

export const issueBadgeQueueJobFromRequest = (
  request: IssueBadgeRequest,
): { assertionId: string; job: IssueBadgeQueueJob } => {
  const assertionId = createTenantScopedId(request.tenantId);
  const idempotencyKey = request.idempotencyKey ?? crypto.randomUUID();

  const job: IssueBadgeQueueJob = {
    jobType: 'issue_badge',
    tenantId: request.tenantId,
    payload: {
      assertionId,
      badgeTemplateId: request.badgeTemplateId,
      recipientIdentity: request.recipientIdentity,
      recipientIdentityType: request.recipientIdentityType,
      ...(request.recipientIdentifiers === undefined
        ? {}
        : {
            recipientIdentifiers: request.recipientIdentifiers,
          }),
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
    jobType: 'revoke_badge',
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
