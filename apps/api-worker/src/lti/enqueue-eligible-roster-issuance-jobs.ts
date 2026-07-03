import { enqueueJobQueueMessageOnce, type SqlDatabase } from "@credtrail/db";
import type { LtiNrpsMember } from "./nrps";
import { issueBadgeQueueJobFromRequest } from "../queue/job-builders";
import {
  evaluateLtiRosterMembersEligibility,
  type LtiRosterEligibilityPreparedEvaluation,
} from "./roster-eligibility";
import {
  ltiIssuanceIdempotencyKeyFromPrefix,
  ltiIssuanceIdempotencyKeyPrefix,
  ltiRosterIssuedBadgeStatesByUserId,
} from "./roster-issuance-helpers";

export interface LtiRosterIssuancePlacementAction {
  readonly tenantId: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly deploymentId: string;
  readonly contextId: string;
  readonly resourceLinkId: string;
  readonly badgeTemplateId: string;
}

export const enqueueEligibleLtiRosterIssuanceJobs = async (input: {
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly ruleId: string;
  readonly badgeTemplateId: string;
  readonly action: LtiRosterIssuancePlacementAction;
  readonly learnerMembers: readonly LtiNrpsMember[];
  readonly prepared: LtiRosterEligibilityPreparedEvaluation;
  readonly nowIso: string;
  readonly sha256Hex: (value: string) => Promise<string>;
}): Promise<{ readonly issueJobsEnqueued: number }> => {
  const issuedStatesByUserId = await ltiRosterIssuedBadgeStatesByUserId({
    db: input.db,
    sha256Hex: input.sha256Hex,
    action: input.action,
    learnerMembers: input.learnerMembers,
  });
  const eligibilityByUserId = await evaluateLtiRosterMembersEligibility({
    db: input.db,
    tenantId: input.tenantId,
    ruleResolution: {
      status: "resolved",
      ruleId: input.ruleId,
    },
    members: input.learnerMembers,
    issuedStatesByUserId,
    nowIso: input.nowIso,
    prepared: input.prepared,
  });
  const idempotencyKeyPrefix = ltiIssuanceIdempotencyKeyPrefix(input.action);
  let issueJobsEnqueued = 0;

  for (const member of input.learnerMembers) {
    const eligibility = eligibilityByUserId.get(member.userId);

    if (
      eligibility === undefined ||
      !eligibility.eligibleForIssuance ||
      member.email === undefined
    ) {
      continue;
    }

    const idempotencyKey = await ltiIssuanceIdempotencyKeyFromPrefix(
      input.sha256Hex,
      idempotencyKeyPrefix,
      member.userId,
    );
    const { job } = issueBadgeQueueJobFromRequest({
      tenantId: input.tenantId,
      badgeTemplateId: input.badgeTemplateId,
      recipientIdentity: member.email,
      recipientIdentityType: "email",
      ...(member.displayName === null ? {} : { recipientDisplayName: member.displayName }),
      ...(member.lisPersonSourcedId === undefined
        ? {}
        : {
            recipientIdentifiers: [
              {
                identifierType: "sourcedId",
                identifier: member.lisPersonSourcedId,
              },
            ],
          }),
      idempotencyKey,
    });
    const inserted = await enqueueJobQueueMessageOnce(input.db, {
      tenantId: job.tenantId,
      jobType: job.jobType,
      payload: job.payload,
      idempotencyKey: job.idempotencyKey,
      nowIso: input.nowIso,
    });

    if (inserted) {
      issueJobsEnqueued += 1;
    }
  }

  return { issueJobsEnqueued };
};
