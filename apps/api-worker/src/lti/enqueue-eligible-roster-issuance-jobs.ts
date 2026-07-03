import { enqueueJobQueueMessageOnce, type SqlDatabase } from "@credtrail/db";
import type { LtiNrpsMember } from "./nrps";
import { issueBadgeQueueJobFromRequest } from "../queue/job-builders";
import {
  evaluateLtiRosterMembersEligibility,
  type LtiRosterEligibilityPreparedEvaluation,
} from "./roster-eligibility";
import {
  ltiIssuanceIdempotencyKeyPrefix,
  ltiRosterIssuedBadgeStatesByUserId,
} from "./roster-issuance-helpers";
import { buildLtiRosterIssueBadgeRequest } from "./roster-issue-request";

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

    const issueRequest = await buildLtiRosterIssueBadgeRequest({
      badgeTemplateId: input.badgeTemplateId,
      member: { ...member, email: member.email },
      eligibility,
      idempotencyKeyPrefix,
      sha256Hex: input.sha256Hex,
    });
    const { job } = issueBadgeQueueJobFromRequest({
      tenantId: input.tenantId,
      ...issueRequest,
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
