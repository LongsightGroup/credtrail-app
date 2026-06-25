import type { SqlDatabase } from "@credtrail/db";
import type { LtiNrpsMember } from "./nrps";
import {
  ltiRosterRulePendingIssuanceBehavior,
  ltiRosterUnavailableIssuanceBehavior,
  type LtiRosterIssuanceBehavior,
} from "./issuance-behavior";
import {
  evaluateLtiRosterMembersEligibility,
  ltiBulkIssuanceRosterLoadedMessage,
  ltiRosterAlreadyIssuedEligibilityDetail,
  prepareLtiRosterEligibilityEvaluationContext,
  resolveLtiRosterEligibilityRuleContext,
  rosterMemberEligibilityFromRuleResolution,
  type LtiRosterEligibilityPreparedEvaluation,
  type LtiRosterEligibilityResult,
  type LtiRosterEligibilityRuleResolution,
  type LtiRosterIssuedBadgeStateForEligibility,
} from "./roster-eligibility";

export interface LtiRosterBulkIssuanceContext {
  ruleResolution: LtiRosterEligibilityRuleResolution;
  prepared: LtiRosterEligibilityPreparedEvaluation | null;
  issuanceBehavior: LtiRosterIssuanceBehavior;
  eligibilityByUserId: ReadonlyMap<string, LtiRosterEligibilityResult>;
  rosterLoadedMessage: string;
}

const issuanceBehaviorFromBulkPreparation = (
  ruleResolution: LtiRosterEligibilityRuleResolution,
  prepared: LtiRosterEligibilityPreparedEvaluation | null,
): LtiRosterIssuanceBehavior => {
  if (ruleResolution.status === "unavailable") {
    return ltiRosterUnavailableIssuanceBehavior(ruleResolution.detail);
  }

  if (ruleResolution.status === "rule_pending") {
    return ltiRosterRulePendingIssuanceBehavior(ruleResolution.detail);
  }

  return prepared!.issuanceBehavior;
};

export const prepareLtiRosterBulkIssuanceContext = async (input: {
  db: SqlDatabase;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  resourceLinkId: string;
  launchRuleId: string | null;
  members: readonly LtiNrpsMember[];
  issuedStatesByUserId: ReadonlyMap<string, LtiRosterIssuedBadgeStateForEligibility>;
  nowIso: string;
  memberEligibilityPolicy: "full" | "skip_when_manual_blocked";
}): Promise<LtiRosterBulkIssuanceContext> => {
  const ruleResolution = await resolveLtiRosterEligibilityRuleContext({
    db: input.db,
    tenantId: input.tenantId,
    issuer: input.issuer,
    clientId: input.clientId,
    deploymentId: input.deploymentId,
    resourceLinkId: input.resourceLinkId,
    launchRuleId: input.launchRuleId,
  });
  const prepared =
    ruleResolution.status === "resolved"
      ? await prepareLtiRosterEligibilityEvaluationContext({
          db: input.db,
          tenantId: input.tenantId,
          ruleId: ruleResolution.ruleId,
        })
      : null;
  const issuanceBehavior = issuanceBehaviorFromBulkPreparation(ruleResolution, prepared);
  const shouldEvaluateMembers =
    input.memberEligibilityPolicy === "full" || issuanceBehavior.manualIssuanceAllowed;
  const eligibilityByUserId = shouldEvaluateMembers
    ? await evaluateLtiRosterMembersEligibility({
        db: input.db,
        tenantId: input.tenantId,
        ruleResolution,
        members: input.members,
        issuedStatesByUserId: input.issuedStatesByUserId,
        nowIso: input.nowIso,
        prepared,
      })
    : new Map<string, LtiRosterEligibilityResult>();
  const eligibilityResults = shouldEvaluateMembers
    ? input.members.map((member) => {
        const eligibility = eligibilityByUserId.get(member.userId);

        if (eligibility === undefined) {
          throw new Error(`Missing roster eligibility for learner ${member.userId}`);
        }

        return eligibility;
      })
    : [];

  return {
    ruleResolution,
    prepared,
    issuanceBehavior,
    eligibilityByUserId,
    rosterLoadedMessage: ltiBulkIssuanceRosterLoadedMessage({
      learnerCount: input.members.length,
      eligibilityResults,
    }),
  };
};

export const ltiRosterIssuanceSkipDetail = (input: {
  issuedState: LtiRosterIssuedBadgeStateForEligibility | null;
  bulkContext: Pick<
    LtiRosterBulkIssuanceContext,
    "ruleResolution" | "prepared" | "issuanceBehavior"
  >;
}): string | null => {
  if (input.issuedState !== null) {
    return ltiRosterAlreadyIssuedEligibilityDetail(input.issuedState);
  }

  if (input.bulkContext.ruleResolution.status !== "resolved") {
    return rosterMemberEligibilityFromRuleResolution(input.bulkContext.ruleResolution).detail;
  }

  if (
    input.bulkContext.prepared !== null &&
    input.bulkContext.prepared.status === "ready" &&
    !input.bulkContext.issuanceBehavior.manualIssuanceAllowed
  ) {
    return input.bulkContext.issuanceBehavior.detail;
  }

  return null;
};
