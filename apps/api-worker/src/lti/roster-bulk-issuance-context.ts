import type { SqlDatabase } from "@credtrail/db";
import type { LtiNrpsMember } from "./nrps";
import {
  ltiRosterRulePendingIssuanceBehavior,
  ltiRosterUnavailableIssuanceBehavior,
  type LtiRosterIssuanceBehavior,
} from "./issuance-behavior";
import {
  evaluateLtiRosterMembersEligibility,
  LTI_ROSTER_NO_RULE_LINKED_DETAIL,
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

export type LtiRosterRuleIssuanceContext =
  | {
      ruleResolution: Exclude<LtiRosterEligibilityRuleResolution, { status: "resolved" }>;
      prepared: null;
      issuanceBehavior: LtiRosterIssuanceBehavior;
    }
  | {
      ruleResolution: Extract<LtiRosterEligibilityRuleResolution, { status: "resolved" }>;
      prepared: LtiRosterEligibilityPreparedEvaluation;
      issuanceBehavior: LtiRosterIssuanceBehavior;
    };

export const prepareLtiRosterRuleIssuanceContext = async (input: {
  db: SqlDatabase;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  resourceLinkId: string;
  launchRuleId: string | null;
}): Promise<LtiRosterRuleIssuanceContext> => {
  const ruleResolution = await resolveLtiRosterEligibilityRuleContext({
    db: input.db,
    tenantId: input.tenantId,
    issuer: input.issuer,
    clientId: input.clientId,
    deploymentId: input.deploymentId,
    resourceLinkId: input.resourceLinkId,
    launchRuleId: input.launchRuleId,
  });

  if (ruleResolution.status === "unavailable") {
    return {
      ruleResolution,
      prepared: null,
      issuanceBehavior: ltiRosterUnavailableIssuanceBehavior(ruleResolution.detail),
    };
  }

  if (ruleResolution.status === "rule_pending") {
    return {
      ruleResolution,
      prepared: null,
      issuanceBehavior: ltiRosterRulePendingIssuanceBehavior(ruleResolution.detail),
    };
  }

  const prepared = await prepareLtiRosterEligibilityEvaluationContext({
    db: input.db,
    tenantId: input.tenantId,
    ruleId: ruleResolution.ruleId,
  });

  return {
    ruleResolution,
    prepared,
    issuanceBehavior: prepared.issuanceBehavior,
  };
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
}): Promise<LtiRosterBulkIssuanceContext> => {
  const ruleContext = await prepareLtiRosterRuleIssuanceContext(input);
  const eligibilityByUserId = await evaluateLtiRosterMembersEligibility({
    db: input.db,
    tenantId: input.tenantId,
    ruleResolution: ruleContext.ruleResolution,
    members: input.members,
    issuedStatesByUserId: input.issuedStatesByUserId,
    nowIso: input.nowIso,
    prepared: ruleContext.prepared,
  });
  const eligibilityResults = input.members.map((member) => {
    const eligibility = eligibilityByUserId.get(member.userId);

    if (eligibility === undefined) {
      throw new Error(`Missing roster eligibility for learner ${member.userId}`);
    }

    return eligibility;
  });

  return {
    ...ruleContext,
    eligibilityByUserId,
    rosterLoadedMessage: ltiBulkIssuanceRosterLoadedMessage({
      learnerCount: input.members.length,
      eligibilityResults,
    }),
  };
};

export const ltiRosterIssuanceSkipDetail = (input: {
  issuedState: LtiRosterIssuedBadgeStateForEligibility | null;
  ruleContext: LtiRosterRuleIssuanceContext;
}): string | null => {
  if (input.issuedState !== null) {
    return ltiRosterAlreadyIssuedEligibilityDetail(input.issuedState);
  }

  const { ruleContext } = input;

  if (ruleContext.ruleResolution.status !== "resolved") {
    return rosterMemberEligibilityFromRuleResolution(ruleContext.ruleResolution).detail;
  }

  if (ruleContext.prepared === null) {
    return LTI_ROSTER_NO_RULE_LINKED_DETAIL;
  }

  if (ruleContext.prepared.status === "rule_pending") {
    return ruleContext.prepared.detail;
  }

  if (
    ruleContext.prepared.status === "ready" &&
    !ruleContext.issuanceBehavior.manualIssuanceAllowed
  ) {
    return ruleContext.issuanceBehavior.detail;
  }

  return null;
};
