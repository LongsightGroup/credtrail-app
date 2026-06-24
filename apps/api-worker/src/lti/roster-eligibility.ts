import {
  findActiveBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleById,
  findLtiResourceLinkPlacement,
  type AssertionLifecycleState,
  type SqlDatabase,
} from "@credtrail/db";
import type { LtiIssuanceActionPayload } from "./issuance-action-token";
import type { LtiNrpsMember } from "./nrps";
import {
  evaluateBadgeIssuanceRuleDefinition,
  summarizeBadgeIssuanceRuleEvaluation,
  type BadgeIssuanceRuleEvaluationNode,
} from "../rules/engine";
import { loadRuleFacts } from "../routes/badge-rule-facts-loader";
import {
  resolveBadgeIssuanceRuleDefinitionValueLists,
  resolveRuleDefinition,
} from "../routes/badge-rule-definition-resolver";

export type LtiRosterEligibilityStatus =
  | "eligible"
  | "not_yet_eligible"
  | "missing_evidence"
  | "already_issued"
  | "rule_pending"
  | "unavailable";

export interface LtiRosterIssuedBadgeStateForEligibility {
  assertionId: string;
  issuedAt: string;
  lifecycleState: AssertionLifecycleState | null;
}

export interface LtiRosterEligibilityResult {
  status: LtiRosterEligibilityStatus;
  label: string;
  detail: string;
  eligibleForIssuance: boolean;
}

interface LtiRosterEligibilityRuleContext {
  ruleId: string | null;
}

const statusResult = (
  status: LtiRosterEligibilityStatus,
  detail: string,
  eligibleForIssuance: boolean,
): LtiRosterEligibilityResult => {
  const labels: Record<LtiRosterEligibilityStatus, string> = {
    eligible: "Eligible",
    not_yet_eligible: "Not yet eligible",
    missing_evidence: "Missing evidence",
    already_issued: "Already issued",
    rule_pending: "Rule pending",
    unavailable: "Unavailable",
  };

  return {
    status,
    label: labels[status],
    detail,
    eligibleForIssuance,
  };
};

const firstLeafDetail = (node: BadgeIssuanceRuleEvaluationNode): string => {
  if (node.children === undefined || node.children.length === 0) {
    return node.detail;
  }

  const preferredChild =
    node.children.find((child) => child.resultKind === "missing_data") ??
    node.children.find((child) => child.resultKind === "failed_condition") ??
    node.children.find((child) => !child.matched) ??
    node.children[0];

  return preferredChild === undefined ? node.detail : firstLeafDetail(preferredChild);
};

export const resolveLtiRosterEligibilityRuleContext = async (input: {
  db: SqlDatabase;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  resourceLinkId: string;
  launchRuleId: string | null;
}): Promise<LtiRosterEligibilityRuleContext> => {
  if (input.launchRuleId !== null) {
    return {
      ruleId: input.launchRuleId,
    };
  }

  let placement;

  try {
    placement = await findLtiResourceLinkPlacement(input.db, {
      issuer: input.issuer,
      clientId: input.clientId,
      deploymentId: input.deploymentId,
      resourceLinkId: input.resourceLinkId,
    });
  } catch {
    return {
      ruleId: null,
    };
  }

  if (placement === null || placement.tenantId !== input.tenantId) {
    return {
      ruleId: null,
    };
  }

  return {
    ruleId: placement.ruleId,
  };
};

export const evaluateLtiRosterMemberEligibility = async (input: {
  db: SqlDatabase;
  tenantId: string;
  ruleId: string | null;
  member: LtiNrpsMember;
  issuedState: LtiRosterIssuedBadgeStateForEligibility | null;
  nowIso: string;
}): Promise<LtiRosterEligibilityResult> => {
  if (input.issuedState !== null) {
    return statusResult(
      "already_issued",
      input.issuedState.lifecycleState === null || input.issuedState.lifecycleState === "active"
        ? "Badge was already issued for this learner."
        : `Badge was already issued and is ${input.issuedState.lifecycleState}.`,
      false,
    );
  }

  if (input.ruleId === null) {
    return statusResult(
      "rule_pending",
      "No active course rule is linked to this placement.",
      false,
    );
  }

  if (input.member.email === null) {
    return statusResult(
      "unavailable",
      "The LMS did not provide an email address for this learner.",
      false,
    );
  }

  const rule = await findBadgeIssuanceRuleById(input.db, input.tenantId, input.ruleId);

  if (rule === null) {
    return statusResult(
      "rule_pending",
      "No active course rule is linked to this placement.",
      false,
    );
  }

  const activeVersion = await findActiveBadgeIssuanceRuleVersion(input.db, {
    tenantId: input.tenantId,
    ruleId: rule.id,
  });

  if (activeVersion === null) {
    return statusResult("rule_pending", "Rule is waiting for review and activation.", false);
  }

  try {
    const definition = await resolveBadgeIssuanceRuleDefinitionValueLists(
      input.db,
      input.tenantId,
      resolveRuleDefinition(activeVersion.ruleJson),
    );
    const facts = await loadRuleFacts({
      db: input.db,
      tenantId: input.tenantId,
      lmsProviderKind: rule.lmsProviderKind,
      lmsConnectionId: rule.lmsConnectionId ?? undefined,
      learnerId: input.member.userId,
      recipientIdentity: input.member.email,
      recipientIdentityType: "email",
      definition,
      nowIso: input.nowIso,
    });
    const evaluation = evaluateBadgeIssuanceRuleDefinition(definition, facts);

    if (evaluation.matched) {
      return statusResult("eligible", "Meets the active badge rule.", true);
    }

    const summary = summarizeBadgeIssuanceRuleEvaluation(evaluation);
    const detail = firstLeafDetail(evaluation.tree);

    if (summary.missingDataCount > 0) {
      return statusResult("missing_evidence", detail, false);
    }

    return statusResult("not_yet_eligible", detail, false);
  } catch (error) {
    return statusResult(
      "unavailable",
      error instanceof Error
        ? error.message
        : "CredTrail could not evaluate this learner against the badge rule.",
      false,
    );
  }
};

export const evaluateLtiRosterMemberIssuanceEligibility = async (input: {
  db: SqlDatabase;
  issuanceAction: LtiIssuanceActionPayload;
  member: LtiNrpsMember;
  issuedState: LtiRosterIssuedBadgeStateForEligibility | null;
  nowIso: string;
}): Promise<LtiRosterEligibilityResult> => {
  const ruleContext = await resolveLtiRosterEligibilityRuleContext({
    db: input.db,
    tenantId: input.issuanceAction.tenantId,
    issuer: input.issuanceAction.issuer,
    clientId: input.issuanceAction.clientId,
    deploymentId: input.issuanceAction.deploymentId,
    resourceLinkId: input.issuanceAction.resourceLinkId,
    launchRuleId: null,
  });

  return evaluateLtiRosterMemberEligibility({
    db: input.db,
    tenantId: input.issuanceAction.tenantId,
    ruleId: ruleContext.ruleId,
    member: input.member,
    issuedState: input.issuedState,
    nowIso: input.nowIso,
  });
};
