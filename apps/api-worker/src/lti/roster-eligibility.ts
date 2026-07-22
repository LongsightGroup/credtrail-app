import {
  findActiveBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleById,
  findLtiResourceLinkPlacement,
  type AssertionLifecycleState,
  type BadgeIssuanceRuleRecord,
  type SqlDatabase,
} from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import { buildIssuanceProvenanceSnapshotJson } from "@credtrail/validation";
import type { AppLogger } from "../app/observability";
import type { LtiNrpsMember } from "./nrps";
import {
  evaluateBadgeIssuanceRuleDefinition,
  primaryEvaluationDetail,
  summarizeBadgeIssuanceRuleEvaluation,
  type BadgeIssuanceRuleEvaluationResult,
} from "../rules/engine";
import { loadRuleFacts } from "../rules/badge-rule-facts-loader";
import {
  resolveBadgeIssuanceRuleDefinitionValueLists,
  resolveRuleDefinition,
} from "../rules/badge-rule-definition-resolver";
import {
  ltiRosterIssuanceBehaviorFromRuleDefinition,
  ltiRosterRulePendingIssuanceBehavior,
  type LtiRosterIssuanceBehavior,
} from "./issuance-behavior";

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
  issuanceProvenance?: {
    ruleId: string;
    versionId: string;
    provenanceJson: string;
  };
}

export type LtiRosterEligibilityRuleResolution =
  | { status: "resolved"; ruleId: string }
  | { status: "rule_pending"; detail: string }
  | { status: "unavailable"; detail: string };

export type LtiRosterEligibilityPreparedEvaluation =
  | {
      status: "ready";
      ruleId: string;
      versionId: string;
      lmsProviderKind: BadgeIssuanceRuleRecord["lmsProviderKind"];
      lmsConnectionId: string | null;
      definition: BadgeIssuanceRuleDefinition;
      issuanceBehavior: LtiRosterIssuanceBehavior;
    }
  | {
      status: "rule_pending";
      detail: string;
      issuanceBehavior: LtiRosterIssuanceBehavior;
    };

export const LTI_ROSTER_NO_RULE_LINKED_DETAIL =
  "No active course rule is linked to this placement.";
const PLACEMENT_LOOKUP_FAILED_DETAIL =
  "CredTrail could not load the course placement for this resource link.";

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

export const ltiBulkIssuanceRosterLoadedMessage = (input: {
  learnerCount: number;
  eligibilityResults: readonly LtiRosterEligibilityResult[];
}): string => {
  const unavailableCount = input.eligibilityResults.filter(
    (eligibility) => eligibility.status === "unavailable",
  ).length;

  if (unavailableCount === 0) {
    return `Loaded ${String(input.learnerCount)} learner${
      input.learnerCount === 1 ? "" : "s"
    } from LMS roster.`;
  }

  return "CredTrail loaded the LMS roster, but rule evidence could not be loaded for one or more learners.";
};

export const rosterMemberEligibilityFromRuleResolution = (
  ruleResolution: Exclude<LtiRosterEligibilityRuleResolution, { status: "resolved" }>,
): LtiRosterEligibilityResult => {
  return statusResult(
    ruleResolution.status === "unavailable" ? "unavailable" : "rule_pending",
    ruleResolution.detail,
    false,
  );
};

export const resolveLtiRosterEligibilityRuleContext = async (input: {
  db: SqlDatabase;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  resourceLinkId: string;
  launchRuleId: string | null;
  ltiLog?: AppLogger | undefined;
}): Promise<LtiRosterEligibilityRuleResolution> => {
  if (input.launchRuleId !== null) {
    return {
      status: "resolved",
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
  } catch (error) {
    input.ltiLog?.warn("Could not resolve LTI resource link placement for roster eligibility", {
      tenantId: input.tenantId,
      resourceLinkId: input.resourceLinkId,
      detail: error instanceof Error ? error.message : "unknown error",
    });

    return {
      status: "unavailable",
      detail: PLACEMENT_LOOKUP_FAILED_DETAIL,
    };
  }

  if (placement === null || placement.tenantId !== input.tenantId || placement.ruleId === null) {
    return {
      status: "rule_pending",
      detail: LTI_ROSTER_NO_RULE_LINKED_DETAIL,
    };
  }

  return {
    status: "resolved",
    ruleId: placement.ruleId,
  };
};

export const prepareLtiRosterEligibilityEvaluationContext = async (input: {
  db: SqlDatabase;
  tenantId: string;
  ruleId: string;
}): Promise<LtiRosterEligibilityPreparedEvaluation> => {
  const rule = await findBadgeIssuanceRuleById(input.db, input.tenantId, input.ruleId);

  if (rule === null) {
    return {
      status: "rule_pending",
      detail: LTI_ROSTER_NO_RULE_LINKED_DETAIL,
      issuanceBehavior: ltiRosterRulePendingIssuanceBehavior(LTI_ROSTER_NO_RULE_LINKED_DETAIL),
    };
  }

  const activeVersion = await findActiveBadgeIssuanceRuleVersion(input.db, {
    tenantId: input.tenantId,
    ruleId: rule.id,
  });

  if (activeVersion === null) {
    return {
      status: "rule_pending",
      detail: "Rule is waiting for review and activation.",
      issuanceBehavior: ltiRosterRulePendingIssuanceBehavior(
        "Rule is waiting for review and activation.",
      ),
    };
  }

  const definition = await resolveBadgeIssuanceRuleDefinitionValueLists(
    input.db,
    input.tenantId,
    resolveRuleDefinition(activeVersion.ruleJson),
  );

  return {
    status: "ready",
    ruleId: rule.id,
    versionId: activeVersion.id,
    lmsProviderKind: rule.lmsProviderKind,
    lmsConnectionId: rule.lmsConnectionId,
    definition,
    issuanceBehavior: ltiRosterIssuanceBehaviorFromRuleDefinition(definition),
  };
};

const eligibilityFromEvaluation = (
  evaluation: BadgeIssuanceRuleEvaluationResult,
  input: {
    ruleId: string;
    versionId: string;
    learnerId: string;
    facts: Awaited<ReturnType<typeof loadRuleFacts>>;
    nowIso: string;
  },
): LtiRosterEligibilityResult => {
  const evaluationSummary = summarizeBadgeIssuanceRuleEvaluation(evaluation);
  const provenanceJson = buildIssuanceProvenanceSnapshotJson({
    outcome: evaluation.matched ? "matched" : "no_match",
    evaluation: {
      matched: evaluation.matched,
      tree: evaluation.tree,
    },
    evaluationSummary,
    facts: { ...input.facts },
    learnerId: input.learnerId,
    nowIso: input.nowIso,
  });

  if (evaluation.matched) {
    return {
      ...statusResult("eligible", "Meets the active badge rule.", true),
      issuanceProvenance: {
        ruleId: input.ruleId,
        versionId: input.versionId,
        provenanceJson,
      },
    };
  }

  const summary = evaluationSummary;
  const detail = primaryEvaluationDetail(evaluation.tree);

  if (summary.missingDataCount > 0) {
    return statusResult("missing_evidence", detail, false);
  }

  return statusResult("not_yet_eligible", detail, false);
};

export const ltiRosterAlreadyIssuedEligibilityDetail = (
  issuedState: LtiRosterIssuedBadgeStateForEligibility,
): string =>
  issuedState.lifecycleState === null || issuedState.lifecycleState === "active"
    ? "Badge was already issued for this learner."
    : `Badge was already issued and is ${issuedState.lifecycleState}.`;

const alreadyIssuedEligibilityResult = (
  issuedState: LtiRosterIssuedBadgeStateForEligibility,
): LtiRosterEligibilityResult => {
  return statusResult(
    "already_issued",
    ltiRosterAlreadyIssuedEligibilityDetail(issuedState),
    false,
  );
};

const memberEligibilityBeforeRuleEvaluation = (input: {
  member: LtiNrpsMember;
  issuedState: LtiRosterIssuedBadgeStateForEligibility | null;
  prepared: LtiRosterEligibilityPreparedEvaluation;
}): LtiRosterEligibilityResult | null => {
  if (input.issuedState !== null) {
    return alreadyIssuedEligibilityResult(input.issuedState);
  }

  if (input.prepared.status === "rule_pending") {
    return statusResult("rule_pending", input.prepared.detail, false);
  }

  if (input.member.email === undefined) {
    return statusResult(
      "unavailable",
      "The LMS did not provide an email address for this learner.",
      false,
    );
  }

  return null;
};

const ltiNrpsMemberWithEmail = (
  member: LtiNrpsMember,
): member is LtiNrpsMember & Required<Pick<LtiNrpsMember, "email">> => {
  return member.email !== undefined;
};

const evaluateLtiRosterMemberEligibilityWithPreparedContext = async (input: {
  db: SqlDatabase;
  tenantId: string;
  member: LtiNrpsMember;
  issuedState: LtiRosterIssuedBadgeStateForEligibility | null;
  nowIso: string;
  prepared: LtiRosterEligibilityPreparedEvaluation;
}): Promise<LtiRosterEligibilityResult> => {
  const earlyResult = memberEligibilityBeforeRuleEvaluation({
    member: input.member,
    issuedState: input.issuedState,
    prepared: input.prepared,
  });

  if (earlyResult !== null) {
    return earlyResult;
  }

  if (input.prepared.status !== "ready" || !ltiNrpsMemberWithEmail(input.member)) {
    return statusResult("rule_pending", LTI_ROSTER_NO_RULE_LINKED_DETAIL, false);
  }

  try {
    const facts = await loadRuleFacts({
      db: input.db,
      tenantId: input.tenantId,
      lmsProviderKind: input.prepared.lmsProviderKind,
      lmsConnectionId: input.prepared.lmsConnectionId ?? undefined,
      learnerId: input.member.userId,
      recipient: {
        identity: input.member.email,
        identityType: "email",
      },
      definition: input.prepared.definition,
      nowIso: input.nowIso,
    });
    const evaluation = evaluateBadgeIssuanceRuleDefinition(input.prepared.definition, facts);

    return eligibilityFromEvaluation(evaluation, {
      ruleId: input.prepared.ruleId,
      versionId: input.prepared.versionId,
      learnerId: input.member.userId,
      facts,
      nowIso: input.nowIso,
    });
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

export const evaluateLtiRosterMemberEligibility = async (input: {
  db: SqlDatabase;
  tenantId: string;
  ruleResolution: LtiRosterEligibilityRuleResolution;
  member: LtiNrpsMember;
  issuedState: LtiRosterIssuedBadgeStateForEligibility | null;
  nowIso: string;
}): Promise<LtiRosterEligibilityResult> => {
  if (input.issuedState !== null) {
    return alreadyIssuedEligibilityResult(input.issuedState);
  }

  if (input.ruleResolution.status !== "resolved") {
    return rosterMemberEligibilityFromRuleResolution(input.ruleResolution);
  }

  const prepared = await prepareLtiRosterEligibilityEvaluationContext({
    db: input.db,
    tenantId: input.tenantId,
    ruleId: input.ruleResolution.ruleId,
  });

  return evaluateLtiRosterMemberEligibilityWithPreparedContext({
    db: input.db,
    tenantId: input.tenantId,
    member: input.member,
    issuedState: input.issuedState,
    nowIso: input.nowIso,
    prepared,
  });
};

export const evaluateLtiRosterMembersEligibility = async (input: {
  db: SqlDatabase;
  tenantId: string;
  ruleResolution: LtiRosterEligibilityRuleResolution;
  members: readonly LtiNrpsMember[];
  issuedStatesByUserId: ReadonlyMap<string, LtiRosterIssuedBadgeStateForEligibility>;
  nowIso: string;
  prepared?: LtiRosterEligibilityPreparedEvaluation | null;
}): Promise<Map<string, LtiRosterEligibilityResult>> => {
  if (input.ruleResolution.status !== "resolved") {
    const unresolvedResult = rosterMemberEligibilityFromRuleResolution(input.ruleResolution);

    return new Map(
      input.members.map((member) => {
        const issuedState = input.issuedStatesByUserId.get(member.userId) ?? null;

        return [
          member.userId,
          issuedState === null ? unresolvedResult : alreadyIssuedEligibilityResult(issuedState),
        ] as const;
      }),
    );
  }

  const prepared =
    input.prepared ??
    (await prepareLtiRosterEligibilityEvaluationContext({
      db: input.db,
      tenantId: input.tenantId,
      ruleId: input.ruleResolution.ruleId,
    }));

  return evaluateLtiRosterMembersEligibilityWithPreparedContext({
    db: input.db,
    tenantId: input.tenantId,
    prepared,
    members: input.members,
    issuedStatesByUserId: input.issuedStatesByUserId,
    nowIso: input.nowIso,
  });
};

const evaluateLtiRosterMembersEligibilityWithPreparedContext = async (input: {
  db: SqlDatabase;
  tenantId: string;
  prepared: LtiRosterEligibilityPreparedEvaluation;
  members: readonly LtiNrpsMember[];
  issuedStatesByUserId: ReadonlyMap<string, LtiRosterIssuedBadgeStateForEligibility>;
  nowIso: string;
}): Promise<Map<string, LtiRosterEligibilityResult>> => {
  const concurrency = 8;
  const eligibilityEntries: Array<readonly [string, LtiRosterEligibilityResult]> = [];
  let nextIndex = 0;
  const evaluateNextMember = async (): Promise<void> => {
    while (nextIndex < input.members.length) {
      const member = input.members[nextIndex];
      nextIndex += 1;

      if (member === undefined) {
        continue;
      }

      const eligibility = await evaluateLtiRosterMemberEligibilityWithPreparedContext({
        db: input.db,
        tenantId: input.tenantId,
        member,
        issuedState: input.issuedStatesByUserId.get(member.userId) ?? null,
        nowIso: input.nowIso,
        prepared: input.prepared,
      });

      eligibilityEntries.push([member.userId, eligibility] as const);
    }
  };

  await Promise.all(
    Array.from({ length: Math.min(concurrency, input.members.length) }, () => evaluateNextMember()),
  );

  return new Map(eligibilityEntries);
};
