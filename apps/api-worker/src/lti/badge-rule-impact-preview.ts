import {
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
  findLtiResourceLinkPlacementForRule,
  listActiveLtiLaunchSessionsForPlatform,
  type LtiLaunchSessionRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { parsePersistedLtiSession, type LTISession } from "@longsightgroup/lti-tool";
import type { AppBindings } from "../app";
import {
  resolveBadgeIssuanceRuleDefinitionValueLists,
  resolveRuleDefinition,
} from "../rules/badge-rule-definition-resolver";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";
import { ltiRosterIssuanceBehaviorFromRuleDefinition } from "./issuance-behavior";
import { loadLtiNrpsRoster } from "./nrps";
import {
  evaluateLtiRosterMembersEligibility,
  type LtiRosterEligibilityPreparedEvaluation,
} from "./roster-eligibility";
import { ltiRosterIssuedBadgeStatesByUserId } from "./roster-issuance-helpers";

export type BadgeRuleImpactPreview =
  | {
      readonly status: "not_requested";
    }
  | {
      readonly status: "ready";
      readonly eligibleNowCount: number;
      readonly evaluatedLearnerCount: number;
      readonly courseContextId: string | null;
      readonly courseTitle: string | null;
      readonly generatedAt: string;
    }
  | {
      readonly status: "unavailable";
      readonly reason: string;
      readonly generatedAt: string;
    };

const matchingPlacementSession = (input: {
  readonly sessions: readonly LtiLaunchSessionRecord[];
  readonly contextId: string | null;
  readonly resourceLinkId: string;
}): LTISession | null => {
  for (const sessionRecord of input.sessions) {
    const session = parsePersistedLtiSession(sessionRecord.dataJson);

    if (
      session !== undefined &&
      session.context.id === input.contextId &&
      session.resourceLink?.id === input.resourceLinkId
    ) {
      return session;
    }
  }

  return null;
};

export const previewBadgeRuleVersionImpact = async (input: {
  readonly db: SqlDatabase;
  readonly env: AppBindings;
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly nowIso: string;
  readonly sha256Hex: (value: string) => Promise<string>;
}): Promise<BadgeRuleImpactPreview> => {
  const [rule, version, placement] = await Promise.all([
    findBadgeIssuanceRuleById(input.db, input.tenantId, input.ruleId),
    findBadgeIssuanceRuleVersionById(input.db, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.versionId,
    }),
    findLtiResourceLinkPlacementForRule(input.db, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
    }),
  ]);

  if (rule === null || version === null) {
    return {
      status: "unavailable",
      reason: "Rule version was not found.",
      generatedAt: input.nowIso,
    };
  }

  if (placement === null) {
    return {
      status: "unavailable",
      reason: "No LMS course placement is linked to this rule yet.",
      generatedAt: input.nowIso,
    };
  }

  const ltiSession = matchingPlacementSession({
    sessions: await listActiveLtiLaunchSessionsForPlatform(input.db, {
      tenantId: input.tenantId,
      issuer: placement.issuer,
      clientId: placement.clientId,
      deploymentId: placement.deploymentId,
      limit: 10,
    }),
    contextId: placement.contextId,
    resourceLinkId: placement.resourceLinkId,
  });

  if (ltiSession === null) {
    return {
      status: "unavailable",
      reason: "No active LMS launch session is available for this course placement.",
      generatedAt: input.nowIso,
    };
  }

  const ltiTool = await createCredTrailLtiTool({
    db: input.db,
    env: input.env,
    defaultTenantId: input.tenantId,
  });
  const rosterResult = await loadLtiNrpsRoster({
    ltiTool,
    ltiSession,
    contextId: ltiSession.context.id,
  });

  if (!rosterResult.success) {
    return {
      status: "unavailable",
      reason: "CredTrail could not load the LMS roster for this course.",
      generatedAt: input.nowIso,
    };
  }

  const definition = await resolveBadgeIssuanceRuleDefinitionValueLists(
    input.db,
    input.tenantId,
    resolveRuleDefinition(version.ruleJson),
  );
  const prepared: LtiRosterEligibilityPreparedEvaluation = {
    status: "ready",
    lmsProviderKind: rule.lmsProviderKind,
    lmsConnectionId: rule.lmsConnectionId,
    definition,
    issuanceBehavior: ltiRosterIssuanceBehaviorFromRuleDefinition(definition),
  };
  const issuedStatesByUserId = await ltiRosterIssuedBadgeStatesByUserId({
    db: input.db,
    sha256Hex: input.sha256Hex,
    action: {
      tenantId: input.tenantId,
      issuer: placement.issuer,
      clientId: placement.clientId,
      deploymentId: placement.deploymentId,
      contextId: ltiSession.context.id,
      resourceLinkId: placement.resourceLinkId,
      badgeTemplateId: rule.badgeTemplateId,
    },
    learnerMembers: rosterResult.roster.learnerMembers,
  });
  const eligibilityByUserId = await evaluateLtiRosterMembersEligibility({
    db: input.db,
    tenantId: input.tenantId,
    ruleResolution: {
      status: "resolved",
      ruleId: input.ruleId,
    },
    members: rosterResult.roster.learnerMembers,
    issuedStatesByUserId,
    nowIso: input.nowIso,
    prepared,
  });
  const eligibilityResults = Array.from(eligibilityByUserId.values());

  return {
    status: "ready",
    eligibleNowCount: eligibilityResults.filter((eligibility) => eligibility.eligibleForIssuance)
      .length,
    evaluatedLearnerCount: rosterResult.roster.learnerMembers.length,
    courseContextId: ltiSession.context.id,
    courseTitle: ltiSession.context.title.trim().length === 0 ? null : ltiSession.context.title,
    generatedAt: input.nowIso,
  };
};
