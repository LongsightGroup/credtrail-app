import {
  createAuditLog,
  expireBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
  findLtiResourceLinkPlacementForRule,
  listActiveLtiLaunchSessionsForPlatform,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type SqlDatabase,
} from "@credtrail/db";
import type { ProcessEndOfTermBadgeRuleQueueJob } from "@credtrail/validation";
import type { AppBindings } from "../app";
import {
  resolveBadgeIssuanceRuleDefinitionValueLists,
  resolveRuleDefinition,
} from "../rules/badge-rule-definition-resolver";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";
import { enqueueEligibleLtiRosterIssuanceJobs } from "./enqueue-eligible-roster-issuance-jobs";
import { ltiRosterIssuanceBehaviorFromRuleDefinition } from "./issuance-behavior";
import { loadLtiNrpsRoster } from "./nrps";
import { matchingPlacementSession } from "./placement-session";

export interface ProcessEndOfTermBadgeRuleResult {
  readonly status: "processed" | "unavailable";
  readonly evaluatedLearnerCount: number;
  readonly issueJobsEnqueued: number;
  readonly reason?: string | undefined;
}

const canProcessEndOfTermVersion = (input: {
  readonly rule: BadgeIssuanceRuleRecord;
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly scheduledFor: string;
}): boolean => {
  if (input.rule.activeVersionId !== input.version.id || input.version.status !== "active") {
    return false;
  }

  if (
    input.version.effectiveStartsAt !== null &&
    input.version.effectiveStartsAt > input.scheduledFor
  ) {
    return false;
  }

  return input.version.expiresAt !== null && input.version.expiresAt <= input.scheduledFor;
};

export const processEndOfTermBadgeRule = async (input: {
  readonly db: SqlDatabase;
  readonly env: AppBindings;
  readonly tenantId: string;
  readonly payload: ProcessEndOfTermBadgeRuleQueueJob["payload"];
  readonly sha256Hex: (value: string) => Promise<string>;
}): Promise<ProcessEndOfTermBadgeRuleResult> => {
  const [rule, version, placement] = await Promise.all([
    findBadgeIssuanceRuleById(input.db, input.tenantId, input.payload.ruleId),
    findBadgeIssuanceRuleVersionById(input.db, {
      tenantId: input.tenantId,
      ruleId: input.payload.ruleId,
      versionId: input.payload.versionId,
    }),
    findLtiResourceLinkPlacementForRule(input.db, {
      tenantId: input.tenantId,
      ruleId: input.payload.ruleId,
    }),
  ]);

  if (rule === null || version === null || placement === null) {
    return {
      status: "unavailable",
      evaluatedLearnerCount: 0,
      issueJobsEnqueued: 0,
      reason: "Rule, version, or LMS placement was not found.",
    };
  }

  if (
    !canProcessEndOfTermVersion({
      rule,
      version,
      scheduledFor: input.payload.scheduledFor,
    })
  ) {
    return {
      status: "unavailable",
      evaluatedLearnerCount: 0,
      issueJobsEnqueued: 0,
      reason: "Rule version is no longer active for end-of-term issuance.",
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
      evaluatedLearnerCount: 0,
      issueJobsEnqueued: 0,
      reason: "No active LMS launch session is available for this course placement.",
    };
  }

  const ltiTool = await createCredTrailLtiTool({
    db: input.db,
    env: input.env,
    tenantId: input.tenantId,
  });
  const rosterResult = await loadLtiNrpsRoster({
    ltiTool,
    ltiSession,
    contextId: ltiSession.context.id,
  });

  if (!rosterResult.success) {
    return {
      status: "unavailable",
      evaluatedLearnerCount: 0,
      issueJobsEnqueued: 0,
      reason: "CredTrail could not load the LMS roster for this course.",
    };
  }

  const definition = await resolveBadgeIssuanceRuleDefinitionValueLists(
    input.db,
    input.tenantId,
    resolveRuleDefinition(version.ruleJson),
  );
  const { issueJobsEnqueued } = await enqueueEligibleLtiRosterIssuanceJobs({
    db: input.db,
    tenantId: input.tenantId,
    ruleId: input.payload.ruleId,
    badgeTemplateId: rule.badgeTemplateId,
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
    prepared: {
      status: "ready",
      ruleId: input.payload.ruleId,
      versionId: version.id,
      lmsProviderKind: rule.lmsProviderKind,
      lmsConnectionId: rule.lmsConnectionId,
      definition,
      issuanceBehavior: ltiRosterIssuanceBehaviorFromRuleDefinition(definition),
    },
    nowIso: input.payload.scheduledFor,
    sha256Hex: input.sha256Hex,
  });

  const expiredVersion = await expireBadgeIssuanceRuleVersion(input.db, {
    tenantId: input.tenantId,
    ruleId: input.payload.ruleId,
    versionId: input.payload.versionId,
    occurredAt: input.payload.scheduledFor,
  });

  if (expiredVersion !== null) {
    await createAuditLog(input.db, {
      tenantId: input.tenantId,
      action: "badge_rule.version_expired",
      targetType: "badge_rule_version",
      targetId: expiredVersion.id,
      metadata: {
        ruleId: input.payload.ruleId,
        expiresAt: expiredVersion.expiresAt,
        endOfTermIssuanceJobsEnqueued: issueJobsEnqueued,
      },
      occurredAt: input.payload.scheduledFor,
    });
  }

  return {
    status: "processed",
    evaluatedLearnerCount: rosterResult.roster.learnerMembers.length,
    issueJobsEnqueued,
  };
};
