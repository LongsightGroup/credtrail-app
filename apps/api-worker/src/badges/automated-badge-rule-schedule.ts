import type { BadgeRuleLifecycleDueVersionRecord } from "@credtrail/db";
import {
  parseBadgeIssuanceRuleDefinitionJson,
  resolveAutomatedBadgeRuleIssuanceTiming,
  type AutomatedBadgeRuleIssuanceTiming,
  type ProcessAutomatedBadgeRuleQueueJob,
} from "@credtrail/validation";

export interface AutomatedBadgeRuleScheduleCommand {
  readonly tenantId: string;
  readonly payload: ProcessAutomatedBadgeRuleQueueJob["payload"];
  readonly idempotencyKey: string;
}

export interface AutomatedBadgeRuleLifecyclePlan {
  readonly evaluationCommands: readonly AutomatedBadgeRuleScheduleCommand[];
  readonly versionsToExpire: readonly BadgeRuleLifecycleDueVersionRecord[];
}

const lifecycleHourBucket = (isoTimestamp: string): string => isoTimestamp.slice(0, 13);

const issuanceTiming = (
  version: BadgeRuleLifecycleDueVersionRecord,
): AutomatedBadgeRuleIssuanceTiming | null =>
  resolveAutomatedBadgeRuleIssuanceTiming(parseBadgeIssuanceRuleDefinitionJson(version.ruleJson));

/** Plans automated evaluation and ordinary expiration without performing persistence work. */
export const planAutomatedBadgeRuleLifecycle = (input: {
  readonly tenantId: string;
  readonly nowIso: string;
  readonly evaluableVersions: readonly BadgeRuleLifecycleDueVersionRecord[];
  readonly dueVersions: readonly BadgeRuleLifecycleDueVersionRecord[];
}): AutomatedBadgeRuleLifecyclePlan => {
  const evaluationCommands: AutomatedBadgeRuleScheduleCommand[] = [];
  const versionsToExpire: BadgeRuleLifecycleDueVersionRecord[] = [];

  for (const version of input.evaluableVersions) {
    if (issuanceTiming(version) !== "immediate") {
      continue;
    }

    evaluationCommands.push({
      tenantId: input.tenantId,
      payload: {
        ruleId: version.ruleId,
        versionId: version.id,
        scheduledFor: input.nowIso,
      },
      idempotencyKey: `automated-rule:${version.ruleId}:${version.id}:hour:${lifecycleHourBucket(input.nowIso)}`,
    });
  }

  for (const version of input.dueVersions) {
    if (issuanceTiming(version) !== "end_of_term" || version.expiresAt === null) {
      versionsToExpire.push(version);
      continue;
    }

    evaluationCommands.push({
      tenantId: input.tenantId,
      payload: {
        ruleId: version.ruleId,
        versionId: version.id,
        scheduledFor: input.nowIso,
      },
      idempotencyKey: `automated-rule:${version.ruleId}:${version.id}:expiry:${version.expiresAt}`,
    });
  }

  return { evaluationCommands, versionsToExpire };
};
