import { logInfo, type ObservabilityContext } from "@credtrail/core-domain";
import {
  markAutomatedBadgeRuleEvaluationNoop,
  markAutomatedBadgeRuleEvaluationRetrying,
  markAutomatedBadgeRuleEvaluationRunning,
  markAutomatedBadgeRuleEvaluationSucceeded,
  type SqlDatabase,
} from "@credtrail/db";
import type { ProcessAutomatedBadgeRuleQueueJob } from "@credtrail/validation";
import { processAutomatedBadgeRule } from "./automated-badge-rule-processor";

/** Processes one automated-rule queue job and translates retry outcomes to queue failure. */
export const processAutomatedBadgeRuleQueueJob = async (input: {
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly payload: ProcessAutomatedBadgeRuleQueueJob["payload"];
  readonly commandId: string;
  readonly sha256Hex: (value: string) => Promise<string>;
  readonly observability: ObservabilityContext;
}): Promise<void> => {
  const startedAt = new Date().toISOString();
  await markAutomatedBadgeRuleEvaluationRunning(input.db, {
    tenantId: input.tenantId,
    commandId: input.commandId,
    startedAt,
  });
  const result = await processAutomatedBadgeRule({
    db: input.db,
    tenantId: input.tenantId,
    payload: input.payload,
    sha256Hex: input.sha256Hex,
  });

  if (result.status === "noop") {
    const completedAt = new Date().toISOString();
    await markAutomatedBadgeRuleEvaluationNoop(input.db, {
      tenantId: input.tenantId,
      commandId: input.commandId,
      completedAt,
      reasonTag: result.reason,
    });
    logInfo(input.observability, "automated_badge_rule_noop", {
      tenantId: input.tenantId,
      ruleId: input.payload.ruleId,
      versionId: input.payload.versionId,
      reason: result.reason,
    });
    return;
  }

  if (result.status === "retry") {
    const attemptedAt = new Date().toISOString();
    await markAutomatedBadgeRuleEvaluationRetrying(input.db, {
      tenantId: input.tenantId,
      commandId: input.commandId,
      attemptedAt,
      reasonTag: result.reason,
      counts: {
        candidateLearnerCount: result.candidateLearnerCount,
        matchedLearnerCount: result.matchedLearnerCount,
        issueJobsEnqueued: 0,
        learnersMissingEmail: result.learnersMissingEmail,
        learnersAlreadyIssued: result.learnersAlreadyIssued,
        learnersUnavailable: result.learnersUnavailable,
        learnerIdentityConflicts: result.learnerIdentityConflicts,
      },
    });
    logInfo(input.observability, "automated_badge_rule_retry_requested", {
      tenantId: input.tenantId,
      ruleId: input.payload.ruleId,
      versionId: input.payload.versionId,
      reason: result.reason,
      candidateLearnerCount: result.candidateLearnerCount,
      matchedLearnerCount: result.matchedLearnerCount,
      learnersMissingEmail: result.learnersMissingEmail,
      learnersAlreadyIssued: result.learnersAlreadyIssued,
      learnersUnavailable: result.learnersUnavailable,
      learnerIdentityConflicts: result.learnerIdentityConflicts,
    });
    throw new Error("Automated badge rule evaluation is incomplete and must be retried");
  }

  const completedAt = new Date().toISOString();
  await markAutomatedBadgeRuleEvaluationSucceeded(input.db, {
    tenantId: input.tenantId,
    commandId: input.commandId,
    completedAt,
    counts: {
      candidateLearnerCount: result.candidateLearnerCount,
      matchedLearnerCount: result.matchedLearnerCount,
      issueJobsEnqueued: result.issueJobsEnqueued,
      learnersMissingEmail: result.learnersMissingEmail,
      learnersAlreadyIssued: result.learnersAlreadyIssued,
      learnersUnavailable: result.learnersUnavailable,
      learnerIdentityConflicts: result.learnerIdentityConflicts,
    },
  });
  logInfo(input.observability, "automated_badge_rule_processed", {
    tenantId: input.tenantId,
    ruleId: input.payload.ruleId,
    versionId: input.payload.versionId,
    candidateLearnerCount: result.candidateLearnerCount,
    matchedLearnerCount: result.matchedLearnerCount,
    issueJobsEnqueued: result.issueJobsEnqueued,
    versionExpired: result.versionExpired,
    learnersMissingEmail: result.learnersMissingEmail,
    learnersAlreadyIssued: result.learnersAlreadyIssued,
    learnersUnavailable: result.learnersUnavailable,
    learnerIdentityConflicts: result.learnerIdentityConflicts,
  });
};
