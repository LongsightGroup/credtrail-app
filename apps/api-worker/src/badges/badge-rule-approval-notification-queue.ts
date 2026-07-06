import { findBadgeIssuanceRuleVersionById, type SqlDatabase } from "@credtrail/db";
import type { SendBadgeRuleApprovalNotificationQueueJob } from "@credtrail/validation";
import type { AppBindings } from "../app";
import {
  notifyBadgeRuleApprovalDecision,
  notifyBadgeRuleApprovalSubmitted,
} from "./badge-rule-approval-notifications";

export const badgeRuleApprovalSubmittedNotificationIdempotencyKey = (input: {
  readonly versionId: string;
  readonly occurredAt: string;
}): string => `approval-submitted:${input.versionId}:${input.occurredAt}`;

export const badgeRuleApprovalDecisionNotificationIdempotencyKey = (input: {
  readonly versionId: string;
  readonly occurredAt: string;
}): string => `approval-decision:${input.versionId}:${input.occurredAt}`;

export const processBadgeRuleApprovalNotificationJob = async (input: {
  readonly db: SqlDatabase;
  readonly env: AppBindings;
  readonly tenantId: string;
  readonly payload: SendBadgeRuleApprovalNotificationQueueJob["payload"];
}): Promise<void> => {
  const version = await findBadgeIssuanceRuleVersionById(input.db, {
    tenantId: input.tenantId,
    ruleId: input.payload.ruleId,
    versionId: input.payload.versionId,
  });

  if (version === null) {
    return;
  }

  if (input.payload.notificationType === "approval_submitted") {
    await notifyBadgeRuleApprovalSubmitted(input.db, {
      env: input.env,
      tenantId: input.tenantId,
      ruleId: input.payload.ruleId,
      version,
      reviewUrl: input.payload.reviewUrl,
      targetStepNumber: input.payload.targetStepNumber,
    });
    return;
  }

  await notifyBadgeRuleApprovalDecision(input.db, {
    env: input.env,
    tenantId: input.tenantId,
    ruleId: input.payload.ruleId,
    version,
    decision: input.payload.decision,
    comment: input.payload.comment,
    reviewUrl: input.payload.reviewUrl,
    nextStepNumber: input.payload.nextStepNumber,
  });
};
