import { findBadgeIssuanceRuleVersionById, type SqlDatabase } from "@credtrail/db";
import type { SendBadgeRuleApprovalNotificationQueueJob } from "@credtrail/validation";
import { buildBadgeRuleVersionReviewPath } from "../admin/access-admin-helpers";
import type { AppBindings } from "../app";
import { canonicalAppUrl } from "../http/canonical-app-url";
import {
  notifyBadgeRuleApprovalDecision,
  notifyBadgeRuleApprovalSubmitted,
} from "./badge-rule-approval-notifications";

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

  const reviewUrl = canonicalAppUrl(
    input.env.PUBLIC_APP_ORIGIN,
    buildBadgeRuleVersionReviewPath(input.tenantId, input.payload.ruleId, input.payload.versionId),
  );

  if (input.payload.notificationType === "approval_submitted") {
    await notifyBadgeRuleApprovalSubmitted(input.db, {
      env: input.env,
      tenantId: input.tenantId,
      ruleId: input.payload.ruleId,
      version,
      reviewUrl,
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
    reviewUrl,
    nextStepNumber: input.payload.nextStepNumber,
  });
};
