import { logError } from "@credtrail/core-domain";
import {
  createAuditLog,
  enqueueJobQueueMessageOnce,
  type BadgeIssuanceRuleVersionRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import { buildBadgeRuleVersionReviewPath } from "../admin/access-admin-helpers";
import type { AppContext } from "../app";
import { observabilityContext } from "../app/observability";
import { badgeRuleApprovalSubmittedNotificationIdempotencyKey } from "./badge-rule-approval-notification-queue";

interface BadgeRuleApprovalSubmissionSideEffectsInput {
  readonly c: AppContext;
  readonly db: SqlDatabase;
  readonly tenantId: string;
  readonly ruleId: string;
  readonly actorUserId: string;
  readonly actorRole: TenantMembershipRole;
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly pendingStepNumber: number | null;
  readonly audit: "record" | "already_recorded";
}

const runSubmissionSideEffect = async (
  input: BadgeRuleApprovalSubmissionSideEffectsInput,
  sideEffect: "audit_log" | "notification_enqueue",
  run: () => Promise<unknown>,
): Promise<void> => {
  try {
    await run();
  } catch (cause: unknown) {
    logError(observabilityContext(input.c.env), "badge_rule_approval_side_effect_failed", {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.version.id,
      sideEffect,
      eventType: "approval_submitted",
      errorKind: cause instanceof Error ? cause.name : typeof cause,
    });
  }
};

/** Records audit and notification effects after a badge-rule approval submission commits. */
export const recordBadgeRuleApprovalSubmissionSideEffects = async (
  input: BadgeRuleApprovalSubmissionSideEffectsInput,
): Promise<void> => {
  const effects: Promise<void>[] = [];

  if (input.audit === "record") {
    effects.push(
      runSubmissionSideEffect(input, "audit_log", () =>
        createAuditLog(input.db, {
          tenantId: input.tenantId,
          actorUserId: input.actorUserId,
          action: "badge_rule.version_submitted_for_approval",
          targetType: "badge_rule_version",
          targetId: input.version.id,
          metadata: {
            role: input.actorRole,
            ruleId: input.ruleId,
            versionNumber: input.version.versionNumber,
            status: input.version.status,
          },
        }),
      ),
    );
  }

  if (input.pendingStepNumber !== null) {
    effects.push(
      runSubmissionSideEffect(input, "notification_enqueue", () =>
        enqueueJobQueueMessageOnce(input.db, {
          tenantId: input.tenantId,
          jobType: "send_badge_rule_approval_notification",
          idempotencyKey: badgeRuleApprovalSubmittedNotificationIdempotencyKey({
            versionId: input.version.id,
            occurredAt: input.version.submittedAt ?? input.version.updatedAt,
          }),
          payload: {
            notificationType: "approval_submitted",
            ruleId: input.ruleId,
            versionId: input.version.id,
            reviewUrl: new URL(
              buildBadgeRuleVersionReviewPath(input.tenantId, input.ruleId, input.version.id),
              input.c.req.url,
            ).toString(),
            targetStepNumber: input.pendingStepNumber,
          },
        }),
      ),
    );
  }

  await Promise.all(effects);
};
