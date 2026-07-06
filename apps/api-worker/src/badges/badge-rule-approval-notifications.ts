import {
  findBadgeIssuanceRuleById,
  findTenantById,
  findUserById,
  listBadgeIssuanceRuleVersionApprovalSteps,
  type BadgeIssuanceRuleApprovalDecision,
  type BadgeIssuanceRuleVersionRecord,
  type SqlDatabase,
} from "@credtrail/db";
import type { AppBindings } from "../app";
import {
  sendBadgeRuleApprovalDecisionEmail,
  sendBadgeRuleApprovalSubmittedNotifications,
} from "../notifications/send-badge-rule-approval-email";

const nextPendingApprovalStep = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    versionId: string;
    targetStepNumber?: number | null | undefined;
  },
) => {
  const steps = await listBadgeIssuanceRuleVersionApprovalSteps(db, input);

  if (input.targetStepNumber !== undefined && input.targetStepNumber !== null) {
    return (
      steps.find(
        (step) => step.stepNumber === input.targetStepNumber && step.status === "pending",
      ) ?? null
    );
  }

  return steps.find((step) => step.status === "pending") ?? null;
};

const decisionLabel = (decision: BadgeIssuanceRuleApprovalDecision): string => {
  switch (decision) {
    case "approved":
      return "Approved";
    case "changes_requested":
      return "Changes requested";
    case "rejected":
      return "Rejected";
  }
};

const uniqueRecipientUserIds = (version: BadgeIssuanceRuleVersionRecord): readonly string[] => {
  return Array.from(
    new Set(
      [version.submittedByUserId, version.createdByUserId].filter(
        (userId): userId is string => userId !== null,
      ),
    ),
  );
};

const tenantDisplayName = async (db: SqlDatabase, tenantId: string): Promise<string> => {
  const tenant = await findTenantById(db, tenantId);

  return tenant?.displayName ?? tenantId;
};

export const notifyBadgeRuleApprovalSubmitted = async (
  db: SqlDatabase,
  input: {
    env: AppBindings;
    tenantId: string;
    ruleId: string;
    version: BadgeIssuanceRuleVersionRecord;
    reviewUrl: string;
    targetStepNumber?: number | null | undefined;
  },
): Promise<void> => {
  const [rule, displayName, firstPendingStep] = await Promise.all([
    findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId),
    tenantDisplayName(db, input.tenantId),
    nextPendingApprovalStep(db, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.version.id,
      targetStepNumber: input.targetStepNumber,
    }),
  ]);

  if (rule === null || firstPendingStep === null) {
    return;
  }

  await sendBadgeRuleApprovalSubmittedNotifications(db, {
    emailBinding: input.env.EMAIL,
    fromEmail: input.env.TRANSACTIONAL_EMAIL_FROM_ADDRESS,
    fromName: input.env.TRANSACTIONAL_EMAIL_FROM_NAME,
    tenantId: input.tenantId,
    tenantDisplayName: displayName,
    ruleName: rule.name,
    versionNumber: input.version.versionNumber,
    reviewUrl: input.reviewUrl,
    step: firstPendingStep,
  });
};

export const notifyBadgeRuleApprovalDecision = async (
  db: SqlDatabase,
  input: {
    env: AppBindings;
    tenantId: string;
    ruleId: string;
    version: BadgeIssuanceRuleVersionRecord;
    decision: BadgeIssuanceRuleApprovalDecision;
    comment: string | null;
    reviewUrl: string;
    nextStepNumber?: number | null | undefined;
  },
): Promise<void> => {
  const [rule, displayName, nextStep] = await Promise.all([
    findBadgeIssuanceRuleById(db, input.tenantId, input.ruleId),
    tenantDisplayName(db, input.tenantId),
    nextPendingApprovalStep(db, {
      tenantId: input.tenantId,
      ruleId: input.ruleId,
      versionId: input.version.id,
      targetStepNumber: input.nextStepNumber,
    }),
  ]);

  if (rule === null) {
    return;
  }

  const hasNextStepNotificationTarget =
    input.nextStepNumber !== undefined && input.nextStepNumber !== null;

  if (input.decision === "approved" && hasNextStepNotificationTarget && nextStep !== null) {
    await sendBadgeRuleApprovalSubmittedNotifications(db, {
      emailBinding: input.env.EMAIL,
      fromEmail: input.env.TRANSACTIONAL_EMAIL_FROM_ADDRESS,
      fromName: input.env.TRANSACTIONAL_EMAIL_FROM_NAME,
      tenantId: input.tenantId,
      tenantDisplayName: displayName,
      ruleName: rule.name,
      versionNumber: input.version.versionNumber,
      reviewUrl: input.reviewUrl,
      step: nextStep,
    });
    return;
  }

  if (input.decision === "approved" && hasNextStepNotificationTarget) {
    return;
  }

  const recipientUsers = await Promise.all(
    uniqueRecipientUserIds(input.version).map((userId) => findUserById(db, userId)),
  );

  await Promise.allSettled(
    recipientUsers.flatMap((user) =>
      user === null
        ? []
        : [
            sendBadgeRuleApprovalDecisionEmail({
              emailBinding: input.env.EMAIL,
              fromEmail: input.env.TRANSACTIONAL_EMAIL_FROM_ADDRESS,
              fromName: input.env.TRANSACTIONAL_EMAIL_FROM_NAME,
              tenantId: input.tenantId,
              tenantDisplayName: displayName,
              ruleName: rule.name,
              versionNumber: input.version.versionNumber,
              reviewUrl: input.reviewUrl,
              recipientEmail: user.email,
              decisionLabel: decisionLabel(input.decision),
              comment: input.comment,
            }),
          ],
    ),
  );
};
