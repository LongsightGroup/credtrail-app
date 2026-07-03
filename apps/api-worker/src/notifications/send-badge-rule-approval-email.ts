import {
  findUserById,
  listTenantMembers,
  tenantMembershipRoleSatisfiesMinimumRole,
  type BadgeIssuanceRuleApprovalStepRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { sendTransactionalEmail } from "./transactional-email";

export interface BadgeRuleApprovalEmailContext {
  readonly emailBinding?: SendEmail | undefined;
  readonly fromEmail?: string | undefined;
  readonly fromName?: string | undefined;
  readonly tenantId: string;
  readonly tenantDisplayName: string;
  readonly ruleName: string;
  readonly versionNumber: number;
  readonly reviewUrl: string;
}

export const sendBadgeRuleApprovalSubmittedEmail = async (
  input: BadgeRuleApprovalEmailContext & {
    readonly recipientEmail: string;
    readonly stepLabel: string;
  },
): Promise<void> => {
  await sendTransactionalEmail({
    emailBinding: input.emailBinding,
    fromEmail: input.fromEmail,
    fromName: input.fromName,
    recipientEmail: input.recipientEmail,
    subject: `Badge rule awaiting approval: ${input.ruleName}`,
    text: [
      `A badge rule version is awaiting your approval in ${input.tenantDisplayName}.`,
      "",
      `Rule: ${input.ruleName}`,
      `Version: ${String(input.versionNumber)}`,
      `Approval step: ${input.stepLabel}`,
      "",
      input.reviewUrl,
    ].join("\n"),
    category: "Badge Rule Approval",
  });
};

export const sendBadgeRuleApprovalDecisionEmail = async (
  input: BadgeRuleApprovalEmailContext & {
    readonly recipientEmail: string;
    readonly decisionLabel: string;
    readonly comment: string | null;
  },
): Promise<void> => {
  await sendTransactionalEmail({
    emailBinding: input.emailBinding,
    fromEmail: input.fromEmail,
    fromName: input.fromName,
    recipientEmail: input.recipientEmail,
    subject: `Badge rule ${input.decisionLabel.toLowerCase()}: ${input.ruleName}`,
    text: [
      `A badge rule version was ${input.decisionLabel.toLowerCase()} in ${input.tenantDisplayName}.`,
      "",
      `Rule: ${input.ruleName}`,
      `Version: ${String(input.versionNumber)}`,
      ...(input.comment === null ? [] : ["", `Reviewer comment: ${input.comment}`]),
      "",
      input.reviewUrl,
    ].join("\n"),
    category: "Badge Rule Approval",
  });
};

const listApproverGroupRecipientEmails = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly groupId: string;
  },
): Promise<readonly string[]> => {
  const result = await db
    .prepare(
      `
      SELECT users.email
      FROM badge_rule_approver_group_members AS members
      INNER JOIN users
        ON users.id = members.user_id
      WHERE members.tenant_id = ?
        AND members.group_id = ?
      ORDER BY users.email ASC
    `,
    )
    .bind(input.tenantId, input.groupId)
    .all<{ email: string }>();

  return result.results.map((row) => row.email);
};

export const resolveBadgeRuleApprovalStepRecipientEmails = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly step: BadgeIssuanceRuleApprovalStepRecord;
  },
): Promise<readonly string[]> => {
  if (input.step.targetType === "user") {
    const user = await findUserById(db, input.step.targetUserId);

    return user === null ? [] : [user.email];
  }

  if (input.step.targetType === "approver_group") {
    const groupEmails = await listApproverGroupRecipientEmails(db, {
      tenantId: input.tenantId,
      groupId: input.step.targetApproverGroupId,
    });

    if (input.step.requiredRole === null) {
      return groupEmails;
    }

    const requiredRole = input.step.requiredRole;
    const tenantMembers = await listTenantMembers(db, input.tenantId);
    const allowedEmails = new Set(
      tenantMembers
        .filter((member) => tenantMembershipRoleSatisfiesMinimumRole(member.role, requiredRole))
        .map((member) => member.email),
    );

    return groupEmails.filter((email) => allowedEmails.has(email));
  }

  if (input.step.requiredRole === null) {
    return [];
  }

  const requiredRole = input.step.requiredRole;
  const tenantMembers = await listTenantMembers(db, input.tenantId);

  return tenantMembers
    .filter((member) => tenantMembershipRoleSatisfiesMinimumRole(member.role, requiredRole))
    .map((member) => member.email);
};

export const sendBadgeRuleApprovalSubmittedNotifications = async (
  db: SqlDatabase,
  input: BadgeRuleApprovalEmailContext & {
    readonly step: BadgeIssuanceRuleApprovalStepRecord;
  },
): Promise<void> => {
  const recipientEmails = await resolveBadgeRuleApprovalStepRecipientEmails(db, {
    tenantId: input.tenantId,
    step: input.step,
  });
  const stepLabel = input.step.label ?? `Step ${String(input.step.stepNumber)}`;

  await Promise.allSettled(
    recipientEmails.map((recipientEmail) =>
      sendBadgeRuleApprovalSubmittedEmail({
        ...input,
        recipientEmail,
        stepLabel,
      }),
    ),
  );
};
