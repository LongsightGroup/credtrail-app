import { sendEmailBatch } from "./send-email-batch";
import type { EmailTracking } from "./email-attempt-store";
import type { TransactionalEmailResult } from "./transactional-email";
import {
  listTenantMembers,
  tenantMembershipRoleSatisfiesMinimumRole,
  type SqlDatabase,
} from "@credtrail/db";
import { sendTransactionalEmail } from "./transactional-email";

export type BadgeRuleLifecycleReminderType = "expiry" | "recertification";

export interface SendBadgeRuleLifecycleReminderNotificationsInput {
  readonly tracking: EmailTracking;
  readonly emailBinding?: SendEmail | undefined;
  readonly fromEmail?: string | undefined;
  readonly fromName?: string | undefined;
  readonly tenantId: string;
  readonly tenantDisplayName: string;
  readonly ruleName: string;
  readonly versionNumber: number;
  readonly dueAt: string;
  readonly reminderType: BadgeRuleLifecycleReminderType;
  readonly adminUrl: string;
}

const lifecycleReminderSubject = (
  input: Pick<SendBadgeRuleLifecycleReminderNotificationsInput, "reminderType" | "ruleName">,
): string => {
  if (input.reminderType === "expiry") {
    return `Badge rule expiring soon: ${input.ruleName}`;
  }

  return `Badge rule recertification due: ${input.ruleName}`;
};

const lifecycleReminderIntro = (
  input: Pick<
    SendBadgeRuleLifecycleReminderNotificationsInput,
    "reminderType" | "tenantDisplayName"
  >,
): string => {
  if (input.reminderType === "expiry") {
    return `A badge rule version in ${input.tenantDisplayName} is approaching its expiry date.`;
  }

  return `A badge rule version in ${input.tenantDisplayName} is due for recertification.`;
};

const lifecycleReminderAction = (reminderType: BadgeRuleLifecycleReminderType): string => {
  if (reminderType === "expiry") {
    return "Review the lifecycle window or let the rule expire automatically.";
  }

  return "Review the rule and record recertification, or suspend it if it should no longer issue.";
};

export const sendBadgeRuleLifecycleReminderNotifications = async (
  db: SqlDatabase,
  input: SendBadgeRuleLifecycleReminderNotificationsInput,
): Promise<readonly TransactionalEmailResult[]> => {
  const tenantMembers = await listTenantMembers(db, input.tenantId);
  const recipientEmails = tenantMembers
    .filter((member) => tenantMembershipRoleSatisfiesMinimumRole(member.role, "admin"))
    .map((member) => member.email);

  return sendEmailBatch(recipientEmails, (recipientEmail) =>
    sendTransactionalEmail({
      tracking: input.tracking,
      kind: "rule_lifecycle",
      emailBinding: input.emailBinding,
      fromEmail: input.fromEmail,
      fromName: input.fromName,
      recipientEmail,
      subject: lifecycleReminderSubject(input),
      content: {
        institution: input.tenantDisplayName,
        title: lifecycleReminderSubject(input),
        paragraphs: [lifecycleReminderIntro(input), lifecycleReminderAction(input.reminderType)],
        details: [
          { label: "Rule", value: input.ruleName },
          { label: "Version", value: String(input.versionNumber) },
          { label: "Due", value: input.dueAt },
        ],
        action: { label: "Review the rule", url: input.adminUrl },
        footer: "Review this rule to keep your institution’s badge issuance up to date.",
      },
      category: "Badge Rule Lifecycle",
    }),
  );
};
