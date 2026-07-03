import { describe, expect, it } from "vitest";
import {
  sendBadgeRuleApprovalDecisionEmail,
  sendBadgeRuleApprovalSubmittedEmail,
} from "./send-badge-rule-approval-email";

interface RecordedEmailMessage {
  readonly to: string;
  readonly subject: string;
  readonly text: string;
  readonly headers?: Record<string, string>;
}

const createRecordingEmailBinding = (): {
  readonly emailBinding: SendEmail;
  readonly messages: RecordedEmailMessage[];
} => {
  const messages: RecordedEmailMessage[] = [];

  return {
    messages,
    emailBinding: {
      send: async (message: RecordedEmailMessage): Promise<{ messageId: string }> => {
        messages.push(message);

        return { messageId: "email_msg_123" };
      },
    } as unknown as SendEmail,
  };
};

describe("badge rule approval email notifications", () => {
  it("sends submitted approval email with the review link and category", async () => {
    const { emailBinding, messages } = createRecordingEmailBinding();

    await sendBadgeRuleApprovalSubmittedEmail({
      emailBinding,
      recipientEmail: "registrar@example.edu",
      tenantId: "tenant_123",
      tenantDisplayName: "Example University",
      ruleName: "CS101 Excellence",
      versionNumber: 3,
      stepLabel: "Registrar review",
      reviewUrl: "https://credtrail.org/tenants/tenant_123/admin/rules/approvals/rule/versions/v3",
    });

    expect(messages).toHaveLength(1);
    expect(messages[0]?.to).toBe("registrar@example.edu");
    expect(messages[0]?.subject).toBe("Badge rule awaiting approval: CS101 Excellence");
    expect(messages[0]?.headers?.["X-CredTrail-Email-Category"]).toBe("Badge Rule Approval");
    expect(messages[0]?.text).toContain("awaiting your approval in Example University.");
    expect(messages[0]?.text).toContain("Registrar review");
    expect(messages[0]?.text).toContain("/admin/rules/approvals/");
  });

  it("includes reviewer comments in decision emails", async () => {
    const { emailBinding, messages } = createRecordingEmailBinding();

    await sendBadgeRuleApprovalDecisionEmail({
      emailBinding,
      recipientEmail: "author@example.edu",
      tenantId: "tenant_123",
      tenantDisplayName: "Example University",
      ruleName: "CS101 Excellence",
      versionNumber: 3,
      decisionLabel: "Changes requested",
      comment: "Raise the minimum grade threshold.",
      reviewUrl: "https://credtrail.org/tenants/tenant_123/admin/rules/approvals/rule/versions/v3",
    });

    expect(messages).toHaveLength(1);
    expect(messages[0]?.subject).toBe("Badge rule changes requested: CS101 Excellence");
    expect(messages[0]?.text).toContain("was changes requested in Example University.");
    expect(messages[0]?.text).toContain("Reviewer comment: Raise the minimum grade threshold.");
  });
});
