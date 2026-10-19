import { createMemoryEmailTracking } from "../test-support/email-attempts";
import { createRecordingEmailBinding } from "../test-support/recording-email";
import { describe, expect, it } from "vitest";
import {
  sendBadgeRuleApprovalDecisionEmail,
  sendBadgeRuleApprovalSubmittedEmail,
} from "./send-badge-rule-approval-email";

describe("badge rule approval email notifications", () => {
  it("sends submitted approval email with the review link and category", async () => {
    const { emailBinding, messages } = createRecordingEmailBinding();

    await sendBadgeRuleApprovalSubmittedEmail({
      tracking: createMemoryEmailTracking(),
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
      tracking: createMemoryEmailTracking(),
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
