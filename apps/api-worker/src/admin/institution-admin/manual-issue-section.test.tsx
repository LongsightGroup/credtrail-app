import { describe, expect, it } from "vitest";

import { appPage, renderAppPageToString } from "../../ui/render-page";
import type { AdminManualIssueReceipt } from "../manual-issue-flash";
import { renderManualIssueSection } from "./manual-issue-section";

const renderManualIssueSectionHtml = (input?: {
  listNotice?: string | null;
  receipt?: AdminManualIssueReceipt | null;
}): string => {
  return renderAppPageToString(
    appPage({
      title: "Manual issue test",
      body: (
        <>
          {renderManualIssueSection({
            tenantId: "tenant_123",
            templateSelectOptions: <option value="badge_template_001">Applied Analytics</option>,
            listNotice: input?.listNotice ?? null,
            listError: null,
            receipt: input?.receipt ?? null,
          })}
        </>
      ),
    }),
  );
};

describe("renderManualIssueSection", () => {
  it("renders direct next-step links after a successful issue", () => {
    const html = renderManualIssueSectionHtml({
      listNotice: "Badge issued for learner@example.edu.",
      receipt: {
        badgeTitle: "Applied Analytics",
        recipientIdentity: "learner@example.edu",
        issuedAt: "2026-09-16T12:00:00.000Z",
        recordPath: "/tenants/tenant_123/admin/operations/issued-badges/credential/evidence",
        publicBadgePath: "/badges/public_assertion_456",
        verificationPath: "/badges/public_assertion_456/verification",
        jsonLdPath: "/badges/public_assertion_456/jsonld",
      },
    });

    expect(html).toContain("Badge issued for learner@example.edu.");
    expect(html).toContain('href="/badges/public_assertion_456"');
    expect(html).toContain('href="/badges/public_assertion_456/verification"');
    expect(html).toContain('href="/badges/public_assertion_456/jsonld"');
    expect(html).toContain("Applied Analytics");
    expect(html).toContain("View badge record");
    expect(html).toContain("Issue another badge");
    expect(html).toContain("Technical details");
    expect(html).not.toContain('id="manual-issue-form"');
    expect(html).toContain("Open public badge");
    expect(html).toContain("Open verification JSON");
    expect(html).toContain("Open JSON-LD");
  });

  it("does not render next-step links when the success notice lacks success links", () => {
    const html = renderManualIssueSectionHtml({
      listNotice: "Badge issued for learner@example.edu.",
    });

    expect(html).toContain("Badge issued for learner@example.edu.");
    expect(html).not.toContain("Open public badge");
    expect(html).not.toContain("/badges/tenant_123%3Aassertion_456");
  });
});
