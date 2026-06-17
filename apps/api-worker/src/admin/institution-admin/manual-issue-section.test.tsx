import { describe, expect, it } from "vitest";

import { appPage, renderAppPageToString } from "../../ui/render-page";
import type { AdminManualIssueSuccessLinks } from "../manual-issue-flash";
import { renderManualIssueSection } from "./manual-issue-section";

const renderManualIssueSectionHtml = (input?: {
  listNotice?: string | null;
  successLinks?: AdminManualIssueSuccessLinks | null;
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
            successLinks: input?.successLinks ?? null,
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
      successLinks: {
        publicBadgePath: "/badges/public_assertion_456",
        verificationPath: "/badges/public_assertion_456/verification",
        jsonLdPath: "/badges/public_assertion_456/jsonld",
      },
    });

    expect(html).toContain("Badge issued for learner@example.edu.");
    expect(html).toContain('href="/badges/public_assertion_456"');
    expect(html).toContain('href="/badges/public_assertion_456/verification"');
    expect(html).toContain('href="/badges/public_assertion_456/jsonld"');
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
