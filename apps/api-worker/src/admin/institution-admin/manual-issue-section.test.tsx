import { expect, it } from "vitest";
import { appPage, renderAppPageToString } from "../../ui/render-page";
import { renderManualIssueSection } from "./manual-issue-section";

it("keeps the issue form available with validation feedback and pathway context", () => {
  const html = renderAppPageToString(
    appPage({
      title: "Issue badge",
      body: (
        <>
          {renderManualIssueSection({
            tenantId: "tenant_123",
            templateSelectOptions: <option value="badge_1">Analytics</option>,
            listError: "Choose a badge template.",
            pathwayHandoffId: "handoff_123",
          })}
        </>
      ),
    }),
  );
  expect(html).toContain("Choose a badge template.");
  expect(html).toContain('id="manual-issue-form"');
  expect(html).toContain('value="handoff_123"');
  expect(html).not.toContain("Issuance receipt");
});
