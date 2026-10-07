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
            issuanceRequestId: "1f016e84-49df-41c8-b560-e331d7d94223",
            hasReadyTemplates: true,
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

it("offers an optional expiry date and echoes it back with validation feedback", () => {
  const html = renderAppPageToString(
    appPage({
      title: "Issue badge",
      body: (
        <>
          {renderManualIssueSection({
            issuanceRequestId: "1f016e84-49df-41c8-b560-e331d7d94223",
            hasReadyTemplates: true,
            tenantId: "tenant_123",
            templateSelectOptions: <option value="badge_1">Analytics</option>,
            correction: {
              issuanceRequestId: "1f016e84-49df-41c8-b560-e331d7d94223",
              recipientIdentity: "learner@example.edu",
              badgeTemplateId: "badge_1",
              validUntil: "2027-01-31",
              message:
                "Enter the expiry as a date (YYYY-MM-DD) later than today, or leave it empty for a badge that does not expire.",
            },
          })}
        </>
      ),
    }),
  );
  expect(html).toContain('name="validUntil"');
  expect(html).toContain('type="date"');
  expect(html).toContain('value="2027-01-31"');
  expect(html).toContain("Leave it empty for a badge that does not expire.");
});
