import { expect, it } from "vitest";
import { renderAppPageToString, appPage } from "../../ui/render-page";
import { renderIssuedBadgesPanel, renderRuleReviewQueuePanel } from "./operations-sections";
import { emptyIssuedBadgesPageFilterValues } from "../issued-badges-admin-helpers";

it.each([5000, 5001])("sets export expectations at the %i record boundary", (count) => {
  const html = renderAppPageToString(
    appPage({
      title: "Records",
      body: (
        <>
          {renderIssuedBadgesPanel({
            tenantId: "tenant_1",
            templateFilterOptions: [],
            activeOrgUnitOptions: [],
            issuedBadgesWorkspace: {
              filters: emptyIssuedBadgesPageFilterValues(),
              assertions: [],
              exportCount: count,
              listNotice: null,
              listError: null,
              lifecycleAssertionId: null,
              lifecycleMode: null,
            },
          })}
        </>
      ),
    }),
  );
  expect(html.includes("Export matching CSV")).toBe(count === 5000);
  expect(html).toContain(count === 5000 ? "across every page" : "Narrow the date range");
});

it("reveals an editable review above the queue only after selecting a decision", () => {
  const entries = [
    {
      evaluationId: "evaluation_1",
      evaluatedAt: "2026-09-17T12:00:00.000Z",
      recipientIdentity: "learner@example.edu",
      ruleId: "rule_1",
      ruleName: "Completion",
      badgeTitle: "Analytics",
      missingInformation: ["Course completion is missing"],
      evaluationSummary: null,
      reviewStatus: "pending",
    },
  ];
  const render = (selectedEvaluationId: string): string =>
    renderAppPageToString(
      appPage({
        title: "Review",
        body: (
          <>
            {renderRuleReviewQueuePanel({
              tenantId: "tenant_1",
              reviewQueueWorkspace: {
                entries,
                selectedEvaluationId,
                listNotice: null,
                listError: null,
              },
            })}
          </>
        ),
      }),
    );
  expect(render("")).not.toContain('name="comment"');
  const html = render("evaluation_1");
  expect(html).toContain("Analytics");
  expect(html).toContain("Course completion is missing");
  expect(html).toContain('name="comment"');
  expect(html).not.toContain("Manual review approved by issuer");
  expect(html.indexOf('id="review-decision-panel"')).toBeLessThan(html.indexOf("<table"));
  expect(render("someone-elses-evaluation")).not.toContain('name="comment"');
});
