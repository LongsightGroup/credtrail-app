import { describe, expect, it } from "vitest";

import { seededDemoLearnerRecordFixture } from "../test-support/seeded-demo-learner-record-fixture";
import { pageAssetPath } from "../ui/page-assets";
import { renderAppPageToString } from "../ui/render-page";
import { createLearnerRecordPage } from "./learner-record-page";

const learnerRecordPage = createLearnerRecordPage({
  formatIsoTimestamp: (value) => value,
});

describe("createLearnerRecordPage", () => {
  it("renders the unified learner record without admin-only export affordances", () => {
    const html = renderAppPageToString(
      learnerRecordPage("tenant_123", seededDemoLearnerRecordFixture.presentation, {
        switchOrganizationPath:
          "/account/organizations?next=%2Ftenants%2Ftenant_123%2Flearner%2Frecord",
      }),
    );

    expect(html).toContain("Unified learner record");
    expect(html).toContain("Institution-verified record");
    expect(html).toContain("Learner-supplemental record");
    expect(html).toContain("Historical record");
    expect(html).toContain("Applied Analytics Badge");
    expect(html).toContain("Clinical Placement Seminar");
    expect(html).toContain("Portfolio Reflection");
    expect(html).toContain("Leadership Society Membership");
    expect(html).toContain("/badges/public_assertion_456");
    expect(html).toContain("Return to learner dashboard");
    expect(html).toContain("Switch organization");
    expect(html).not.toContain("standards mapping");
    expect(html).not.toContain("Download export");
    expect(html).toContain(pageAssetPath("learnerRecordCss"));
  });

  it("renders a truthful empty state when the learner record has no items yet", () => {
    const html = renderAppPageToString(
      learnerRecordPage("tenant_123", {
        ...seededDemoLearnerRecordFixture.presentation,
        summary: {
          total: 0,
          issuerVerified: 0,
          supplemental: 0,
          active: 0,
          historical: 0,
          badgeAssertions: 0,
          recordEntries: 0,
        },
        sections: [],
      }),
    );

    expect(html).toContain("Nothing has been added yet");
    expect(html).toContain(
      "This learner account does not have any badge assertions or non-badge learner-record entries yet.",
    );
  });

  it("places governed pathway progress above the flat learner-record inventory", () => {
    const html = renderAppPageToString(
      learnerRecordPage("tenant_123", seededDemoLearnerRecordFixture.presentation, {
        pathways: [
          {
            enrollmentId: "pthe_123",
            pathwayId: "pth_123",
            pathwayVersionId: "pthv_123",
            pathwayTitle: "Clinical Leadership",
            learnerDescription: "Build verified clinical leadership practice.",
            ownerOrgUnitName: "College of Health",
            versionNumber: 2,
            enrollmentStatus: "active",
            completionBehavior: "review_required",
            evaluation: {
              id: "pthev_123",
              enrollmentId: "pthe_123",
              pathwayVersionId: "pthv_123",
              sequenceNumber: 3,
              result: "needs_review",
              qualifyingEvidenceIds: ["assertion_123"],
              rationale: "All requirements are satisfied; final credential review is required",
              evaluatedAt: "2026-08-13T10:00:00.000Z",
              requirements: [
                {
                  requirementId: "pthr_123",
                  position: 1,
                  title: "Clinical Placement Badge",
                  description: null,
                  state: "met",
                  evidenceIds: ["assertion_123"],
                  rationale: "Institution-verified evidence is current",
                },
              ],
            },
            evaluationHistory: [],
            state: {
              _tag: "needs_review",
              handoffId: "pthh_123",
              badgeTemplateId: "badge_final",
            },
            nextRequirement: null,
            completedAt: null,
            enrolledAt: "2026-08-01T10:00:00.000Z",
          },
        ],
      }),
    );

    expect(html).toContain("Active pathways");
    expect(html).toContain("Clinical Leadership");
    expect(html).toContain("Needs review");
    expect(html).toContain("Clinical Placement Badge");
    expect(html).toContain(
      "Learner-added items never satisfy an official requirement automatically",
    );
    expect(html.indexOf("Active pathways")).toBeLessThan(
      html.indexOf("Institution-verified record"),
    );
  });
});
