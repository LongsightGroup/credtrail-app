import { describe, expect, it } from "vitest";

import type { LearnerRecordPresentationModel } from "../learner-record/learner-record-presentation";
import { getSeededDemoLearnerRecordFixture } from "../learner-record/seeded-demo-learner-record-fixture";
import { pageAssetPath } from "../ui/page-assets";
import { renderAppPageToString } from "../ui/render-page";
import { createLearnerRecordPage } from "./learner-record-page";

const learnerRecordPage = createLearnerRecordPage({
  formatIsoTimestamp: (value) => value,
});

const samplePresentation = (): LearnerRecordPresentationModel => {
  return getSeededDemoLearnerRecordFixture().presentation;
};

describe("createLearnerRecordPage", () => {
  it("renders the unified learner record without admin-only export affordances", () => {
    const html = renderAppPageToString(
      learnerRecordPage("tenant_123", samplePresentation(), {
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
        ...samplePresentation(),
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
});
