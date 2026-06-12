import { describe, expect, it } from "vitest";
import { renderAppPageToString } from "../ui/render-page";
import { ltiLaunchResultPage } from "./pages";

describe("ltiLaunchResultPage", () => {
  it("renders a concise course-summary empty state when no badges are placed", () => {
    const html = renderAppPageToString(
      ltiLaunchResultPage({
        roleKind: "instructor",
        tenantId: "tenant_123",
        userId: "usr_123",
        membershipRole: "admin",
        learnerProfileId: "lpr_123",
        issuer: "https://canvas.example.edu",
        deploymentId: "deployment_123",
        subjectId: "instructor-001",
        targetLinkUri: "https://credtrail.example.edu/v1/lti/launch",
        messageType: "LtiResourceLinkRequest",
        launchDisplayName: "Instructor One",
        dashboardPath: "/tenants/tenant_123/learner/dashboard",
        instructorViews: {
          mode: { kind: "course-summary" },
          bulkIssuanceView: null,
          courseBadgeSummaryView: {
            status: "ready",
            message: "No badges have been placed in this LMS course yet.",
            courseContextTitle: "Demo1 123 456 SP24",
            learnerCount: 3,
            badgeCount: 0,
            issuedCount: 0,
            canPlaceBadgesFromLti: true,
            rows: [],
          },
        },
      }),
    );

    expect(html).toContain("Course badge summary");
    expect(html).toContain(
      "Place a CredTrail badge from your LMS content picker to start badging this course.",
    );
    expect(html).toContain("No badges placed yet");
    expect(html).toContain(
      "Use the LMS add-content or external-tool flow, choose CredTrail, then select a badge template.",
    );
    expect(html).toContain("Demo1 123 456 SP24");
    expect(html).toContain("<dt>Learners</dt>");
    expect(html).toContain("<dd>3</dd>");
    expect(html).toContain("<dt>Badges</dt>");
    expect(html).toContain("<dd>0</dd>");
    expect(html).not.toContain("Search learners, badges, or status in this course.");
    expect(html).not.toContain("data-lti-course-summary-search");
    expect(html).not.toContain("<table");
  });
});
