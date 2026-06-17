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
            badges: [],
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
    expect(html).not.toContain("Badges in this course");
    expect(html).not.toContain("data-lti-course-summary-search");
    expect(html).not.toContain("<table");
  });

  it("renders placed badge overview records with criteria links", () => {
    const html = renderAppPageToString(
      ltiLaunchResultPage({
        roleKind: "instructor",
        tenantId: "tenant_123",
        userId: "usr_123",
        membershipRole: "issuer",
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
            message: "Showing badge progress for 2 badges in this course.",
            courseContextTitle: "Demo1 123 456 SP24",
            learnerCount: 0,
            badgeCount: 2,
            issuedCount: 0,
            canPlaceBadgesFromLti: true,
            badges: [
              {
                badgeTemplateId: "badge_template_001",
                title: "TypeScript Foundations",
                summary: "Awarded for completing TypeScript fundamentals.",
                imageUri: "https://example.edu/badges/typescript.png",
                criteriaPath: "/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001",
              },
              {
                badgeTemplateId: "badge_template_002",
                title: "Governance Design",
                summary: "Open criteria to review how learners qualify for this badge.",
                imageUri: null,
                criteriaPath: "/showcase/tenant_123/criteria?badgeTemplateId=badge_template_002",
              },
            ],
            rows: [],
          },
        },
      }),
    );

    expect(html).toContain("Badges in this course");
    expect(html).toContain("TypeScript Foundations");
    expect(html).toContain("Awarded for completing TypeScript fundamentals.");
    expect(html).toContain('src="https://example.edu/badges/typescript.png"');
    expect(html).toContain('alt="TypeScript Foundations badge artwork"');
    expect(html).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001");
    expect(html).toContain("Governance Design");
    expect(html).toContain("Open criteria to review how learners qualify for this badge.");
    expect(html).toContain("GD");
    expect(html).toContain("Active");
    expect(html).toContain("No learner badge rows yet");
  });
});
