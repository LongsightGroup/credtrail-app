import { describe, expect, it } from "vitest";
import { renderAppPageToString } from "../ui/render-page";
import { ltiLaunchResultPage } from "./pages";
import type {
  LtiBadgeSummaryCard,
  LtiBulkIssuanceView,
  LtiLearnerBadgeSummaryView,
} from "./view-models";

type LtiLaunchResultPageInput = Parameters<typeof ltiLaunchResultPage>[0];

const sampleSelectedBadge = (overrides: Partial<LtiBadgeSummaryCard> = {}): LtiBadgeSummaryCard => {
  return {
    badgeTemplateId: "badge_template_001",
    title: "TypeScript Foundations",
    summary: "Awarded for completing TypeScript fundamentals.",
    imageUri: "https://example.edu/badges/typescript.png",
    criteriaPath: "/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001",
    ...overrides,
  };
};

const sampleBulkIssuanceView = (
  overrides: Partial<LtiBulkIssuanceView> = {},
): LtiBulkIssuanceView => {
  return {
    status: "ready",
    message: "Loaded 1 learner from LMS roster.",
    selectedBadge: sampleSelectedBadge(),
    courseContextTitle: "Demo1 123 456 SP24",
    courseContextId: "course-123",
    contextMembershipsUrl: "https://canvas.example.edu/api/lti/courses/42/names_and_roles",
    learnerCount: 1,
    totalCount: 1,
    issuanceActionPath: "/v1/lti/resource-link/issue",
    issuanceActionToken: "token_123",
    members: [
      {
        userId: "learner-001",
        sourcedId: "sourced-learner-001",
        displayName: "Learner One",
        email: "learner-one@example.edu",
        roleSummary: "Learner",
        status: "Active",
        issuedAssertionId: null,
        issuedAt: null,
        issuanceLifecycleState: null,
      },
    ],
    ...overrides,
  };
};

const sampleLaunchResultInput = (
  overrides: Partial<LtiLaunchResultPageInput> = {},
): LtiLaunchResultPageInput => {
  return {
    roleKind: "instructor",
    tenantId: "tenant_123",
    userId: "usr_123",
    membershipRole: "issuer",
    learnerProfileId: "lpr_123",
    issuer: "https://canvas.example.edu",
    deploymentId: "deployment_123",
    subjectId: "instructor-001",
    targetLinkUri: "https://credtrail.example.edu/v1/lti/launch?badgeTemplateId=badge_template_001",
    messageType: "LtiResourceLinkRequest",
    launchDisplayName: "Instructor One",
    dashboardPath: "/tenants/tenant_123/learner/dashboard",
    learnerView: null,
    instructorViews: {
      kind: "bulk",
      bulkIssuanceView: sampleBulkIssuanceView(),
      courseBadgeSummaryView: null,
    },
    ...overrides,
  };
};

const sampleLearnerBadgeSummaryView = (
  overrides: Partial<LtiLearnerBadgeSummaryView> = {},
): LtiLearnerBadgeSummaryView => {
  return {
    scope: "course",
    status: "ready",
    message: "Showing 2 active badges in this course.",
    badges: [
      {
        badge: sampleSelectedBadge({
          badgeTemplateId: "badge_template_001",
          title: "TypeScript Foundations",
        }),
        status: {
          label: "Issued",
          modifier: "issued",
        },
        issuedAt: "2026-02-11T14:00:00.000Z",
        claimActionPath: "/tenants/tenant_123/learner/badges/tenant_123%3Aassertion_existing/claim",
      },
      {
        badge: sampleSelectedBadge({
          badgeTemplateId: "badge_template_002",
          title: "Governance Design",
          summary: "Open criteria to review how learners qualify for this badge.",
          imageUri: null,
          criteriaPath: "/showcase/tenant_123/criteria?badgeTemplateId=badge_template_002",
        }),
        status: {
          label: "Not issued",
          modifier: "not_issued",
        },
        issuedAt: null,
        claimActionPath: null,
      },
    ],
    ...overrides,
  };
};

describe("ltiLaunchResultPage", () => {
  it("renders learner greeting, dashboard handoff, badge rows, and no troubleshooting details", () => {
    const html = renderAppPageToString(
      ltiLaunchResultPage(
        sampleLaunchResultInput({
          roleKind: "learner",
          membershipRole: "viewer",
          launchDisplayName: "Jennifer Truman",
          instructorViews: null,
          learnerView: sampleLearnerBadgeSummaryView(),
        }),
      ),
    );

    expect(html).toContain("Hi, Jennifer Truman");
    expect(html).toContain("Open CredTrail dashboard");
    expect(html).toContain("Badges in this course");
    expect(html).toContain("TypeScript Foundations");
    expect(html).toContain("Governance Design");
    expect(html).toContain('src="https://example.edu/badges/typescript.png"');
    expect(html).toContain("GD");
    expect(html).toContain("Issued");
    expect(html).toContain("Issued Feb 11, 2026, 2:00 PM UTC");
    expect(html).toContain('method="post"');
    expect(html).toContain(
      'action="/tenants/tenant_123/learner/badges/tenant_123%3Aassertion_existing/claim"',
    );
    expect(html).toContain("Claim badge and open sharing options");
    expect(html).toContain("Not issued");
    expect(html).toContain("Not issued yet.");
    expect(html).not.toContain("Launch troubleshooting details");
    expect(html).not.toContain("Claim from dashboard");
  });

  it("renders degraded learner launch health in the hero without troubleshooting details", () => {
    const html = renderAppPageToString(
      ltiLaunchResultPage(
        sampleLaunchResultInput({
          roleKind: "learner",
          membershipRole: "viewer",
          launchDisplayName: "Jennifer Truman",
          instructorViews: null,
          learnerView: sampleLearnerBadgeSummaryView({
            status: "error",
            message:
              "CredTrail could not load badge details for this LMS launch. Open your dashboard to continue.",
            badges: [],
          }),
        }),
      ),
    );

    expect(html).toContain("CredTrail could not load badge details");
    expect(html).toContain(
      "Your LMS account is linked. Open your dashboard to review issued badges and sharing options.",
    );
    expect(html).toContain("Open CredTrail dashboard");
    expect(html).toContain(
      "CredTrail could not load badge details for this LMS launch. Open your dashboard to continue.",
    );
    expect(html).not.toContain("<h1>Hi, Jennifer Truman</h1>");
    expect(html).not.toContain("Launch troubleshooting details");
  });

  it("renders selected learner badge fallback copy without a claim action when not issued", () => {
    const html = renderAppPageToString(
      ltiLaunchResultPage(
        sampleLaunchResultInput({
          roleKind: "learner",
          membershipRole: "viewer",
          launchDisplayName: null,
          instructorViews: null,
          learnerView: sampleLearnerBadgeSummaryView({
            scope: "selected",
            message: "Review the badge selected for this LMS lesson.",
            badges: [
              {
                badge: sampleSelectedBadge({
                  badgeTemplateId: "badge_template_002",
                  title: "Governance Design",
                  summary: "Open criteria to review how learners qualify for this badge.",
                  imageUri: null,
                  criteriaPath: "/showcase/tenant_123/criteria?badgeTemplateId=badge_template_002",
                }),
                status: {
                  label: "Not issued",
                  modifier: "not_issued",
                },
                issuedAt: null,
                claimActionPath: null,
              },
            ],
          }),
        }),
      ),
    );

    expect(html).toContain("Your CredTrail badges");
    expect(html).toContain("Selected badge");
    expect(html).toContain("Governance Design");
    expect(html).toContain("Open criteria to review how learners qualify for this badge.");
    expect(html).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_002");
    expect(html).toContain("GD");
    expect(html).toContain("Not issued");
    expect(html).not.toContain("Claim badge and open sharing options");
    expect(html).not.toContain("Launch troubleshooting details");
  });

  it("renders selected badge context before the bulk issuance roster", () => {
    const html = renderAppPageToString(ltiLaunchResultPage(sampleLaunchResultInput()));

    expect(html).toContain("Hi, Instructor One");
    expect(html).toContain(
      "Review the selected badge, then choose learners from this course roster to issue it.",
    );
    expect(html).toContain("lti-launch__selected-badge");
    expect(html).toContain("TypeScript Foundations");
    expect(html).toContain("Awarded for completing TypeScript fundamentals.");
    expect(html).toContain('src="https://example.edu/badges/typescript.png"');
    expect(html).toContain('alt="TypeScript Foundations badge artwork"');
    expect(html).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_001");
    expect(html).toContain("Active");
    expect(html.indexOf("lti-launch__selected-badge")).toBeLessThan(
      html.indexOf('class="lti-launch__bulk-table"'),
    );
    expect(html).toContain('name="issuance_action_token"');
    expect(html).toContain('name="learner_user_id"');
  });

  it("renders selected badge fallback copy and placeholder artwork", () => {
    const html = renderAppPageToString(
      ltiLaunchResultPage(
        sampleLaunchResultInput({
          targetLinkUri:
            "https://credtrail.example.edu/v1/lti/launch?badgeTemplateId=badge_template_002",
          instructorViews: {
            kind: "bulk",
            bulkIssuanceView: sampleBulkIssuanceView({
              status: "unavailable",
              message:
                "This LMS launch did not include a learner roster, so CredTrail cannot issue badges from this tool yet.",
              selectedBadge: sampleSelectedBadge({
                badgeTemplateId: "badge_template_002",
                title: "Governance Design",
                summary: "Open criteria to review how learners qualify for this badge.",
                imageUri: null,
                criteriaPath: "/showcase/tenant_123/criteria?badgeTemplateId=badge_template_002",
              }),
              contextMembershipsUrl: null,
              learnerCount: 0,
              totalCount: 0,
              issuanceActionPath: null,
              issuanceActionToken: null,
              members: [],
            }),
            courseBadgeSummaryView: null,
          },
        }),
      ),
    );

    expect(html).toContain("Governance Design");
    expect(html).toContain("GD");
    expect(html).toContain("Open criteria to review how learners qualify for this badge.");
    expect(html).toContain("/showcase/tenant_123/criteria?badgeTemplateId=badge_template_002");
    expect(html).not.toContain("Governance Design badge artwork");
  });

  it("renders a concise course-summary empty state when no badges are placed", () => {
    const html = renderAppPageToString(
      ltiLaunchResultPage({
        ...sampleLaunchResultInput({
          targetLinkUri: "https://credtrail.example.edu/v1/lti/launch",
          membershipRole: "admin",
          launchDisplayName: "Instructor One",
        }),
        instructorViews: {
          kind: "course-summary",
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
    expect(html).toContain("<dt>Badge placements</dt>");
    expect(html).toContain("<dd>0</dd>");
    expect(html).toContain("<dt>Issued credentials</dt>");
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
        learnerView: null,
        instructorViews: {
          kind: "course-summary",
          bulkIssuanceView: null,
          courseBadgeSummaryView: {
            status: "ready",
            message: "Showing progress for 2 badge placements in this course.",
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
