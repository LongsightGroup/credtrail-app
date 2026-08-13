import { describe, expect, it } from "vitest";
import type { LearnerPathwayRecord, TenantRecord } from "@credtrail/db";
import { renderAppPageToString } from "../ui/render-page";
import { learnerPathwaysAdminPage } from "./learner-pathway-pages";

const tenant: TenantRecord = {
  id: "tenant_123",
  slug: "pathway-university",
  displayName: "Pathway University",
  planTier: "institution",
  issuerDomain: "credentials.example.edu",
  didWeb: "did:web:credentials.example.edu",
  isActive: true,
  createdAt: "2026-08-01T10:00:00.000Z",
  updatedAt: "2026-08-01T10:00:00.000Z",
};

const pathway: LearnerPathwayRecord = {
  id: "pth_123",
  tenantId: tenant.id,
  ownerOrgUnitId: "org_123",
  ownerOrgUnitName: "College of Health",
  status: "published",
  currentPublishedVersionId: "pthv_123",
  version: {
    id: "pthv_123",
    number: 1,
    status: "published",
    title: "Clinical Leadership",
    learnerDescription: "Build verified clinical leadership practice.",
    completionBehavior: "review_required",
    finalBadgeTemplateId: "badge_final",
    publishedAt: "2026-08-12T10:00:00.000Z",
  },
  requirementCount: 3,
  activeEnrollmentCount: 12,
  createdAt: "2026-08-01T10:00:00.000Z",
  updatedAt: "2026-08-12T10:00:00.000Z",
};

describe("learner pathway admin pages", () => {
  it("keeps the pathway registry list-first with human-readable ownership", () => {
    const html = renderAppPageToString(
      learnerPathwaysAdminPage({
        tenant,
        userId: "usr_123",
        userEmail: "admin@example.edu",
        membershipRole: "admin",
        pathways: [pathway],
        notice: null,
        error: null,
      }),
    );

    expect(html).toContain("Learner pathways");
    expect(html).toContain("New pathway");
    expect(html).toContain("Clinical Leadership");
    expect(html).toContain("College of Health");
    expect(html).not.toContain("org_123");
    expect(html.indexOf("Programs")).toBeLessThan(html.indexOf("Clinical Leadership"));
  });
});
