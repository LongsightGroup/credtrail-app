import { describe, expect, it } from "vitest";
import {
  createEnv,
  mockedFindBadgeIssuanceRuleById,
  mockedFindTenantOrgUnitById,
  mockedListBadgeIssuanceRuleVersions,
  mockedListBadgeIssuanceRuleValueLists,
  sampleDetailRule,
  sampleDetailVersion,
} from "./institution-admin-test-utils/rules-test-harness";
import { app } from "./index";
import { readScriptAssetSource } from "./page-asset-test-utils";
import { pageAssetPath } from "./ui/page-assets";

const INSTITUTION_ADMIN_RULE_VERSION_JS = readScriptAssetSource("institutionAdminRuleVersionJs");

const requestRulePage = (path: string): Promise<Response> => {
  return Promise.resolve(
    app.request(
      path,
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    ),
  );
};

describe("GET /tenants/:tenantId/admin/rules/:ruleId", () => {
  it("redirects the stable rule URL to its active version", async () => {
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");
    const latestVersion = sampleDetailVersion("brv_detail_latest", 2, "draft");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([latestVersion, activeVersion]);

    const response = await requestRulePage("/tenants/tenant_123/admin/rules/brl_detail");

    expect(response.status).toBe(302);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active",
    );
  });

  it("supports selecting a saved version from the stable rule URL", async () => {
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");
    const latestVersion = sampleDetailVersion("brv_detail_latest", 2, "draft");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion, latestVersion]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail?versionId=brv_detail_latest",
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_latest",
    );
  });

  it("uses the latest version when the rule has no active version", async () => {
    const firstVersion = sampleDetailVersion("brv_detail_first", 1, "rejected");
    const latestVersion = sampleDetailVersion("brv_detail_latest", 2, "draft");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(null));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([firstVersion, latestVersion]);

    const response = await requestRulePage("/tenants/tenant_123/admin/rules/brl_detail");

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_latest",
    );
  });

  it("does not hide an invalid active-version reference", async () => {
    const latestVersion = sampleDetailVersion("brv_detail_latest", 2, "draft");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule("brv_detail_missing"));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([latestVersion]);

    const response = await requestRulePage("/tenants/tenant_123/admin/rules/brl_detail");

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "Badge rule version not found" });
  });

  it("reports an incomplete setup when a rule has no versions", async () => {
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(null));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([]);

    const response = await requestRulePage("/tenants/tenant_123/admin/rules/brl_detail");

    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "Badge rule setup is incomplete" });
  });
});

describe("GET /tenants/:tenantId/admin/rules/:ruleId/versions/:versionId", () => {
  it("renders the canonical read-only version record with scoped assets", async () => {
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");
    const latestVersion = sampleDetailVersion("brv_detail_latest", 2, "draft");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion, latestVersion]);
    mockedFindTenantOrgUnitById.mockResolvedValue({
      id: "tenant_123:org:cs",
      tenantId: "tenant_123",
      unitType: "department",
      slug: "computer-science",
      displayName: "Computer Science",
      parentOrgUnitId: "tenant_123:org:institution",
      createdByUserId: "usr_admin",
      isActive: true,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_latest",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("Advanced TypeScript Rule");
    expect(body).not.toContain("Mutable rule head name");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Organization scope");
    expect(body).toContain("Computer Science (department)");
    expect(body).toContain('src="https://example.edu/badges/typescript.png"');
    expect(body).toContain("What this version requires");
    expect(body).toContain('data-rule-lms-reference="course"');
    expect(body).toContain('data-rule-lms-reference="assignment"');
    expect(body).toContain('data-rule-lms-label="">Course</span>');
    expect(body).toContain('data-rule-lms-label="">Assignment</span>');
    expect(body).toContain("ID: course_101");
    expect(body).toContain("ID: assignment_7");
    expect(body).toContain('data-rule-lms-label-status="" role="status" hidden=""');
    expect(body).toContain(
      'data-lms-labels-url="/v1/tenants/tenant_123/badge-rules/brl_detail/versions/brv_detail_latest/lms-reference-labels"',
    );
    expect(body).toContain('data-rule-version-navigation=""');
    expect(body).toContain('name="versionId"');
    expect(body).toContain(
      'data-version-url="/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active"',
    );
    expect(body).toContain(
      'data-version-url="/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_latest"',
    );
    expect(body).toContain("Version 1 — Active now");
    expect(body).toContain("Version 2 — Draft · latest version");
    expect(body).toContain("Version 2 of 2");
    expect(body).toContain("← Previous version");
    expect(body).toContain("Next version →");
    expect(body).toContain("This draft is read-only here and cannot issue badges");
    expect(body).toContain("Version note:");
    expect(body).toContain("Technical details");
    expect(body).toContain("Rule ID");
    expect(body).toContain("brl_detail");
    expect(body).toContain("Version ID");
    expect(body).toContain("brv_detail_latest");
    expect(body).toContain(pageAssetPath("institutionAdminRuleVersionCss"));
    expect(body).toContain(pageAssetPath("institutionAdminRuleVersionJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminRuleApprovalReviewCss"));
    expect(body).not.toContain(pageAssetPath("institutionAdminRuleApprovalReviewJs"));
    expect(mockedFindTenantOrgUnitById).toHaveBeenCalledWith(
      expect.anything(),
      "tenant_123",
      "tenant_123:org:cs",
    );
    expect(INSTITUTION_ADMIN_RULE_VERSION_JS).toContain("window.location.assign(destination)");
  });

  it("renders historical metadata only from the selected version snapshot", async () => {
    const historicalVersion = {
      ...sampleDetailVersion("brv_detail_historical", 1, "active"),
      snapshot: {
        ...sampleDetailVersion("brv_detail_historical", 1, "active").snapshot,
        name: "Original course rule",
        description: "Original rule description.",
        badgeTemplateTitle: "Original course badge",
        badgeTemplateImageUri: "https://example.edu/badges/original.png",
        lmsProviderKind: "sakai" as const,
        lmsConnectionId: null,
      },
    };
    const currentRule = {
      ...sampleDetailRule(historicalVersion.id),
      name: "Replacement rule name",
      description: "Replacement description.",
      lmsProviderKind: "canvas" as const,
      lmsConnectionId: "lms_replacement",
    };
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(currentRule);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([historicalVersion]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_historical",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Original course rule");
    expect(body).toContain("Original rule description.");
    expect(body).toContain("Original course badge");
    expect(body).toContain('src="https://example.edu/badges/original.png"');
    expect(body).toContain("Sakai");
    expect(body).not.toContain("Replacement rule name");
    expect(body).not.toContain("Replacement description.");
    expect(body).not.toContain("lms-reference-labels");
  });

  it("expands saved course lists into inspectable course requirements", async () => {
    const activeVersion = {
      ...sampleDetailVersion("brv_detail_active", 1, "active"),
      ruleJson: JSON.stringify({
        conditions: {
          type: "grade_threshold",
          courseListId: "brvl_courses",
          minScore: 80,
        },
      }),
    };
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion]);
    mockedListBadgeIssuanceRuleValueLists.mockResolvedValue([
      {
        id: "brvl_courses",
        tenantId: "tenant_123",
        label: "Required programming courses",
        kind: "course_ids",
        values: ["course_101", "course_202"],
        createdByUserId: "usr_admin",
        archivedAt: null,
        createdAt: "2026-08-01T00:00:00.000Z",
        updatedAt: "2026-08-01T00:00:00.000Z",
      },
    ]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('data-course-id="course_101"');
    expect(body).toContain('data-course-id="course_202"');
    expect(body).toContain("ID: course_101");
    expect(body).toContain("ID: course_202");
    expect(body).not.toContain("ID: brvl_courses");
  });

  it("rejects a version that does not belong to the rule", async () => {
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_another_rule",
    );

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "Badge rule version not found" });
  });
});
