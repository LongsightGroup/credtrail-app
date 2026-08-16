import type { BadgeIssuanceRuleRecord } from "@credtrail/db";
import { BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE } from "@credtrail/db";
import { describe, expect, it } from "vitest";
import {
  createEnv,
  fakeDb,
  mockedFindBadgeIssuanceRuleBuilderDraftDb,
  mockedFindBadgeIssuanceRuleById,
  mockedFindTenantMembership,
  mockedListBadgeIssuanceRules,
  mockedListBadgeIssuanceRuleVersions,
  sampleMembership,
} from "./institution-admin-test-utils/rules-test-harness";
import { app } from "./index";
import { buildBadgeRuleVersionRecord } from "./test-support/badge-rule-version";

const adminFlashCookieHeader = (response: Response): string => {
  const setCookieHeaders =
    typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [response.headers.get("set-cookie") ?? ""];

  return setCookieHeaders.map((entry) => entry.split(";")[0]).join("; ");
};

describe("GET /tenants/:tenantId/admin/rules/drafts/:draftId/edit", () => {
  it("restores only the unfinished draft named by the URL", async () => {
    const env = createEnv();
    mockedFindBadgeIssuanceRuleBuilderDraftDb.mockResolvedValue({
      id: "brd_exact",
      tenantId: "tenant_123",
      userId: "usr_admin",
      targetKind: "unfinished",
      ruleId: null,
      versionId: null,
      currentStep: "conditions",
      draftJson: JSON.stringify({
        name: "Exact draft",
        description: "Resume this one",
        badgeTemplateId: "badge_template_001",
        lmsConnectionId: "lms_canvas",
        definitionJson: "",
        builderState: {},
      }),
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:05:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/drafts/brd_exact/edit",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(mockedFindBadgeIssuanceRuleBuilderDraftDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_admin",
      draftId: "brd_exact",
    });
    expect(body).toContain(
      "&quot;badgeRuleBuilderDraftApiPath&quot;:&quot;/v1/tenants/tenant_123/badge-rule-builder-drafts/brd_exact&quot;",
    );
    expect(body).toContain("&quot;name&quot;:&quot;Exact draft&quot;");
  });
});

describe("GET /tenants/:tenantId/admin/rules/:ruleId/edit", () => {
  it("loads eligible draft rule settings into the builder and keeps retesting available", async () => {
    const env = createEnv();
    const editRule: BadgeIssuanceRuleRecord = {
      id: "brl_draft",
      tenantId: "tenant_123",
      name: "Draft QA Rule",
      description: "Mutable rule-row description.",
      badgeTemplateId: "badge_template_mutable",
      orgUnitId: "tenant_123:org:institution",
      ownerOrgUnitId: "tenant_123:org:institution",
      lmsProviderKind: "sakai",
      lmsConnectionId: "lms_mutable",
      activeVersionId: null,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:10:00.000Z",
    };
    const editVersion = buildBadgeRuleVersionRecord({
      id: "brv_draft_2",
      ruleId: "brl_draft",
      versionNumber: 2,
      status: "rejected",
      ruleJson:
        '{"conditions":{"type":"assignment_submission","courseId":"course_101","assignmentId":"assignment_1","minScore":90},"options":{"reviewOnMissingFacts":true}}',
      changeSummary: "Raise final assignment score",
      createdByUserId: "usr_admin",
      submittedByUserId: "usr_admin",
      submittedAt: "2026-02-18T12:05:00.000Z",
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      snapshot: {
        name: "Versioned Draft QA Rule",
        description: "Fix the score threshold before review.",
        badgeTemplateId: "badge_template_001",
        lmsProviderKind: "canvas",
        lmsConnectionId: "lms_canvas",
      },
      createdAt: "2026-02-18T12:10:00.000Z",
      updatedAt: "2026-02-18T12:10:00.000Z",
    });

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(editRule);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([editVersion]);
    mockedListBadgeIssuanceRules.mockResolvedValue([editRule]);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/brl_draft/edit",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(mockedListBadgeIssuanceRules).toHaveBeenCalledTimes(1);
    expect(mockedListBadgeIssuanceRuleVersions).toHaveBeenCalledTimes(2);
    expect(mockedListBadgeIssuanceRuleVersions).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_draft",
    });
    expect(body).toContain("Edit Badge Awarding Rule");
    expect(body).toContain(
      "Review the current settings, test your changes, then submit a new version for approval.",
    );
    expect(body).toContain("Testing never issues a badge.");
    expect(body).toContain('id="rule-builder-test"');
    expect(body).toContain('id="rule-builder-save-draft"');
    expect(body).toContain("Save draft version");
    expect(body).toContain("Save and submit for approval");
    expect(body).not.toContain("Copy existing rule settings");
    expect(body).toContain('value="Versioned Draft QA Rule"');
    expect(body).not.toContain('value="Draft QA Rule"');
    expect(body).not.toContain("Mutable rule-row description.");
    expect(body).not.toContain("badge_template_mutable");
    expect(body).not.toContain("lms_mutable");
    expect(body).toContain('data-rule-builder-preserve-name="true"');
    expect(body).toContain('value="Fix the score threshold before review."');
    expect(body).toMatch(
      /<option[^>]*value="badge_template_001"[^>]*selected=""[^>]*>TypeScript Foundations[^<]*<\/option>/,
    );
    expect(body).not.toContain("TypeScript Foundations (badge_template_001)");
    expect(body).toContain(
      '<option value="lms_canvas" data-provider-kind="canvas" selected="">Canvas Test (Canvas)</option>',
    );
    expect(body).toContain("&quot;editRule&quot;:{&quot;id&quot;:&quot;brl_draft&quot;");
    expect(body).toContain("&quot;latestVersionStatus&quot;:&quot;rejected&quot;");
    expect(body).toContain("&quot;lmsProviderKind&quot;:&quot;canvas&quot;");
    expect(body).toContain("&quot;assignmentId&quot;:&quot;assignment_1&quot;");
    expect(body).toContain("&quot;minScore&quot;:90");
  });

  it("keeps the admin builder restricted to owner and admin roles", async () => {
    const env = createEnv();
    mockedFindTenantMembership.mockResolvedValue(sampleMembership("issuer"));

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/brl_draft/edit",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(403);
    expect(mockedFindBadgeIssuanceRuleById).not.toHaveBeenCalled();
  });

  it("redirects protected rules back to the rules page with an error flash", async () => {
    const env = createEnv();
    mockedFindBadgeIssuanceRuleById.mockResolvedValue({
      id: "brl_active",
      tenantId: "tenant_123",
      name: "Active protected rule",
      description: null,
      badgeTemplateId: "badge_template_001",
      orgUnitId: "tenant_123:org:institution",
      ownerOrgUnitId: "tenant_123:org:institution",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_canvas",
      activeVersionId: "brv_active",
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([
      buildBadgeRuleVersionRecord({
        id: "brv_active",
        ruleId: "brl_active",
        versionNumber: 1,
        status: "active",
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        changeSummary: "Initial draft",
        createdByUserId: "usr_admin",
        submittedByUserId: "usr_admin",
        submittedAt: "2026-02-18T12:10:00.000Z",
        approvedByUserId: "usr_admin",
        approvedAt: "2026-02-18T12:20:00.000Z",
        activatedByUserId: "usr_admin",
        activatedAt: "2026-02-18T12:30:00.000Z",
        updatedAt: "2026-02-18T12:30:00.000Z",
      }),
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/brl_active/edit",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/rules");

    const flashCookie = adminFlashCookieHeader(response);
    const flashResponse = await app.request(
      "/tenants/tenant_123/admin/rules",
      {
        headers: {
          Cookie: `better-auth.session_token=session-token; ${flashCookie}`,
        },
      },
      env,
    );
    const flashBody = await flashResponse.text();

    expect(flashResponse.status).toBe(200);
    expect(flashBody).toContain(BADGE_ISSUANCE_RULE_BUILDER_EDIT_DENIED_MESSAGE);
  });
});
