import type {
  BadgeIssuanceRuleApprovalStepRecord,
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  PendingBadgeIssuanceRuleApprovalRecord,
} from "@credtrail/db";
import { buildCompleteTrustEdCredentialMetadata } from "@credtrail/validation/testing";
import { describe, expect, it } from "vitest";
import {
  createEnv,
  fakeDb,
  mockedCreateAuditLogDb,
  mockedCreateBadgeTemplate,
  mockedDecideBadgeIssuanceRuleVersionDb,
  mockedDeleteDraftBadgeIssuanceRuleDb,
  mockedFindBadgeIssuanceRuleVersionByIdDb,
  mockedFindBadgeTemplateById,
  mockedFindBadgeTemplateImageRevisionById,
  mockedFindBadgeIssuanceRuleById,
  mockedFindLtiResourceLinkPlacementForRule,
  mockedFindTenantMembership,
  mockedListAccessibleTenantContextsForUser,
  mockedListBadgeIssuanceRuleVersionApprovalEvents,
  mockedListBadgeIssuanceRuleVersionApprovalStepsDb,
  mockedListBadgeIssuanceRules,
  mockedListBadgeIssuanceRuleVersions,
  mockedListBadgeTemplateImageRevisionCountsByTenant,
  mockedListBadgeTemplateImageRevisions,
  mockedListBadgeTemplates,
  mockedListPendingBadgeIssuanceRuleApprovalsForActor,
  mockedCountBadgeTemplateImageRevisions,
  mockedSetBadgeTemplateArchivedState,
  mockedSubmitBadgeIssuanceRuleVersionForApprovalDb,
  mockedUpdateBadgeTemplate,
  sampleMembership,
} from "./institution-admin-page-test-utils";
import { app } from "./index";
import { readScriptAssetSource, readStyleAssetSource } from "./page-asset-test-utils";
import { pageAssetPath } from "./ui/page-assets";

const INSTITUTION_ADMIN_CSS = readStyleAssetSource("institutionAdminCss");
const INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS = readScriptAssetSource(
  "institutionAdminBadgeTemplateEditorJs",
);
const INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS = readScriptAssetSource(
  "institutionAdminBadgeTemplateListJs",
);
const INSTITUTION_ADMIN_JS = readScriptAssetSource("institutionAdminJs");
const INSTITUTION_ADMIN_RULE_BUILDER_JS = readScriptAssetSource("institutionAdminRuleBuilderJs");

const adminFlashCookieHeader = (response: Response): string => {
  const setCookieHeaders =
    typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [response.headers.get("set-cookie") ?? ""];

  return setCookieHeaders.map((entry) => entry.split(";")[0]).join("; ");
};

const samplePendingApprovalStep = (): BadgeIssuanceRuleApprovalStepRecord => ({
  id: "bras_123",
  tenantId: "tenant_123",
  versionId: "brv_approval",
  stepNumber: 1,
  targetType: "role_threshold",
  requiredRole: "admin",
  targetUserId: null,
  targetApproverGroupId: null,
  orgUnitId: "tenant_123:org:cs",
  label: "Department approval",
  status: "pending",
  decidedByUserId: null,
  decidedAt: null,
  decisionComment: null,
  createdAt: "2026-02-18T12:00:00.000Z",
  updatedAt: "2026-02-18T12:00:00.000Z",
});

const samplePendingApprovalEntry = (): PendingBadgeIssuanceRuleApprovalRecord => ({
  tenantId: "tenant_123",
  ruleId: "brl_approval",
  ruleName: "CS101 Excellence Rule",
  badgeTemplateId: "badge_template_001",
  badgeTemplateName: "TypeScript Foundations",
  orgUnitId: "tenant_123:org:cs",
  orgUnitDisplayName: "Computer Science",
  versionId: "brv_approval",
  versionNumber: 2,
  versionCreatedByUserId: "usr_author",
  submittedByUserId: "usr_author",
  submittedByEmail: "author@example.edu",
  submittedAt: "2026-02-18T12:15:00.000Z",
  currentStep: samplePendingApprovalStep(),
});

describe("GET /tenants/:tenantId/admin/rules", () => {
  it("renders the rules workspace", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/rules",
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
    expect(body).toContain(">Rules<");
    expect(body).not.toContain("Rule Builder Workspace");
    expect(body).toMatch(/>\s*Create badge rule\s*<\/a>/);
    expect(body).toMatch(/class="[^"]*ct-action-group/);
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/new"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/templates"');
    expect(body).toMatch(/>\s*Manage badge templates\s*<\/a>/);
    expect(body).toContain("Check a rule before issuing");
    expect(body).not.toContain("Create Badge Template");
    expect(body).not.toContain('id="badge-template-create-form"');
    expect(body).not.toContain("Manage Badge Template Images");
    expect(body).not.toContain('id="badge-template-image-upload-form"');
    expect(body).not.toContain("Reusable Rule Lists");
    expect(body).not.toContain("Optional shortcut for rules that check the same courses");
    expect(body).not.toContain("Skip this unless");
    expect(body).not.toContain('id="rule-value-list-form"');
    expect(body).toContain('method="post"');
    expect(body).not.toContain('action="/tenants/tenant_123/admin/rules/value-lists"');
    expect(body).not.toContain('id="rule-value-list-status"');
    expect(body).not.toContain('id="rule-value-list-body"');
    expect(body).not.toContain("badge-rule-value-lists");
    expect(body).toContain("Test a Rule");
    expect(body).toContain('id="rule-evaluate-form"');
    expect(body).not.toContain("Approval and Audit History");
    expect(body).not.toContain('id="rule-governance-form"');
    expect(body).not.toContain("ct-grid--sidebar");
    expect(body).toContain("Badge Rules (1)");
    expect(body).toContain("Version 1");
    expect(body).toContain("Version ID: brv_123");
    expect(body).not.toContain("v1 (brv_123)");
    expect(body).toContain("Submit for approval");
    expect(body).toContain(
      "Submit draft version for &quot;CS101 Excellence Rule&quot; for approval?",
    );
    expect(body).toContain('method="post"');
    expect(body).toContain("/versions/brv_123/submit-approval");
    expect(INSTITUTION_ADMIN_JS).not.toContain(
      "Approved versions can be activated from the rules table.",
    );
    expect(body).not.toContain("Badge Templates (1)");
    expect(body).not.toContain("Create Tenant API Key");
    expect(body).not.toContain('id="issued-badges-panel"');
  });

  it("shows visible edit links and eligible delete actions for draft and rejected rules", async () => {
    const env = createEnv();
    const makeRule = (
      id: string,
      name: string,
      activeVersionId: string | null,
    ): BadgeIssuanceRuleRecord => ({
      id,
      tenantId: "tenant_123",
      name,
      description: null,
      badgeTemplateId: "badge_template_001",
      orgUnitId: "tenant_123:org:institution",
      ownerOrgUnitId: "tenant_123:org:institution",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_canvas",
      activeVersionId,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });
    const makeVersion = (
      ruleId: string,
      status: BadgeIssuanceRuleVersionRecord["status"],
      versionNumber = 1,
    ): BadgeIssuanceRuleVersionRecord => ({
      id: `${ruleId}_v${String(versionNumber)}`,
      tenantId: "tenant_123",
      ruleId,
      versionNumber,
      status,
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
      changeSummary: "Initial draft",
      createdByUserId: "usr_admin",
      submittedByUserId: status === "draft" ? null : "usr_admin",
      submittedAt: status === "draft" ? null : "2026-02-18T12:05:00.000Z",
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: status === "active" ? "usr_admin" : null,
      activatedAt: status === "active" ? "2026-02-18T12:30:00.000Z" : null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });
    const versionsByRuleId = new Map<string, BadgeIssuanceRuleVersionRecord[]>([
      ["brl_draft", [makeVersion("brl_draft", "draft")]],
      ["brl_rejected", [makeVersion("brl_rejected", "rejected")]],
      ["brl_pending", [makeVersion("brl_pending", "pending_approval")]],
      ["brl_approved", [makeVersion("brl_approved", "approved")]],
      ["brl_active", [makeVersion("brl_active", "active")]],
      [
        "brl_historical",
        [makeVersion("brl_historical", "rejected", 2), makeVersion("brl_historical", "active")],
      ],
    ]);

    mockedListBadgeIssuanceRules.mockResolvedValue([
      makeRule("brl_draft", "Draft cleanup rule", null),
      makeRule("brl_rejected", "Rejected cleanup rule", null),
      makeRule("brl_pending", "Pending protected rule", null),
      makeRule("brl_approved", "Approved protected rule", null),
      makeRule("brl_active", "Active protected rule", "brl_active_v1"),
      makeRule("brl_historical", "Historical protected rule", "brl_historical_v1"),
    ]);
    mockedListBadgeIssuanceRuleVersions.mockImplementation(async (_db, input) => {
      return versionsByRuleId.get(input.ruleId) ?? [];
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(
      '<a class="ct-admin__rule-name-link" href="/tenants/tenant_123/admin/rules/brl_draft/edit"><strong>Draft cleanup rule</strong></a>',
    );
    expect(body).toContain(
      '<a class="ct-admin__rule-name-link" href="/tenants/tenant_123/admin/rules/brl_rejected/edit"><strong>Rejected cleanup rule</strong></a>',
    );
    expect(body).toMatch(
      /class="[^"]*ct-admin__button[^"]*ct-action--secondary[^"]*ct-action--sm[^"]*" href="\/tenants\/tenant_123\/admin\/rules\/brl_draft\/edit"/,
    );
    expect(body).toMatch(
      /class="[^"]*ct-admin__button[^"]*ct-action--secondary[^"]*ct-action--sm[^"]*" href="\/tenants\/tenant_123\/admin\/rules\/brl_rejected\/edit"/,
    );
    expect(body).toContain('action="/tenants/tenant_123/admin/rules/brl_draft/delete"');
    expect(body).toContain('action="/tenants/tenant_123/admin/rules/brl_rejected/delete"');
    expect(body).toContain(
      'data-confirm-message="Delete draft rule &quot;Draft cleanup rule&quot;? This removes its draft and rejected versions."',
    );
    expect(body).toContain("data-action-menu-trigger=");
    expect(body).toContain("data-action-menu-panel");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_pending/edit");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_pending/delete");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_approved/edit");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_approved/delete");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_active/edit");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_active/delete");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_historical/edit");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_historical/delete");
  });
});

describe("GET /tenants/:tenantId/admin/rules/approvals", () => {
  it("renders the pending approval queue for the signed-in reviewer", async () => {
    const env = createEnv();

    mockedListPendingBadgeIssuanceRuleApprovalsForActor.mockResolvedValue([
      samplePendingApprovalEntry(),
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/approvals",
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
    expect(mockedListPendingBadgeIssuanceRuleApprovalsForActor).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      actorUserId: "usr_admin",
      actorRole: "admin",
      limit: 100,
    });
    expect(body).toContain(">Approvals<");
    expect(body).toContain("1 badge rule version awaiting your decision.");
    expect(body).toContain("CS101 Excellence Rule");
    expect(body).toContain("Computer Science");
    expect(body).toContain("Department approval");
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval"',
    );
  });
});

describe("GET /tenants/:tenantId/admin/rules/approvals/:ruleId/versions/:versionId", () => {
  it("renders a reviewer workspace with summary, diff, impact preview, and decision actions", async () => {
    const env = createEnv();
    const rule: BadgeIssuanceRuleRecord = {
      id: "brl_approval",
      tenantId: "tenant_123",
      name: "CS101 Excellence Rule",
      description: "Issue badge for CS101 completion and grade threshold.",
      badgeTemplateId: "badge_template_001",
      orgUnitId: "tenant_123:org:cs",
      ownerOrgUnitId: "tenant_123:org:cs",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_canvas",
      activeVersionId: "brv_base",
      createdByUserId: "usr_author",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    };
    const baseVersion: BadgeIssuanceRuleVersionRecord = {
      id: "brv_base",
      tenantId: "tenant_123",
      ruleId: "brl_approval",
      versionNumber: 1,
      status: "active",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"CS101","minScore":90}}',
      changeSummary: "Initial version",
      createdByUserId: "usr_author",
      submittedByUserId: "usr_author",
      submittedAt: "2026-02-18T12:05:00.000Z",
      approvedByUserId: "usr_registrar",
      approvedAt: "2026-02-18T12:10:00.000Z",
      activatedByUserId: "usr_admin",
      activatedAt: "2026-02-18T12:12:00.000Z",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:12:00.000Z",
    };
    const pendingVersion: BadgeIssuanceRuleVersionRecord = {
      ...baseVersion,
      id: "brv_approval",
      versionNumber: 2,
      status: "pending_approval",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"CS101","minScore":80}}',
      changeSummary: "Lower threshold",
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      updatedAt: "2026-02-18T12:20:00.000Z",
    };

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(rule);
    mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValue(pendingVersion);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([baseVersion, pendingVersion]);
    mockedListBadgeIssuanceRuleVersionApprovalStepsDb.mockResolvedValue([
      samplePendingApprovalStep(),
    ]);
    mockedListBadgeIssuanceRuleVersionApprovalEvents.mockResolvedValue([]);
    mockedListPendingBadgeIssuanceRuleApprovalsForActor.mockResolvedValue([
      samplePendingApprovalEntry(),
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("What This Rule Says");
    expect(body).toContain("What Changed");
    expect(body).toContain("Minimum grade lowered from 90% to 80%.");
    expect(body).toContain("Impact Preview");
    expect(body).toContain("Refresh impact");
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval/impact-preview"',
    );
    expect(body).not.toContain("No LMS course placement is linked to this rule yet.");
    expect(mockedFindLtiResourceLinkPlacementForRule).not.toHaveBeenCalled();
    expect(body).toContain("Approval Chain");
    expect(body).toContain("Department approval");
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval/decision"',
    );
    expect(body).not.toContain('name="returnTo"');
    expect(body).toContain('name="decision" value="approved"');
    expect(body).toContain('name="decision" value="changes_requested"');
    expect(body).toContain('name="decision" value="rejected"');
  });
});

describe("POST /tenants/:tenantId/admin/rules/approvals/:ruleId/versions/:versionId/impact-preview", () => {
  it("runs the live LMS impact preview only when the reviewer refreshes it", async () => {
    const env = createEnv();
    const rule: BadgeIssuanceRuleRecord = {
      id: "brl_approval",
      tenantId: "tenant_123",
      name: "CS101 Excellence Rule",
      description: "Issue badge for CS101 completion and grade threshold.",
      badgeTemplateId: "badge_template_001",
      orgUnitId: "tenant_123:org:cs",
      ownerOrgUnitId: "tenant_123:org:cs",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_canvas",
      activeVersionId: "brv_base",
      createdByUserId: "usr_author",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    };
    const pendingVersion: BadgeIssuanceRuleVersionRecord = {
      id: "brv_approval",
      tenantId: "tenant_123",
      ruleId: "brl_approval",
      versionNumber: 2,
      status: "pending_approval",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"CS101","minScore":80}}',
      changeSummary: "Lower threshold",
      createdByUserId: "usr_author",
      submittedByUserId: "usr_author",
      submittedAt: "2026-02-18T12:15:00.000Z",
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:20:00.000Z",
    };

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(rule);
    mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValue(pendingVersion);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([pendingVersion]);
    mockedListBadgeIssuanceRuleVersionApprovalStepsDb.mockResolvedValue([
      samplePendingApprovalStep(),
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval/impact-preview",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(mockedFindLtiResourceLinkPlacementForRule).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_approval",
    });
    expect(body).toContain("No LMS course placement is linked to this rule yet.");
    expect(body).toContain("Refresh impact");
  });
});

describe("POST /tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/submit-approval", () => {
  it("submits eligible draft versions for policy approval", async () => {
    const env = createEnv();
    const draftVersion: BadgeIssuanceRuleVersionRecord = {
      id: "brv_123",
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionNumber: 1,
      status: "draft",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
      changeSummary: "Initial draft",
      createdByUserId: "usr_admin",
      submittedByUserId: null,
      submittedAt: null,
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    };
    const pendingVersion: BadgeIssuanceRuleVersionRecord = {
      ...draftVersion,
      status: "pending_approval",
    };

    mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValue(draftVersion);
    mockedSubmitBadgeIssuanceRuleVersionForApprovalDb.mockResolvedValue({
      status: "submitted",
      version: pendingVersion,
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/brl_123/versions/brv_123/submit-approval",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/rules");
    expect(mockedSubmitBadgeIssuanceRuleVersionForApprovalDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
      actorUserId: "usr_admin",
      actorRole: "admin",
    });
    expect(mockedDecideBadgeIssuanceRuleVersionDb).not.toHaveBeenCalled();
    expect(mockedCreateAuditLogDb).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "badge_rule.version_submitted_for_approval",
        targetId: "brv_123",
      }),
    );

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
    expect(flashBody).toContain("Rule version submitted for approval.");
  });

  it("shows the policy-approved activation step when submission does not require approval", async () => {
    const env = createEnv();
    const draftVersion: BadgeIssuanceRuleVersionRecord = {
      id: "brv_123",
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionNumber: 1,
      status: "draft",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
      changeSummary: "Initial draft",
      createdByUserId: "usr_admin",
      submittedByUserId: null,
      submittedAt: null,
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    };
    const approvedVersion: BadgeIssuanceRuleVersionRecord = {
      ...draftVersion,
      status: "approved",
      approvedByUserId: "usr_admin",
      approvedAt: "2026-02-18T12:10:00.000Z",
    };

    mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValue(draftVersion);
    mockedSubmitBadgeIssuanceRuleVersionForApprovalDb.mockResolvedValue({
      status: "submitted",
      version: approvedVersion,
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/brl_123/versions/brv_123/submit-approval",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(mockedDecideBadgeIssuanceRuleVersionDb).not.toHaveBeenCalled();
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

    expect(flashBody).toContain(
      "Rule version approved by policy. Activate it from the rules table when ready.",
    );
  });

  it("describes ineligible versions as not submittable", async () => {
    const env = createEnv();

    mockedSubmitBadgeIssuanceRuleVersionForApprovalDb.mockResolvedValue({
      status: "not_submittable",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/brl_123/versions/brv_123/submit-approval",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
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

    expect(response.status).toBe(303);
    expect(mockedSubmitBadgeIssuanceRuleVersionForApprovalDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
      actorUserId: "usr_admin",
      actorRole: "admin",
    });
    expect(flashBody).toContain(
      "Only draft or rejected versions can be submitted from this action.",
    );
    expect(flashBody).not.toContain("approved from this action");
  });
});

describe("POST /tenants/:tenantId/admin/rules/:ruleId/delete", () => {
  it("deletes eligible draft rules, audits the deletion, and shows a success flash", async () => {
    const env = createEnv();
    const deletedRule: BadgeIssuanceRuleRecord = {
      id: "brl_draft",
      tenantId: "tenant_123",
      name: "Draft cleanup rule",
      description: null,
      badgeTemplateId: "badge_template_001",
      orgUnitId: "tenant_123:org:institution",
      ownerOrgUnitId: "tenant_123:org:institution",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_canvas",
      activeVersionId: null,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    };
    const deletedVersion: BadgeIssuanceRuleVersionRecord = {
      id: "brv_draft",
      tenantId: "tenant_123",
      ruleId: "brl_draft",
      versionNumber: 1,
      status: "draft",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
      changeSummary: "Initial draft",
      createdByUserId: "usr_admin",
      submittedByUserId: null,
      submittedAt: null,
      approvedByUserId: null,
      approvedAt: null,
      activatedByUserId: null,
      activatedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    };

    mockedDeleteDraftBadgeIssuanceRuleDb.mockResolvedValue({
      status: "deleted",
      rule: deletedRule,
      versions: [deletedVersion],
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/brl_draft/delete",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/rules");
    expect(mockedDeleteDraftBadgeIssuanceRuleDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_draft",
    });
    expect(mockedCreateAuditLogDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      actorUserId: "usr_admin",
      action: "badge_rule.deleted",
      targetType: "badge_rule",
      targetId: "brl_draft",
      metadata: {
        role: "admin",
        ruleName: "Draft cleanup rule",
        versions: [
          {
            id: "brv_draft",
            versionNumber: 1,
            status: "draft",
          },
        ],
      },
    });

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
    expect(flashBody).toContain("Draft rule deleted.");
  });

  it("blocks delete attempts for protected rules and shows an error flash", async () => {
    const env = createEnv();
    mockedDeleteDraftBadgeIssuanceRuleDb.mockResolvedValue({
      status: "not_deletable",
      rule: {
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
      },
      versions: [
        {
          id: "brv_active",
          tenantId: "tenant_123",
          ruleId: "brl_active",
          versionNumber: 1,
          status: "active",
          ruleJson:
            '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
          changeSummary: "Initial draft",
          createdByUserId: "usr_admin",
          submittedByUserId: "usr_admin",
          submittedAt: "2026-02-18T12:10:00.000Z",
          approvedByUserId: "usr_admin",
          approvedAt: "2026-02-18T12:20:00.000Z",
          activatedByUserId: "usr_admin",
          activatedAt: "2026-02-18T12:30:00.000Z",
          createdAt: "2026-02-18T12:00:00.000Z",
          updatedAt: "2026-02-18T12:30:00.000Z",
        },
      ],
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/brl_active/delete",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/rules");
    expect(mockedCreateAuditLogDb).not.toHaveBeenCalled();

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
    expect(flashBody).toContain("Only never-active draft or rejected rules can be deleted.");
  });
});

describe("POST /tenants/:tenantId/admin/rules/approvals/:ruleId/versions/:versionId/decision", () => {
  it("decides from the review workspace and redirects back to that review page", async () => {
    const env = createEnv();
    const approvedVersion: BadgeIssuanceRuleVersionRecord = {
      id: "brv_approval",
      tenantId: "tenant_123",
      ruleId: "brl_approval",
      versionNumber: 2,
      status: "approved",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
      changeSummary: "Lower threshold",
      createdByUserId: "usr_author",
      submittedByUserId: "usr_author",
      submittedAt: "2026-02-18T12:15:00.000Z",
      approvedByUserId: "usr_admin",
      approvedAt: "2026-02-18T12:20:00.000Z",
      activatedByUserId: null,
      activatedAt: null,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:20:00.000Z",
    };

    mockedDecideBadgeIssuanceRuleVersionDb.mockResolvedValue({
      status: "decided",
      version: approvedVersion,
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval/decision",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          decision: "approved",
          comment: "Looks good.",
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval",
    );
    expect(mockedDecideBadgeIssuanceRuleVersionDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_approval",
      versionId: "brv_approval",
      decision: "approved",
      actorUserId: "usr_admin",
      actorRole: "admin",
      comment: "Looks good.",
    });
    expect(mockedCreateAuditLogDb).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "badge_rule.version_approval_decided",
        targetId: "brv_approval",
      }),
    );
  });
});

describe("GET /tenants/:tenantId/admin/rules/templates", () => {
  it("renders badge template maintenance outside the rules overview", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates",
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
    expect(body).toContain(">Badge Templates<");
    expect(body).toMatch(
      /href="\/tenants\/tenant_123\/admin\/rules\/templates"[^>]*aria-current="page"/,
    );
    expect(body).toContain("Create Badge Template");
    expect(body).toContain(
      "Start with the badge name. CredTrail opens artwork setup after creation.",
    );
    expect(body).toContain(">Badge name<");
    expect(body).toContain("Create and add artwork");
    expect(body).toContain('id="template-create-panel"');
    expect(body).toContain('id="badge-template-create-form"');
    expect(body).toContain('action="/tenants/tenant_123/admin/rules/templates"');
    expect(body).toContain('method="post"');
    expect(body).toContain('id="badge-template-create-status"');
    expect(body).toContain('id="badge-template-table-status"');
    expect(body).not.toContain('id="badge-template-create-next-actions"');
    expect(body).not.toContain('name="slug"');
    expect(body).not.toContain('id="badge-template-create-slug-hint"');
    expect(body).not.toContain('pattern="[a-z0-9]+(-[a-z0-9]+)*"');
    expect(body).not.toContain("Edit Badge Template");
    expect(body).not.toContain('id="template-editor-artwork"');
    expect(body).not.toContain('id="template-image-panel"');
    expect(body).toContain('class="ct-admin__panel ct-admin__add-disclosure"');
    expect(body).not.toContain('id="badge-template-image-upload-form"');
    expect(body).not.toContain('id="badge-template-image-generation-form"');
    expect(body).not.toContain('id="badge-template-image-generation-open"');
    expect(body).not.toContain('id="template-edit-panel"');
    expect(body).not.toContain('id="badge-template-edit-form"');
    expect(body).toContain("data-action-menu-trigger=");
    expect(body).toContain("data-action-menu-panel");
    expect(body).toContain("aria-controls=");
    expect(body).not.toContain('role="menu"');
    expect(body).not.toContain('role="menuitem"');
    expect(body).not.toContain('id="badge-template-editor-criteria-link"');
    expect(body).not.toContain('id="badge-template-editor-public-link"');
    expect(body).not.toContain('id="badge-template-editor-history-link"');
    expect(body).not.toContain('data-template-edit-template-id="badge_template_001"');
    expect(body).not.toContain('data-template-manage-image-template-id="badge_template_001"');
    expect(body).toMatch(/class="[^"]*ct-action-group/);
    expect(body).toMatch(
      /class="[^"]*ct-admin__button[^"]*ct-action--secondary[^"]*ct-action--sm[^"]*" href="\/tenants\/tenant_123\/admin\/rules\/templates\/badge_template_001"/,
    );
    expect(body).not.toContain("ct-admin__template-primary-action");
    expect(body).toContain("Edit template");
    expect(body).toContain("View public page ↗");
    expect(body).toContain("View criteria page ↗");
    expect(body).toContain("View history");
    expect(body).toContain("Archive");
    expect(body).not.toContain(">Public<");
    expect(body).toContain('id="badge-template-history-dialog"');
    expect(body).not.toContain('id="badge-template-image-revision-form"');
    expect(body).not.toContain("Load image history");
    expect(body).toContain('data-template-history-template-id="badge_template_001"');
    expect(body).toContain('data-template-history-image-revision-count="3"');
    expect(body).not.toContain("3 image versions");
    expect(body).toContain('data-template-row-id="badge_template_001"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/templates/badge_template_001"');
    expect(body).toContain('class="ct-admin__template-image-link"');
    expect(body).toContain('aria-label="Open full size image for TypeScript Foundations"');
    expect(body).toContain('href="https://example.edu/badges/typescript.png"');
    expect(body).toContain("Open form");
    expect(body).toContain("Badge Templates (1)");
    expect(body).toContain("Template records, public links, and artwork maintenance");
    expect(body).toContain('id="badge-template-table-body"');
    expect(body.indexOf('id="template-create-panel"')).toBeLessThan(
      body.indexOf('id="badge-template-table-body"'),
    );
    expect(body).toContain('<th scope="col">Status</th>');
    expect(body).not.toContain('<th scope="col">ID</th>');
    expect(body).toContain('<th scope="col">Actions</th>');
    expect(body).not.toContain(">Slug</th>");
    expect(body).not.toContain(">Slug<");
    expect(body).toContain('name="q"');
    expect(body).toContain("Include archived templates");
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/rules/templates?badgeTemplateId=badge_template_001&amp;history=1"',
    );
    expect(body).toContain("autoOpenTemplateAuditTemplateId&quot;:null");
    expect(body).toContain("badgeTemplateListPageQuery");
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
    expect(body).toContain(pageAssetPath("institutionAdminBadgeTemplateListJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminBadgeTemplateEditorJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminTemplateEditorCss"));
    expect(INSTITUTION_ADMIN_JS).not.toContain("badge-template-create-form");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).toContain(
      "initBadgeTemplateHistoryDialogFromPage",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).toContain(
      "badge-template-history-dialog-close",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("history-timeline");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("badge-template-create-form");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain(
      "deriveBadgeTemplateSlugFromTitle",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain(
      "That badge name creates a URL key already used by another template.",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("Template created. URL key:");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain(
      "Opening the editor to add artwork",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("badgeTemplateEditorPath");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain(
      "window.location.assign(editorPath)",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("openTemplateEditor");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("template-edit-panel");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("openTemplateImagePanel");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain(
      "badgeTemplateCreateNextActions",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("badgeTemplateListPagePath");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("upsertBadgeTemplateTableRow");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain(
      "badgeTemplateAdminTableRowPathPrefix",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("/table-row");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain(
      "badgeTemplateTenantPathSegment",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("new WeakSet");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).toContain(
      "badge-template-image-generation-open",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).toContain(
      "badge-template-image-generation-apply-form",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).not.toContain(
      "updateBadgeTemplatePreviewImage",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).not.toContain(
      "applyBadgeTemplateEditorArtworkFragmentHtml",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).not.toContain(
      "'<div><strong>Current artwork</strong><p>'",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).not.toContain(
      "Open full size previous badge image",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).not.toContain(
      "deriveBadgeTemplateSlugFromTitle",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).not.toContain(
      "badgeTemplateEditForm.addEventListener",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).not.toContain(
      "initInstitutionAdminBadgeTemplateListPage",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).toContain("dataset.trustedRepeatableTitle");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).not.toContain("querySelector('legend')");
    expect(body).not.toContain("ct-grid--sidebar");
    expect(body).not.toContain("Reusable Rule Lists");
    expect(body).not.toContain('id="rule-value-list-form"');
    expect(body).not.toContain("Test a Rule");
    expect(body).not.toContain('id="rule-evaluate-form"');
  });

  it("fails loudly when image revision storage is not available", async () => {
    const env = createEnv();
    mockedListBadgeTemplateImageRevisionCountsByTenant.mockRejectedValueOnce(
      new Error('relation "badge_template_image_revisions" does not exist'),
    );

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    expect(response.status).toBe(500);
  });

  it("renders a dedicated badge template editor page", async () => {
    const env = createEnv();

    mockedFindBadgeTemplateById.mockResolvedValue({
      id: "badge_template_001",
      tenantId: "tenant_123",
      slug: "typescript-foundations",
      title: "TypeScript Foundations",
      description: "Awarded for TypeScript basics.",
      criteriaUri: "https://example.edu/criteria",
      imageUri: "https://example.edu/badges/typescript.png",
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: false,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001",
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
    expect(body).toContain(">Edit Badge Template<");
    expect(body).toContain("Prepare the badge details, artwork, criteria, and public record");
    expect(body).not.toContain("Back to badge templates");
    expect(body).toContain('id="badge-template-editor-preview-frame"');
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/rules/templates/badge_template_001/image-upload"',
    );
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/rules/templates/badge_template_001/image-generations/apply"',
    );
    expect(body).toContain('src="https://example.edu/badges/typescript.png"');
    expect(body).toContain("Ready for rules");
    expect(body).toContain('id="badge-template-editor-ready-status"');
    expect(body).toContain("Template details");
    expect(body).toContain("Save template details");
    expect(body).not.toContain(">Save details<");
    expect(body).toContain('id="badge-template-edit-form"');
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/rules/templates/badge_template_001/details"',
    );
    expect(body).toContain('name="badgeTemplateId" type="hidden" value="badge_template_001"');
    expect(body).toContain(">URL key<");
    expect(body).toMatch(
      /<dt>URL key<\/dt>\s*<dd>\s*<span>typescript-foundations<\/span>\s*<details class="ct-admin__template-editor-advanced ct-admin__template-editor-inline-edit">/,
    );
    expect(body).toContain('<summary aria-label="Edit URL key">Edit</summary>');
    expect(body).toContain('name="slug" type="text"');
    expect(body).toContain('maxlength="120"');
    expect(body).toContain('required=""');
    expect(body).toContain('value="typescript-foundations"');
    expect(body).toContain(">Criteria page URL<");
    expect(body).toContain('value="https://example.edu/criteria"');
    expect(body).not.toContain('name="trustedCriteriaUri"');
    expect(body).toContain('id="template-editor-trusted-credential"');
    expect(body).toContain("TrustEd readiness");
    expect(body).toContain(
      "Add TrustEd-ready public details only if this badge needs them. You can still issue the",
    );
    expect(body).toContain("Complete TrustEd checklist");
    expect(body).toContain("TrustEd details are optional for this badge.");
    expect(body).not.toContain("checks satisfied");
    expect(body).toContain("No TrustEd details have been added yet.");
    expect(body).toContain("No entries");
    expect(body).toContain("Save TrustEd metadata");
    expect(body).not.toContain('name="trustedSkills[0].name"');
    expect(body).toContain('name="trustedSkills[__INDEX__].name"');
    expect(body).toContain('data-trusted-repeatable-add="trustedSkills"');
    expect(body).toContain('id="template-editor-artwork"');
    expect(body).toContain('id="badge-template-editor-current-artwork"');
    expect(body).toContain('id="badge-template-editor-current-artwork-media"');
    expect(body).toContain('id="badge-template-editor-current-artwork-status"');
    expect(body).toContain('id="badge-template-editor-current-artwork-detail"');
    expect(body).toContain("One approved image is used for issued badges and public badge pages.");
    expect(body).toContain("Current artwork");
    expect(body).toContain("Approved image");
    expect(body).toContain("Approved artwork is set. This template is ready for rules.");
    expect(body).toContain("Replace artwork");
    expect(body).toContain("Upload a new image to replace the current artwork.");
    expect(body).not.toContain('aria-label="Artwork method"');
    expect(body).not.toContain('id="badge-template-artwork-mode-upload"');
    expect(body).not.toContain('id="badge-template-artwork-mode-generate"');
    expect(body).toContain('id="badge-template-image-upload-form"');
    expect(body).toContain("Upload approved image");
    expect(body).toContain('id="badge-template-image-generation-form"');
    expect(body).toContain("Generate a draft");
    expect(body).toContain("Use this draft");
    expect(body).toContain('id="badge-template-image-generation-open"');
    expect(body).toContain('id="template-editor-public-record"');
    expect(body).toContain('id="badge-template-editor-history-link"');
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/rules/templates?badgeTemplateId=badge_template_001&amp;history=1"',
    );
    expect(body.indexOf('id="template-editor-details"')).toBeLessThan(
      body.indexOf('id="template-editor-trusted-credential"'),
    );
    expect(body.indexOf('id="template-editor-trusted-credential"')).toBeLessThan(
      body.indexOf('id="template-editor-artwork"'),
    );
    expect(body.indexOf('id="template-editor-artwork"')).toBeLessThan(
      body.indexOf('id="template-editor-public-record"'),
    );
    expect(body).not.toContain('id="template-editor-criteria"');
    expect(body).not.toContain('id="template-editor-visibility"');
    expect(body).not.toContain('id="template-editor-activity"');
    expect(body).not.toContain('id="badge-template-table-body"');
    expect(body).toContain(pageAssetPath("institutionAdminBadgeTemplateEditorJs"));
    expect(body).toContain(pageAssetPath("institutionAdminTemplateEditorCss"));
    expect(body).not.toContain(pageAssetPath("institutionAdminBadgeTemplateListJs"));
    expect(mockedFindBadgeTemplateById).toHaveBeenCalledWith(
      fakeDb,
      "tenant_123",
      "badge_template_001",
    );
  });

  it("surfaces invalid stored TrustEd metadata in the badge template editor", async () => {
    const env = createEnv();

    mockedFindBadgeTemplateById.mockResolvedValue({
      id: "badge_template_001",
      tenantId: "tenant_123",
      slug: "typescript-foundations",
      title: "TypeScript Foundations",
      description: "Awarded for TypeScript basics.",
      criteriaUri: "https://example.edu/criteria",
      imageUri: "https://example.edu/badges/typescript.png",
      trustedCredentialMetadataJson: "{not-json",
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: false,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Stored TrustEd metadata is invalid.");
    expect(body).toContain("Review and save this section to repair it.");
    expect(body).toContain("JSON");
    expect(body).not.toContain("Required TrustEd Credential checklist metadata is present");
  });

  it("surfaces incomplete TrustEd metadata with actionable preview and open editors", async () => {
    const env = createEnv();
    const incompleteMetadata = buildCompleteTrustEdCredentialMetadata({
      skills: [],
      frameworkAlignments: [],
      issuerAuthority: null,
      evidence: [],
      results: [],
      criteria: null,
      assessments: [],
      achievementType: null,
    });

    mockedFindBadgeTemplateById.mockResolvedValue({
      ...sampleActiveBadgeTemplate,
      trustedCredentialMetadataJson: JSON.stringify(incompleteMetadata),
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('ct-admin__status-pill--warning">Incomplete</span>');
    expect(body).toContain("Add at least one represented skill.");
    expect(body).toContain("4 more required items in the checklist below.");
    expect(body).toContain("checks satisfied");
    expect(body).toMatch(
      /<details[^>]*class="ct-admin__template-editor-advanced ct-admin__template-editor-trusted-editor"[^>]*\bopen\b/,
    );
    expect(body).toMatch(
      /<details[^>]*data-trusted-repeatable="trustedSkills"[^>]*data-trusted-repeatable-title="Skill"[^>]*\bopen\b/,
    );
    expect(body).toContain('name="trustedSkills[0].name"');
    expect(body).toContain('data-trusted-repeatable-title="Skill"');
  });

  it("renders all stored TrustEd repeatable metadata rows in the badge template editor", async () => {
    const env = createEnv();

    mockedFindBadgeTemplateById.mockResolvedValue({
      ...sampleActiveBadgeTemplate,
      trustedCredentialMetadataJson: JSON.stringify({
        skills: [
          {
            name: "Applied data analysis",
            identifierUri: "https://skills.example.edu/applied-data",
            source: "Example Skills Framework",
          },
          {
            name: "Stakeholder communication",
            identifierUri: "https://skills.example.edu/communication",
            source: "Example Skills Framework",
          },
        ],
        frameworkAlignments: [],
        issuerAuthority: null,
        evidence: [],
        results: [],
        criteria: null,
        assessments: [],
        achievementType: null,
        rubrics: [],
        duration: null,
        credits: null,
        endorsements: [],
      }),
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Applied data analysis");
    expect(body).toContain("Stakeholder communication");
    expect(body).toContain('name="trustedSkills[1].name"');
    expect(body).toContain('data-trusted-repeatable-remove="trustedSkills"');
  });

  it("preserves list context in badge template editor navigation links", async () => {
    const env = createEnv();

    mockedFindBadgeTemplateById.mockResolvedValue({
      id: "badge_template_001",
      tenantId: "tenant_123",
      slug: "typescript-foundations",
      title: "TypeScript Foundations",
      description: "Awarded for TypeScript basics.",
      criteriaUri: "https://example.edu/criteria",
      imageUri: "https://example.edu/badges/typescript.png",
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: false,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001?q=typescript&includeArchived=1&returnTo=rule-builder",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).not.toContain("Back to badge templates");
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/rules/templates?q=typescript&amp;includeArchived=1&amp;returnTo=rule-builder&amp;badgeTemplateId=badge_template_001&amp;history=1"',
    );
  });

  const sampleActiveBadgeTemplate = {
    id: "badge_template_001",
    tenantId: "tenant_123",
    slug: "typescript-foundations",
    title: "TypeScript Foundations",
    description: "Awarded for TypeScript basics.",
    criteriaUri: "https://example.edu/criteria",
    imageUri: "https://example.edu/badges/typescript.png",
    createdByUserId: "usr_admin",
    ownerOrgUnitId: "tenant_123:org:institution",
    governanceMetadataJson: null,
    isArchived: false,
    createdAt: "2026-02-18T12:00:00.000Z",
    updatedAt: "2026-02-18T12:00:00.000Z",
  };

  it("POST create redirects to the new template editor for artwork setup", async () => {
    const env = createEnv();

    mockedCreateBadgeTemplate.mockResolvedValue({
      ...sampleActiveBadgeTemplate,
      id: "badge_template_new",
      slug: "advanced-typescript",
      title: "Advanced TypeScript",
      description: "Advanced course badge.",
      imageUri: null,
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          title: "Advanced TypeScript",
          description: "Advanced course badge.",
        }),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/templates/badge_template_new?details=created#template-editor-artwork",
    );
    expect(mockedCreateBadgeTemplate).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      slug: "advanced-typescript",
      title: "Advanced TypeScript",
      description: "Advanced course badge.",
      criteriaUri: undefined,
      imageUri: undefined,
      ownerOrgUnitId: "tenant_123:org:institution",
      createdByUserId: "usr_admin",
    });
  });

  it("POST details saves template fields and redirects back to the editor", async () => {
    const env = createEnv();

    mockedFindBadgeTemplateById.mockResolvedValue(sampleActiveBadgeTemplate);
    mockedUpdateBadgeTemplate.mockResolvedValue({
      ...sampleActiveBadgeTemplate,
      title: "Advanced TypeScript",
      description: null,
      criteriaUri: "https://example.edu/advanced-criteria",
      updatedAt: "2026-02-19T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001/details",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          title: "Advanced TypeScript",
          slug: "advanced-typescript",
          description: "",
          criteriaUri: "https://example.edu/advanced-criteria",
        }),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001?details=saved",
    );
    expect(mockedUpdateBadgeTemplate).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      id: "badge_template_001",
      slug: "advanced-typescript",
      title: "Advanced TypeScript",
      description: null,
      criteriaUri: "https://example.edu/advanced-criteria",
    });
  });

  it("POST details saves TrustEd credential metadata", async () => {
    const env = createEnv();

    mockedFindBadgeTemplateById.mockResolvedValue(sampleActiveBadgeTemplate);
    mockedUpdateBadgeTemplate.mockResolvedValue(sampleActiveBadgeTemplate);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001/details",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          title: "TypeScript Foundations",
          slug: "typescript-foundations",
          description: "Awarded for TypeScript basics.",
          criteriaUri: "https://example.edu/criteria",
          "trustedSkills[0].name": "Applied data analysis",
          "trustedSkills[0].identifierUri":
            "https://skills.example.edu/skills/applied-data-analysis",
          "trustedSkills[0].source": "Example Skills Framework",
          "trustedFrameworkAlignments[0].targetName": "Analyze civic datasets",
          "trustedFrameworkAlignments[0].targetUri":
            "https://case.example.edu/frameworks/data-analysis/items/analyze-civic-data",
          "trustedFrameworkAlignments[0].frameworkName": "Example CASE Framework",
          "trustedFrameworkAlignments[0].frameworkUri":
            "https://case.example.edu/frameworks/data-analysis",
          trustedIssuerAuthorityName: "Middle States Commission on Higher Education",
          trustedIssuerAuthorityUri: "https://www.msche.org/institution/0000/",
          trustedIssuerAuthorityType: "accreditor",
          "trustedEvidence[0].name": "Capstone analysis portfolio",
          "trustedEvidence[0].uri": "https://evidence.example.edu/learners/123/capstone",
          "trustedEvidence[0].description": "Portfolio evidence reviewed by program faculty.",
          "trustedResults[0].value": "Pass",
          "trustedResults[0].resultDate": "2026-05-18",
          trustedCriteriaText: "Complete the applied analytics project and faculty review.",
          "trustedAssessments[0].description": "Faculty-scored applied analytics capstone.",
          "trustedAssessments[0].assessmentDate": "2026-05-18",
          trustedAchievementType: "Project",
          "trustedRubrics[0].name": "Applied analytics rubric",
          "trustedRubrics[0].uri": "https://credentials.example.edu/rubrics/applied-analytics",
          trustedDurationValue: "6 weeks",
          trustedCreditsAvailable: "3 credits",
          trustedCreditsEarned: "3 credits",
          "trustedEndorsements[0].endorserName": "Regional Workforce Council",
          "trustedEndorsements[0].endorserUri":
            "https://workforce.example.edu/endorsements/applied-analytics",
        }),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(mockedUpdateBadgeTemplate).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        trustedCredentialMetadataJson: expect.stringContaining("Applied data analysis"),
      }),
    );
    expect(mockedUpdateBadgeTemplate).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        trustedCredentialMetadataJson: expect.stringContaining("https://example.edu/criteria"),
      }),
    );
  });

  it("POST details preserves list filters when the template is not found before update", async () => {
    const env = createEnv();

    mockedFindBadgeTemplateById.mockResolvedValue(null);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates/badge_template_missing/details?q=typescript&includeArchived=1&returnTo=rule-builder",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          title: "Advanced TypeScript",
          slug: "advanced-typescript",
        }),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = decodeURIComponent(response.headers.get("location") ?? "");
    expect(location).toContain("/tenants/tenant_123/admin/rules/templates");
    expect(location).toContain("q=typescript");
    expect(location).toContain("includeArchived=1");
    expect(location).toContain("returnTo=rule-builder");
    expect(location).not.toContain("listError=");
    expect(adminFlashCookieHeader(response)).toContain("ct_admin_flash_list_message_tenant_123");
    expect(mockedUpdateBadgeTemplate).not.toHaveBeenCalled();
  });

  it("POST details preserves list filters when the template disappears during update", async () => {
    const env = createEnv();

    mockedFindBadgeTemplateById.mockResolvedValue(sampleActiveBadgeTemplate);
    mockedUpdateBadgeTemplate.mockResolvedValue(null);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001/details?q=typescript&includeArchived=1&returnTo=rule-builder",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          title: "Advanced TypeScript",
          slug: "advanced-typescript",
        }),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = decodeURIComponent(response.headers.get("location") ?? "");
    expect(location).toContain("/tenants/tenant_123/admin/rules/templates");
    expect(location).toContain("q=typescript");
    expect(location).toContain("includeArchived=1");
    expect(location).toContain("returnTo=rule-builder");
    expect(location).not.toContain("listError=");
    expect(adminFlashCookieHeader(response)).toContain("ct_admin_flash_list_message_tenant_123");
  });

  it("POST archive redirects with a notice and preserves list filters", async () => {
    const env = createEnv();

    mockedFindBadgeTemplateById.mockResolvedValue(sampleActiveBadgeTemplate);
    mockedSetBadgeTemplateArchivedState.mockResolvedValue({
      ...sampleActiveBadgeTemplate,
      isArchived: true,
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001/archive?q=typescript&includeArchived=1",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = decodeURIComponent(response.headers.get("location") ?? "");
    expect(location).toContain("/tenants/tenant_123/admin/rules/templates");
    expect(location).not.toContain("listNotice=");
    expect(location).toContain("q=typescript");
    expect(location).toContain("includeArchived=1");
    expect(adminFlashCookieHeader(response)).toContain("ct_admin_flash_list_message_tenant_123");

    const pageResponse = await app.request(
      location,
      {
        headers: {
          Cookie: `better-auth.session_token=session-token; ${adminFlashCookieHeader(response)}`,
        },
      },
      env,
    );
    const body = await pageResponse.text();

    expect(pageResponse.status).toBe(200);
    expect(body).toContain("Badge template archived.");
    expect(mockedSetBadgeTemplateArchivedState).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      id: "badge_template_001",
      isArchived: true,
    });
  });

  it("POST image revision restore redirects to history with filters and notice", async () => {
    const env = createEnv();
    const revision = {
      id: "btir_123",
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
      previousImageUri: "https://example.edu/old.png",
      newImageUri: "https://example.edu/badges/typescript.png",
      sourceType: "upload" as const,
      promptText: null,
      provider: null,
      model: null,
      metadataJson: null,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
    };

    mockedFindBadgeTemplateById.mockResolvedValue(sampleActiveBadgeTemplate);
    mockedFindBadgeTemplateImageRevisionById.mockResolvedValue(revision);
    mockedUpdateBadgeTemplate.mockResolvedValue({
      ...sampleActiveBadgeTemplate,
      imageUri: revision.previousImageUri,
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates/badge_template_001/image-revisions/btir_123/restore?q=typescript&includeArchived=1",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = decodeURIComponent(response.headers.get("location") ?? "");
    expect(location).toContain("history=1");
    expect(location).toContain("badgeTemplateId=badge_template_001");
    expect(location).toContain("q=typescript");
    expect(location).toContain("includeArchived=1");
    expect(location).not.toContain("listNotice=");
    expect(adminFlashCookieHeader(response)).toContain("ct_admin_flash_list_message_tenant_123");
  });

  it("renders restore actions with list query context in the history dialog", async () => {
    const env = createEnv();
    const revision = {
      id: "btir_123",
      tenantId: "tenant_123",
      badgeTemplateId: "badge_template_001",
      previousImageUri: "https://example.edu/old.png",
      newImageUri: "https://example.edu/badges/typescript.png",
      sourceType: "upload" as const,
      promptText: null,
      provider: null,
      model: null,
      metadataJson: null,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
    };

    mockedListBadgeTemplates.mockResolvedValue([sampleActiveBadgeTemplate]);
    mockedFindBadgeTemplateById.mockResolvedValue(sampleActiveBadgeTemplate);
    mockedListBadgeTemplateImageRevisions.mockResolvedValue([revision]);
    mockedCountBadgeTemplateImageRevisions.mockResolvedValue(1);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates?q=typescript&badgeTemplateId=badge_template_001&history=1",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("/restore?q=typescript");
    expect(body).not.toContain('method="dialog"');
    expect(body).toContain('id="badge-template-history-dialog-close"');
  });

  it("renders archive actions as POST forms on the template list", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/rules/templates/badge_template_001/archive"',
    );
    expect(body).toContain('method="post"');
    expect(body).toContain("Archive");
  });

  it("preserves rule-builder return context on the badge template page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates?returnTo=rule-builder",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("&quot;returnToRuleBuilder&quot;:true");
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/rules/templates?returnTo=rule-builder&amp;badgeTemplateId=badge_template_001&amp;history=1"',
    );
  });

  it("supports template search, archived filters, and deep-linked history", async () => {
    const env = createEnv();

    mockedListBadgeTemplates.mockResolvedValue([
      {
        id: "badge_template_001",
        tenantId: "tenant_123",
        slug: "typescript-foundations",
        title: "TypeScript Foundations",
        description: "Awarded for TypeScript basics.",
        criteriaUri: "https://example.edu/criteria",
        imageUri: "https://example.edu/badges/typescript.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_archived",
        tenantId: "tenant_123",
        slug: "legacy-workshop",
        title: "Legacy Workshop",
        description: "Retired workshop template.",
        criteriaUri: "https://example.edu/criteria/legacy",
        imageUri: null,
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: true,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
    ]);
    mockedFindBadgeTemplateById.mockResolvedValue({
      id: "badge_template_archived",
      tenantId: "tenant_123",
      slug: "legacy-workshop",
      title: "Legacy Workshop",
      description: "Retired workshop template.",
      criteriaUri: "https://example.edu/criteria/legacy",
      imageUri: null,
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: true,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates?q=legacy&includeArchived=1&badgeTemplateId=badge_template_archived&history=1",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(mockedListBadgeTemplates).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      includeArchived: true,
    });
    expect(body).toContain("Legacy Workshop");
    expect(body).not.toContain("TypeScript Foundations");
    expect(body).toContain('value="legacy"');
    expect(body).toContain('name="includeArchived"');
    expect(body).toContain("Archived");
    expect(body).toContain(
      "autoOpenTemplateAuditTemplateId&quot;:&quot;badge_template_archived&quot;",
    );
    expect(body).toContain("history=1");
    expect(body).toContain("includeArchived=1");
    expect(body).toContain('data-auto-open-history-template-id="badge_template_archived"');
    expect(body).toContain("Showing recent changes for this template");
    expect(body).toContain('id="badge-template-history-dialog"');
  });

  it("redirects deep-linked archived template history to include archived templates", async () => {
    const env = createEnv();

    mockedFindBadgeTemplateById.mockResolvedValue({
      id: "badge_template_archived",
      tenantId: "tenant_123",
      slug: "legacy-workshop",
      title: "Legacy Workshop",
      description: "Retired workshop template.",
      criteriaUri: "https://example.edu/criteria/legacy",
      imageUri: null,
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: true,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/templates?badgeTemplateId=badge_template_archived&history=1",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toContain("includeArchived=1");
    expect(response.headers.get("location")).toContain("badgeTemplateId=badge_template_archived");
    expect(response.headers.get("location")).toContain("history=1");
  });

  it("pins deep-linked templates excluded by search and reports missing templates", async () => {
    const env = createEnv();
    const activeTemplate = {
      id: "badge_template_001",
      tenantId: "tenant_123",
      slug: "typescript-foundations",
      title: "TypeScript Foundations",
      description: "Awarded for TypeScript basics.",
      criteriaUri: "https://example.edu/criteria",
      imageUri: "https://example.edu/badges/typescript.png",
      createdByUserId: "usr_admin",
      ownerOrgUnitId: "tenant_123:org:institution",
      governanceMetadataJson: null,
      isArchived: false,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    };
    const archivedTemplate = {
      ...activeTemplate,
      id: "badge_template_archived",
      slug: "legacy-workshop",
      title: "Legacy Workshop",
      isArchived: true,
    };

    mockedListBadgeTemplates.mockResolvedValue([activeTemplate, archivedTemplate]);

    const pinnedResponse = await app.request(
      "/tenants/tenant_123/admin/rules/templates?q=nonexistent&includeArchived=1&badgeTemplateId=badge_template_archived&history=1",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const pinnedBody = await pinnedResponse.text();

    expect(pinnedResponse.status).toBe(200);
    expect(pinnedBody).toContain("Legacy Workshop");
    expect(pinnedBody).not.toContain('data-template-row-id="badge_template_001"');
    expect(pinnedBody).toContain(
      "autoOpenTemplateAuditTemplateId&quot;:&quot;badge_template_archived&quot;",
    );

    mockedFindBadgeTemplateById.mockResolvedValue(null);

    const missingResponse = await app.request(
      "/tenants/tenant_123/admin/rules/templates?badgeTemplateId=missing_template&history=1",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const missingBody = await missingResponse.text();

    expect(missingResponse.status).toBe(200);
    expect(missingBody).toContain("does not match a badge template in this tenant");
    expect(missingBody).toContain("autoOpenTemplateAuditTemplateId&quot;:null");
  });
});

describe("GET /tenants/:tenantId/admin/rules/new", () => {
  it("redirects to login when no session cookie is present", async () => {
    const env = createEnv();
    const response = await app.request("/tenants/tenant_123/admin/rules/new", undefined, env);

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/login?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin%2Frules%2Fnew&reason=auth_required",
    );
  });

  it("renders dedicated rule-builder page for admin membership", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/new",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("Badge Awarding Rule");
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
    expect(body).toContain(pageAssetPath("institutionAdminRuleBuilderJs"));
    expect(body).toContain("Define when learners earn this badge");
    expect(body).toContain('class="ct-admin-content ct-admin-content--rule-builder"');
    expect(body).toContain('class="ct-admin__builder-shell ct-stack"');
    expect(body).toContain('aria-label="Rule builder steps"');
    expect(body).toContain('id="rule-builder-steps"');
    expect(body).not.toContain('id="rule-builder-stepper"');
    expect(body).not.toContain("ct-admin__builder-rail");
    expect(body).not.toContain("ct-admin__builder-main");
    expect(body).toContain("ct-admin__builder-steps--vertical-stepper");
    expect(body).toMatch(
      /id="builder-step-metadata"[\s\S]*?id="rule-builder-step-footer"[\s\S]*?id="rule-builder-step-next"[\s\S]*?data-rule-step-row="conditions"/,
    );
    expect(INSTITUTION_ADMIN_CSS).toContain(
      ".ct-admin__stepper-step:not(.is-active) .ct-admin__step-copy small",
    );
    expect(INSTITUTION_ADMIN_CSS).not.toContain(
      ".ct-admin__stepper-step:not(.is-active) .ct-admin__step-copy small {\n  display: none;",
    );
    expect(INSTITUTION_ADMIN_CSS).toContain(
      ".ct-admin__builder-steps--vertical-stepper .ct-admin__step-button.is-locked,\n.ct-admin__builder-steps--vertical-stepper .ct-admin__step-button:disabled {\n  opacity: 1;",
    );
    expect(INSTITUTION_ADMIN_CSS).not.toContain(".ct-admin__form button");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__table .ct-action-group");
    expect(INSTITUTION_ADMIN_CSS).toContain("flex-wrap: nowrap;");
    expect(body).toContain('data-rule-step-row="metadata"');
    expect(body).toContain('class="ct-admin__stepper-header"');
    expect(body).toContain('class="ct-admin__stepper-content"');
    expect(body).not.toContain("ct-admin__builder-step-label");
    expect(body).not.toContain("ct-admin__builder-step-panel");
    expect(body).toMatch(
      /class="ct-admin__stepper-step"[^>]*data-rule-step-row="metadata"[\s\S]*?class="ct-admin__stepper-header"[\s\S]*?class="ct-admin__stepper-content"[\s\S]*?id="builder-step-metadata"/,
    );
    expect(body).toContain('id="rule-create-form"');
    expect(body).toContain("ruleBuilderContext");
    expect(body).toContain("lmsConnectionsApiPath");
    expect(body).toContain('data-rule-step-target="metadata"');
    expect(body).toContain('data-rule-step-target="conditions"');
    expect(body).toContain('data-rule-step-target="test"');
    expect(body).not.toContain('data-rule-step-target="review"');
    expect(body).toContain('id="rule-builder-condition-list"');
    expect(body).toContain('id="rule-builder-definition-json"');
    expect(body).not.toContain('id="rule-builder-step-prev"');
    expect(body).toContain('id="rule-builder-step-next"');
    expect(body).toContain('id="rule-builder-submit"');
    expect(body).toContain('id="rule-builder-flow-list"');
    expect(body).toMatch(
      /id="rule-builder-add-condition"[^>]*class="[^"]*ct-admin__button[^"]*ct-action--sm/,
    );
    expect(body).toMatch(/class="[^"]*ct-admin__builder-toolbar[^"]*ct-action-group/);
    expect(body).toMatch(/class="[^"]*ct-admin__builder-step-nav[^"]*ct-action-group/);
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__builder-grid.ct-grid");
    expect(body).toContain('id="rule-builder-require-every-requirement"');
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("rule-builder-require-every-requirement");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("prefers-reduced-motion: reduce");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("shouldScrollToActiveBuilderPanel");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toMatch(/setRuleBuilderRootLogic\(["']all["']\)/);
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).not.toContain("data-rule-builder-root-logic-option");
    expect(body).toMatch(
      /id="rule-builder-step-next"[^>]*class="[^"]*ct-admin__button[^"]*ct-action--sm/,
    );
    expect(body).toMatch(
      /id="rule-builder-submit"[^>]*form="rule-create-form"[^>]*class="[^"]*ct-admin__button[^"]*ct-action--primary/,
    );
    expect(body).toMatch(/id="rule-builder-submit"[^>]*hidden/);
    expect(body).not.toMatch(/id="rule-builder-step-next"[^>]*hidden/);
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain(
      "ruleBuilderSubmitButton.hidden = !isLastStep",
    );
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain(
      "ruleBuilderStepNextButton.hidden = isLastStep",
    );
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("ruleBuilderStepFooter");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain(
      "activePanel.append(ruleBuilderStepFooter)",
    );
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain(
      "return targetIndex < activeRuleBuilderStepIndex",
    );
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain(
      "setBuilderStepState(activeRuleBuilderStepIndex + 1)",
    );
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toMatch(
      /Choose ["'] \+ article \+ missingLabels\[0\]/,
    );
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toMatch(
      /and an ["'] \+ missingLabels\[1\] \+ ["'] before continuing/,
    );
    expect(body).toContain('id="rule-builder-test-preset"');
    expect(body).not.toContain('id="rule-builder-apply-test-preset"');
    expect(body).toContain('id="rule-builder-test-output"');
    expect(body).not.toContain("Sample course ID");
    expect(body).not.toContain('name="testCourseId"');
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain(
      "facts = buildSampleFactsFromConditions(readConditionsForPreview())",
    );
    expect(body).not.toContain('id="rule-builder-value-list-body"');
    expect(body).not.toContain("badge-rule-value-lists");
    expect(body).toContain("valueLists");
    expect(body).toContain("Rules page");
    expect(body).toContain("Reload this builder");
    expect(body).toContain('name="reviewOnMissingFacts"');
    expect(body).not.toContain('id="rule-builder-simulate"');
    expect(body).not.toContain('id="rule-builder-simulate-output"');
    expect(body).not.toContain("Historical simulation");
    expect(body).toContain('class="ct-admin__builder-steps-title">Build this rule</h2>');
    expect(body).not.toContain("Follow these steps in order");
    expect(body).not.toContain('class="ct-admin__step-kicker"');
    expect(body).toContain("Continue to Requirements");
    expect(body).toContain('id="rule-builder-step-callout"');
    expect(body).toContain("Set up this rule");
    expect(body).toContain("Each requirement describes what a learner must do.");
    expect(body).toContain("Exclude learners who match this requirement");
    expect(body).not.toContain("Each row describes one fact CredTrail checks");
    expect(body).not.toContain("Require completed");
    expect(body).not.toContain("Reusable course list");
    expect(body).not.toContain("The awarding pattern starts the requirements list");
    expect(body).not.toContain("Use pattern");
    expect(body).not.toContain("rule-builder-apply-test-preset");
    expect(body).not.toContain("Confirm the badge and Learning Management System source");
    expect(body).not.toContain('id="rule-builder-return-to-pattern"');
    expect(body).not.toContain('id="rule-builder-condition-empty"');
    expect(body).not.toContain("No requirements yet");
    expect(body).not.toContain("Select Step 1 above");
    expect(body).not.toContain("Back to Step 1");
    expect(body).toContain("Advanced JSON tools");
    expect(body).not.toContain("Advanced tools and reusable lists");
    expect(body).not.toContain("Reusable lists");
    expect(body).not.toContain("Reviewer roles (optional)");
    expect(body).not.toContain("Leave blank for admin review");
    expect(body).not.toContain('value="admin,owner"');
    expect(body).not.toContain("Start from a proven pattern");
    expect(body).not.toContain("Start from an existing rule");
    expect(body).not.toContain("Load rule");
    expect(body).toContain("Choose the badge, LMS connection, and how learners earn it");
    expect(body).toContain('name="lmsConnectionId"');
    expect(body).toContain("Canvas Test (Canvas)");
    expect(body).toContain('id="rule-builder-lms-status"');
    expect(body).toContain('role="alert"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/lms-connections"');
    expect(body).toContain("Update LMS connection");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain(
      "Sakai blocked CredTrail from reading your site list (403).",
    );
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("Save a Sakai username and password");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("setLmsLookupStatus(message, true)");
    expect(body).toContain("Need a new template?");
    expect(body).toContain("Create one in Badge Templates");
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/rules/templates?returnTo=rule-builder"',
    );
    expect(body).toContain("and continue here");
    expect(body).toContain("Copy existing rule settings");
    expect(body).toContain("Select rule to copy");
    expect(body).toContain("Copy settings");
    expect(body).not.toContain("Save progress");
    expect(body).not.toContain("Resume saved progress");
    expect(body).toContain("Edit requirement details");
    expect(body).toContain('id="rule-builder-test-result"');
    expect(body).toContain("Import and export");
    expect(body).not.toContain("Authoring approach");
    expect(body).toContain("Survey completion");
    expect(body).toContain("Custom field");
    expect(body).toContain("Rule flow preview");
    expect(body).not.toContain("Data sources");
    expect(body).not.toContain("Draft readiness");
    expect(body).toContain("Requirement catalog");
    expect(body).not.toContain("Five-minute walkthrough");
    expect(body).not.toContain("RULE_BUILDER_TUTORIAL_EMBED_URL");
    expect(body).not.toContain("Model, test, then release");
    expect(body).not.toContain('aria-label="Rule builder setup"');
    expect(body).toContain('href="/tenants/tenant_123/admin"');
    expect(body).toContain('href="/tenants/tenant_123/admin/operations/learner-records"');
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/templates"');
    expect(body).toContain('class="ct-admin-sidebar__link-label">Templates</span>');
    expect(body).toContain('class="ct-admin-sidebar__menu-chevron"');
    expect(body).toMatch(
      /<details class="ct-admin-sidebar__group-details"[^>]*open[\s\S]*?Badge Program[\s\S]*?Templates[\s\S]*?Rules/,
    );
    expect(body).not.toContain('class="ct-admin-sidebar__link-label">New Rule</span>');
    expect(body).not.toContain('href="/tenants/tenant_123/admin/rules/new" aria-current="page"');
    expect(body).toContain("&quot;rulesListPath&quot;:&quot;/tenants/tenant_123/admin/rules&quot;");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("window.location.assign(rulesListPath)");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).not.toContain(
      "window.location.assign(tenantAdminPath)",
    );
    expect(body).toContain('href="/tenants/tenant_123/admin/access/members"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/governance"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/api-keys"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/org-units"');
    expect(INSTITUTION_ADMIN_JS).not.toContain("rule-builder-condition-list");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("rule-builder-condition-list");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).not.toContain("credtrail:rule-builder:");
  });

  it("preselects a returned badge template in the rule builder", async () => {
    const env = createEnv();
    mockedListBadgeTemplates.mockResolvedValue([
      {
        id: "badge_template_001",
        tenantId: "tenant_123",
        slug: "typescript-foundations",
        title: "TypeScript Foundations",
        description: "Awarded for TypeScript basics.",
        criteriaUri: "https://example.edu/criteria",
        imageUri: "https://example.edu/badges/typescript.png",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
      {
        id: "badge_template_002",
        tenantId: "tenant_123",
        slug: "advanced-analytics",
        title: "Advanced Analytics",
        description: "Awarded for analytics mastery.",
        criteriaUri: null,
        imageUri: null,
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/new?badgeTemplateId=badge_template_002",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(
      '<option value="badge_template_002" selected="">Advanced Analytics (badge_template_002)</option>',
    );
    expect(body).toContain(
      '<option value="badge_template_001">TypeScript Foundations (badge_template_001)</option>',
    );
  });

  it("keeps the switch-organization sidebar link on the dedicated rule-builder page", async () => {
    const env = createEnv();
    mockedListAccessibleTenantContextsForUser.mockResolvedValue([
      {
        tenantId: "tenant_123",
        tenantSlug: "tenant-123",
        tenantDisplayName: "Tenant 123",
        tenantPlanTier: "team",
        membershipRole: "admin",
      },
      {
        tenantId: "tenant_456",
        tenantSlug: "tenant-456",
        tenantDisplayName: "Tenant 456",
        tenantPlanTier: "enterprise",
        membershipRole: "admin",
      },
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/new",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Switch organization");
    expect(body).toContain(
      "/account/organizations?next=%2Ftenants%2Ftenant_123%2Fadmin%2Frules%2Fnew",
    );
  });
});

describe("GET /tenants/:tenantId/admin/rules/:ruleId/edit", () => {
  it("loads eligible draft rule settings into the builder and keeps retesting available", async () => {
    const env = createEnv();
    const editRule: BadgeIssuanceRuleRecord = {
      id: "brl_draft",
      tenantId: "tenant_123",
      name: "Draft QA Rule",
      description: "Fix the score threshold before review.",
      badgeTemplateId: "badge_template_001",
      orgUnitId: "tenant_123:org:institution",
      ownerOrgUnitId: "tenant_123:org:institution",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_canvas",
      activeVersionId: null,
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:10:00.000Z",
    };
    const editVersion: BadgeIssuanceRuleVersionRecord = {
      id: "brv_draft_2",
      tenantId: "tenant_123",
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
      createdAt: "2026-02-18T12:10:00.000Z",
      updatedAt: "2026-02-18T12:10:00.000Z",
    };

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(editRule);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([editVersion]);

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
    expect(mockedListBadgeIssuanceRules).not.toHaveBeenCalled();
    expect(mockedListBadgeIssuanceRuleVersions).toHaveBeenCalledTimes(1);
    expect(mockedListBadgeIssuanceRuleVersions).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_draft",
    });
    expect(body).toContain("Edit Badge Awarding Rule");
    expect(body).toContain(
      "Review the current settings, test changes, then save a new draft version.",
    );
    expect(body).toContain(
      "Try the rule with a sample learner, then save a new draft version for review.",
    );
    expect(body).toContain('id="rule-builder-test"');
    expect(body).toContain("Save changes as draft");
    expect(body).not.toContain("Copy existing rule settings");
    expect(body).toContain('value="Draft QA Rule"');
    expect(body).toContain('data-rule-builder-preserve-name="true"');
    expect(body).toContain('value="Fix the score threshold before review."');
    expect(body).toContain(
      '<option value="badge_template_001" selected="">TypeScript Foundations (badge_template_001)</option>',
    );
    expect(body).toContain(
      '<option value="lms_canvas" data-provider-kind="canvas" selected="">Canvas Test (Canvas)</option>',
    );
    expect(body).toContain("&quot;editRule&quot;:{&quot;id&quot;:&quot;brl_draft&quot;");
    expect(body).toContain("&quot;latestVersionStatus&quot;:&quot;rejected&quot;");
    expect(body).toContain("&quot;assignmentId&quot;:&quot;assignment_1&quot;");
    expect(body).toContain("&quot;minScore&quot;:90");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain(
      "const ruleBuilderSubmitApiPath = isRuleBuilderEditMode",
    );
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain(
      "badgeRuleApiPath + '/' + encodeURIComponent(editRuleContext.id) + '/draft'",
    );
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("New draft version saved.");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("Rule draft created.");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).not.toContain("New draft version saved: ");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).not.toContain("Rule draft created: ");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain(
      "New draft version saved via visual builder",
    );
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
      {
        id: "brv_active",
        tenantId: "tenant_123",
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
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:30:00.000Z",
      },
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
    expect(flashBody).toContain("Only never-active draft or rejected rules can be edited.");
  });
});
