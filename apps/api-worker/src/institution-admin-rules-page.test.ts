import type {
  BadgeIssuanceRuleApprovalStepRecord,
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  PendingBadgeIssuanceRuleApprovalRecord,
} from "@credtrail/db";
import { buildCompleteTrustEdCredentialMetadata } from "@credtrail/validation/testing";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { setAdminListMessageFlash } from "./admin/admin-list-message-flash";
import type { AppEnv } from "./app/types";
import {
  createEnv,
  fakeDb,
  mockedCreateAuditLogDb,
  mockedCreateBadgeTemplate,
  mockedDecideBadgeIssuanceRuleVersionDb,
  mockedDeleteNeverActiveBadgeIssuanceRuleDb,
  mockedDeleteBadgeIssuanceRuleBuilderDraftByIdDb,
  mockedFindBadgeIssuanceRuleVersionByIdDb,
  mockedFindBadgeTemplateById,
  mockedFindBadgeTemplateImageRevisionById,
  mockedFindBadgeIssuanceRuleById,
  mockedFindLtiResourceLinkPlacementForRule,
  mockedEnqueueJobQueueMessageOnce,
  mockedFindTenantMembership,
  mockedFindUserById,
  mockedListBadgeIssuanceRuleVersionApprovalEvents,
  mockedListBadgeIssuanceRuleVersionApprovalStepsDb,
  mockedListBadgeIssuanceRules,
  mockedListBadgeIssuanceRuleRegistryPageDb,
  mockedListBadgeIssuanceRuleBuilderDraftsForUserDb,
  mockedListBadgeIssuanceRuleVersions,
  mockedListBadgeIssuanceRuleVersionsForRules,
  mockedListBadgeTemplateImageRevisionCountsByTenant,
  mockedListBadgeTemplateImageRevisions,
  mockedListBadgeTemplates,
  mockedListPendingBadgeIssuanceRuleApprovalsForActor,
  mockedReopenApprovedBadgeIssuanceRuleVersionDb,
  mockedCountBadgeTemplateImageRevisions,
  mockedSetBadgeTemplateArchivedState,
  mockedSubmitBadgeIssuanceRuleVersionForApprovalDb,
  mockedWithdrawBadgeIssuanceRuleVersionSubmissionDb,
  mockedUpdateBadgeTemplate,
  sampleRuleBadgeTemplate,
  sampleMembership,
} from "./institution-admin-test-utils/rules-test-harness";
import { buildBadgeRuleVersionRecord } from "./test-support/badge-rule-version";
import { app } from "./index";
import { readScriptAssetSource } from "./page-asset-test-utils";
import { pageAssetPath } from "./ui/page-assets";

const INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS = readScriptAssetSource(
  "institutionAdminBadgeTemplateEditorJs",
);
const INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS = readScriptAssetSource(
  "institutionAdminBadgeTemplateListJs",
);
const INSTITUTION_ADMIN_JS = readScriptAssetSource("institutionAdminJs");

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
  versionName: "Snapshot approval rule",
  badgeTemplateId: "badge_template_001",
  badgeTemplateTitle: "TypeScript Foundations",
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
    expect(body).toContain("Test each rule in the builder before saving it.");
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
    expect(body).not.toContain("Check a rule before issuing");
    expect(body).not.toContain("Test a Rule");
    expect(body).not.toContain('id="rule-evaluate-form"');
    expect(INSTITUTION_ADMIN_JS).not.toContain(
      'badgeRuleApiPath + "/" + encodeURIComponent(ruleId) + "/evaluate"',
    );
    expect(body).not.toContain("Approval and Audit History");
    expect(body).not.toContain('id="rule-governance-form"');
    expect(body).not.toContain("ct-grid--sidebar");
    expect(body).toContain("Badge Rules");
    expect(body).toContain("1 shown · 1 matching rule");
    expect(body).toContain('placeholder="Search rules, badges, or LMS"');
    expect(body).toContain('aria-sort="descending"');
    expect(body).toContain("TypeScript Foundations");
    expect(body).not.toContain("Badge unavailable");
    expect(body).toContain("Version 1");
    expect(body).not.toContain("Version ID: brv_123");
    expect(body).not.toContain("v1 (brv_123)");
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/brl_123/versions/brv_123"');
    expect(body).toContain(">View</a>");
    expect(body).toContain("Submit for approval");
    expect(body).toContain(
      "Submit draft version for &quot;CS101 Excellence Rule&quot; for approval? You will not be able to approve it yourself.",
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

  it("renders rule identity and LMS metadata from the selected immutable version", async () => {
    const env = createEnv();
    mockedListBadgeIssuanceRules.mockResolvedValue([
      {
        id: "brl_123",
        tenantId: "tenant_123",
        name: "Mutable parent name",
        description: null,
        badgeTemplateId: "badge_template_current",
        orgUnitId: "tenant_123:org:institution",
        ownerOrgUnitId: "tenant_123:org:institution",
        lmsProviderKind: "canvas",
        lmsConnectionId: "lms_canvas",
        activeVersionId: "brv_active",
        createdByUserId: "usr_admin",
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:30:00.000Z",
      },
    ]);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([
      buildBadgeRuleVersionRecord({
        id: "brv_pending",
        ruleId: "brl_123",
        versionNumber: 2,
        status: "pending_approval",
        ruleJson: '{"conditions":{"type":"course_membership","courseId":"course_202"}}',
        changeSummary: "Pending revision",
        createdByUserId: "usr_author",
        submittedByUserId: "usr_author",
        submittedAt: "2026-02-18T12:20:00.000Z",
        approvedByUserId: null,
        approvedAt: null,
        activatedByUserId: null,
        activatedAt: null,
        snapshot: {
          name: "Pending revision",
          badgeTemplateTitle: "Pending badge",
          lmsProviderKind: "canvas",
        },
        createdAt: "2026-02-18T12:20:00.000Z",
        updatedAt: "2026-02-18T12:20:00.000Z",
      }),
      buildBadgeRuleVersionRecord({
        id: "brv_active",
        ruleId: "brl_123",
        versionNumber: 1,
        status: "active",
        ruleJson: '{"conditions":{"type":"course_membership","courseId":"course_101"}}',
        changeSummary: "Published version",
        createdByUserId: "usr_admin",
        submittedByUserId: "usr_admin",
        submittedAt: "2026-02-18T12:05:00.000Z",
        approvedByUserId: "usr_approver",
        approvedAt: "2026-02-18T12:10:00.000Z",
        activatedByUserId: "usr_admin",
        activatedAt: "2026-02-18T12:15:00.000Z",
        snapshot: {
          name: "Published course rule",
          badgeTemplateTitle: "Published badge",
          lmsProviderKind: "sakai",
        },
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:15:00.000Z",
      }),
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules",
      { headers: { Cookie: "better-auth.session_token=session-token" } },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Published course rule");
    expect(body).toContain("Published badge");
    expect(body).toContain(">Sakai<");
    expect(body).not.toContain("Mutable parent name");
  });

  it("uses the active version snapshot name in lifecycle confirmations", async () => {
    const env = createEnv();
    mockedListBadgeIssuanceRules.mockResolvedValue([
      {
        id: "brl_lifecycle",
        tenantId: "tenant_123",
        name: "Mutable lifecycle head",
        description: null,
        badgeTemplateId: "badge_template_001",
        orgUnitId: "tenant_123:org:institution",
        ownerOrgUnitId: "tenant_123:org:institution",
        lmsProviderKind: "canvas",
        lmsConnectionId: "lms_canvas",
        activeVersionId: "brv_lifecycle",
        createdByUserId: "usr_admin",
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:10:00.000Z",
      },
    ]);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([
      buildBadgeRuleVersionRecord({
        id: "brv_lifecycle",
        ruleId: "brl_lifecycle",
        versionNumber: 1,
        status: "active",
        ruleJson: '{"conditions":{"type":"course_membership","courseId":"course_101"}}',
        changeSummary: null,
        createdByUserId: "usr_admin",
        submittedByUserId: "usr_admin",
        submittedAt: "2026-02-18T12:02:00.000Z",
        approvedByUserId: "usr_approver",
        approvedAt: "2026-02-18T12:05:00.000Z",
        activatedByUserId: "usr_admin",
        activatedAt: "2026-02-18T12:10:00.000Z",
        snapshot: {
          name: "Versioned lifecycle rule",
        },
        recertificationDueAt: "2026-12-01T00:00:00.000Z",
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:10:00.000Z",
      }),
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules",
      { headers: { Cookie: "better-auth.session_token=session-token" } },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Record recertification for &quot;Versioned lifecycle rule&quot;?");
    expect(body).not.toContain("Mutable lifecycle head");
  });

  it("shows each unfinished builder draft with exact edit and delete actions", async () => {
    const env = createEnv();
    mockedListBadgeIssuanceRuleBuilderDraftsForUserDb.mockResolvedValue([
      {
        id: "brd_alpha",
        tenantId: "tenant_123",
        userId: "usr_admin",
        targetKind: "unfinished",
        ruleId: null,
        versionId: null,
        currentStep: "conditions",
        draftJson: JSON.stringify({
          name: "CS pathway draft",
          badgeTemplateId: "badge_template_001",
          lmsConnectionId: "lms_canvas",
        }),
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:05:00.000Z",
      },
      {
        id: "brd_beta",
        tenantId: "tenant_123",
        userId: "usr_admin",
        targetKind: "unfinished",
        ruleId: null,
        versionId: null,
        currentStep: "metadata",
        draftJson: "{}",
        createdAt: "2026-02-18T12:01:00.000Z",
        updatedAt: "2026-02-18T12:04:00.000Z",
      },
    ]);

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
    expect(body).toContain("Your unfinished setups (2)");
    expect(body).toContain("1 shown · 1 matching rule");
    expect(body).toContain("CS pathway draft");
    expect(body).toContain("Untitled rule");
    expect(body).toContain("Setup incomplete");
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/drafts/brd_alpha/edit"');
    expect(body).toContain('action="/tenants/tenant_123/admin/rules/drafts/brd_beta/delete"');
  });

  it("applies registry search, status, sorting, and cursor pagination", async () => {
    const env = createEnv();
    mockedListBadgeIssuanceRuleRegistryPageDb.mockResolvedValueOnce({
      rules: [],
      totalCount: 51,
      previousCursor: null,
      nextCursor: { value: "capstone completion", ruleId: "brl_051", totalCount: 51 },
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules?q=capstone&status=active&sort=rule&direction=asc&limit=25",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(mockedListBadgeIssuanceRuleRegistryPageDb).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        tenantId: "tenant_123",
        searchQuery: "capstone",
        latestStatus: "active",
        sort: "rule",
        direction: "asc",
        limit: 25,
      }),
    );
    expect(body).toContain('value="capstone"');
    expect(body).toContain('value="active" selected');
    expect(body).toContain("51 matching rules");
    expect(body).toContain("No governed rules match these filters.");
    expect(body).toMatch(/href="[^"]*after=[^"]+"[^>]*>\s*Next\s*<\/a>/);
  });

  it("redirects malformed registry controls to the safe default list", async () => {
    const response = await app.request(
      "/tenants/tenant_123/admin/rules?limit=999",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/rules");
    expect(mockedListBadgeIssuanceRuleRegistryPageDb).not.toHaveBeenCalled();
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
      name: string,
      status: BadgeIssuanceRuleVersionRecord["status"],
      versionNumber = 1,
    ): BadgeIssuanceRuleVersionRecord =>
      buildBadgeRuleVersionRecord({
        id: `${ruleId}_v${String(versionNumber)}`,
        ruleId,
        versionNumber,
        status,
        submittedByUserId: status === "draft" ? null : "usr_admin",
        submittedAt: status === "draft" ? null : "2026-02-18T12:05:00.000Z",
        approvedByUserId: status === "approved" ? "usr_admin" : null,
        approvedAt: status === "approved" ? "2026-02-18T12:20:00.000Z" : null,
        activatedByUserId: status === "active" ? "usr_admin" : null,
        activatedAt: status === "active" ? "2026-02-18T12:30:00.000Z" : null,
        snapshot: { name },
      });
    const versionsByRuleId = new Map<string, BadgeIssuanceRuleVersionRecord[]>([
      ["brl_draft", [makeVersion("brl_draft", "Draft cleanup rule", "draft")]],
      ["brl_rejected", [makeVersion("brl_rejected", "Rejected cleanup rule", "rejected")]],
      ["brl_pending", [makeVersion("brl_pending", "Pending protected rule", "pending_approval")]],
      ["brl_approved", [makeVersion("brl_approved", "Approved protected rule", "approved")]],
      ["brl_active", [makeVersion("brl_active", "Active protected rule", "active")]],
      [
        "brl_historical",
        [
          makeVersion("brl_historical", "Historical protected rule", "rejected", 2),
          makeVersion("brl_historical", "Historical protected rule", "active"),
        ],
      ],
      ["brl_incomplete", []],
    ]);

    mockedListBadgeIssuanceRules.mockResolvedValue([
      makeRule("brl_draft", "Draft cleanup rule", null),
      makeRule("brl_rejected", "Rejected cleanup rule", null),
      makeRule("brl_pending", "Pending protected rule", null),
      makeRule("brl_approved", "Approved protected rule", null),
      makeRule("brl_active", "Active protected rule", "brl_active_v1"),
      makeRule("brl_historical", "Historical protected rule", "brl_historical_v1"),
      makeRule("brl_incomplete", "Incomplete cleanup rule", null),
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
    expect(mockedListBadgeIssuanceRuleVersionsForRules).toHaveBeenCalledTimes(1);
    expect(mockedListBadgeIssuanceRuleVersionsForRules).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleIds: [
        "brl_draft",
        "brl_rejected",
        "brl_pending",
        "brl_approved",
        "brl_active",
        "brl_historical",
        "brl_incomplete",
      ],
    });
    expect(body).toContain(
      '<a class="ct-admin__rule-name-link" href="/tenants/tenant_123/admin/rules/brl_draft/versions/brl_draft_v1"><strong>Draft cleanup rule</strong></a>',
    );
    expect(body).toContain(
      '<a class="ct-admin__rule-name-link" href="/tenants/tenant_123/admin/rules/brl_rejected/versions/brl_rejected_v1"><strong>Rejected cleanup rule</strong></a>',
    );
    expect(body).toMatch(
      /class="[^"]*ct-admin__button[^"]*ct-action--quiet[^"]*ct-action--sm[^"]*" href="\/tenants\/tenant_123\/admin\/rules\/brl_draft\/edit"/,
    );
    expect(body).toMatch(
      /class="[^"]*ct-admin__button[^"]*ct-action--quiet[^"]*ct-action--sm[^"]*" href="\/tenants\/tenant_123\/admin\/rules\/brl_rejected\/edit"/,
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
    expect(body).toContain(
      "/tenants/tenant_123/admin/rules/brl_pending/versions/brl_pending_v1/withdraw-submission",
    );
    expect(body).toContain("Withdraw submission");
    expect(body).not.toContain(
      "/tenants/tenant_123/admin/rules/brl_pending/versions/brl_pending_v1/decision",
    );
    expect(body).not.toMatch(/>\s*Approve\s*<\/button>/);
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_approved/edit");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_approved/delete");
    expect(body).toContain(
      "/tenants/tenant_123/admin/rules/approvals/brl_approved/versions/brl_approved_v1",
    );
    expect(body).toContain("Review approval");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_active/edit");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_active/delete");
    expect(body).toContain("/tenants/tenant_123/admin/rules/brl_historical/edit");
    expect(body).not.toContain("/tenants/tenant_123/admin/rules/brl_historical/delete");
    expect(body).toContain("<strong>Incomplete cleanup rule</strong>");
    expect(body).toContain("Setup incomplete");
    expect(body).toContain("No version was created");
    expect(body).toContain("Needs cleanup");
    expect(body).toContain('action="/tenants/tenant_123/admin/rules/brl_incomplete/delete"');
    expect(body).toContain(
      'data-confirm-message="Delete incomplete rule &quot;Incomplete cleanup rule&quot;? This rule has no saved versions and cannot be used for awarding."',
    );
    expect(body).not.toContain('href="/tenants/tenant_123/admin/rules/brl_incomplete"');
  });
});

describe("GET /tenants/:tenantId/admin/rules/approvals", () => {
  it("renders the pending approval queue for the signed-in reviewer", async () => {
    const env = createEnv();

    mockedListPendingBadgeIssuanceRuleApprovalsForActor.mockResolvedValue([
      samplePendingApprovalEntry(),
    ]);
    mockedFindUserById.mockImplementation(async (_db, userId) => ({
      id: userId,
      email: userId === "usr_author" ? "author@example.edu" : "admin@tenant-123.edu",
    }));

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
    expect(body).toContain("Snapshot approval rule");
    expect(body).not.toContain("Mutable approval rule head");
    expect(body).toContain("Computer Science");
    expect(body).toContain("Department approval");
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval"',
    );
    expect(body).not.toContain(pageAssetPath("institutionAdminRuleVersionCss"));
    expect(body).not.toContain(pageAssetPath("institutionAdminRuleVersionJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminRuleApprovalReviewCss"));
    expect(body).not.toContain(pageAssetPath("institutionAdminRuleApprovalReviewJs"));
  });
});

describe("GET /tenants/:tenantId/admin/rules/approvals/:ruleId/versions/:versionId", () => {
  it("offers live LMS impact as an explicit reviewer action", async () => {
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
    const baseVersion = buildBadgeRuleVersionRecord({
      id: "brv_base",
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
      snapshot: {
        name: "CS101 Excellence Rule",
        description: "Issue badge for CS101 completion and grade threshold.",
        badgeTemplateTitle: "TypeScript Foundations",
        badgeTemplateImageUri: "https://example.edu/badges/typescript.png",
        lmsConnectionId: "lms_canvas",
      },
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:12:00.000Z",
    });
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
      snapshot: {
        ...baseVersion.snapshot,
        name: "CS101 Excellence Rule — revised",
        badgeTemplateId: "badge_template_002",
        badgeTemplateTitle: "CS101 Distinction Badge",
        orgUnitId: "tenant_123:org:registrar",
        lmsProviderKind: "sakai",
        lmsConnectionId: "lms_sakai",
      },
      updatedAt: "2026-02-18T12:20:00.000Z",
    };

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(rule);
    mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValue(pendingVersion);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([baseVersion, pendingVersion]);
    mockedFindUserById.mockImplementation(async (_db, userId) => ({
      id: userId,
      email: userId === "usr_author" ? "author@example.edu" : "admin@tenant-123.edu",
    }));
    mockedFindBadgeTemplateById.mockResolvedValue(sampleRuleBadgeTemplate);
    mockedListBadgeIssuanceRuleVersionApprovalStepsDb.mockResolvedValue([
      samplePendingApprovalStep(),
    ]);
    mockedListBadgeIssuanceRuleVersionApprovalEvents.mockResolvedValue([
      {
        id: "brae_submitted",
        tenantId: "tenant_123",
        versionId: "brv_approval",
        stepNumber: 1,
        action: "submitted",
        actorUserId: "usr_author",
        actorRole: "issuer",
        comment: "Ready for review.",
        occurredAt: "2026-02-18T12:15:00.000Z",
        createdAt: "2026-02-18T12:15:00.000Z",
      },
    ]);
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
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("What this version requires");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("https://example.edu/badges/typescript.png");
    expect(body).not.toContain("Review summary");
    expect(body).toContain("Submitted by");
    expect(body).toContain("author@example.edu");
    expect(body).toContain("What changed");
    expect(body).toContain("Rule settings");
    expect(body).toContain("Before");
    expect(body).toContain("Now");
    expect(body).toContain("CS101 Excellence Rule — revised");
    expect(body).toContain("CS101 Distinction Badge (badge_template_002)");
    expect(body).toContain("tenant_123:org:registrar");
    expect(body).toContain("Sakai");
    expect(body).toContain("lms_sakai");
    expect(body).toContain("Earning requirements");
    expect(body).toContain("Loosens requirements");
    expect(body).toContain("Minimum grade lowered from 90% to 80%.");
    expect(body).toContain("Learner impact");
    expect(body).toContain("Check learner impact");
    expect(body).toContain("This reads current LMS data and may take a moment.");
    expect(body).toContain("Approval makes it eligible for activation; it does not replace");
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval/impact-preview"',
    );
    expect(body).not.toContain("No LMS course placement is linked to this rule yet.");
    expect(body).toContain("Approval progress");
    expect(body).toContain("Show full audit history (1 event)");
    expect(body).toContain('data-rule-version-navigation=""');
    expect(body).toContain('action="/tenants/tenant_123/admin/rules/approvals/brl_approval"');
    expect(body).toContain(
      'data-version-url="/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_base"',
    );
    expect(body).toContain(
      'data-version-url="/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval"',
    );
    expect(body).toContain(pageAssetPath("institutionAdminRuleVersionCss"));
    expect(body).toContain(pageAssetPath("institutionAdminRuleVersionJs"));
    expect(body).toContain(pageAssetPath("institutionAdminRuleApprovalReviewCss"));
    expect(body).toContain(pageAssetPath("institutionAdminRuleApprovalReviewJs"));
    expect(body).toContain("Department approval");
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval/decision"',
    );
    expect(body).not.toContain('name="returnTo"');
    expect(body).toContain('value="approved"');
    expect(body).toContain('value="changes_requested"');
    expect(body).toContain('value="rejected"');
    expect(body).toContain("Approve version");
    expect(body).toContain("Return for changes");
    expect(body).toContain("Reject version");
    expect(body).toContain("Record decision");
    expect(body).toContain('data-rule-review-decision-form=""');
    expect(body).toContain(
      'data-rule-review-comment-required-decisions="rejected changes_requested"',
    );
    expect(body).toContain('data-rule-review-comment=""');
  });

  it("redirects a server-rendered version selection within the approval workspace", async () => {
    const response = await app.request(
      "/tenants/tenant_123/admin/rules/approvals/brl_approval?versionId=brv_base",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_base",
    );
  });

  it("lets the final approver reopen an approved version before activation", async () => {
    const env = createEnv();
    mockedFindTenantMembership.mockResolvedValue(sampleMembership("approver"));
    const rule: BadgeIssuanceRuleRecord = {
      id: "brl_approval",
      tenantId: "tenant_123",
      name: "CS101 Excellence Rule",
      description: null,
      badgeTemplateId: "badge_template_001",
      orgUnitId: "tenant_123:org:cs",
      ownerOrgUnitId: "tenant_123:org:cs",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_canvas",
      activeVersionId: null,
      createdByUserId: "usr_author",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:20:00.000Z",
    };
    const approvedVersion = buildBadgeRuleVersionRecord({
      id: "brv_approval",
      ruleId: "brl_approval",
      versionNumber: 2,
      status: "approved",
      ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"CS101","minScore":80}}',
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
    });

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(rule);
    mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValue(approvedVersion);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([approvedVersion]);
    mockedFindBadgeTemplateById.mockResolvedValue(sampleRuleBadgeTemplate);
    mockedListBadgeIssuanceRuleVersionApprovalStepsDb.mockResolvedValue([
      {
        ...samplePendingApprovalStep(),
        status: "approved",
        decidedByUserId: "usr_admin",
        decidedAt: "2026-02-18T12:20:00.000Z",
      },
    ]);
    mockedListBadgeIssuanceRuleVersionApprovalEvents.mockResolvedValue([]);

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
    expect(body).toContain("Correct this approval");
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval/reopen"',
    );
    expect(body).toContain('name="comment"');
    expect(body).toContain("Reopen as draft");
    expect(body).not.toContain('name="decision" value="approved"');
  });

  it("blocks unassigned review URLs without consuming the approval flash", async () => {
    const env = createEnv();
    const flashApp = new Hono<AppEnv>();
    flashApp.get("/flash", async (c) => {
      await setAdminListMessageFlash(c, {
        tenantId: "tenant_123",
        userId: "usr_admin",
        workspace: "rule_approvals",
        tone: "success",
        message: "Previous approval saved.",
      });
      return c.body(null, 204);
    });
    const flashResponse = await flashApp.request("https://credtrail.test/flash", {}, env);
    const flashCookie = adminFlashCookieHeader(flashResponse);
    expect(flashCookie).toContain("ct_admin_flash_list_message_tenant_123");
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
      activeVersionId: null,
      createdByUserId: "usr_author",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    };
    const pendingVersion = buildBadgeRuleVersionRecord({
      id: "brv_approval",
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
    });

    mockedFindTenantMembership.mockResolvedValue(sampleMembership("approver"));
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(rule);
    mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValue(pendingVersion);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([pendingVersion]);
    mockedFindBadgeTemplateById.mockResolvedValue(sampleRuleBadgeTemplate);
    mockedListBadgeIssuanceRuleVersionApprovalStepsDb.mockResolvedValue([
      {
        ...samplePendingApprovalStep(),
        targetType: "user",
        requiredRole: null,
        targetUserId: "usr_registrar",
        targetApproverGroupId: null,
      },
    ]);

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval",
      {
        headers: {
          Cookie: `better-auth.session_token=session-token; ${flashCookie}`,
        },
      },
      env,
    );

    expect(response.status).toBe(403);
    expect(adminFlashCookieHeader(response)).not.toContain(
      "ct_admin_flash_list_message_tenant_123",
    );
    expect(mockedFindLtiResourceLinkPlacementForRule).not.toHaveBeenCalled();
  });
});

describe("POST /tenants/:tenantId/admin/rules/approvals/:ruleId/versions/:versionId/impact-preview", () => {
  it("refreshes the live LMS impact preview on reviewer request", async () => {
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
    const pendingVersion = buildBadgeRuleVersionRecord({
      id: "brv_approval",
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
    });

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(rule);
    mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValue(pendingVersion);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([pendingVersion]);
    mockedFindBadgeTemplateById.mockResolvedValue(sampleRuleBadgeTemplate);
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
    const draftVersion = buildBadgeRuleVersionRecord();
    const pendingVersion: BadgeIssuanceRuleVersionRecord = {
      ...draftVersion,
      status: "pending_approval",
    };

    mockedFindBadgeIssuanceRuleVersionByIdDb.mockResolvedValue(draftVersion);
    mockedSubmitBadgeIssuanceRuleVersionForApprovalDb.mockResolvedValue({
      status: "submitted",
      version: pendingVersion,
      pendingStepNumber: 1,
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
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/rules");
    expect(mockedSubmitBadgeIssuanceRuleVersionForApprovalDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
      actorUserId: "usr_admin",
      actorRole: "admin",
    });
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

    expect(flashResponse.status).toBe(200);
    expect(flashBody).toContain("Rule version submitted for approval.");
  });

  it("shows the policy-approved activation step when submission does not require approval", async () => {
    const env = createEnv();
    const draftVersion = buildBadgeRuleVersionRecord();
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
      pendingStepNumber: null,
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
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(mockedDecideBadgeIssuanceRuleVersionDb).not.toHaveBeenCalled();
    expect(mockedEnqueueJobQueueMessageOnce).not.toHaveBeenCalled();
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
    const deletedVersion = buildBadgeRuleVersionRecord({
      id: "brv_draft",
      ruleId: "brl_draft",
    });

    mockedDeleteNeverActiveBadgeIssuanceRuleDb.mockResolvedValue({
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
    expect(mockedDeleteNeverActiveBadgeIssuanceRuleDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_draft",
      actorUserId: "usr_admin",
      actorRole: "admin",
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
    expect(flashBody).toContain("Rule deleted.");
  });

  it("blocks delete attempts for protected rules and shows an error flash", async () => {
    const env = createEnv();
    mockedDeleteNeverActiveBadgeIssuanceRuleDb.mockResolvedValue({
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
        buildBadgeRuleVersionRecord({
          id: "brv_active",
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
          updatedAt: "2026-02-18T12:30:00.000Z",
        }),
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
    expect(flashBody).toContain(
      "Only incomplete or never-active draft or rejected rules can be deleted.",
    );
  });
});

describe("POST /tenants/:tenantId/admin/rules/drafts/:draftId/delete", () => {
  it("deletes only the unfinished draft named by the route", async () => {
    const env = createEnv();
    mockedDeleteBadgeIssuanceRuleBuilderDraftByIdDb.mockResolvedValue({
      id: "brd_exact",
      tenantId: "tenant_123",
      userId: "usr_admin",
      targetKind: "unfinished",
      ruleId: null,
      versionId: null,
      currentStep: "metadata",
      draftJson: "{}",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/drafts/brd_exact/delete",
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
    expect(mockedDeleteBadgeIssuanceRuleBuilderDraftByIdDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      userId: "usr_admin",
      draftId: "brd_exact",
    });
    expect(mockedCreateAuditLogDb).toHaveBeenCalledWith(
      fakeDb,
      expect.objectContaining({
        action: "badge_rule.builder_draft_deleted",
        targetId: "brd_exact",
      }),
    );
  });
});

describe("POST /tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/withdraw-submission", () => {
  it("returns the submitter's pending version to draft", async () => {
    const env = createEnv();
    mockedWithdrawBadgeIssuanceRuleVersionSubmissionDb.mockResolvedValue({
      status: "withdrawn",
      version: buildBadgeRuleVersionRecord({
        id: "brv_approval",
        ruleId: "brl_approval",
        versionNumber: 2,
        status: "draft",
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        changeSummary: "Lower threshold",
        createdByUserId: "usr_admin",
        submittedByUserId: null,
        submittedAt: null,
        approvedByUserId: null,
        approvedAt: null,
        activatedByUserId: null,
        activatedAt: null,
        updatedAt: "2026-02-18T12:20:00.000Z",
      }),
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/brl_approval/versions/brv_approval/withdraw-submission",
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
    expect(mockedWithdrawBadgeIssuanceRuleVersionSubmissionDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_approval",
      versionId: "brv_approval",
      actorUserId: "usr_admin",
      actorRole: "admin",
    });
  });
});

describe("POST /tenants/:tenantId/admin/rules/approvals/:ruleId/versions/:versionId/reopen", () => {
  it("reopens an approved version with an audit reason", async () => {
    const env = createEnv();
    mockedFindTenantMembership.mockResolvedValue(sampleMembership("approver"));
    mockedReopenApprovedBadgeIssuanceRuleVersionDb.mockResolvedValue({
      status: "reopened",
      version: buildBadgeRuleVersionRecord({
        id: "brv_approval",
        ruleId: "brl_approval",
        versionNumber: 2,
        status: "draft",
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
        changeSummary: "Lower threshold",
        createdByUserId: "usr_author",
        submittedByUserId: null,
        submittedAt: null,
        approvedByUserId: null,
        approvedAt: null,
        activatedByUserId: null,
        activatedAt: null,
        updatedAt: "2026-02-18T12:20:00.000Z",
      }),
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/approvals/brl_approval/versions/brv_approval/reopen",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          comment: "Approved before checking the threshold.",
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/rules/approvals");
    expect(mockedReopenApprovedBadgeIssuanceRuleVersionDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_approval",
      versionId: "brv_approval",
      actorUserId: "usr_admin",
      actorRole: "approver",
      comment: "Approved before checking the threshold.",
    });
  });
});

describe("POST /tenants/:tenantId/admin/rules/approvals/:ruleId/versions/:versionId/decision", () => {
  it("reports an overlong reviewer comment instead of misclassifying the decision", async () => {
    const env = createEnv();
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
          decision: "rejected",
          comment: "x".repeat(2001),
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(mockedDecideBadgeIssuanceRuleVersionDb).not.toHaveBeenCalled();

    const flashResponse = await app.request(
      "/tenants/tenant_123/admin/rules/approvals",
      {
        headers: {
          Cookie: `better-auth.session_token=session-token; ${adminFlashCookieHeader(response)}`,
        },
      },
      env,
    );

    expect(await flashResponse.text()).toContain(
      "Keep the reviewer comment to 2,000 characters or fewer.",
    );
  });

  it("allows an assigned approver role to post a review workspace decision", async () => {
    mockedFindTenantMembership.mockResolvedValue(sampleMembership("approver"));
    const env = createEnv();
    const approvedVersion = buildBadgeRuleVersionRecord({
      id: "brv_approval",
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
      updatedAt: "2026-02-18T12:20:00.000Z",
    });

    mockedDecideBadgeIssuanceRuleVersionDb.mockResolvedValue({
      status: "decided",
      version: approvedVersion,
      decidedStepNumber: 1,
      nextStepNumber: null,
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
        }).toString(),
      },
      env,
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(mockedDecideBadgeIssuanceRuleVersionDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_approval",
      versionId: "brv_approval",
      decision: "approved",
      actorUserId: "usr_admin",
      actorRole: "approver",
    });
  });

  it("decides from the review workspace and redirects back to that review page", async () => {
    const env = createEnv();
    const approvedVersion = buildBadgeRuleVersionRecord({
      id: "brv_approval",
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
      updatedAt: "2026-02-18T12:20:00.000Z",
    });

    mockedDecideBadgeIssuanceRuleVersionDb.mockResolvedValue({
      status: "decided",
      version: approvedVersion,
      decidedStepNumber: 1,
      nextStepNumber: null,
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
    expect(response.headers.get("cache-control")).toBe("no-store");
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
    expect(body).toContain("New badge template");
    expect(body).toContain("Create badge template");
    expect(body).toContain(
      "Start with the badge name. CredTrail opens artwork setup after creation.",
    );
    expect(body).toContain(">Badge name<");
    expect(body).toContain("Create and add artwork");
    expect(body).toContain('id="template-create-panel"');
    expect(body).toContain('class="ct-admin__inline-action-panel"');
    expect(body).toContain('aria-controls="template-create-panel"');
    expect(body).toContain('data-admin-inline-panel-trigger="template-create-panel"');
    expect(body).toContain('data-admin-inline-panel-close="template-create-panel"');
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
    expect(body).not.toContain("Open form");
    expect(body).not.toContain("Hide form");
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
    expect(body).toContain(
      'href="https://credtrail.test/badges/assets/tenant_123/badge_template_001/asset_typescript"',
    );
    expect(body).toContain("New badge template");
    expect(body).not.toContain("Open form");
    expect(body).not.toContain("Hide form");
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
      governanceMetadataJson: JSON.stringify({
        stability: "institution_registry",
        ltiInstructorPlacement: { enabled: true },
      }),
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
    expect(body).toContain("Needs managed image");
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
    expect(body).toContain('id="template-editor-lms-placement"');
    expect(body).toContain("LMS placement");
    expect(body).toContain("Allow instructors to place this template from an LMS course");
    expect(body).toContain('name="ltiInstructorPlacement"');
    expect(body).toContain('value="enabled"');
    expect(body).toContain('aria-describedby="badge-template-placement-hint"');
    expect(body).toMatch(/name="ltiInstructorPlacement"[^>]*checked=""/);
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/rules/templates/badge_template_001/lti-placement-policy"',
    );
    expect(body).toContain("Save LMS placement policy");
    expect(body).toContain("Turning this off prevents new placements");
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
    expect(body).toContain("This image is used for future issuance and future rule versions.");
    expect(body).toContain("Current artwork");
    expect(body).toContain("Needs managed image");
    expect(body).toContain(
      "Replace this image with artwork uploaded or generated in CredTrail before using the template in rules.",
    );
    expect(body).toContain("Replace artwork");
    expect(body).toContain("Upload an approved image or generate a draft to review.");
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

  it("keeps the badge template editor available when artwork storage cannot be checked", async () => {
    const env = createEnv();
    env.BADGE_OBJECTS = {
      get: async () => {
        throw new Error("temporary object storage outage");
      },
    } as unknown as R2Bucket;
    mockedFindBadgeTemplateById.mockResolvedValue({
      id: "badge_template_001",
      tenantId: "tenant_123",
      slug: "typescript-foundations",
      title: "TypeScript Foundations",
      description: "Awarded for TypeScript basics.",
      criteriaUri: "https://example.edu/criteria",
      imageUri:
        "https://credtrail.test/badges/assets/tenant_123/badge_template_001/asset_typescript",
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
    expect(body).toContain("Image check unavailable");
    expect(body).toContain("Check unavailable");
    expect(body).toContain(
      "CredTrail cannot check the stored image right now. Try again before replacing it.",
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
