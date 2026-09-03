import type { BadgeIssuanceRuleRecord, BadgeIssuanceRuleVersionRecord } from "@credtrail/db";
import { describe, expect, it } from "vitest";
import {
  createEnv,
  mockedFindBadgeIssuanceRuleBuilderDraftDb,
  mockedListAccessibleTenantContextsForUser,
  mockedListBadgeIssuanceRules,
  mockedListBadgeIssuanceRuleVersions,
  mockedListBadgeTemplates,
  mockedListTenantLmsConnectionsDb,
} from "./institution-admin-test-utils/rules-test-harness";
import { buildBadgeRuleVersionRecord } from "./test-support/badge-rule-version";
import { app } from "./index";
import { pageAssetPath } from "./ui/page-assets";

const requestRuleBuilder = (env: ReturnType<typeof createEnv>, query = ""): Promise<Response> => {
  return Promise.resolve(
    app.request(
      `/tenants/tenant_123/admin/rules/new${query}`,
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    ),
  );
};

const copySourceRule = (): BadgeIssuanceRuleRecord => ({
  id: "brl_copy",
  tenantId: "tenant_123",
  name: "Mutable rule head",
  description: null,
  badgeTemplateId: "mutable_template_head",
  orgUnitId: "tenant_123:org:institution",
  ownerOrgUnitId: "tenant_123:org:institution",
  lmsProviderKind: "canvas",
  lmsConnectionId: "lms_canvas",
  activeVersionId: null,
  createdByUserId: "usr_admin",
  createdAt: "2026-02-18T12:00:00.000Z",
  updatedAt: "2026-02-18T12:10:00.000Z",
});

const copySourceVersion = (
  overrides: Partial<BadgeIssuanceRuleVersionRecord> = {},
): BadgeIssuanceRuleVersionRecord =>
  buildBadgeRuleVersionRecord({
    id: "brv_copy",
    ruleId: "brl_copy",
    versionNumber: 3,
    status: "draft",
    ruleJson: JSON.stringify({
      conditions: {
        all: [
          { type: "course_completion", courseId: "course_101", minCompletionPercent: 100 },
          { type: "grade_threshold", courseId: "course_101", minScore: 85 },
        ],
      },
      options: { issuanceTiming: "end_of_term", reviewOnMissingFacts: true },
    }),
    changeSummary: "Source governance history",
    snapshot: {
      name: "Versioned copy source",
      description: "Immutable version description",
      badgeTemplateId: "badge_template_001",
      lmsConnectionId: "lms_canvas",
    },
    ...overrides,
  });

describe("rule-builder badge template availability", () => {
  it("keeps templates without canonical managed artwork out of the picker", async () => {
    mockedListBadgeTemplates.mockResolvedValue([
      {
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
      {
        id: "badge_template_003",
        tenantId: "tenant_123",
        slug: "old-host-artwork",
        title: "Old Host Artwork",
        description: "Uses the right path on the wrong public host.",
        criteriaUri: null,
        imageUri:
          "https://old-host.example/badges/assets/tenant_123/badge_template_003/asset_old_host",
        createdByUserId: "usr_admin",
        ownerOrgUnitId: "tenant_123:org:institution",
        governanceMetadataJson: null,
        isArchived: false,
        createdAt: "2026-02-18T12:00:00.000Z",
        updatedAt: "2026-02-18T12:00:00.000Z",
      },
    ]);

    const response = await requestRuleBuilder(createEnv(), "?badgeTemplateId=badge_template_002");
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).not.toContain('value="badge_template_002"');
    expect(body).not.toContain('value="badge_template_003"');
    expect(body).toMatch(
      /<option[^>]*value="badge_template_001"[^>]*>TypeScript Foundations[^<]*<\/option>/,
    );
    expect(body).toContain("2 badge templates need artwork.");
    expect(body).toContain("Add artwork in Badge Templates");
  });

  it("renders managed templates without loading stored image bodies", async () => {
    const env = createEnv();
    env.BADGE_OBJECTS = {
      get: async () => {
        throw new Error("The rule builder must not load badge image objects");
      },
    } as unknown as R2Bucket;

    const response = await requestRuleBuilder(env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toMatch(
      /<option[^>]*value="badge_template_001"[^>]*>TypeScript Foundations[^<]*<\/option>/,
    );
    expect(body).not.toContain("could not verify badge artwork");
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

  it("renders the three-step authoring workflow", async () => {
    const response = await requestRuleBuilder(createEnv());
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("Badge Awarding Rule");
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
    expect(body).toContain(pageAssetPath("institutionAdminRuleBuilderJs"));
    expect(body).toContain('aria-label="Rule builder steps"');
    expect(body).toContain('data-rule-step-target="metadata"');
    expect(body).toContain('data-rule-step-target="conditions"');
    expect(body).toContain('data-rule-step-target="test"');
    expect(body).not.toContain('data-rule-step-target="review"');
    expect(body).toContain("Step 1 of 3");
    expect(body).toContain("Test and submit");
    expect(body).toMatch(
      /data-rule-step-row="test"[\s\S]*?<\/ol>[\s\S]*?id="rule-builder-step-footer"[\s\S]*?id="rule-builder-step-next"/,
    );
    expect(body).toMatch(
      /id="rule-builder-submit"[^>]*name="action"[^>]*value="submit_for_approval"/,
    );
    expect(body).toMatch(
      /id="rule-builder-save-formal-draft"[^>]*name="action"[^>]*value="save_draft"/,
    );
    expect(body).toMatch(/id="rule-builder-submit"[^>]*hidden/);
    expect(body).toMatch(/id="rule-builder-save-formal-draft"[^>]*hidden/);
    expect(body).not.toMatch(/id="rule-builder-step-next"[^>]*hidden/);
  });

  it("makes learner testing explicit and non-issuing", async () => {
    const response = await requestRuleBuilder(createEnv());
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('name="testDataSource"');
    expect(body).toContain("A learner in the selected LMS");
    expect(body).toContain("Generated example data");
    expect(body).toContain("Learner to test");
    expect(body).toContain('id="rule-builder-learner-select"');
    expect(body).toContain('id="rule-builder-learner-filter-query"');
    expect(body).toContain("This roster is too large for one list. Search to narrow it.");
    expect(body).toContain("Testing never issues a badge.");
    expect(body).not.toContain("Credential recipient email");
    expect(body).not.toContain("Sample course ID");
    expect(body).not.toContain('name="testCourseId"');
    expect(body).not.toContain('id="rule-builder-test-preset"');
    expect(body).not.toContain("Historical simulation");
    expect(body).toMatch(
      /id="rule-builder-example-score-field"[^>]*hidden[\s\S]*?id="rule-builder-example-score"[^>]*disabled[^>]*aria-describedby="rule-builder-example-score-hint"/,
    );
    expect(body).toMatch(
      /id="rule-builder-example-completion-field"[^>]*hidden[\s\S]*?id="rule-builder-example-completion"[^>]*disabled[^>]*aria-describedby="rule-builder-example-completion-hint"/,
    );
    expect(body).toContain('id="rule-builder-example-test-guidance"');
    expect(body).toContain('aria-live="polite"');
    expect(body).toContain('data-rule-builder-example-control="score"');
    expect(body).toContain('data-rule-builder-example-control="completion"');
  });

  it("asks for workflow decisions without exposing schema-oriented setup", async () => {
    const response = await requestRuleBuilder(createEnv());
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Choose the badge, LMS connection, and how learners earn it");
    expect(body).toContain("Each requirement describes what a learner must do.");
    expect(body).toContain("Exclude learners who match this requirement");
    expect(body).toContain("Advanced JSON tools");
    expect(body).toContain("Canvas Test (Canvas)");
    expect(body).not.toContain('id="rule-builder-lms-status"');
    expect(body).not.toContain("Update LMS connection");
    expect(body).toContain("Choose a badge template");
    expect(body).toMatch(
      /id="rule-builder-badge-template-fallback-field"[\s\S]*?id="rule-builder-badge-template-select"[^>]*name="badgeTemplateId"[^>]*required/,
    );
    expect(body).toMatch(/id="rule-builder-badge-template-enhanced-field"[^>]*hidden/);
    expect(body).toMatch(
      /<label[^>]*for="rule-builder-badge-template-combobox"[^>]*>[\s\S]*?Badge template[\s\S]*?<\/label>/,
    );
    expect(body).toMatch(
      /id="rule-builder-badge-template-combobox"[^>]*role="combobox"[^>]*aria-autocomplete="list"[^>]*aria-controls="rule-builder-badge-template-listbox"[^>]*aria-expanded="false"/,
    );
    expect(body).toMatch(/id="rule-builder-badge-template-listbox"[^>]*role="listbox"[^>]*hidden/);
    expect(body).toContain('data-template-title="TypeScript Foundations"');
    expect(body).toContain('placeholder="Search badge templates"');
    expect(body).not.toContain("Find a badge " + "template");
    expect(body).not.toContain("Search by badge " + "name");
    expect(body).toContain("badge template ready for rules, A to Z.");
    expect(body).toContain("used by 1 other rule");
    expect(body).toContain("I confirm this rule is another valid way to earn the same badge.");
    expect(body).not.toMatch(/value="badge_template_001"[^>]*selected/);
    expect(body).not.toContain("Copy existing rule " + "settings");
    expect(body).not.toContain('id="rule-builder-clone-' + 'rule"');
    expect(body).toContain("Edit requirement details");
    expect(body).toContain("Import and export");
    expect(body).toContain("Requirement catalog");
    expect(body).not.toContain("Reusable course list");
    expect(body).not.toContain("Reviewer roles (optional)");
    expect(body).not.toContain("Start from a proven pattern");
    expect(body).not.toContain("Authoring approach");
  });

  it("shows LMS setup guidance only when the builder has no usable connection", async () => {
    mockedListTenantLmsConnectionsDb.mockResolvedValue([]);

    const response = await requestRuleBuilder(createEnv());
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Create an LMS connection before building rules.");
    expect(body).toContain("Create LMS connection");
    expect(body).not.toContain('id="rule-builder-lms-status"');
  });

  it("keeps navigation and unfinished-work recovery in the builder context", async () => {
    const response = await requestRuleBuilder(createEnv());
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('href="/tenants/tenant_123/admin/rules"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/templates"');
    expect(body).toMatch(
      /<details class="ct-admin-sidebar__group-details"[^>]*open[\s\S]*?Badge Program[\s\S]*?Templates[\s\S]*?Rules/,
    );
    expect(body).not.toContain('class="ct-admin-sidebar__link-label">New Rule</span>');
    expect(body).toContain("&quot;rulesListPath&quot;:&quot;/tenants/tenant_123/admin/rules&quot;");
    expect(body).toContain('id="rule-builder-save-draft"');
    expect(body).toContain("Save unfinished work");
    expect(body).toContain("Unfinished work not saved yet.");
    expect(body).toMatch(
      /&quot;badgeRuleBuilderDraftApiPath&quot;:&quot;\/v1\/tenants\/tenant_123\/badge-rule-builder-drafts\/brd_[^&]+&quot;/,
    );
    expect(body).toMatch(
      /&quot;badgeRuleAuthoringResultApiPath&quot;:&quot;\/v1\/tenants\/tenant_123\/badge-rule-authoring-results\/brd_[^&]+&quot;/,
    );
    expect(mockedFindBadgeIssuanceRuleBuilderDraftDb).not.toHaveBeenCalled();
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

  it("prefills a separate rule from the latest immutable source version", async () => {
    const env = createEnv();
    mockedListBadgeIssuanceRules.mockResolvedValue([copySourceRule()]);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([copySourceVersion()]);

    const response = await requestRuleBuilder(env, "?copyRuleId=brl_copy");
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Copy Badge Awarding Rule");
    expect(body).toContain("Creating a new rule from Versioned copy source.");
    expect(body).toContain('name="name" type="hidden" value="Copy of Versioned copy source"');
    expect(body).toContain('data-rule-builder-preserve-name="true"');
    expect(body).toContain('name="description" type="text" value="Immutable version description"');
    expect(body).toMatch(/value="badge_template_001"[^>]*selected/);
    expect(body).toMatch(/value="lms_canvas"[^>]*selected/);
    expect(body).toContain("&quot;issuanceTiming&quot;:&quot;end_of_term&quot;");
    expect(body).toContain("&quot;reviewOnMissingFacts&quot;:true");
    expect(body).toContain("\\&quot;minScore\\&quot;:85");
    expect(body).toContain("&quot;changeSummary&quot;:&quot;&quot;");
    expect(body).toContain("&quot;lastTestSummary&quot;:&quot;&quot;");
    expect(body).not.toContain("Mutable rule head");
    expect(body).not.toContain("brv_copy");
    expect(body).not.toContain("Source governance history");
    expect(body).not.toContain("Copy existing rule " + "settings");
  });

  it("redirects unavailable, versionless, and cross-tenant copy sources to the rule list", async () => {
    const missing = await requestRuleBuilder(createEnv(), "?copyRuleId=brl_missing");
    expect(missing.status).toBe(303);
    expect(missing.headers.get("location")).toBe("/tenants/tenant_123/admin/rules");
    expect(missing.headers.get("set-cookie")).toContain("admin_flash");

    mockedListBadgeIssuanceRules.mockResolvedValue([copySourceRule()]);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([]);
    const versionless = await requestRuleBuilder(createEnv(), "?copyRuleId=brl_copy");
    expect(versionless.status).toBe(303);
    expect(versionless.headers.get("location")).toBe("/tenants/tenant_123/admin/rules");

    const crossTenant = await requestRuleBuilder(createEnv(), "?copyRuleId=brl_other_tenant");
    expect(crossTenant.status).toBe(303);
    expect(crossTenant.headers.get("location")).toBe("/tenants/tenant_123/admin/rules");
  });

  it("rejects copy sources with invalid definitions or unavailable dependencies", async () => {
    mockedListBadgeIssuanceRules.mockResolvedValue([copySourceRule()]);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([
      copySourceVersion({ ruleJson: '{"conditions":{"type":"unknown"}}' }),
    ]);
    const invalidDefinition = await requestRuleBuilder(createEnv(), "?copyRuleId=brl_copy");
    expect(invalidDefinition.status).toBe(303);

    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([
      copySourceVersion({
        snapshot: {
          ...copySourceVersion().snapshot,
          badgeTemplateId: "badge_template_unavailable",
        },
      }),
    ]);
    const unavailableTemplate = await requestRuleBuilder(createEnv(), "?copyRuleId=brl_copy");
    expect(unavailableTemplate.status).toBe(303);

    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([
      copySourceVersion({
        snapshot: {
          ...copySourceVersion().snapshot,
          lmsConnectionId: "lms_unavailable",
        },
      }),
    ]);
    const unavailableConnection = await requestRuleBuilder(createEnv(), "?copyRuleId=brl_copy");
    expect(unavailableConnection.status).toBe(303);
  });

  it("redirects malformed rule-builder query values", async () => {
    const response = await requestRuleBuilder(createEnv(), "?copyRuleId=not%20valid");

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/tenants/tenant_123/admin/rules");
  });
});
