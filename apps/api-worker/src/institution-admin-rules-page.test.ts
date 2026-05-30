import { describe, expect, it } from "vitest";
import {
  createEnv,
  fakeDb,
  mockedFindBadgeTemplateById,
  mockedFindBadgeTemplateImageRevisionById,
  mockedListAccessibleTenantContextsForUser,
  mockedListBadgeTemplateImageRevisionCountsByTenant,
  mockedListBadgeTemplateImageRevisions,
  mockedListBadgeTemplates,
  mockedCountBadgeTemplateImageRevisions,
  mockedSetBadgeTemplateArchivedState,
  mockedUpdateBadgeTemplate,
} from "./institution-admin-page-test-utils";
import { app } from "./index";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS } from "./ui/page-assets/content/institution-admin-badge-template-editor-js";
import { INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS } from "./ui/page-assets/content/institution-admin-badge-template-list-js";
import { INSTITUTION_ADMIN_JS } from "./ui/page-assets/content/institution-admin-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_JS } from "./ui/page-assets/content/institution-admin-rule-builder-js";
import { pageAssetPath } from "./ui/page-assets";

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
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/new"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/templates"');
    expect(body).toMatch(/>\s*Manage badge templates\s*<\/a>/);
    expect(body).toContain("Advanced rule tools");
    expect(body).not.toContain("Create Badge Template");
    expect(body).not.toContain('id="badge-template-create-form"');
    expect(body).not.toContain("Manage Badge Template Images");
    expect(body).not.toContain('id="badge-template-image-upload-form"');
    expect(body).toContain("Rule Value Lists");
    expect(body).toContain(
      "Rule value lists are reusable sets of course IDs or badge-template IDs for rule conditions.",
    );
    expect(body).toContain("They do not create badge templates.");
    expect(body).toContain('id="rule-value-list-form"');
    expect(body).toContain("Evaluate Rule");
    expect(body).toContain('id="rule-evaluate-form"');
    expect(body).toContain("Rule Governance Context");
    expect(body).not.toContain("ct-grid--sidebar");
    expect(body).toContain("Badge Rules (1)");
    expect(body).toContain("Version 1");
    expect(body).toContain("Version ID: brv_123");
    expect(body).not.toContain("v1 (brv_123)");
    expect(body).toContain("Mark ready");
    expect(INSTITUTION_ADMIN_JS).toContain("This does not activate the rule.");
    expect(INSTITUTION_ADMIN_JS).toContain("Draft is ready for review. It is not active yet.");
    expect(body).not.toContain("Badge Templates (1)");
    expect(body).not.toContain("Create Tenant API Key");
    expect(body).not.toContain("Issued Badges Ledger");
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
    expect(body).toContain('class="ct-admin__template-actions"');
    expect(body).toContain(
      'class="ct-admin__button ct-admin__button--tiny ct-admin__button--secondary" href="/tenants/tenant_123/admin/rules/templates/badge_template_001"',
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
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).toContain("badge-template-create-form");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).toContain("deriveBadgeTemplateSlugFromTitle");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).toContain(
      "That badge name creates a URL key already used by another template.",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).toContain("Template created. URL key:");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).toContain("Opening the editor to add artwork");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).toContain("badgeTemplateEditorPath");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).toContain(
      "window.location.assign(editorPath)",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("openTemplateEditor");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("template-edit-panel");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain("openTemplateImagePanel");
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).not.toContain(
      "badgeTemplateCreateNextActions",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_JS).toContain("badgeTemplateListPagePath");
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
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).toContain(
      "Open full size previous badge image",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).not.toContain(
      "deriveBadgeTemplateSlugFromTitle",
    );
    expect(INSTITUTION_ADMIN_BADGE_TEMPLATE_EDITOR_JS).not.toContain(
      "initInstitutionAdminBadgeTemplateListPage",
    );
    expect(body).not.toContain("ct-grid--sidebar");
    expect(body).not.toContain("Rule Value Lists");
    expect(body).not.toContain('id="rule-value-list-form"');
    expect(body).not.toContain("Evaluate Rule");
    expect(body).not.toContain('id="rule-evaluate-form"');
  });

  it("renders the template list when image revision storage is not available yet", async () => {
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
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(">Badge Templates<");
    expect(body).toContain('data-template-row-id="badge_template_001"');
    expect(body).toContain('data-template-history-image-revision-count="0"');
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
    expect(body).toContain("Back to badge templates");
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
    expect(body).toContain('name="badgeTemplateId" value="badge_template_001"');
    expect(body).toContain(">URL key<");
    expect(body).toContain('name="slug" type="text" required="" maxlength="120"');
    expect(body).toContain('value="typescript-foundations"');
    expect(body).toContain(">Criteria page URL<");
    expect(body).toContain('value="https://example.edu/criteria"');
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
          Cookie: "better-auth.session_token=session-token",
        },
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = decodeURIComponent(response.headers.get("location") ?? "");
    expect(location).toContain("/tenants/tenant_123/admin/rules/templates");
    expect(location).toContain("listNotice=Badge+template+archived.");
    expect(location).toContain("q=typescript");
    expect(location).toContain("includeArchived=1");
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
    expect(location).toContain("listNotice=Badge+image+restored.");
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
    expect(body).not.toContain('class="ct-admin__builder-shell ct-grid"');
    expect(body).toContain('id="rule-create-form"');
    expect(body).toContain("tenantMembersApiPath");
    expect(body).toContain('data-rule-step-target="metadata"');
    expect(body).toContain('data-rule-step-target="conditions"');
    expect(body).toContain('data-rule-step-target="test"');
    expect(body).not.toContain('data-rule-step-target="review"');
    expect(body).toContain('id="rule-builder-condition-list"');
    expect(body).toContain('id="rule-builder-definition-json"');
    expect(body).toContain('id="rule-builder-step-prev"');
    expect(body).toContain('id="rule-builder-step-next"');
    expect(body).toContain('id="rule-builder-submit"');
    expect(body).toContain('id="rule-builder-flow-list"');
    expect(body).toMatch(
      /id="rule-builder-add-condition"[^>]*class="ct-admin__button ct-admin__button--tiny"/,
    );
    expect(body).toContain('id="rule-builder-require-every-requirement"');
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("rule-builder-require-every-requirement");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("setRuleBuilderRootLogic('all')");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).not.toContain("data-rule-builder-root-logic-option");
    expect(body).toMatch(
      /id="rule-builder-step-next"[^>]*class="ct-admin__button ct-admin__button--tiny"/,
    );
    expect(body).toMatch(
      /id="rule-builder-submit"[^>]*form="rule-create-form"[^>]*class="ct-admin__button"/,
    );
    expect(body).toContain('id="rule-builder-test-preset"');
    expect(body).not.toContain('id="rule-builder-apply-test-preset"');
    expect(body).toContain('id="rule-builder-test-output"');
    expect(body).not.toContain('id="rule-builder-value-list-body"');
    expect(body).toContain('name="reviewOnMissingFacts"');
    expect(body).not.toContain('id="rule-builder-simulate"');
    expect(body).not.toContain('id="rule-builder-simulate-output"');
    expect(body).not.toContain("Historical simulation");
    expect(body).toContain("Follow these steps in order");
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
    expect(body).toContain('id="rule-builder-return-to-pattern"');
    expect(body).toContain("No requirements yet");
    expect(body).toContain("Back to Step 1");
    expect(body).toContain("Advanced JSON tools");
    expect(body).not.toContain("Advanced tools and reusable lists");
    expect(body).not.toContain("Reusable lists");
    expect(body).toContain("Reviewer roles (optional)");
    expect(body).toContain("Leave blank for admin review");
    expect(body).not.toContain('value="admin,owner"');
    expect(body).not.toContain("Start from a proven pattern");
    expect(body).not.toContain("Start from an existing rule");
    expect(body).not.toContain("Load rule");
    expect(body).toContain("Choose the badge, LMS connection, and how learners earn it");
    expect(body).toContain('name="lmsConnectionId"');
    expect(body).toContain("Canvas Test (Canvas)");
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
    expect(body).toContain(">Badge Templates</a>");
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/new" aria-current="page"');
    expect(body).toContain("&quot;rulesListPath&quot;:&quot;/tenants/tenant_123/admin/rules&quot;");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("window.location.assign(rulesListPath)");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).not.toContain(
      "window.location.assign(tenantAdminPath)",
    );
    expect(body).toContain('href="/tenants/tenant_123/admin/access/members"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/governance"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/api-keys"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/org-units"');
    expect(body).toContain('href="/admin/audit-logs?tenantId=tenant_123"');
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
