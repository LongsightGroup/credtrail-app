import { describe, expect, it } from "vitest";
import {
  createEnv,
  fakeDb,
  mockedFindTenantById,
  mockedFindTenantMembership,
  mockedFindUserById,
  mockedListAccessibleTenantContextsForUser,
  mockedListBadgeIssuanceRules,
  mockedListBadgeIssuanceRuleVersions,
  mockedListBadgeTemplates,
  sampleMembership,
} from "./institution-admin-page-test-utils";
import { app } from "./index";
import { pageAssetPath } from "./ui/page-assets";

describe("GET /tenants/:tenantId/admin", () => {
  it("redirects to login when no session cookie is present", async () => {
    const env = createEnv();
    const response = await app.request("/tenants/tenant_123/admin", undefined, env);

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/login?tenantId=tenant_123&next=%2Ftenants%2Ftenant_123%2Fadmin&reason=auth_required",
    );
  });

  it("returns 403 page when membership role is below admin", async () => {
    const env = createEnv();
    mockedFindTenantMembership.mockResolvedValue(sampleMembership("viewer"));

    const response = await app.request(
      "/tenants/tenant_123/admin",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(403);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(body).toContain("Admin role required");
    expect(body).toContain("institution admin access");
    expect(body).toContain(pageAssetPath("institutionAdminCss"));
    expect(body).toContain('class="ct-admin-content"');
    expect(body).toContain('class="ct-admin-page-header"');
    expect(body).toContain('class="ct-admin__panel ct-stack"');
    expect(body).toContain('class="ct-admin__button ct-admin__button--secondary"');
    expect(body).not.toContain('style="');
  });

  it("shows empty-state rule guidance when no rules exist", async () => {
    const env = createEnv();
    mockedListBadgeIssuanceRules.mockResolvedValue([]);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([]);

    const response = await app.request(
      "/tenants/tenant_123/admin",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("No badge rules found.");
    expect(body).toContain("/tenants/tenant_123/admin/rules/new");
    expect(body).toContain("Create your first rule.");
  });

  it("renders institution admin dashboard for admin membership", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin",
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
    expect(body).toContain("Institution Admin");
    expect(body).toContain("Choose a workspace.");
    expect(body).not.toContain("Start Here");
    expect(body).not.toContain("instead of forcing every task onto one page");
    expect(body).toContain("Institution admin workspaces");
    expect(body).toContain("Issue &amp; Inspect");
    expect(body).toContain("Operations");
    expect(body).toContain("Reporting");
    expect(body).toContain("Rules");
    expect(body).toContain("Access");
    expect(body).toContain("Analytics");
    expect(body).toContain("Management");
    expect(body).toContain("Configuration");
    expect(body.match(/class="ct-admin-sidebar__section-icon"/g)?.length).toBe(4);
    expect(body).toContain('aria-label="Open Issue &amp; Inspect workspace"');
    expect(body).toContain('aria-label="Open Reporting workspace"');
    expect(body).toContain('aria-label="Open Rules workspace"');
    expect(body).toContain('aria-label="Open Access workspace"');
    expect(body).not.toMatch(/>\s*Open operations\s*<\/a>/);
    expect(body).not.toMatch(/>\s*Open reporting\s*<\/a>/);
    expect(body).not.toMatch(/>\s*Open rules\s*<\/a>/);
    expect(body).not.toMatch(/>\s*Open access\s*<\/a>/);
    expect(body).not.toMatch(/>\s*Manage members\s*<\/a>/);
    expect(body).not.toContain("Enterprise Auth");
    expect(body).not.toContain("Manual Issue Badge");
    expect(body).not.toContain("Create Tenant API Key");
    expect(body).not.toContain("Issued Badges Ledger");
    expect(body).toContain('href="/tenants/tenant_123/admin/operations"');
    expect(body).toContain('href="/tenants/tenant_123/admin/reporting"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/templates"');
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/new"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access"');
    expect(body).toContain('href="/showcase/tenant_123"');
    expect(body).toContain("/v1/tenants/tenant_123/assertions/manual-issue");
    expect(body).toContain("/v1/tenants/tenant_123/api-keys");
    expect(body).toContain("/v1/tenants/tenant_123/org-units");
    expect(body).not.toContain("/v1/tenants/tenant_123/badge-templates");
    expect(body).toContain("/v1/tenants/tenant_123/users");
    expect(body).toContain("/v1/tenants/tenant_123/badge-rules");
    expect(body).toContain("/v1/tenants/tenant_123/badge-rule-value-lists");
    expect(body).toContain("/v1/tenants/tenant_123/badge-rules/preview-simulate");
    expect(body).toContain("/v1/tenants/tenant_123/badge-rules/review-queue");
    expect(body).toContain("admin@tenant-123.edu");
    expect(body).toContain('title="User ID: usr_admin"');
    expect(body).toContain("/assets/ui/foundation.");
    expect(body).toContain("/assets/ui/institution-admin.");
    expect(body).not.toContain("Switch organization");
    expect(mockedListBadgeTemplates).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      includeArchived: false,
    });
    expect(mockedFindUserById).toHaveBeenCalledWith(fakeDb, "usr_admin");
    expect(mockedListBadgeIssuanceRules).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
    });
    expect(mockedListBadgeIssuanceRuleVersions).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_123",
    });
  });

  it("shows an explicit switch-organization entry point only for multi-tenant admins", async () => {
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
      "/tenants/tenant_123/admin",
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
    expect(body).toContain("/account/organizations?next=%2Ftenants%2Ftenant_123%2Fadmin");
    expect(body).not.toContain("Choose a CredTrail organization");
  });

  it("keeps enterprise auth off the admin hub even for enterprise tenants", async () => {
    const env = createEnv();
    mockedFindTenantById.mockResolvedValue({
      id: "tenant_123",
      slug: "tenant-123",
      displayName: "Tenant 123",
      planTier: "enterprise",
      issuerDomain: "tenant-123.credtrail.test",
      didWeb: "did:web:credtrail.test:tenant_123",
      isActive: true,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).not.toContain("Enterprise Auth");
    expect(body).not.toContain("Login mode");
    expect(body).not.toContain('id="enterprise-auth-policy-form"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access"');
  });
});
