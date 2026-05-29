import { describe, expect, it } from "vitest";
import {
  createEnv,
  mockedFindTenantById,
} from "./institution-admin-page-test-utils";
import { app } from "./index";
import { INSTITUTION_ADMIN_API_KEYS_JS } from "./ui/page-assets/content/institution-admin-api-keys-js";
import { INSTITUTION_ADMIN_JS } from "./ui/page-assets/content/institution-admin-js";
import { INSTITUTION_ADMIN_ORG_UNITS_JS } from "./ui/page-assets/content/institution-admin-org-units-js";
import { pageAssetPath } from "./ui/page-assets";

describe("GET /tenants/:tenantId/admin/access", () => {
  it("renders the access workspace", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access",
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
    expect(body).toContain(">Access<");
    expect(body).toContain("Members");
    expect(body).toContain('href="/tenants/tenant_123/admin/access/members"');
    expect(body).toContain('aria-label="Open Members page"');
    expect(body).not.toMatch(/>\s*Manage members\s*<\/a>/);
    expect(body).toContain("Access pages");
    expect(body).toContain("Governance");
    expect(body).toContain('href="/tenants/tenant_123/admin/access/governance"');
    expect(body).toContain('aria-label="Open Governance page"');
    expect(body).toContain("API Keys");
    expect(body).toContain("Org Units");
    expect(body).toContain('href="/tenants/tenant_123/admin/access/api-keys"');
    expect(body).toContain('aria-label="Open API Keys page"');
    expect(body).toContain('href="/tenants/tenant_123/admin/access/org-units"');
    expect(body).toContain('aria-label="Open Org Units page"');
    expect(body).not.toContain("Save scoped role");
    expect(body).not.toContain('id="tenant-member-form"');
    expect(body).not.toContain('id="membership-scope-form"');
    expect(body).not.toContain('id="api-key-form"');
    expect(body).not.toContain('id="org-unit-form"');
    expect(body).not.toContain("Manual Issue Badge");
    expect(body).not.toContain("Rule Value Lists");
  });

  it("renders enterprise auth settings inside the access workspace for enterprise tenants", async () => {
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
      "/tenants/tenant_123/admin/access",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Enterprise Auth");
    expect(body).toContain("Login mode");
    expect(body).toContain("Campus OIDC");
    expect(body).toContain("Hosted enterprise sign-in supports OIDC providers.");
    expect(body).toContain("Legacy SAML compatibility");
    expect(body).toContain("Members");
    expect(body).toContain("Governance");
    expect(body).toContain("API Keys");
    expect(body).toContain("Org Units");
    expect(body).not.toContain("OIDC or SAML connection metadata");
    expect(body).not.toContain('name="enforceForRoles"');
    expect(body).not.toContain('<option value="saml">');
    expect(body).toContain('id="enterprise-auth-policy-form"');
    expect(body).toContain('id="enterprise-auth-provider-form"');
    expect(body).toContain("Break-glass local accounts");
    expect(body).toContain("admin@tenant-123.edu");
    expect(body).toContain("/v1/tenants/tenant_123/break-glass-accounts");
    expect(body).toContain("/v1/tenants/tenant_123/auth-policy");
    expect(body).toContain("/v1/tenants/tenant_123/auth-providers");
  });
});

describe("GET /tenants/:tenantId/admin/access/governance", () => {
  it("renders governance delegation on its own page with current assignments", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/governance",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Governance Delegation");
    expect(body).toContain("must already exist in this tenant");
    expect(body).toContain('id="membership-scope-form"');
    expect(body).toContain('id="membership-scope-panel"');
    expect(body).toContain('name="userId"');
    expect(body).toContain("issuer@tenant-123.edu (issuer)");
    expect(body).toContain("Scoped Roles");
    expect(body).toContain("Current Scoped Roles (1)");
    expect(body).toContain('data-membership-scope-remove-user-id="usr_issuer"');
    expect(body).toContain("Current Delegations (1)");
    expect(body).toContain('id="delegated-grant-panel"');
    expect(body).toContain('name="delegateUserId"');
    expect(body).toContain("Limit to badge template (optional)");
    expect(body).toContain('data-delegated-grant-remove-id="dag_123"');
    expect(body).toContain("Issue badges");
    expect(body.indexOf('id="membership-scope-body"')).toBeLessThan(
      body.indexOf('id="membership-scope-panel"'),
    );
    expect(body.indexOf('id="delegated-grant-body"')).toBeLessThan(
      body.indexOf('id="delegated-grant-panel"'),
    );
    expect(body).not.toContain("Tenant member user ID");
    expect(body).not.toContain("Delegate user ID");
    expect(body).not.toContain("Limit to badge template IDs");
    expect(body).not.toContain('id="api-key-form"');
    expect(body).not.toContain('id="org-unit-form"');
  });
});

describe("GET /tenants/:tenantId/admin/access/members", () => {
  it("renders tenant members on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/members",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Members");
    expect(body).toContain("Add colleagues");
    expect(body).toContain('<details class="ct-admin__panel ct-admin__add-disclosure">');
    expect(body).toContain("Open form");
    expect(body).toContain('id="tenant-member-form"');
    expect(body).toContain('name="email"');
    expect(body).toContain('name="role"');
    expect(body).toContain('name="sendInvite"');
    expect(body).toContain("Hide form");
    expect(body).toContain("Save member");
    expect(body).toContain(
      'class="ct-admin__panel ct-admin__panel--table ct-admin__members-table ct-stack"',
    );
    expect(body).toContain("/v1/tenants/tenant_123/members");
    expect(body).toContain("admin@tenant-123.edu");
    expect(body).toContain("issuer@tenant-123.edu");
    expect(body).toContain('data-tenant-member-role-user-id="usr_issuer"');
    expect(body).toContain('data-tenant-member-invite-user-id="usr_issuer"');
    expect(body).toContain('data-tenant-member-remove-user-id="usr_issuer"');
    expect(body).toContain("Current user");
    expect(body).not.toContain('id="membership-scope-form"');
    expect(body).not.toContain('id="api-key-form"');
    expect(body).not.toContain('id="org-unit-form"');
  });
});

describe("GET /tenants/:tenantId/admin/access/api-keys", () => {
  it("renders API keys on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/api-keys",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("API Keys");
    expect(body).toContain(
      '<details id="api-key-panel" class="ct-admin__panel ct-admin__add-disclosure">',
    );
    expect(body).toContain("Open form");
    expect(body).toContain("Hide form");
    expect(body).toContain('id="api-key-form"');
    expect(body).toContain("Create API key");
    expect(body).toContain('id="api-key-active-count"');
    expect(body).toContain("Active API Keys (1)");
    expect(body).toContain('id="api-key-body"');
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
    expect(body).toContain(pageAssetPath("institutionAdminApiKeysJs"));
    expect(INSTITUTION_ADMIN_JS).not.toContain("insertApiKeyRow");
    expect(INSTITUTION_ADMIN_API_KEYS_JS).toContain("insertApiKeyRowHtml");
    expect(INSTITUTION_ADMIN_API_KEYS_JS).toContain("Store the secret before closing this form");
    expect(body).toContain(
      'class="ct-admin__panel ct-admin__panel--table ct-admin__api-keys-table ct-stack"',
    );
    expect(body).not.toContain('id="org-unit-form"');
    expect(body).not.toContain('id="membership-scope-form"');
  });
});

describe("GET /tenants/:tenantId/admin/access/org-units", () => {
  it("renders org units on a dedicated page", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/access/org-units",
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      env,
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Org Units");
    expect(body).toContain(
      '<details id="org-unit-panel" class="ct-admin__panel ct-admin__add-disclosure">',
    );
    expect(body).toContain("Open form");
    expect(body).toContain("Hide form");
    expect(body).toContain('id="org-unit-form"');
    expect(body).toContain("Create org unit");
    expect(body).not.toContain('name="slug" type="hidden"');
    expect(body).toContain("CredTrail creates the internal org key from the display name.");
    expect(body).not.toContain("<label>ID");
    expect(body).toContain(pageAssetPath("institutionAdminShellJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminJs"));
    expect(body).toContain(pageAssetPath("institutionAdminOrgUnitsJs"));
    expect(INSTITUTION_ADMIN_JS).not.toContain("deriveUrlKey");
    expect(INSTITUTION_ADMIN_ORG_UNITS_JS).not.toContain("deriveUrlKey");
    expect(INSTITUTION_ADMIN_ORG_UNITS_JS).toContain("Unit type and display name are required.");
    expect(body).toContain("Org Units (");
    expect(body).toContain(
      'class="ct-admin__panel ct-admin__panel--table ct-admin__org-units-table ct-stack"',
    );
    expect(body).not.toContain('id="api-key-form"');
    expect(body).not.toContain('id="membership-scope-form"');
  });
});
