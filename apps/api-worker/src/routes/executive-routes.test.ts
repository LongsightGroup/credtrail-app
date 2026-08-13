import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockedFindTenantMembership,
  mockedLoadTenantExecutiveDashboard,
  mockedResolveBetterAuthPrincipal,
  mockedResolveBetterAuthRequestedTenant,
} = vi.hoisted(() => {
  return {
    mockedFindTenantMembership: vi.fn(),
    mockedLoadTenantExecutiveDashboard: vi.fn(),
    mockedResolveBetterAuthPrincipal: vi.fn(),
    mockedResolveBetterAuthRequestedTenant: vi.fn(),
  };
});

vi.mock("@credtrail/db", async () => {
  const actual = await vi.importActual<typeof import("@credtrail/db")>("@credtrail/db");

  return {
    ...actual,
    findTenantMembership: mockedFindTenantMembership,
  };
});

vi.mock("@credtrail/db/postgres", () => {
  return {
    createPostgresDatabase: vi.fn(() => ({
      prepare: vi.fn(),
    })),
  };
});

vi.mock("../auth/better-auth-adapter", async () => {
  const actual = await vi.importActual<typeof import("../auth/better-auth-adapter")>(
    "../auth/better-auth-adapter",
  );

  return {
    ...actual,
    createBetterAuthProvider: vi.fn(() => ({
      requestMagicLink: vi.fn(),
      createMagicLinkSession: vi.fn(),
      createLtiSession: vi.fn(),
      resolveAuthenticatedPrincipal: mockedResolveBetterAuthPrincipal,
      resolveRequestedTenantContext: mockedResolveBetterAuthRequestedTenant,
      revokeCurrentSession: vi.fn(async () => {}),
    })),
  };
});

vi.mock("../executive/executive-rollup-loader", async () => {
  const actual = await vi.importActual<typeof import("../executive/executive-rollup-loader")>(
    "../executive/executive-rollup-loader",
  );

  return {
    ...actual,
    loadTenantExecutiveDashboard: mockedLoadTenantExecutiveDashboard,
  };
});

import { findTenantMembership } from "@credtrail/db";

import { createSeededDemoExecutiveDashboardSlice } from "../executive/seeded-demo-executive-fixture";
import { app } from "../index";
import { pageAssetPath } from "../ui/page-assets";

const mockedFindTenantMembershipDb = vi.mocked(findTenantMembership);

const createEnv = () => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
  };
};

beforeEach(() => {
  mockedFindTenantMembershipDb.mockReset();
  mockedLoadTenantExecutiveDashboard.mockReset();
  mockedResolveBetterAuthPrincipal.mockReset();
  mockedResolveBetterAuthRequestedTenant.mockReset();

  mockedFindTenantMembershipDb.mockResolvedValue({
    tenantId: "tenant_123",
    userId: "usr_exec",
    role: "viewer",
    createdAt: "2026-03-21T12:00:00.000Z",
    updatedAt: "2026-03-21T12:00:00.000Z",
  });
  mockedResolveBetterAuthPrincipal.mockResolvedValue({
    userId: "usr_exec",
    authSessionId: "ses_exec",
    authMethod: "better_auth",
    expiresAt: "2026-03-22T14:00:00.000Z",
  });
  mockedResolveBetterAuthRequestedTenant.mockResolvedValue({
    tenantId: "tenant_123",
  });
  mockedLoadTenantExecutiveDashboard.mockResolvedValue(
    createSeededDemoExecutiveDashboardSlice("scoped"),
  );
});

describe("executive routes", () => {
  it("returns the executive dashboard payload for tenant-wide and scoped members through the JSON route", async () => {
    const response = await app.request(
      "/v1/tenants/tenant_123/executive?state=active&focusOrgUnitId=tenant_123%3Aorg%3Acollege-eng",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(200);
    expect(mockedLoadTenantExecutiveDashboard).toHaveBeenCalledWith({
      db: expect.any(Object),
      tenantId: "tenant_123",
      userId: "usr_exec",
      membershipRole: "viewer",
      query: {
        state: "active",
        focusOrgUnitId: "tenant_123:org:college-eng",
      },
    });

    await expect(response.json()).resolves.toMatchObject({
      status: "ok",
      dashboard: {
        tenantId: "tenant_123",
        defaults: {
          audience: "college",
        },
        rollup: {
          focusDisplayName: "College of Engineering",
        },
      },
    });
  });

  it("returns 403 when the executive loader rejects the member's visible scope", async () => {
    mockedLoadTenantExecutiveDashboard.mockResolvedValueOnce(null);

    const response = await app.request(
      "/v1/tenants/tenant_123/executive?focusOrgUnitId=tenant_123%3Aorg%3Acollege-eng",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({
      error: "Executive dashboard access is unavailable for this tenant scope",
    });
  });

  it("renders a read-only executive page that stays outside admin operations and preserves JSON handoff", async () => {
    const response = await app.request(
      "/tenants/tenant_123/executive?state=active&focusOrgUnitId=tenant_123%3Aorg%3Acollege-eng",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(200);
    const html = await response.text();

    expect(html).toContain("College executive view");
    expect(html).toContain("College of Engineering credential momentum");
    expect(html).toContain("Executive snapshot");
    expect(html).toContain("College of Engineering");
    expect(html).toContain("Compare departments");
    expect(html).toContain("Read-only route");
    expect(html).toContain("Scoped view");
    expect(html).toContain('aria-label="Executive drilldown path"');
    expect(html).not.toContain("Back to Tenant 123 Institution");
    expect(html).not.toContain("Tenant 123 Institution");
    expect(html).toContain("Computer Science");
    expect(html).toContain('data-reporting-visual-kind="trend-series"');
    expect(html).toContain('data-reporting-visual-kind="comparison-ranked"');
    expect(html).toContain(
      "/v1/tenants/tenant_123/executive?window=last-90-days&amp;audience=college&amp;state=active&amp;focusOrgUnitId=tenant_123%3Aorg%3Acollege-eng&amp;comparisonLevel=department",
    );
    expect(html).not.toContain("issuedFrom=2025-12-23");
    expect(html).not.toContain("issuedTo=2026-03-22");
    expect(html).toContain(pageAssetPath("executiveDashboardCss"));
    expect(html).not.toContain("Institution Admin");
    expect(html).not.toContain("Rules and Access");
    expect(html).not.toContain(".executive-hero {");
    expect(html.indexOf('aria-label="Executive KPI summary"')).toBeLessThan(
      html.indexOf('data-reporting-visual-kind="trend-series"'),
    );
    expect(html.indexOf('data-reporting-visual-kind="trend-series"')).toBeLessThan(
      html.indexOf('data-reporting-visual-kind="comparison-ranked"'),
    );
  });

  it("normalizes scoped deep links into the visible executive slice without echoing hidden focus ids", async () => {
    const response = await app.request(
      "/tenants/tenant_123/executive?state=active&focusOrgUnitId=tenant_123%3Aorg%3Adepartment-secret&comparisonLevel=program",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(200);
    const html = await response.text();

    expect(html).toContain("College of Engineering credential momentum");
    expect(html).not.toContain("Back to Tenant 123 Institution");
    expect(html).not.toContain("Tenant 123 Institution");
    expect(html).toContain(
      "/v1/tenants/tenant_123/executive?window=last-90-days&amp;audience=college&amp;state=active&amp;focusOrgUnitId=tenant_123%3Aorg%3Acollege-eng&amp;comparisonLevel=department",
    );
    expect(html).not.toContain("tenant_123%3Aorg%3Adepartment-secret");
    expect(html).not.toContain("/admin/reporting");
  });

  it("renders a 403 executive page when the member does not have executive visibility", async () => {
    mockedLoadTenantExecutiveDashboard.mockResolvedValueOnce(null);

    const response = await app.request(
      "/tenants/tenant_123/executive",
      {
        headers: {
          cookie: "better-auth.session_token=better-auth-test",
        },
      },
      createEnv(),
    );

    expect(response.status).toBe(403);
    const html = await response.text();
    expect(html).toContain("Executive dashboard unavailable");
    expect(html).toContain("Your tenant membership does not expose an executive dashboard slice.");
  });
});
