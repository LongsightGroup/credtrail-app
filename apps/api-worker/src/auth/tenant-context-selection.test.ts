import { describe, expect, it } from "vitest";
import {
  buildOrganizationsPath,
  preferredTenantLandingPath,
  resolveChosenTenantLocation,
  resolveTenantContextSelection,
  toAccessibleTenantContextViews,
} from "./tenant-context-selection";

const sampleContexts = () =>
  toAccessibleTenantContextViews([
    {
      tenantId: "tenant_admin",
      tenantSlug: "tenant-admin",
      tenantDisplayName: "Admin Tenant",
      tenantPlanTier: "enterprise",
      membershipRole: "admin",
    },
    {
      tenantId: "tenant_viewer",
      tenantSlug: "tenant-viewer",
      tenantDisplayName: "Viewer Tenant",
      tenantPlanTier: "team",
      membershipRole: "viewer",
    },
  ]);

describe("tenant context selection", () => {
  it("computes conservative preferred tenant landing paths from membership role", () => {
    expect(preferredTenantLandingPath("tenant_admin", "admin")).toBe("/tenants/tenant_admin/admin");
    expect(preferredTenantLandingPath("tenant_owner", "owner")).toBe("/tenants/tenant_owner/admin");
    expect(preferredTenantLandingPath("tenant_viewer", "viewer")).toBe(
      "/tenants/tenant_viewer/learner/dashboard",
    );
    expect(preferredTenantLandingPath("tenant_issuer", "issuer")).toBe(
      "/tenants/tenant_issuer/learner/dashboard",
    );
  });

  it("redirects directly to a requested tenant route when the user can access that tenant", () => {
    const result = resolveTenantContextSelection({
      contexts: sampleContexts(),
      requestedTenant: null,
      nextPath: "/tenants/tenant_admin/admin",
    });

    expect(result).toEqual({
      kind: "redirect",
      tenantId: "tenant_admin",
      location: "/tenants/tenant_admin/admin",
    });
  });

  it("rejects requested tenant routes the user does not belong to", () => {
    const result = resolveTenantContextSelection({
      contexts: sampleContexts(),
      requestedTenant: null,
      nextPath: "/tenants/tenant_missing/admin",
    });

    expect(result).toEqual({
      kind: "unavailable",
      reason: "requested_tenant_forbidden",
    });
  });

  it("reuses remembered tenant context when no explicit tenant route is requested", () => {
    const result = resolveTenantContextSelection({
      contexts: sampleContexts(),
      requestedTenant: {
        tenantId: "tenant_viewer",
      },
      nextPath: "",
    });

    expect(result).toEqual({
      kind: "redirect",
      tenantId: "tenant_viewer",
      location: "/tenants/tenant_viewer/learner/dashboard",
    });
  });

  it("sends multi-tenant users to the chooser when no explicit or remembered tenant applies", () => {
    const result = resolveTenantContextSelection({
      contexts: sampleContexts(),
      requestedTenant: null,
      nextPath: null,
    });

    expect(result).toEqual({
      kind: "chooser",
      location: "/account/organizations",
    });
  });

  it("redirects single-tenant users directly to their only accessible tenant", () => {
    const result = resolveTenantContextSelection({
      contexts: toAccessibleTenantContextViews([
        {
          tenantId: "tenant_only",
          tenantSlug: "tenant-only",
          tenantDisplayName: "Only Tenant",
          tenantPlanTier: "institution",
          membershipRole: "viewer",
        },
      ]),
      requestedTenant: null,
      nextPath: null,
    });

    expect(result).toEqual({
      kind: "redirect",
      tenantId: "tenant_only",
      location: "/tenants/tenant_only/learner/dashboard",
    });
  });

  it("returns chooser path with next parameter when needed", () => {
    expect(buildOrganizationsPath("/somewhere")).toBe("/account/organizations?next=%2Fsomewhere");
  });

  it("does not preserve protocol-relative next parameters for chooser paths", () => {
    expect(buildOrganizationsPath("//evil.example/path")).toBe("/account/organizations");
  });

  it("resolves chosen tenant destination from explicit selection", () => {
    expect(
      resolveChosenTenantLocation({
        contexts: sampleContexts(),
        tenantId: "tenant_admin",
        nextPath: "/tenants/tenant_admin/admin",
      }),
    ).toBe("/tenants/tenant_admin/admin");
    expect(
      resolveChosenTenantLocation({
        contexts: sampleContexts(),
        tenantId: "tenant_viewer",
        nextPath: "/showcase/tenant_viewer",
      }),
    ).toBe("/tenants/tenant_viewer/learner/dashboard");
  });

  it("falls back to preferred tenant destination for protocol-relative selected next paths", () => {
    expect(
      resolveChosenTenantLocation({
        contexts: sampleContexts(),
        tenantId: "tenant_admin",
        nextPath: "//evil.example/tenants/tenant_admin/admin",
      }),
    ).toBe("/tenants/tenant_admin/admin");
  });
});
