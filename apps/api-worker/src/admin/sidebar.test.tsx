import { describe, expect, it } from "vitest";

import { appPage, renderAppPageToString } from "../ui/render-page";
import { buildInstitutionAdminSidebarSectionsForTenant } from "./institution-admin-sidebar";
import { AdminSidebar } from "./sidebar";

const renderSidebarHtml = (
  view: Parameters<typeof buildInstitutionAdminSidebarSectionsForTenant>[1],
  planTier = "team",
): string => {
  return renderAppPageToString(
    appPage({
      title: "Sidebar test",
      body: (
        <AdminSidebar
          brandHref="/tenants/tenant_123/admin"
          sections={buildInstitutionAdminSidebarSectionsForTenant("tenant_123", view, planTier)}
          footerLinks={[]}
        />
      ),
    }),
  );
};

describe("AdminSidebar", () => {
  it("renders Kumo-style chevrons only on multi-link collapsible groups", () => {
    const html = renderSidebarHtml("home");

    expect(html).toContain('class="ct-admin-sidebar__menu-chevron"');
    expect(html).toContain('class="ct-admin-sidebar__group-details"');
    expect(html).toContain("Issuance");
    expect(html).toContain("Badge Program");
    expect(html).toContain("Reporting");
    expect(html).toContain("People &amp; Access");
    expect(html).not.toContain('class="ct-admin-sidebar__group-caret"');

    const detailsCount = html.match(/class="ct-admin-sidebar__group-details"/g)?.length;
    expect(detailsCount).toBe(5);
  });

  it("combines badge templates and rule authoring in one badge program group", () => {
    const html = renderSidebarHtml("rulesBuilder");

    expect(html).toMatch(
      /<details class="ct-admin-sidebar__group-details"[^>]*open[\s\S]*?Badge Program[\s\S]*?Templates[\s\S]*?Rules[\s\S]*?New Rule/,
    );
    expect(html).toContain('href="/tenants/tenant_123/admin/rules/templates"');
    expect(html).toContain('href="/tenants/tenant_123/admin/rules"');
    expect(html).toContain('href="/tenants/tenant_123/admin/rules/new"');
  });

  it("keeps org units inside people and access instead of a standalone group", () => {
    const html = renderSidebarHtml("accessOrgUnits");

    expect(html).toMatch(
      /<details class="ct-admin-sidebar__group-details"[^>]*open[\s\S]*?People &amp; Access[\s\S]*?Members[\s\S]*?LMS Connections[\s\S]*?Org Units/,
    );
    expect(html).not.toMatch(/<a class="ct-admin-sidebar__link"[^>]*>Org Units<\/a>/);
  });

  it("hides authentication nav for non-enterprise tenants", () => {
    const html = renderSidebarHtml("accessMembers", "team");

    expect(html).not.toContain('href="/tenants/tenant_123/admin/access/authentication"');
    expect(html).not.toContain(">Authentication<");
  });

  it("shows authentication nav for enterprise tenants", () => {
    const html = renderSidebarHtml("accessMembers", "enterprise");

    expect(html).toContain('href="/tenants/tenant_123/admin/access/authentication"');
    expect(html).toContain(">Authentication<");
  });

  it("opens reporting and badge program groups when a child page is active", () => {
    const reportingHtml = renderSidebarHtml("reportingExplore");
    const rulesHtml = renderSidebarHtml("rulesBuilder");

    expect(reportingHtml).toMatch(
      /<details class="ct-admin-sidebar__group-details"[^>]*open[\s\S]*?Reporting[\s\S]*?Explore/,
    );
    expect(rulesHtml).toMatch(
      /<details class="ct-admin-sidebar__group-details"[^>]*open[\s\S]*?Badge Program[\s\S]*?New Rule/,
    );
  });
});
