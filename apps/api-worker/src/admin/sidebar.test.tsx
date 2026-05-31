import { describe, expect, it } from "vitest";

import { appPage, renderAppPageToString } from "../ui/render-page";
import { buildInstitutionAdminSidebarSectionsForTenant } from "./institution-admin-sidebar";
import { AdminSidebar } from "./sidebar";

const renderSidebarHtml = (
  view: Parameters<typeof buildInstitutionAdminSidebarSectionsForTenant>[1],
): string => {
  return renderAppPageToString(
    appPage({
      title: "Sidebar test",
      body: (
        <AdminSidebar
          brandHref="/tenants/tenant_123/admin"
          sections={buildInstitutionAdminSidebarSectionsForTenant("tenant_123", view)}
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
    expect(html).toContain("Reporting");
    expect(html).not.toContain('class="ct-admin-sidebar__group-caret"');

    const detailsCount = html.match(/class="ct-admin-sidebar__group-details"/g)?.length;
    expect(detailsCount).toBe(5);
  });

  it("flattens single-link groups into direct navigation links", () => {
    const html = renderSidebarHtml("rulesTemplates");

    expect(html).toContain('href="/tenants/tenant_123/admin/rules/templates"');
    expect(html).toContain("Templates");
    expect(html).not.toMatch(
      /<summary[^>]*>[\s\S]*?Badge Templates[\s\S]*?ct-admin-sidebar__menu-chevron/,
    );
  });

  it("opens reporting and rule groups when a child page is active", () => {
    const reportingHtml = renderSidebarHtml("reportingExplore");
    const rulesHtml = renderSidebarHtml("rulesBuilder");

    expect(reportingHtml).toMatch(
      /<details class="ct-admin-sidebar__group-details"[^>]*open[\s\S]*?Reporting[\s\S]*?Explore/,
    );
    expect(rulesHtml).toMatch(
      /<details class="ct-admin-sidebar__group-details"[^>]*open[\s\S]*?Rules[\s\S]*?Rule Builder/,
    );
  });
});
