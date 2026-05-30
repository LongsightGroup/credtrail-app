import { describe, expect, it } from "vitest";
import {
  AdminActions,
  AdminCheckboxRow,
  AdminEmptyTableRow,
  AdminField,
  AdminFieldset,
  AdminForm,
  AdminMeta,
  AdminMetricCard,
  AdminPageHeader,
  AdminPanel,
  AdminShell,
  AdminSidebar,
  IssuedBadgeActions,
  AdminSidebarToggle,
  AdminStatus,
  AdminStatusPill,
  AdminTable,
  AdminTopbar,
  AdminWorkspaceCard,
  adminMetricCardClass,
  adminButtonClass,
  adminPanelClass,
} from "./admin/components";
import { renderIssuedBadgeRowsToString } from "./admin/issued-badge-rows-render";
import { designSystemAdminPage } from "./admin/design-system-page";
import { app } from "./index";
import { pageAssetPath } from "./ui/page-assets";
import { DESIGN_SYSTEM_CSS } from "./ui/page-assets/content/design-system-css";
import { FOUNDATION_CSS } from "./ui/page-assets/content/foundation-css";
import { GENERATED_DESIGN_TOKENS_CSS } from "./ui/page-assets/content/generated/design-tokens-css";
import { INSTITUTION_ADMIN_CSS } from "./ui/page-assets/content/institution-admin-css";
import { INSTITUTION_ADMIN_ISSUED_BADGES_JS } from "./ui/page-assets/content/institution-admin-issued-badges-js";
import { INSTITUTION_ADMIN_JS } from "./ui/page-assets/content/institution-admin-js";
import { INSTITUTION_ADMIN_RULE_BUILDER_JS } from "./ui/page-assets/content/institution-admin-rule-builder-js";
import { renderAppPageToString } from "./ui/render-page";

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
  BOOTSTRAP_ADMIN_TOKEN: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
    BOOTSTRAP_ADMIN_TOKEN: "bootstrap-secret",
  };
};

describe("design token asset generation", () => {
  it("loads generated tokens through the shared foundation CSS asset", () => {
    expect(GENERATED_DESIGN_TOKENS_CSS).toContain("--ct-brand-midnight-900");
    expect(GENERATED_DESIGN_TOKENS_CSS).toContain("--ct-theme-gradient-action");
    expect(GENERATED_DESIGN_TOKENS_CSS).toContain("--ct-radius-sm");
    expect(FOUNDATION_CSS).toContain(GENERATED_DESIGN_TOKENS_CSS);
    expect(FOUNDATION_CSS).toContain("color-scheme: light");
  });
});

describe("CredTrail UI styleguide", () => {
  it("renders issued badge actions through the shared admin components", () => {
    const renderable = IssuedBadgeActions({
      assertionId: "sakai:abc-123",
      viewBadgeHref: "/badges/sakai%3Aabc-123",
      rawJsonHref: "/credentials/v1/sakai%3Aabc-123/jsonld",
      auditLifecycleHref:
        "/tenants/tenant_123/admin/operations/issued-badges?lifecycle=sakai%3Aabc-123&lifecycleMode=audit",
      revokeLifecycleHref:
        "/tenants/tenant_123/admin/operations/issued-badges?lifecycle=sakai%3Aabc-123&lifecycleMode=revoke",
      canRevoke: true,
    }) as { toString(): string };
    const html = renderable.toString();

    expect(adminButtonClass({ size: "tiny" })).toBe("ct-admin__button ct-admin__button--tiny");
    expect(adminButtonClass({ variant: "secondary", size: "tiny" })).toBe(
      "ct-admin__button ct-admin__button--tiny ct-admin__button--secondary",
    );
    expect(html).toContain('class="ct-admin__action-bar"');
    expect(html).toContain('aria-label="Actions for assertion sakai:abc-123"');
    expect(html).toContain('href="/badges/sakai%3Aabc-123"');
    expect(html).toContain("lifecycle=sakai%3Aabc-123");
    expect(html).toContain("Open JSON-LD");
    expect(html).toContain("Revoke badge");
    expect(html).not.toContain("ct-admin__action-pill");
  });

  it("renders the shared admin sidebar toggle with one accessible label", () => {
    const renderable = AdminSidebarToggle() as { toString(): string };
    const html = renderable.toString();

    expect(html).toContain('class="ct-admin-topbar__toggle"');
    expect(html).toContain('aria-label="Toggle navigation"');
    expect(html).toContain("data-sidebar-toggle");
    expect(html).toContain('aria-hidden="true"');
  });

  it("renders the shared admin shell, sidebar, and topbar from typed components", () => {
    const renderable = AdminShell({
      sidebar: AdminSidebar({
        brandHref: "/tenants/sakai/admin",
        sections: [
          {
            links: [{ href: "/tenants/sakai/admin", label: "Home", isCurrent: true }],
          },
          {
            label: "Operations",
            links: [
              {
                href: "/tenants/sakai/admin/operations/issued-badges",
                label: "Issued Badges",
                isSub: true,
              },
            ],
          },
        ],
        footerLinks: [{ href: "/admin/audit-logs", label: "Audit logs", isExternal: true }],
      }),
      topbar: AdminTopbar({
        title: "Sakai",
        chips: [{ label: "admin" }],
        userLabel: "admin@example.edu",
        userTitle: "User ID: usr_admin",
      }),
      children: "Admin content",
    }) as { toString(): string };
    const html = renderable.toString();

    expect(html).toContain('class="ct-admin-shell"');
    expect(html).toContain('class="ct-admin-sidebar"');
    expect(html).toContain('class="ct-admin-sidebar__section-summary"');
    expect(html).toContain('class="ct-admin-sidebar__section-caret"');
    expect(html).toContain('aria-current="page"');
    expect(html).toContain("Issued Badges");
    expect(html).toContain('class="ct-admin-topbar"');
    expect(html).toContain("admin@example.edu");
  });

  it("renders shared admin surface primitives", () => {
    const headerHtml = (
      AdminPageHeader({
        title: "Operations",
        description: "Focused admin workspace.",
        compact: true,
      }) as { toString(): string }
    ).toString();
    const panelHtml = (
      AdminPanel({
        variant: "table",
        dataAttributes: { "data-reporting-state": "rich" },
        children: "Panel body",
      }) as { toString(): string }
    ).toString();
    const metricHtml = (
      AdminMetricCard({ stack: true, children: "Metric body" }) as {
        toString(): string;
      }
    ).toString();
    const workspaceHtml = (
      AdminWorkspaceCard({ children: "Workspace body" }) as {
        toString(): string;
      }
    ).toString();
    const linkedWorkspaceHtml = (
      AdminWorkspaceCard({
        href: "/tenants/sakai/admin/reporting",
        ariaLabel: "Open Reporting workspace",
        children: "Reporting workspace",
      }) as {
        toString(): string;
      }
    ).toString();

    expect(adminPanelClass({ variant: "table" })).toBe(
      "ct-admin__panel ct-admin__panel--table ct-stack",
    );
    expect(adminMetricCardClass({ stack: true })).toBe("ct-admin__metric-card ct-stack");
    expect(headerHtml).toContain("ct-admin-page-header--compact");
    expect(panelHtml).toContain('class="ct-admin__panel ct-admin__panel--table ct-stack"');
    expect(panelHtml).toContain('data-reporting-state="rich"');
    expect(metricHtml).toContain('class="ct-admin__metric-card ct-stack"');
    expect(workspaceHtml).toContain('class="ct-admin__workspace-card ct-stack"');
    expect(workspaceHtml).toContain("<article");
    expect(linkedWorkspaceHtml).toContain("<a");
    expect(linkedWorkspaceHtml).toContain('href="/tenants/sakai/admin/reporting"');
    expect(linkedWorkspaceHtml).toContain('aria-label="Open Reporting workspace"');
  });

  it("renders shared admin table primitives", () => {
    const renderable = AdminTable({
      headers: ["Name", "State"],
      compact: true,
      tbodyId: "demo-body",
      tbodyDataAttributes: { "data-reporting-bar-group": "demo" },
      children: "Table body",
    }) as { toString(): string };
    const html = renderable.toString();
    const metaHtml = (AdminMeta({ children: "example_id" }) as { toString(): string }).toString();
    const pillHtml = (
      AdminStatusPill({ tone: "active", children: "active" }) as {
        toString(): string;
      }
    ).toString();
    const emptyRowHtml = (
      AdminEmptyTableRow({ colSpan: 2, children: "No rows." }) as {
        toString(): string;
      }
    ).toString();

    expect(html).toContain('class="ct-admin__table ct-admin__table--compact"');
    expect(html).toContain('id="demo-body"');
    expect(html).toContain('data-reporting-bar-group="demo"');
    expect(metaHtml).toContain('class="ct-admin__meta"');
    expect(pillHtml).toContain('class="ct-admin__status-pill ct-admin__status-pill--active"');
    expect(emptyRowHtml).toContain('class="ct-admin__empty"');
  });

  it("renders shared admin form primitives", () => {
    const fieldHtml = (
      AdminField({ label: "Label", children: "Control" }) as {
        toString(): string;
      }
    ).toString();
    const checkboxHtml = (
      AdminCheckboxRow({ children: "Checkbox" }) as {
        toString(): string;
      }
    ).toString();
    const fieldsetHtml = (
      AdminFieldset({ legend: "Group", children: "Fields" }) as {
        toString(): string;
      }
    ).toString();
    const statusHtml = (
      AdminStatus({ id: "demo-status", tone: "warning", children: "Ready" }) as {
        toString(): string;
      }
    ).toString();
    const actionsHtml = (
      AdminActions({ children: "Actions" }) as {
        toString(): string;
      }
    ).toString();
    const formHtml = (
      AdminForm({ id: "demo-form", children: "Fields" }) as {
        toString(): string;
      }
    ).toString();

    expect(formHtml).toContain('class="ct-admin__form ct-stack"');
    expect(fieldHtml).toContain("<label");
    expect(fieldHtml).toContain('class="ct-admin__field"');
    expect(fieldHtml).toContain("Label");
    expect(checkboxHtml).toContain('class="ct-admin__checkbox-row ct-checkbox-row"');
    expect(fieldsetHtml).toContain('class="ct-admin__fieldset ct-stack"');
    expect(statusHtml).toContain('class="ct-admin__status"');
    expect(statusHtml).toContain('data-tone="warning"');
    expect(actionsHtml).toContain('class="ct-admin__actions"');
  });

  it("renders issued badge table rows through the shared admin components", () => {
    const html = renderIssuedBadgeRowsToString(
      [
        {
          assertionId: "sakai:abc-123",
          tenantId: "tenant_123",
          publicId: "public_abc",
          badgeTemplateId: "badge_template_001",
          badgeTitle: "Sakai 1000+ Commits Contributor",
          badgeImageUri: null,
          recipientIdentity: "learner@example.edu",
          recipientIdentityType: "email",
          issuedAt: "2026-03-04T17:49:18.000Z",
          issuedByUserId: "usr_issuer",
          revokedAt: null,
          state: "active",
          source: "default_active",
          reasonCode: null,
          reason: null,
          transitionedAt: null,
        },
      ],
      (assertionId) =>
        `/tenants/tenant_123/admin/operations/issued-badges?lifecycle=${encodeURIComponent(assertionId)}&lifecycleMode=audit`,
      (assertionId) =>
        `/tenants/tenant_123/admin/operations/issued-badges?lifecycle=${encodeURIComponent(assertionId)}&lifecycleMode=revoke`,
    );

    expect(html).toContain('data-issued-badge-row="true"');
    expect(html).toContain("Sakai 1000+ Commits Contributor");
    expect(html).toContain("learner@example.edu");
    expect(html).toContain("lifecycleMode=audit");
    expect(html).toContain("lifecycleMode=revoke");
    expect(html).toContain("Open JSON-LD");
    expect(html).not.toContain("ct-admin__action-pill");
  });

  it("renders an empty issued badge table row when no assertions match", () => {
    const html = renderIssuedBadgeRowsToString(
      [],
      () =>
        "/tenants/tenant_123/admin/operations/issued-badges?lifecycleMode=audit",
      () =>
        "/tenants/tenant_123/admin/operations/issued-badges?lifecycleMode=revoke",
    );

    expect(html).toContain('colspan="6"');
    expect(html).toContain("No assertions matched the selected filters.");
  });

  it("renders the internal styleguide with the registered design-system asset", () => {
    const html = renderAppPageToString(designSystemAdminPage());

    expect(html).toContain("CredTrail UI Styleguide");
    expect(html).toContain("JSX components");
    expect(html).toContain("PageLayout");
    expect(html).toContain("appPage");
    expect(html).toContain("AdminShell");
    expect(html).toContain("AdminPageHeader");
    expect(html).toContain("AdminPanel");
    expect(html).toContain("AdminMetricCard");
    expect(html).toContain("AdminWorkspaceCard");
    expect(html).toContain("AdminSidebar");
    expect(html).toContain("AdminTopbar");
    expect(html).toContain("AdminTable");
    expect(html).toContain("AdminEmptyTableRow");
    expect(html).toContain("AdminMeta");
    expect(html).toContain("AdminStatusPill");
    expect(html).toContain("AdminForm");
    expect(html).toContain("AdminField");
    expect(html).toContain("AdminCheckboxRow");
    expect(html).toContain("AdminFieldset / AdminStatus");
    expect(html).toContain("AdminActions");
    expect(html).toContain("AdminSidebarToggle");
    expect(html).toContain("RuleBuilderConditionCardTemplate");
    expect(html).toContain("PublicBadgeButtonLink / PublicBadgeButton");
    expect(html).toContain("LoginSubmitButton / LoginActionLink");
    expect(html).toContain("LtiLaunchCard / LtiSubmitButton");
    expect(html).toContain("LearnerButton / LearnerButtonRow");
    expect(html).toContain("Style Dictionary");
    expect(html).toContain("design/tokens/credtrail.tokens.json");
    expect(html).toContain("pnpm build:design-tokens");
    expect(html).toContain(pageAssetPath("designSystemCss"));
    expect(html).toContain(pageAssetPath("institutionAdminCss"));
    expect(html).toContain("ct-admin__button ct-admin__button--secondary");
    expect(html).toContain("ct-admin__cta-link");
    expect(html).toContain("ct-admin__action-bar");
    expect(html).toContain("Surfaces");
    expect(html).not.toContain("ct-admin__action-pill");
  });

  it("serves the styleguide behind the bootstrap admin UI token", async () => {
    const response = await app.request(
      "/admin/styleguide?token=bootstrap-secret",
      undefined,
      createEnv(),
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("CredTrail UI Styleguide");
    expect(body).toContain(pageAssetPath("designSystemCss"));
  });

  it("keeps action examples on the approved admin button system", () => {
    const legacyClass = "ct-admin__action-pill";

    expect(INSTITUTION_ADMIN_CSS).not.toContain(legacyClass);
    expect(INSTITUTION_ADMIN_JS).not.toContain(legacyClass);
    expect(INSTITUTION_ADMIN_ISSUED_BADGES_JS).toContain("loadAssertionLifecycle");
    expect(INSTITUTION_ADMIN_ISSUED_BADGES_JS).not.toContain("issuedBadgeRowsPath");
    expect(INSTITUTION_ADMIN_ISSUED_BADGES_JS).toContain("accept: 'application/json'");
    expect(DESIGN_SYSTEM_CSS).not.toContain(legacyClass);
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__button");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__issued-actions .ct-admin__button");
    expect(DESIGN_SYSTEM_CSS).toContain(".ct-design-system__action-demo");
  });

  it("keeps client-generated admin buttons and condition cards on shared templates", () => {
    expect(INSTITUTION_ADMIN_JS).toContain(
      "const createAdminButtonElement = (className, label, attributes) =>",
    );
    expect(INSTITUTION_ADMIN_JS).toContain(
      "createAdminButtonElement(adminButtonTinyClass, 'Issue badge'",
    );
    expect(INSTITUTION_ADMIN_JS).toContain(
      "createAdminButtonElement(adminButtonTinySecondaryClass, 'Dismiss'",
    );
    expect(INSTITUTION_ADMIN_JS).not.toContain("rule-builder-condition-card-template");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("rule-builder-condition-card-template");
    expect(INSTITUTION_ADMIN_RULE_BUILDER_JS).toContain("cloneRuleBuilderConditionCard");
    expect(INSTITUTION_ADMIN_JS).not.toContain("const renderAdminButton");
  });

  it("keeps admin button links and native buttons on the same sizing model", () => {
    expect(INSTITUTION_ADMIN_CSS).toMatch(/\.ct-admin__button \{[\s\S]*box-sizing: border-box;/);
    expect(INSTITUTION_ADMIN_CSS).toMatch(
      /\.ct-admin__form button \{[\s\S]*box-sizing: border-box;/,
    );
    expect(INSTITUTION_ADMIN_CSS).toMatch(/\.ct-admin-topbar__toggle \{[\s\S]*appearance: none;/);
    expect(INSTITUTION_ADMIN_CSS).toMatch(/\.ct-admin__step-button \{[\s\S]*appearance: none;/);
  });
});
