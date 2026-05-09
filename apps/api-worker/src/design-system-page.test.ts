import { describe, expect, it } from "vitest";
import {
  IssuedBadgeActions,
  adminButtonClass,
  renderIssuedBadgeRowsToString,
} from "./admin/components";
import { designSystemAdminPage } from "./admin/design-system-page";
import { app } from "./index";
import { pageAssetPath } from "./ui/page-assets";
import { DESIGN_SYSTEM_CSS } from "./ui/page-assets/content/design-system-css";
import { FOUNDATION_CSS } from "./ui/page-assets/content/foundation-css";
import { GENERATED_DESIGN_TOKENS_CSS } from "./ui/page-assets/content/generated/design-tokens-css";
import { INSTITUTION_ADMIN_CSS } from "./ui/page-assets/content/institution-admin-css";
import { INSTITUTION_ADMIN_JS } from "./ui/page-assets/content/institution-admin-js";
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
    expect(html).toContain('data-issued-action="audit"');
    expect(html).toContain("Open JSON-LD");
    expect(html).toContain("Revoke badge");
    expect(html).not.toContain("ct-admin__action-pill");
  });

  it("renders issued badge table rows through the shared admin components", () => {
    const html = renderIssuedBadgeRowsToString([
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
    ]);

    expect(html).toContain('data-issued-badge-row="true"');
    expect(html).toContain("Sakai 1000+ Commits Contributor");
    expect(html).toContain("learner@example.edu");
    expect(html).toContain('data-issued-action="audit"');
    expect(html).toContain("Open JSON-LD");
    expect(html).not.toContain("ct-admin__action-pill");
  });

  it("renders an empty issued badge table row when no assertions match", () => {
    const html = renderIssuedBadgeRowsToString([]);

    expect(html).toContain('colspan="6"');
    expect(html).toContain("No assertions matched the selected filters.");
  });

  it("renders the internal styleguide with the registered design-system asset", () => {
    const html = renderAppPageToString(designSystemAdminPage());

    expect(html).toContain("CredTrail UI Styleguide");
    expect(html).toContain("JSX components");
    expect(html).toContain("PageLayout");
    expect(html).toContain("appPage");
    expect(html).toContain("Style Dictionary");
    expect(html).toContain("design/tokens/credtrail.tokens.json");
    expect(html).toContain("pnpm build:design-tokens");
    expect(html).toContain(pageAssetPath("designSystemCss"));
    expect(html).toContain(pageAssetPath("institutionAdminCss"));
    expect(html).toContain("ct-admin__button ct-admin__button--secondary");
    expect(html).toContain("ct-admin__cta-link");
    expect(html).toContain("ct-admin__action-bar");
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
    expect(INSTITUTION_ADMIN_JS).toContain("issuedBadgeRowsPath");
    expect(INSTITUTION_ADMIN_JS).toContain("accept: 'text/html'");
    expect(DESIGN_SYSTEM_CSS).not.toContain(legacyClass);
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__button");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__issued-actions .ct-admin__button");
    expect(DESIGN_SYSTEM_CSS).toContain(".ct-design-system__action-demo");
  });

  it("keeps admin button links and native buttons on the same sizing model", () => {
    expect(INSTITUTION_ADMIN_CSS).toMatch(/\.ct-admin__button \{[\s\S]*box-sizing: border-box;/);
    expect(INSTITUTION_ADMIN_CSS).toMatch(
      /\.ct-admin__form button \{[\s\S]*box-sizing: border-box;/,
    );
  });
});
