import { describe, expect, it } from "vitest";
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
    expect(DESIGN_SYSTEM_CSS).not.toContain(legacyClass);
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__button");
    expect(INSTITUTION_ADMIN_CSS).toContain(".ct-admin__issued-actions .ct-admin__button");
    expect(DESIGN_SYSTEM_CSS).toContain(".ct-design-system__action-demo");
  });
});
