import { readdirSync, readFileSync } from "node:fs";
import { Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { app } from "./index";
import { pageAssetPath, type PageAssetKey } from "./ui/page-assets";

const createEnv = (): {
  APP_ENV: string;
  DATABASE_URL: string;
  BADGE_OBJECTS: R2Bucket;
  PLATFORM_DOMAIN: string;
} => {
  return {
    APP_ENV: "test",
    DATABASE_URL: "postgres://credtrail-test.local/db",
    BADGE_OBJECTS: {} as R2Bucket,
    PLATFORM_DOMAIN: "credtrail.test",
  };
};

describe("GET /assets/ui/:assetFilename", () => {
  it("serves registered page assets with immutable caching headers", async () => {
    const env = createEnv();
    const assetKeys: readonly PageAssetKey[] = [
      "foundationCss",
      "authLoginCss",
      "authLoginJs",
      "designSystemCss",
      "executiveDashboardCss",
      "institutionAdminCss",
      "institutionAdminJs",
      "institutionAdminShellJs",
      "institutionAdminApiKeysJs",
      "institutionAdminBadgeTemplateJs",
      "institutionAdminIssuedBadgesJs",
      "institutionAdminOrgUnitsJs",
      "institutionAdminRuleBuilderJs",
      "learnerRecordCss",
      "ltiPagesCss",
    ];

    for (const assetKey of assetKeys) {
      const response = await app.request(pageAssetPath(assetKey), undefined, env);
      const expectedContentType = assetKey.endsWith("Css") ? "text/css" : "text/javascript";

      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toContain("immutable");
      expect(response.headers.get("x-content-type-options")).toBe("nosniff");
      expect(response.headers.get("content-type")).toContain(expectedContentType);
    }
  });

  it("serves JavaScript assets that parse as browser scripts", async () => {
    const env = createEnv();
    const scriptAssetKeys: readonly PageAssetKey[] = [
      "authLoginJs",
      "institutionAdminJs",
      "institutionAdminShellJs",
      "institutionAdminApiKeysJs",
      "institutionAdminBadgeTemplateJs",
      "institutionAdminIssuedBadgesJs",
      "institutionAdminOrgUnitsJs",
      "institutionAdminRuleBuilderJs",
      "ltiPostMessageStorageJs",
      "publicBadgeJs",
    ];

    for (const assetKey of scriptAssetKeys) {
      const response = await app.request(pageAssetPath(assetKey), undefined, env);
      const body = await response.text();

      expect(response.status).toBe(200);
      expect(() => new Script(body, { filename: `${String(assetKey)}.js` })).not.toThrow();
    }
  });

  it("keeps admin browser controllers split into focused source files", () => {
    const assetContentDir = new URL("./ui/page-assets/content/", import.meta.url);
    const adminScriptFiles = readdirSync(assetContentDir).filter((fileName) => {
      return fileName.startsWith("institution-admin") && fileName.endsWith("-js.ts");
    });

    expect(adminScriptFiles.length).toBeGreaterThan(0);

    for (const fileName of adminScriptFiles) {
      const source = readFileSync(new URL(fileName, assetContentDir), "utf8");
      const lineCount = source.split("\n").length;

      expect(lineCount).toBeLessThan(1000);
    }
  });

  it("does not carry the old rule-value-list null shim in the rule builder asset", async () => {
    const response = await app.request(
      pageAssetPath("institutionAdminRuleBuilderJs"),
      undefined,
      createEnv(),
    );
    const body = await response.text();

    expect(body).not.toContain("const ruleValueListBody = null");
    expect(body).not.toContain("ruleValueListBody instanceof HTMLElement");
  });

  it("returns 404 for unknown page assets", async () => {
    const response = await app.request("/assets/ui/does-not-exist.js", undefined, createEnv());

    expect(response.status).toBe(404);
  });
});
