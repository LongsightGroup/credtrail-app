import { readdirSync, readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { app } from "./index";
import { INSTITUTION_ADMIN_SHELL_JS } from "./ui/page-assets/content/institution-admin-shell-js";
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

type ToggleListener = (event: { target: unknown; newState: string }) => void;

interface BrowserRect {
  readonly top: number;
  readonly right: number;
  readonly bottom: number;
  readonly left: number;
  readonly width: number;
  readonly height: number;
}

const createBrowserRect = (input: {
  readonly x?: number;
  readonly y?: number;
  readonly width?: number;
  readonly height?: number;
}): BrowserRect => {
  const left = input.x ?? 0;
  const top = input.y ?? 0;
  const width = input.width ?? 0;
  const height = input.height ?? 0;

  return {
    top,
    right: left + width,
    bottom: top + height,
    left,
    width,
    height,
  };
};

class FakeBrowserElement {
  public readonly style: Record<string, string> = {};
  public readonly classList: { contains: (className: string) => boolean };
  public id: string;
  private readonly attributes: ReadonlyMap<string, string>;
  private readonly classes: ReadonlySet<string>;
  private readonly rect: BrowserRect;
  private closestElement: FakeBrowserElement | null = null;
  private hidden = false;

  public constructor(input: {
    id?: string;
    attributes?: ReadonlyMap<string, string>;
    classes?: ReadonlySet<string>;
    rect?: BrowserRect;
  }) {
    this.id = input.id ?? "";
    this.attributes = input.attributes ?? new Map<string, string>();
    this.classes = input.classes ?? new Set<string>();
    this.rect = input.rect ?? createBrowserRect({});
    this.classList = {
      contains: (className: string): boolean => this.classes.has(className),
    };
  }

  public getAttribute(name: string): string | null {
    return this.attributes.get(name) ?? null;
  }

  public getBoundingClientRect(): BrowserRect {
    return this.rect;
  }

  public contains(target: unknown): boolean {
    return target === this;
  }

  public closest(_selector: string): FakeBrowserElement | null {
    return this.closestElement;
  }

  public setClosest(element: FakeBrowserElement): void {
    this.closestElement = element;
  }

  public hidePopover(): void {
    this.hidden = true;
  }

  public wasHidden(): boolean {
    return this.hidden;
  }
}

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

  it("positions shared admin action popovers when they open from keyboard activation", () => {
    let toggleListener: ToggleListener | null = null;
    const trigger = new FakeBrowserElement({
      attributes: new Map([["popovertarget", "row-actions"]]),
      rect: createBrowserRect({ x: 280, y: 210, width: 30, height: 20 }),
    });
    const popover = new FakeBrowserElement({
      id: "row-actions",
      classes: new Set(["ct-admin__action-menu-popover"]),
      rect: createBrowserRect({ x: 0, y: 0, width: 120, height: 80 }),
    });
    const menuItem = new FakeBrowserElement({});
    menuItem.setClosest(popover);
    const shellWindow: {
      CredTrailAdminActionMenus?: {
        close: (element: unknown) => void;
        position: (popover: unknown, trigger: unknown) => void;
      };
      innerWidth: number;
      innerHeight: number;
    } = {
      innerWidth: 320,
      innerHeight: 240,
    };
    const documentStub = {
      addEventListener: (type: string, listener: ToggleListener): void => {
        if (type === "toggle") {
          toggleListener = listener;
        }
      },
      querySelector: (): null => null,
      querySelectorAll: (): FakeBrowserElement[] => [trigger],
    };
    const context = createContext({
      document: documentStub,
      Element: FakeBrowserElement,
      HTMLElement: FakeBrowserElement,
      window: shellWindow,
    });

    new Script(INSTITUTION_ADMIN_SHELL_JS).runInContext(context);
    const openListener = toggleListener as ToggleListener | null;
    expect(openListener).not.toBeNull();

    openListener?.({ target: popover, newState: "open" });

    expect(popover.style.position).toBe("fixed");
    expect(popover.style.top).toBe("126px");
    expect(popover.style.left).toBe("190px");
    expect(popover.style.right).toBe("auto");

    shellWindow.CredTrailAdminActionMenus?.close(menuItem);
    expect(popover.wasHidden()).toBe(true);
  });

  it("returns 404 for unknown page assets", async () => {
    const response = await app.request("/assets/ui/does-not-exist.js", undefined, createEnv());

    expect(response.status).toBe(404);
  });
});
