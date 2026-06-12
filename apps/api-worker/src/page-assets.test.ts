import { readdirSync, readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { INSTITUTION_ADMIN_SHELL_JS } from "./ui/page-assets/content/institution-admin-shell-js";
import { PUBLIC_BADGE_JS } from "./ui/page-assets/content/public-badge-js";
import { pageAssetPath, type PageAssetKey } from "./ui/page-assets";

const readGeneratedAsset = (assetKey: PageAssetKey): string => {
  const publicAssetPath = pageAssetPath(assetKey).replace(/^\//, "");

  return readFileSync(new URL(`../public/${publicAssetPath}`, import.meta.url), "utf8");
};

type ShellEventListener = (event: {
  target?: unknown;
  key?: string;
  preventDefault?: () => void;
  stopPropagation?: () => void;
}) => void;

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
  public hidden = true;
  private readonly attributes: ReadonlyMap<string, string>;
  private readonly classes: ReadonlySet<string>;
  private readonly rect: BrowserRect;
  private closestElement: FakeBrowserElement | null = null;

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

  public setAttribute(name: string, value: string): void {
    if (this.attributes instanceof Map) {
      this.attributes.set(name, value);
    }
  }

  public removeAttribute(name: string): void {
    if (this.attributes instanceof Map) {
      this.attributes.delete(name);
    }
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

  public wasHidden(): boolean {
    return this.hidden;
  }
}

describe("page asset manifest", () => {
  it("points registered page assets at generated static files", () => {
    const assetKeys: readonly PageAssetKey[] = [
      "foundationCss",
      "authLoginCss",
      "authLoginJs",
      "designSystemCss",
      "executiveDashboardCss",
      "institutionAdminCss",
      "institutionAdminJs",
      "institutionAdminShellJs",
      "institutionAdminAccessJs",
      "institutionAdminBadgeTemplateListJs",
      "institutionAdminBadgeTemplateEditorJs",
      "institutionAdminTemplateEditorCss",
      "institutionAdminIssuedBadgesJs",
      "institutionAdminRuleBuilderJs",
      "learnerRecordCss",
      "ltiPagesCss",
    ];

    for (const assetKey of assetKeys) {
      const path = pageAssetPath(assetKey);

      expect(path).toMatch(/^\/assets\/ui\/.+\.[a-f0-9]{10}\.(?:css|js)$/);
      expect(readGeneratedAsset(assetKey).length).toBeGreaterThan(0);
    }
  });

  it("emits static asset caching headers", () => {
    const headers = readFileSync(new URL("../public/_headers", import.meta.url), "utf8");

    expect(headers).toContain("/assets/ui/*");
    expect(headers).toContain("Cache-Control: public, max-age=31536000, immutable");
    expect(headers).toContain("X-Content-Type-Options: nosniff");
  });

  it("emits foundation CSS with a fingerprinted Newsreader font file", () => {
    const foundationCss = readGeneratedAsset("foundationCss");

    expect(foundationCss).toContain('font-family: "Newsreader"');
    expect(foundationCss).toMatch(/\/assets\/ui\/fonts\/newsreader-latin\.[a-f0-9]{10}\.woff2/);
    expect(foundationCss).not.toContain("base64");
  });

  it("emits JavaScript assets that parse as browser scripts", () => {
    const scriptAssetKeys: readonly PageAssetKey[] = [
      "authLoginJs",
      "institutionAdminJs",
      "institutionAdminShellJs",
      "institutionAdminAccessJs",
      "institutionAdminBadgeTemplateListJs",
      "institutionAdminBadgeTemplateEditorJs",
      "institutionAdminIssuedBadgesJs",
      "institutionAdminRuleBuilderJs",
      "ltiPostMessageStorageJs",
      "publicBadgeJs",
    ];

    for (const assetKey of scriptAssetKeys) {
      const body = readGeneratedAsset(assetKey);

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

  it("does not carry the old rule-value-list null shim in the rule builder asset", () => {
    const body = readGeneratedAsset("institutionAdminRuleBuilderJs");

    expect(body).not.toContain("const ruleValueListBody = null");
    expect(body).not.toContain("ruleValueListBody instanceof HTMLElement");
    expect(body).not.toContain("innerHTML");
  });

  it("keeps browser wallet import progressively enhanced with wallet fallbacks", () => {
    expect(PUBLIC_BADGE_JS).toContain("chapiButton.hidden = false");
    expect(PUBLIC_BADGE_JS).toContain("DCC Learner Wallet");
    expect(PUBLIC_BADGE_JS).toContain("Download .jsonld VC");
  });

  it("positions shared admin action panels next to their trigger", () => {
    let clickListener: ShellEventListener | null = null;
    let scrollListener: ShellEventListener | null = null;
    const trigger = new FakeBrowserElement({
      attributes: new Map([["data-action-menu-trigger", "row-actions"]]),
      rect: createBrowserRect({ x: 280, y: 210, width: 30, height: 20 }),
    });
    const popover = new FakeBrowserElement({
      id: "row-actions",
      classes: new Set(["ct-admin__action-menu-popover"]),
      rect: createBrowserRect({ x: 0, y: 0, width: 120, height: 80 }),
    });
    const menuItem = new FakeBrowserElement({});
    trigger.setClosest(trigger);
    menuItem.setClosest(popover);
    const shellWindow: {
      CredTrailAdminActionMenus?: {
        close: (element: unknown) => void;
        position: (popover: unknown, trigger: unknown) => void;
      };
      innerWidth: number;
      innerHeight: number;
      requestAnimationFrame: (callback: () => void) => number;
    } = {
      innerWidth: 320,
      innerHeight: 240,
      requestAnimationFrame: (callback: () => void): number => {
        callback();
        return 1;
      },
    };
    const documentStub = {
      addEventListener: (type: string, listener: ShellEventListener): void => {
        if (type === "click") {
          clickListener = listener;
        }
        if (type === "scroll") {
          scrollListener = listener;
        }
      },
      getElementById: (id: string): FakeBrowserElement | null => {
        return id === "row-actions" ? popover : null;
      },
      querySelector: (_selector: string): FakeBrowserElement | null => {
        return null;
      },
    };
    const context = createContext({
      CSS: { escape: (value: string): string => value },
      document: documentStub,
      Element: FakeBrowserElement,
      HTMLElement: FakeBrowserElement,
      window: shellWindow,
    });

    new Script(INSTITUTION_ADMIN_SHELL_JS).runInContext(context);
    const openListener = clickListener as ShellEventListener | null;
    const closeOnScrollListener = scrollListener as ShellEventListener | null;
    expect(openListener).not.toBeNull();
    expect(closeOnScrollListener).not.toBeNull();

    openListener?.({
      target: trigger,
      preventDefault: (): void => {},
      stopPropagation: (): void => {},
    });

    expect(popover.hidden).toBe(false);
    expect(trigger.getAttribute("aria-expanded")).toBe("true");
    expect(popover.style.position).toBe("fixed");
    expect(popover.style.top).toBe("126px");
    expect(popover.style.left).toBe("190px");
    expect(popover.style.right).toBe("auto");

    shellWindow.CredTrailAdminActionMenus?.close(menuItem);
    expect(popover.wasHidden()).toBe(true);
    expect(trigger.getAttribute("aria-expanded")).toBe("false");

    openListener?.({
      target: trigger,
      preventDefault: (): void => {},
      stopPropagation: (): void => {},
    });
    closeOnScrollListener?.({});
    expect(popover.wasHidden()).toBe(true);
  });
});
