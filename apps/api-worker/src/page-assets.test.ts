import { readdirSync, readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { readScriptAssetSource, readStyleSourceFile } from "./page-asset-test-utils";
import { PAGE_ASSET_BUILD_SOURCES } from "./ui/page-assets/build-registry";
import { pageAssetPath, type PageAssetKey } from "./ui/page-assets";
import {
  ADMIN_STATUS_PILL_CLASS_SCRIPT_SOURCE,
  scriptPageAssetSourceName,
} from "./ui/page-assets/script-asset-fragments";

const INSTITUTION_ADMIN_SHELL_JS = readScriptAssetSource("institutionAdminShellJs");
const LTI_DEEP_LINK_SETUP_JS = readScriptAssetSource("ltiDeepLinkSetupJs");
const PUBLIC_BADGE_JS = readScriptAssetSource("publicBadgeJs");

const scriptAssetKeys = Object.entries(PAGE_ASSET_BUILD_SOURCES).flatMap(([assetKey, source]) => {
  return source.kind === "script" ? [assetKey as PageAssetKey] : [];
});

const readGeneratedAsset = (assetKey: PageAssetKey): string => {
  const publicAssetPath = pageAssetPath(assetKey).replace(/^\//, "");

  return readFileSync(new URL(`../public/${publicAssetPath}`, import.meta.url), "utf8");
};

const cssRuleBody = (css: string, selector: string): string => {
  const ruleStart = css.indexOf(`${selector} {`);

  if (ruleStart === -1) {
    return "";
  }

  const bodyStart = css.indexOf("{", ruleStart);
  const bodyEnd = css.indexOf("}", bodyStart);

  return bodyStart === -1 || bodyEnd === -1 ? "" : css.slice(bodyStart + 1, bodyEnd);
};

const cssRulesMatchingSelector = (
  css: string,
  predicate: (selector: string) => boolean,
): readonly string[] => {
  return Array.from(css.matchAll(/(?<selector>[^{}]+)\{(?<body>[^{}]+)\}/g))
    .filter((match) => {
      const selector = match.groups?.selector;

      return selector?.split(",").some((entry) => predicate(entry.trim())) === true;
    })
    .map((match) => {
      const selector = match.groups?.selector ?? "";
      const body = match.groups?.body ?? "";

      return `${selector.trim()} {${body}}`;
    });
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
  private focused = false;
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

  public closest(selector: string): FakeBrowserElement | null {
    if (this.matchesSelector(selector)) {
      return this;
    }

    if (this.closestElement !== null && this.closestElement.matchesSelector(selector)) {
      return this.closestElement;
    }

    return null;
  }

  public setClosest(element: FakeBrowserElement): void {
    this.closestElement = element;
  }

  public focus(): void {
    this.focused = true;
  }

  public wasHidden(): boolean {
    return this.hidden;
  }

  public wasFocused(): boolean {
    return this.focused;
  }

  private matchesSelector(selector: string): boolean {
    if (selector.startsWith(".")) {
      return this.classes.has(selector.slice(1));
    }

    const attributeMatch = selector.match(/^\[([^=\]]+)(?:="([^"]*)")?\]$/);
    const attributeName = attributeMatch?.[1];

    if (attributeName === undefined) {
      return false;
    }

    const attributeValue = this.getAttribute(attributeName);
    const expectedValue = attributeMatch?.[2];

    return expectedValue === undefined ? attributeValue !== null : attributeValue === expectedValue;
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
    expect(foundationCss).toContain(".ct-action");
    expect(foundationCss).toContain(".ct-action-group");
    expect(foundationCss).toContain(".ct-action--danger");
    expect(foundationCss).toContain(".ct-form");
    expect(foundationCss).toContain(".ct-field");
    expect(foundationCss).toContain(".ct-input");
    expect(foundationCss).toContain(".ct-select");
    expect(foundationCss).toContain(".ct-textarea");
    expect(foundationCss).toContain(".ct-checkbox-field");
    expect(foundationCss).toContain("[hidden]:not([hidden='until-found'])");
  });

  it("keeps action hover colors owned by action primitives", () => {
    const actionsCss = readStyleSourceFile("actions.css");
    const actionHoverRule = cssRuleBody(actionsCss, ".ct-action:hover:not(:disabled)");
    const primaryRule = cssRuleBody(actionsCss, ".ct-action--primary");
    const textRule = cssRuleBody(actionsCss, ".ct-action--text");
    const nonTextActionCss = actionsCss.replace(textRule, "");

    expect(actionHoverRule).toContain("color: var(--ct-action-hover-color)");
    expect(actionHoverRule).toContain("background: var(--ct-action-hover-background)");
    expect(actionHoverRule).toContain("border-color: var(--ct-action-hover-border)");
    expect(primaryRule).toContain("--ct-action-hover-color: var(--ct-theme-text-on-brand)");
    expect(primaryRule).toContain(
      "--ct-action-hover-background: var(--ct-theme-gradient-action-hover)",
    );
    expect(textRule).toContain(
      "--ct-action-hover-color: var(--ct-theme-link-hover, var(--ct-theme-link))",
    );
    expect(nonTextActionCss).not.toContain("--ct-theme-link-hover");
  });

  it("keeps broad foundation link hover rules from targeting action links", () => {
    const foundationCss = readGeneratedAsset("foundationCss");
    const broadLinkHoverRules = cssRulesMatchingSelector(foundationCss, (selector) => {
      return /(^|[\s>+~])a:hover\b/.test(selector);
    }).filter((rule) => !rule.includes(":not(.ct-action)") && !rule.startsWith("a:hover {"));

    expect(broadLinkHoverRules).toEqual([]);
  });

  it("keeps admin forms from bypassing primitive action and field contracts", () => {
    const institutionAdminCss = readGeneratedAsset("institutionAdminCss");

    expect(institutionAdminCss).not.toContain(".ct-admin__form button {");
    expect(institutionAdminCss).not.toContain(".ct-admin__form button:not(.ct-admin__step-button)");
    expect(institutionAdminCss).not.toContain(".ct-admin__form button:focus-visible");
    expect(institutionAdminCss).not.toContain(".ct-admin__form input:not([type='checkbox'])");
    expect(institutionAdminCss).not.toContain(".ct-admin__form select,");
    expect(institutionAdminCss).not.toContain(".ct-admin__form textarea {");
    expect(institutionAdminCss).not.toContain("ct-admin__add-disclosure-control");
    expect(institutionAdminCss).toContain("ct-admin__inline-action-form");
    expect(institutionAdminCss).not.toContain(
      "ct-admin__inline-action-panel .ct-admin__add-disclosure-form",
    );
  });

  it("keeps template editor forms on primitive class contracts", () => {
    const templateEditorCss = readGeneratedAsset("institutionAdminTemplateEditorCss");

    expect(templateEditorCss).not.toContain(
      ".ct-admin__template-editor-body input:not([type='checkbox'])",
    );
    expect(templateEditorCss).not.toContain(".ct-admin__template-editor-body select,");
    expect(templateEditorCss).not.toContain(".ct-admin__template-editor-body textarea {");
    expect(templateEditorCss).toContain(".ct-admin__template-editor-body .ct-input[type='file']");
  });

  it("keeps LTI Deep Linking setup buttons on primitive action contracts", () => {
    const ltiPagesCss = readGeneratedAsset("ltiPagesCss");

    expect(ltiPagesCss).not.toContain(".lti-deep-link__form button {");
    expect(ltiPagesCss).toContain(".lti-deep-link__setup");
    expect(ltiPagesCss).toContain(".lti-deep-link__actions");
  });

  it("keeps LTI gradebook picker URLs aligned with lookup routes", () => {
    const generatedScript = readGeneratedAsset("ltiDeepLinkSetupJs");

    expect(LTI_DEEP_LINK_SETUP_JS).toContain("apiBase + '/gradebook-items'");
    expect(LTI_DEEP_LINK_SETUP_JS).toContain(
      "apiBase + '/gradebook-items/' + encodeURIComponent(assignmentId) + '/workflow-states'",
    );
    expect(generatedScript).toContain(
      "apiBase + '/gradebook-items/' + encodeURIComponent(assignmentId) + '/workflow-states'",
    );
    expect(generatedScript).not.toContain(
      "apiBase + '/' + encodeURIComponent(assignmentId) + '/workflow-states'",
    );
  });

  it("emits JavaScript assets that parse as browser scripts", () => {
    for (const assetKey of scriptAssetKeys) {
      const body = readGeneratedAsset(assetKey);

      expect(() => new Script(body, { filename: `${String(assetKey)}.js` })).not.toThrow();
    }
  });

  it("assembles JavaScript fragments into parseable browser scripts", () => {
    for (const assetKey of scriptAssetKeys) {
      const body = readScriptAssetSource(assetKey);

      expect(() => new Script(body, { filename: `${String(assetKey)}.source.js` })).not.toThrow();
    }
  });

  it("keeps generated JavaScript fragment names visible in assembled sources", () => {
    const body = readScriptAssetSource("institutionAdminRuleBuilderJs");

    expect(scriptPageAssetSourceName(ADMIN_STATUS_PILL_CLASS_SCRIPT_SOURCE)).toBe(
      "admin-status-pill-class-helper.js",
    );
    expect(body).toContain("/* admin-status-pill-class-helper.js */");
  });

  it("keeps admin browser controllers split into focused source files", () => {
    const assetContentDir = new URL("./ui/page-assets/content/js/", import.meta.url);
    const adminScriptFiles = readdirSync(assetContentDir).filter((fileName) => {
      return fileName.startsWith("institution-admin") && fileName.endsWith(".js");
    });

    expect(adminScriptFiles.length).toBeGreaterThan(0);
    expect(readdirSync(assetContentDir)).not.toEqual(
      expect.arrayContaining([
        "open-iife.js",
        "close-iife.js",
        "admin-status-pill-class-helper.js",
      ]),
    );

    for (const fileName of adminScriptFiles) {
      const source = readFileSync(new URL(fileName, assetContentDir), "utf8");
      const lineCount = source.split("\n").length;

      expect(lineCount).toBeLessThan(1000);
    }
  });

  it("keeps authored JavaScript fragments free of inline IIFE wrappers", () => {
    const assetContentDir = new URL("./ui/page-assets/content/js/", import.meta.url);
    const jsFiles = readdirSync(assetContentDir).filter((fileName) => fileName.endsWith(".js"));

    for (const fileName of jsFiles) {
      const source = readFileSync(new URL(fileName, assetContentDir), "utf8").trim();

      expect(source).not.toMatch(/^\(\(\)\s*=>\s*\{/);
      expect(source).not.toMatch(/\}\)\(\);\s*$/);
    }
  });

  it("keeps authored CSS files below giant-file size", () => {
    const assetContentDir = new URL("./ui/page-assets/content/", import.meta.url);
    const cssFiles = readdirSync(assetContentDir).filter((fileName) => fileName.endsWith(".css"));

    expect(cssFiles.length).toBeGreaterThan(0);

    for (const fileName of cssFiles) {
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
    expect(PUBLIC_BADGE_JS).toContain("supportsBrowserWalletImport");
    expect(PUBLIC_BADGE_JS).toContain("navigator.webdriver");
    expect(PUBLIC_BADGE_JS).toContain("chapiRow.hidden = false");
    expect(PUBLIC_BADGE_JS).toContain("Open in wallet app");
    expect(PUBLIC_BADGE_JS).toContain("download JSON-LD instead");
    expect(PUBLIC_BADGE_JS).toContain("copy-badge-url-technical-button");
  });

  it("opens and closes shared admin inline panels", () => {
    let clickListener: ShellEventListener | null = null;
    let preventDefaultCount = 0;
    const trigger = new FakeBrowserElement({
      attributes: new Map([["data-admin-inline-panel-trigger", "member-panel"]]),
    });
    const panel = new FakeBrowserElement({ id: "member-panel" });
    const closeButton = new FakeBrowserElement({
      attributes: new Map([["data-admin-inline-panel-close", "member-panel"]]),
    });
    const documentStub = {
      addEventListener: (type: string, listener: ShellEventListener): void => {
        if (type === "click") {
          clickListener = listener;
        }
      },
      getElementById: (id: string): FakeBrowserElement | null => {
        return id === "member-panel" ? panel : null;
      },
      querySelector: (selector: string): FakeBrowserElement | null => {
        return selector === '[data-admin-inline-panel-trigger="member-panel"]' ? trigger : null;
      },
      querySelectorAll: (selector: string): FakeBrowserElement[] => {
        return selector === "[data-admin-inline-panel-trigger]" ? [trigger] : [];
      },
    };
    const context = createContext({
      CSS: { escape: (value: string): string => value },
      document: documentStub,
      Element: FakeBrowserElement,
      HTMLElement: FakeBrowserElement,
      window: { innerWidth: 320, innerHeight: 240 },
    });

    new Script(INSTITUTION_ADMIN_SHELL_JS).runInContext(context);
    const panelClickListener = clickListener as ShellEventListener | null;
    expect(panelClickListener).not.toBeNull();
    expect(trigger.getAttribute("aria-expanded")).toBe("false");

    panelClickListener?.({
      target: trigger,
      preventDefault: (): void => {
        preventDefaultCount += 1;
      },
    });

    expect(panel.hidden).toBe(false);
    expect(trigger.getAttribute("aria-expanded")).toBe("true");

    panelClickListener?.({
      target: closeButton,
      preventDefault: (): void => {
        preventDefaultCount += 1;
      },
    });

    expect(panel.hidden).toBe(true);
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    expect(trigger.wasFocused()).toBe(true);
    expect(preventDefaultCount).toBe(2);
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
      querySelectorAll: (_selector: string): FakeBrowserElement[] => {
        return [];
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
