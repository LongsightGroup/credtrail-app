import { readdirSync, readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { INSTITUTION_ADMIN_SHELL_JS } from "./ui/page-assets/content/institution-admin-shell-js";
import { LTI_DEEP_LINK_SETUP_JS } from "./ui/page-assets/content/lti-deep-link-setup-js";
import { PUBLIC_BADGE_JS } from "./ui/page-assets/content/public-badge-js";
import { pageAssetPath, type PageAssetKey } from "./ui/page-assets";

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
    expect(foundationCss).toContain(".ct-action");
    expect(foundationCss).toContain(".ct-action-group");
    expect(foundationCss).toContain(".ct-action--danger");
    expect(foundationCss).toContain(".ct-form");
    expect(foundationCss).toContain(".ct-field");
    expect(foundationCss).toContain(".ct-input");
    expect(foundationCss).toContain(".ct-select");
    expect(foundationCss).toContain(".ct-textarea");
    expect(foundationCss).toContain(".ct-checkbox-field");
  });

  it("keeps action hover colors owned by action primitives", () => {
    const actionsCss = readFileSync(
      new URL("./ui/page-assets/content/actions.css", import.meta.url),
      "utf8",
    );
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
    expect(PUBLIC_BADGE_JS).toContain("supportsBrowserWalletImport");
    expect(PUBLIC_BADGE_JS).toContain("navigator.webdriver");
    expect(PUBLIC_BADGE_JS).toContain("chapiRow.hidden = false");
    expect(PUBLIC_BADGE_JS).toContain("Open in wallet app");
    expect(PUBLIC_BADGE_JS).toContain("download JSON-LD instead");
    expect(PUBLIC_BADGE_JS).toContain("copy-badge-url-technical-button");
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
