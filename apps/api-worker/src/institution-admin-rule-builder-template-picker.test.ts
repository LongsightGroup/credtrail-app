import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import {
  FakeElement,
  FakeInput,
  FakeOption,
  FakeSelect,
} from "./test-support/browser-page-asset-harness";

const templatePickerAssetSource = (): string => {
  return readFileSync(
    new URL(
      "./ui/page-assets/content/js/institution-admin-rule-builder-template-picker.js",
      import.meta.url,
    ),
    "utf8",
  );
};

const templateOption = (input: {
  value: string;
  title: string;
  ruleUsageCount?: number | undefined;
  ruleUsageNames?: string | undefined;
}): FakeOption => {
  const option = new FakeOption();
  option.value = input.value;
  option.textContent = input.title;
  option.dataset.templateSearchText = `${input.title} ${input.value}`;
  option.dataset.ruleUsageCount = String(input.ruleUsageCount ?? 0);
  option.dataset.ruleUsageNames = input.ruleUsageNames ?? "";
  return option;
};

describe("institution admin rule-builder badge template picker", () => {
  it("filters templates and requires an explicit confirmation before reuse", () => {
    const searchField = new FakeElement();
    searchField.hidden = true;
    const search = new FakeInput();
    const select = new FakeSelect();
    const placeholder = templateOption({ value: "", title: "Choose a badge template" });
    placeholder.selected = true;
    const analytics = templateOption({
      value: "badge_analytics",
      title: "Advanced Analytics",
      ruleUsageCount: 2,
      ruleUsageNames: "Analytics completion · Honors analytics",
    });
    const typescript = templateOption({
      value: "badge_typescript",
      title: "TypeScript Foundations",
    });
    select.append(placeholder, analytics, typescript);
    const status = new FakeElement();
    const reuse = new FakeElement();
    reuse.hidden = true;
    const reuseMessage = new FakeElement();
    const reuseConfirmation = new FakeInput();
    let navigationUpdates = 0;
    const context = createContext({
      console,
      HTMLInputElement: FakeInput,
      HTMLElement: FakeElement,
      HTMLOptionElement: FakeOption,
      HTMLSelectElement: FakeSelect,
      reuse,
      reuseConfirmation,
      reuseMessage,
      search,
      searchField,
      status,
      select,
      onStateChange: (): void => {
        navigationUpdates += 1;
      },
      controller: undefined,
    });

    new Script(templatePickerAssetSource()).runInContext(context);
    new Script(`
      controller = createBadgeTemplatePickerController({
        searchField,
        searchInput: search,
        select,
        searchStatus: status,
        reusePanel: reuse,
        reuseMessage,
        reuseConfirmation,
        onStateChange,
      });
    `).runInContext(context);

    expect(searchField.hidden).toBe(false);
    expect(status.textContent).toBe("2 badge templates ready for rules, A to Z.");
    expect(reuse.hidden).toBe(true);

    search.value = "typescript";
    search.dispatch("input");
    expect(analytics.hidden).toBe(true);
    expect(analytics.disabled).toBe(true);
    expect(typescript.hidden).toBe(false);
    expect(status.textContent).toBe("1 badge template shown.");

    search.value = "";
    search.dispatch("input");
    select.value = "badge_analytics";
    select.dispatch("change");

    expect(reuse.hidden).toBe(false);
    expect(reuseConfirmation.required).toBe(true);
    expect(reuseConfirmation.checked).toBe(false);
    expect(reuseMessage.textContent).toContain("already used by 2 other awarding rules");
    expect(reuseMessage.textContent).toContain("Analytics completion · Honors analytics");
    expect(reuseMessage.textContent).toContain(
      "Each rule keeps its own approval and issuance history.",
    );
    expect(new Script("controller.isComplete()").runInContext(context)).toBe(false);
    expect(new Script("controller.isReuseAcknowledged()").runInContext(context)).toBe(false);

    reuseConfirmation.checked = true;
    reuseConfirmation.dispatch("change");
    expect(new Script("controller.isComplete()").runInContext(context)).toBe(true);
    expect(new Script("controller.isReuseAcknowledged()").runInContext(context)).toBe(true);
    expect(navigationUpdates).toBe(2);
  });
});
