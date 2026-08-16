import { readFileSync } from "node:fs";
import { type Context, createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import {
  FakeBrowserEvent,
  FakeDocument,
  FakeElement,
  FakeInput,
  FakeOption,
  FakeSelect,
  FakeTimers,
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
  readonly value: string;
  readonly title: string;
  readonly ruleUsageCount?: number | undefined;
  readonly ruleUsageNames?: string | undefined;
}): FakeOption => {
  const option = new FakeOption();
  option.value = input.value;
  option.textContent = input.title;
  option.dataset.templateTitle = input.title;
  option.dataset.ruleUsageCount = String(input.ruleUsageCount ?? 0);
  option.dataset.ruleUsageNames = input.ruleUsageNames ?? "";
  return option;
};

interface PickerFixture {
  readonly combobox: FakeInput;
  readonly context: Context;
  readonly enhancedField: FakeElement;
  readonly fallbackField: FakeElement;
  readonly listbox: FakeElement;
  readonly navigationUpdates: () => number;
  readonly reuseConfirmation: FakeInput;
  readonly reuseMessage: FakeElement;
  readonly reusePanel: FakeElement;
  readonly select: FakeSelect;
  readonly status: FakeElement;
  readonly timers: FakeTimers;
}

const pickerFixture = (
  input: {
    readonly includeOptions?: boolean | undefined;
    readonly selectedValue?: string | undefined;
  } = {},
): PickerFixture => {
  const fallbackField = new FakeElement();
  const enhancedField = new FakeElement();
  enhancedField.hidden = true;
  const combobox = new FakeInput();
  combobox.setAttribute("aria-expanded", "false");
  const listbox = new FakeElement();
  listbox.hidden = true;
  const select = new FakeSelect();
  select.required = true;
  const placeholder = templateOption({ value: "", title: "Choose a badge template" });
  placeholder.disabled = true;
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
  select.append(placeholder, ...(input.includeOptions === false ? [] : [analytics, typescript]));
  select.value = input.selectedValue ?? (input.includeOptions === false ? "" : "badge_analytics");
  const status = new FakeElement();
  status.textContent = "2 badge templates ready for rules, A to Z.";
  const reusePanel = new FakeElement();
  reusePanel.hidden = true;
  const reuseMessage = new FakeElement();
  const reuseConfirmation = new FakeInput();
  const timers = new FakeTimers();
  const document = new FakeDocument();
  let updateCount = 0;
  const context = createContext({
    Event: FakeBrowserEvent,
    HTMLInputElement: FakeInput,
    HTMLElement: FakeElement,
    HTMLOptionElement: FakeOption,
    HTMLSelectElement: FakeSelect,
    clearTimeout: timers.clearTimeout,
    combobox,
    console,
    controller: undefined,
    document,
    enhancedField,
    fallbackField,
    listbox,
    onStateChange: (): void => {
      updateCount += 1;
    },
    reuseConfirmation,
    reuseMessage,
    reusePanel,
    select,
    setTimeout: timers.setTimeout,
    status,
  });

  new Script(templatePickerAssetSource()).runInContext(context);
  new Script(`
    controller = createBadgeTemplatePickerController({
      fallbackField,
      enhancedField,
      comboboxInput: combobox,
      select,
      listbox,
      searchStatus: status,
      reusePanel,
      reuseMessage,
      reuseConfirmation,
      onStateChange,
    });
  `).runInContext(context);

  return {
    combobox,
    context,
    enhancedField,
    fallbackField,
    listbox,
    navigationUpdates: (): number => updateCount,
    reuseConfirmation,
    reuseMessage,
    reusePanel,
    select,
    status,
    timers,
  };
};

const optionRows = (listbox: FakeElement): readonly FakeElement[] => {
  return listbox.querySelectorAll('[role="option"]');
};

describe("institution admin rule-builder badge template picker", () => {
  it("enhances the native fallback into one initialized combobox", () => {
    const fixture = pickerFixture();
    const rows = optionRows(fixture.listbox);

    expect(fixture.fallbackField.hidden).toBe(true);
    expect(fixture.enhancedField.hidden).toBe(false);
    expect(fixture.select.required).toBe(false);
    expect(fixture.select.value).toBe("badge_analytics");
    expect(fixture.combobox.required).toBe(true);
    expect(fixture.combobox.value).toBe("Advanced Analytics");
    expect(fixture.combobox.validationMessage).toBe("");
    expect(fixture.combobox.getAttribute("aria-expanded")).toBe("false");
    expect(fixture.combobox.getAttribute("aria-activedescendant")).toBeNull();
    expect(fixture.listbox.hidden).toBe(true);
    expect(rows).toHaveLength(2);
    expect(rows[0]?.dataset.templateValue).toBe("badge_analytics");
    expect(rows[0]?.textContent).not.toContain("badge_analytics");
    expect(rows[0]?.getAttribute("aria-selected")).toBe("true");
  });

  it("filters rows immediately and debounces polite result announcements", () => {
    const fixture = pickerFixture();
    const rows = optionRows(fixture.listbox);
    const emptyRow = fixture.listbox.querySelector("[data-empty-result]");

    fixture.combobox.value = "typescript";
    fixture.combobox.dispatch("input");
    expect(fixture.listbox.hidden).toBe(false);
    expect(rows[0]?.hidden).toBe(true);
    expect(rows[1]?.hidden).toBe(false);
    expect(fixture.status.textContent).toBe("2 badge templates ready for rules, A to Z.");
    fixture.timers.runAll();
    expect(fixture.status.textContent).toBe("1 badge template shown.");
    expect(fixture.select.value).toBe("badge_analytics");

    fixture.combobox.value = "no such badge";
    fixture.combobox.dispatch("input");
    expect(rows.every((row) => row.hidden)).toBe(true);
    expect(emptyRow?.hidden).toBe(false);
    expect(fixture.select.value).toBe("badge_analytics");
    fixture.timers.runAll();
    expect(fixture.status.textContent).toBe("No badge templates match this search.");
  });

  it("uses arrow navigation and Enter to commit through the native change seam", () => {
    const fixture = pickerFixture();
    let nativeChangeCount = 0;
    fixture.select.addEventListener("change", () => {
      nativeChangeCount += 1;
    });
    fixture.combobox.value = "typescript";
    fixture.combobox.dispatch("input");

    const arrowEvent = new FakeBrowserEvent("keydown", { key: "ArrowDown" });
    fixture.combobox.dispatchEvent(arrowEvent);
    const typescriptRow = optionRows(fixture.listbox)[1];
    expect(arrowEvent.defaultPrevented).toBe(true);
    expect(fixture.combobox.getAttribute("aria-activedescendant")).toBe(typescriptRow?.id);
    expect(typescriptRow?.scrollIntoViewCount).toBe(1);

    const enterEvent = new FakeBrowserEvent("keydown", { key: "Enter" });
    fixture.combobox.dispatchEvent(enterEvent);
    expect(enterEvent.defaultPrevented).toBe(true);
    expect(fixture.select.value).toBe("badge_typescript");
    expect(nativeChangeCount).toBe(1);
    expect(fixture.navigationUpdates()).toBe(1);
    expect(fixture.listbox.hidden).toBe(true);
    expect(fixture.combobox.getAttribute("aria-expanded")).toBe("false");
    expect(fixture.combobox.getAttribute("aria-activedescendant")).toBeNull();
    expect(fixture.combobox.value).toBe("TypeScript Foundations");
    expect(fixture.status.textContent).toBe("TypeScript Foundations selected.");
  });

  it("Escape and Tab restore the committed title without capturing text-editing keys", () => {
    const fixture = pickerFixture();
    fixture.combobox.value = "unfinished query";
    fixture.combobox.dispatch("input");
    const printableEvent = new FakeBrowserEvent("keydown", { key: "a" });
    fixture.combobox.dispatchEvent(printableEvent);
    expect(printableEvent.defaultPrevented).toBe(false);

    const escapeEvent = new FakeBrowserEvent("keydown", { key: "Escape" });
    fixture.combobox.dispatchEvent(escapeEvent);
    expect(escapeEvent.defaultPrevented).toBe(true);
    expect(fixture.combobox.value).toBe("Advanced Analytics");
    expect(fixture.select.value).toBe("badge_analytics");
    expect(fixture.status.textContent).toBe("Advanced Analytics selected.");

    fixture.combobox.dispatch("focus");
    fixture.combobox.value = "another query";
    fixture.combobox.dispatch("input");
    const tabEvent = new FakeBrowserEvent("keydown", { key: "Tab" });
    fixture.combobox.dispatchEvent(tabEvent);
    expect(tabEvent.defaultPrevented).toBe(false);
    expect(fixture.listbox.hidden).toBe(true);
    expect(fixture.combobox.value).toBe("Advanced Analytics");
    expect(fixture.select.value).toBe("badge_analytics");
    expect(fixture.status.textContent).toBe("Advanced Analytics selected.");
  });

  it("commits pointer selection through the keyboard's shared path", () => {
    const fixture = pickerFixture();
    const typescriptRow = optionRows(fixture.listbox)[1];
    const pointerEvent = new FakeBrowserEvent("pointerdown");

    typescriptRow?.dispatchEvent(pointerEvent);
    typescriptRow?.dispatch("click");
    expect(pointerEvent.defaultPrevented).toBe(true);
    expect(fixture.select.value).toBe("badge_typescript");
    expect(fixture.combobox.value).toBe("TypeScript Foundations");
    expect(fixture.listbox.hidden).toBe(true);
    expect(fixture.combobox.focusCount).toBe(1);
    expect(fixture.navigationUpdates()).toBe(1);
  });

  it("keeps reused templates gated until the administrator confirms reuse", () => {
    const fixture = pickerFixture({ selectedValue: "badge_typescript" });
    fixture.combobox.dispatch("focus");
    const analyticsRow = optionRows(fixture.listbox)[0];
    analyticsRow?.dispatchEvent(new FakeBrowserEvent("pointerdown"));
    analyticsRow?.dispatch("click");

    expect(fixture.reusePanel.hidden).toBe(false);
    expect(fixture.reuseConfirmation.required).toBe(true);
    expect(fixture.reuseConfirmation.checked).toBe(false);
    expect(fixture.reuseMessage.textContent).toContain("already used by 2 other awarding rules");
    expect(fixture.reuseMessage.textContent).toContain("Analytics completion · Honors analytics");
    expect(fixture.reuseMessage.textContent).toContain(
      "Each rule keeps its own approval and issuance history.",
    );
    expect(new Script("controller.isComplete()").runInContext(fixture.context)).toBe(false);
    expect(new Script("controller.isReuseAcknowledged()").runInContext(fixture.context)).toBe(
      false,
    );

    fixture.reuseConfirmation.checked = true;
    fixture.reuseConfirmation.dispatch("change");
    expect(new Script("controller.isComplete()").runInContext(fixture.context)).toBe(true);
    expect(new Script("controller.isReuseAcknowledged()").runInContext(fixture.context)).toBe(true);
  });

  it("syncs programmatic native selections into the title and reuse state", () => {
    const fixture = pickerFixture({ selectedValue: "badge_typescript" });
    fixture.select.value = "badge_analytics";
    new Script("controller.sync(true)").runInContext(fixture.context);

    expect(fixture.combobox.value).toBe("Advanced Analytics");
    expect(fixture.combobox.validationMessage).toBe("");
    expect(optionRows(fixture.listbox)[0]?.getAttribute("aria-selected")).toBe("true");
    expect(fixture.reusePanel.hidden).toBe(false);
    expect(fixture.reuseConfirmation.required).toBe(true);
    expect(fixture.reuseConfirmation.checked).toBe(false);
  });

  it("leaves the native fallback visible when no templates are selectable", () => {
    const fixture = pickerFixture({ includeOptions: false });

    expect(fixture.fallbackField.hidden).toBe(false);
    expect(fixture.enhancedField.hidden).toBe(true);
    expect(fixture.select.required).toBe(true);
    expect(fixture.combobox.required).toBe(false);
    expect(fixture.listbox.children).toHaveLength(0);
  });
});
