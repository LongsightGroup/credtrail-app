import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";

class FakeElement {
  dataset: Record<string, string> = {};
  hidden = false;
  textContent: string | null = "";

  querySelector(): FakeElement | null {
    return null;
  }
}

class FakeStatusElement extends FakeElement {
  readonly message = new FakeElement();

  override querySelector(): FakeElement {
    return this.message;
  }
}

class FakeOption extends FakeElement {
  disabled = false;
  selected = false;
  value = "";
}

type FakeOptions = FakeOption[] & {
  item(index: number): FakeOption | null;
};

const fakeOptions = (options: readonly FakeOption[]): FakeOptions => {
  const collection = [...options] as FakeOptions;
  collection.item = (index): FakeOption | null => collection[index] ?? null;
  return collection;
};

class FakeSelect {
  dataset: Record<string, string> = {};
  disabled = false;
  required = true;
  options = fakeOptions([]);

  get selectedOptions(): readonly FakeOption[] {
    return this.options.filter((option) => option.selected);
  }

  get value(): string {
    return this.selectedOptions[0]?.value ?? "";
  }

  replaceChildren(...options: FakeOption[]): void {
    this.options = fakeOptions(options);
  }

  append(option: FakeOption): void {
    this.options = fakeOptions([...this.options, option]);
  }

  insertBefore(option: FakeOption, before: FakeOption): void {
    const beforeIndex = this.options.indexOf(before);
    const insertIndex = beforeIndex < 0 ? this.options.length : beforeIndex;
    this.options = fakeOptions([
      ...this.options.slice(0, insertIndex),
      option,
      ...this.options.slice(insertIndex),
    ]);
  }
}

interface PickerHarness {
  readonly hydrateCourseSelect: (
    card: object,
    select: FakeSelect,
    query: string,
  ) => Promise<boolean>;
}

const loadPickerHarness = (input: {
  readonly fetchImpl: typeof fetch;
  readonly status: FakeStatusElement;
}): PickerHarness => {
  const primitives = readFileSync(
    new URL("./ui/page-assets/content/js/lms-gradebook-picker-primitives.js", import.meta.url),
    "utf8",
  );
  const picker = readFileSync(
    new URL(
      "./ui/page-assets/content/js/institution-admin-rule-builder-lms-picker.js",
      import.meta.url,
    ),
    "utf8",
  );
  const context = createContext({
    AbortController,
    AbortSignal,
    Error,
    HTMLInputElement: class {},
    HTMLSelectElement: FakeSelect,
    HTMLElement: FakeElement,
    Map,
    Promise,
    Set,
    URLSearchParams,
    WeakMap,
    document: {
      createElement: (): FakeOption => new FakeOption(),
    },
    encodeURIComponent,
    fetch: input.fetchImpl,
    getSelectedLmsConnectionId: (): string => "connection-1",
    lmsConnectionsApiPath: "/v1/lms/connections",
    ruleBuilderLmsStatus: input.status,
    window: {
      clearTimeout,
      setTimeout,
    },
  });

  new Script(
    `${primitives}\n${picker}\nglobalThis.__pickerHarness = { hydrateCourseSelect };`,
  ).runInContext(context);

  return context.__pickerHarness as PickerHarness;
};

describe("rule-builder LMS course picker", () => {
  it("aborts a stale request when the same card receives a replacement select", async () => {
    const requestedUrls: string[] = [];
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;
      requestedUrls.push(url);

      if (url.includes("q=old")) {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new Error("aborted"));
          });
        });
      }

      return Promise.resolve(
        Response.json({
          courses: [{ courseId: "new-course", title: "New course" }],
          hasMore: false,
        }),
      );
    }) as typeof fetch;
    const status = new FakeStatusElement();
    const harness = loadPickerHarness({ fetchImpl, status });
    const card = {};
    const staleSelect = new FakeSelect();
    const currentSelect = new FakeSelect();

    const staleRequest = harness.hydrateCourseSelect(card, staleSelect, "old");
    const currentRequest = harness.hydrateCourseSelect(card, currentSelect, "new");

    await expect(currentRequest).resolves.toBe(true);
    await expect(staleRequest).resolves.toBe(false);
    expect(requestedUrls).toEqual([
      "/v1/lms/connections/connection-1/courses?q=old",
      "/v1/lms/connections/connection-1/courses?q=new",
    ]);
    expect(currentSelect.options.map((option) => option.value)).toEqual(["", "new-course"]);
    expect(status.hidden).toBe(true);
    expect(status.message.textContent).toBe("");
  });

  it("preserves an existing selection that is absent from refreshed results", async () => {
    const fetchImpl = (() =>
      Promise.resolve(
        Response.json({
          courses: [{ courseId: "other-course", title: "Other course" }],
          hasMore: false,
        }),
      )) as typeof fetch;
    const status = new FakeStatusElement();
    const harness = loadPickerHarness({ fetchImpl, status });
    const select = new FakeSelect();
    const selectedOption = new FakeOption();
    selectedOption.value = "selected-course";
    selectedOption.textContent = "Selected course";
    selectedOption.selected = true;
    select.options = fakeOptions([selectedOption]);

    await expect(harness.hydrateCourseSelect({}, select, "other")).resolves.toBe(true);
    expect(select.selectedOptions.map((option) => option.value)).toEqual(["selected-course"]);
    expect(select.options.map((option) => option.value)).toEqual([
      "",
      "selected-course",
      "other-course",
    ]);
  });
});
