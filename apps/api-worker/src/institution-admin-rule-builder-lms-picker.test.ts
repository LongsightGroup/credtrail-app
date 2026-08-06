import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";

class FakeElement {
  dataset: Record<string, string> = {};
  children: FakeElement[] = [];
  readonly classList: {
    add(...tokens: readonly string[]): void;
    contains(token: string): boolean;
    remove(...tokens: readonly string[]): void;
  };
  className = "";
  hidden = false;
  readonly tagName: string;
  textContent: string | null = "";

  constructor(tagName = "DIV") {
    this.tagName = tagName;
    this.classList = {
      add: (...tokens): void => {
        const classes = new Set(this.className.split(/\s+/).filter((entry) => entry.length > 0));
        tokens.forEach((token) => classes.add(token));
        this.className = [...classes].join(" ");
      },
      contains: (token): boolean => this.className.split(/\s+/).includes(token),
      remove: (...tokens): void => {
        const removed = new Set(tokens);
        this.className = this.className
          .split(/\s+/)
          .filter((entry) => entry.length > 0 && !removed.has(entry))
          .join(" ");
      },
    };
  }

  append(...children: FakeElement[]): void {
    this.children.push(...children);
  }

  addEventListener(): void {}

  replaceChildren(...children: FakeElement[]): void {
    this.children = [...children];
  }

  setAttribute(name: string, value: string): void {
    if (name.startsWith("data-")) {
      const datasetName = name
        .slice("data-".length)
        .replace(/-([a-z])/g, (_match, letter: string) => letter.toUpperCase());
      this.dataset[datasetName] = value;
    }
  }

  querySelector(selector: string): FakeElement | null {
    return this.querySelectorAll(selector)[0] ?? null;
  }

  querySelectorAll(selector: string): readonly FakeElement[] {
    return this.children.flatMap((child) => [
      ...(child.matches(selector) ? [child] : []),
      ...child.querySelectorAll(selector),
    ]);
  }

  private matches(selector: string): boolean {
    if (selector.startsWith(".")) {
      return this.classList.contains(selector.slice(1));
    }

    const attributeSelectors = [...selector.matchAll(/\[data-([a-z-]+)(?:="([^"]*)")?\]/g)];

    if (attributeSelectors.length === 0) {
      return false;
    }

    return attributeSelectors.every((match) => {
      const attributeName = match[1];

      if (attributeName === undefined) {
        return false;
      }

      const datasetName = attributeName.replace(/-([a-z])/g, (_match, letter: string) =>
        letter.toUpperCase(),
      );
      const expectedValue = match[2];
      return expectedValue === undefined
        ? datasetName in this.dataset
        : this.dataset[datasetName] === expectedValue;
    });
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

  constructor() {
    super("OPTION");
  }
}

class FakeInput extends FakeElement {
  checked = false;
  disabled = false;
  type = "text";
  value = "";

  constructor() {
    super("INPUT");
  }
}

type FakeOptions = FakeOption[] & {
  item(index: number): FakeOption | null;
};

const fakeOptions = (options: readonly FakeOption[]): FakeOptions => {
  const collection = [...options] as FakeOptions;
  collection.item = (index): FakeOption | null => collection[index] ?? null;
  return collection;
};

class FakeSelect extends FakeElement {
  disabled = false;
  multiple = false;
  required = false;
  options = fakeOptions([]);
  private assignedValue = "";

  constructor() {
    super("SELECT");
  }

  override setAttribute(name: string, value: string): void {
    super.setAttribute(name, value);

    if (name === "multiple") {
      this.multiple = true;
    }

    if (name === "required") {
      this.required = true;
    }
  }

  get selectedOptions(): readonly FakeOption[] {
    return this.options.filter((option) => option.selected);
  }

  get value(): string {
    return this.selectedOptions[0]?.value ?? this.assignedValue;
  }

  set value(value: string) {
    this.assignedValue = value;
    this.options.forEach((option) => {
      option.selected = option.value === value;
    });
  }

  override replaceChildren(...options: FakeOption[]): void {
    super.replaceChildren(...options);
    this.options = fakeOptions(options);
  }

  override append(...children: FakeElement[]): void {
    super.append(...children);
    const options = children.filter(
      (candidate): candidate is FakeOption => candidate instanceof FakeOption,
    );
    this.options = fakeOptions([...this.options, ...options]);
  }

  insertBefore(option: FakeOption, before: FakeOption): void {
    const beforeIndex = this.options.indexOf(before);
    const insertIndex = beforeIndex < 0 ? this.options.length : beforeIndex;
    this.options = fakeOptions([
      ...this.options.slice(0, insertIndex),
      option,
      ...this.options.slice(insertIndex),
    ]);
    super.replaceChildren(...this.options);
  }
}

interface PickerHarness {
  readonly conditionList: FakeElement;
  readonly createCourseSelectField: (
    labelText: string,
    fieldName: string,
    selectedValue: string,
    multiple: boolean,
  ) => FakeElement;
  readonly hydrateCourseSelect: (
    card: object,
    select: FakeSelect,
    query: string,
  ) => Promise<boolean>;
  readonly hydrateGradebookItemSelect: (input: {
    itemSelect: FakeSelect;
    itemsUrl: string;
    query: string;
    fallbackMessage: string;
  }) => Promise<boolean>;
  readonly hydrateGradebookItemsForCard: (card: FakeElement, query: string) => Promise<void>;
  readonly hydrateWorkflowStateSelect: (input: {
    stateSelect: FakeSelect;
    workflowStatesUrl: string;
    fallbackMessage: string;
  }) => Promise<boolean>;
  readonly readConditionFromCard: (card: FakeElement, strict: boolean) => unknown;
  readonly refreshConditionCardValueListOptions: () => void;
  readonly renderConditionFields: (card: FakeElement, seed: object) => void;
}

const loadPickerHarness = (input: {
  readonly fetchImpl: typeof fetch;
  readonly status: FakeStatusElement;
}): PickerHarness => {
  const conditionFields = readFileSync(
    new URL(
      "./ui/page-assets/content/js/institution-admin-rule-builder-condition-fields.js",
      import.meta.url,
    ),
    "utf8",
  );
  const conditionModel = readFileSync(
    new URL(
      "./ui/page-assets/content/js/institution-admin-rule-builder-condition-model.js",
      import.meta.url,
    ),
    "utf8",
  );
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
  const fieldRenderers = readFileSync(
    new URL(
      "./ui/page-assets/content/js/institution-admin-rule-builder-condition-field-renderers.js",
      import.meta.url,
    ),
    "utf8",
  );
  const summary = readFileSync(
    new URL(
      "./ui/page-assets/content/js/institution-admin-rule-builder-summary.js",
      import.meta.url,
    ),
    "utf8",
  );
  const conditionList = new FakeElement();
  conditionList.className = "ct-admin__condition-list";
  const context = createContext({
    AbortController,
    AbortSignal,
    Error,
    HTMLButtonElement: class {},
    HTMLInputElement: FakeInput,
    HTMLSelectElement: FakeSelect,
    HTMLTemplateElement: class {},
    HTMLTextAreaElement: class {},
    HTMLElement: FakeElement,
    Map,
    Promise,
    Set,
    URLSearchParams,
    WeakMap,
    document: {
      createElement: (tagName: string): FakeElement => {
        if (tagName === "input") {
          return new FakeInput();
        }

        if (tagName === "option") {
          return new FakeOption();
        }

        if (tagName === "select") {
          return new FakeSelect();
        }

        return new FakeElement(tagName.toUpperCase());
      },
    },
    encodeURIComponent,
    fetch: input.fetchImpl,
    bindExclusiveFieldPair: (): void => undefined,
    conditionTypeLabels: {},
    getCoursePlaceholder: (): string => "COURSE_ID",
    getSelectedLmsConnectionId: (): string => "connection-1",
    lmsConnectionsApiPath: "/v1/lms/connections",
    ruleBuilderConditionList: conditionList,
    ruleBuilderLmsStatus: input.status,
    ruleCreateStatus: new FakeElement(),
    ruleValueLists: [],
    setStatus: (): void => undefined,
    window: {
      clearTimeout,
      setTimeout,
    },
  });

  new Script(
    `${conditionFields}\n${conditionModel}\n${primitives}\n${picker}\n${fieldRenderers}\n${summary}\nglobalThis.__pickerHarness = { conditionList: ruleBuilderConditionList, createCourseSelectField, hydrateCourseSelect, hydrateGradebookItemSelect: lmsHydrateGradebookItemSelect, hydrateGradebookItemsForCard: hydrateGradebookItemSelect, hydrateWorkflowStateSelect: lmsHydrateWorkflowStateSelect, readConditionFromCard, refreshConditionCardValueListOptions, renderConditionFields };`,
  ).runInContext(context);

  return context.__pickerHarness as PickerHarness;
};

describe("rule-builder LMS course picker", () => {
  it("makes restored single- and multi-course selections available before hydration", () => {
    const status = new FakeStatusElement();
    const harness = loadPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("not called"))) as typeof fetch,
      status,
    });
    const singleField = harness.createCourseSelectField(
      "LMS course",
      "courseId",
      "course-101",
      false,
    );
    const multiField = harness.createCourseSelectField(
      "Courses",
      "courseIds",
      "course-101,course-202,course-303",
      true,
    );
    const singleSelect = singleField.children[1];
    const multiSelect = multiField.children[1];

    expect(singleSelect).toBeInstanceOf(FakeSelect);
    expect(multiSelect).toBeInstanceOf(FakeSelect);

    if (!(singleSelect instanceof FakeSelect) || !(multiSelect instanceof FakeSelect)) {
      throw new Error("Course fields did not render native selects");
    }

    expect(singleSelect.selectedOptions.map((option) => option.value)).toEqual(["course-101"]);
    expect(singleSelect.required).toBe(true);
    expect(multiSelect.selectedOptions.map((option) => option.value)).toEqual([
      "course-101",
      "course-202",
      "course-303",
    ]);
    expect(multiSelect.required).toBe(false);
  });

  it("keeps restored pathway courses through the startup refresh while hydration is pending", async () => {
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;

      if (url.includes("q=settle")) {
        return Promise.resolve(
          Response.json({
            courses: [{ courseId: "course-101", title: "Course 101" }],
            hasMore: false,
          }),
        );
      }

      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new Error("aborted"));
        });
      });
    }) as typeof fetch;
    const status = new FakeStatusElement();
    const harness = loadPickerHarness({ fetchImpl, status });
    const card = new FakeElement();
    card.className = "ct-admin__condition-card";
    const typeSelect = new FakeSelect();
    typeSelect.className = "ct-admin__condition-type";
    typeSelect.value = "program_completion";
    const negate = new FakeInput();
    negate.dataset.field = "negate";
    const fields = new FakeElement();
    fields.className = "ct-admin__condition-fields";
    const summary = new FakeElement();
    summary.className = "ct-admin__condition-summary";
    card.append(typeSelect, negate, fields, summary);
    harness.conditionList.append(card);

    harness.renderConditionFields(card, {
      type: "program_completion",
      courseIds: ["course-101", "course-202", "course-303"],
      minimumCompleted: 2,
    });
    harness.refreshConditionCardValueListOptions();

    const select = card.querySelector('[data-field="courseIds"]');

    if (!(select instanceof FakeSelect)) {
      throw new Error("Course field did not render a native select");
    }

    expect(select.selectedOptions.map((option) => option.value).sort()).toEqual([
      "course-101",
      "course-202",
      "course-303",
    ]);
    expect(harness.readConditionFromCard(card, false)).toEqual({
      type: "program_completion",
      courseIds: ["course-101", "course-202", "course-303"],
      minimumCompleted: 2,
    });

    await expect(harness.hydrateCourseSelect(card, select, "settle")).resolves.toBe(true);
    expect(select.selectedOptions.map((option) => option.value).sort()).toEqual([
      "course-101",
      "course-202",
      "course-303",
    ]);
  });

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

  it("keeps the latest gradebook-item response and bypasses the browser cache", async () => {
    const requestCacheModes: Array<RequestCache | undefined> = [];
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;
      requestCacheModes.push(init?.cache);

      if (url.includes("old-course")) {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        });
      }

      return Promise.resolve(
        Response.json({ items: [{ assignmentId: "new-item", title: "New item" }] }),
      );
    }) as typeof fetch;
    const harness = loadPickerHarness({ fetchImpl, status: new FakeStatusElement() });
    const select = new FakeSelect();

    const staleRequest = harness.hydrateGradebookItemSelect({
      itemSelect: select,
      itemsUrl: "/old-course/items",
      query: "",
      fallbackMessage: "Unavailable",
    });
    const currentRequest = harness.hydrateGradebookItemSelect({
      itemSelect: select,
      itemsUrl: "/new-course/items",
      query: "",
      fallbackMessage: "Unavailable",
    });

    await expect(currentRequest).resolves.toBe(true);
    await expect(staleRequest).resolves.toBe(false);
    expect(select.options.map((option) => option.value)).toEqual(["", "new-item"]);
    expect(requestCacheModes).toEqual(["no-store", "no-store"]);
  });

  it("keeps a cleared course empty when its previous gradebook request finishes", async () => {
    const requestedUrls: string[] = [];
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;
      requestedUrls.push(url);

      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    }) as typeof fetch;
    const harness = loadPickerHarness({ fetchImpl, status: new FakeStatusElement() });
    const card = new FakeElement();
    const courseSelect = new FakeSelect();
    courseSelect.dataset.field = "courseId";
    courseSelect.value = "old-course";
    const itemSelect = new FakeSelect();
    itemSelect.dataset.field = "assignmentId";
    itemSelect.dataset.lmsGradebookItemSelect = "";
    const stateSelect = new FakeSelect();
    stateSelect.dataset.lmsWorkflowStateSelect = "";
    card.append(courseSelect, itemSelect, stateSelect);

    const staleRequest = harness.hydrateGradebookItemsForCard(card, "");
    courseSelect.value = "";
    const clearedRequest = harness.hydrateGradebookItemsForCard(card, "");

    await expect(clearedRequest).resolves.toBeUndefined();
    await expect(staleRequest).resolves.toBeUndefined();
    expect(requestedUrls).toEqual([
      "/v1/lms/connections/connection-1/courses/old-course/gradebook-items",
    ]);
    expect(itemSelect.options.map((option) => option.textContent)).toEqual(["Select course first"]);
    expect(itemSelect.disabled).toBe(true);
    expect(stateSelect.options.map((option) => option.textContent)).toEqual([
      "Select gradebook item first",
    ]);
    expect(stateSelect.disabled).toBe(true);
  });

  it("keeps the latest workflow-state response", async () => {
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;

      if (url.includes("old-item")) {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        });
      }

      return Promise.resolve(
        Response.json({ states: [{ value: "graded", label: "Graded", preselected: true }] }),
      );
    }) as typeof fetch;
    const harness = loadPickerHarness({ fetchImpl, status: new FakeStatusElement() });
    const select = new FakeSelect();

    const staleRequest = harness.hydrateWorkflowStateSelect({
      stateSelect: select,
      workflowStatesUrl: "/old-item/workflow-states",
      fallbackMessage: "Unavailable",
    });
    const currentRequest = harness.hydrateWorkflowStateSelect({
      stateSelect: select,
      workflowStatesUrl: "/new-item/workflow-states",
      fallbackMessage: "Unavailable",
    });

    await expect(currentRequest).resolves.toBe(true);
    await expect(staleRequest).resolves.toBe(false);
    expect(select.options.map((option) => option.value)).toEqual(["", "graded"]);
    expect(select.selectedOptions.map((option) => option.value)).toEqual(["graded"]);
  });

  it("clears an older workflow-state request as soon as gradebook items reload", async () => {
    let resolveItems: (response: Response) => void = () => {
      throw new Error("Gradebook item request did not start");
    };
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;

      if (url.includes("old-item/workflow-states")) {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        });
      }

      if (url.includes("new-course/gradebook-items")) {
        return new Promise<Response>((resolve) => {
          resolveItems = resolve;
        });
      }

      return Promise.reject(new Error(`Unexpected LMS request: ${url}`));
    }) as typeof fetch;
    const harness = loadPickerHarness({ fetchImpl, status: new FakeStatusElement() });
    const card = new FakeElement();
    const courseSelect = new FakeSelect();
    courseSelect.dataset.field = "courseId";
    courseSelect.value = "new-course";
    const itemSelect = new FakeSelect();
    itemSelect.dataset.field = "assignmentId";
    itemSelect.dataset.lmsGradebookItemSelect = "";
    const stateSelect = new FakeSelect();
    stateSelect.dataset.lmsWorkflowStateSelect = "";
    card.append(courseSelect, itemSelect, stateSelect);

    const staleStateRequest = harness.hydrateWorkflowStateSelect({
      stateSelect,
      workflowStatesUrl: "/old-item/workflow-states",
      fallbackMessage: "Unavailable",
    });
    const currentItemRequest = harness.hydrateGradebookItemsForCard(card, "");

    await expect(staleStateRequest).resolves.toBe(false);
    expect(stateSelect.options.map((option) => option.textContent)).toEqual([
      "Select gradebook item first",
    ]);
    expect(stateSelect.disabled).toBe(true);

    resolveItems(Response.json({ items: [] }));
    await expect(currentItemRequest).resolves.toBeUndefined();
  });
});
