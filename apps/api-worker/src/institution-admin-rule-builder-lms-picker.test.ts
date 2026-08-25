import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import {
  FakeElement,
  FakeInput,
  FakeOption,
  FakeSelect,
} from "./test-support/browser-page-asset-harness";

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
  readonly hydrateGradebookItemsForCard: (card: FakeElement, query: string) => Promise<boolean>;
  readonly hydrateWorkflowStateSelect: (input: {
    stateSelect: FakeSelect;
    workflowStatesUrl: string;
    fallbackMessage: string;
  }) => Promise<boolean>;
  readonly readConditionFromCard: (card: FakeElement, strict: boolean) => unknown;
  readonly refreshConditionCardValueListOptions: () => void;
  readonly renderConditionFields: (card: FakeElement, seed: object) => void;
}

const loadPickerHarness = (input: { readonly fetchImpl: typeof fetch }): PickerHarness => {
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
    getDefaultCourseId: (): string => "",
    getSelectedLmsConnectionId: (): string => "connection-1",
    lmsConnectionsApiPath: "/v1/lms/connections",
    ruleBuilderConditionList: conditionList,
    ruleValueLists: [],
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

const createCourseLookupFixture = (
  fieldName = "courseId",
): { readonly card: FakeElement; readonly select: FakeSelect; readonly status: FakeElement } => {
  const card = new FakeElement();
  const select = new FakeSelect();
  select.dataset.field = fieldName;
  const status = new FakeElement("P");
  status.setAttribute("data-lms-course-status", fieldName);
  status.hidden = true;
  card.append(select, status);
  return { card, select, status };
};

const createAssignmentLookupFixture = (): {
  readonly card: FakeElement;
  readonly itemSelect: FakeSelect;
  readonly status: FakeElement;
} => {
  const card = new FakeElement();
  const courseSelect = new FakeSelect();
  courseSelect.dataset.field = "courseId";
  courseSelect.value = "course-101";
  const itemSelect = new FakeSelect();
  itemSelect.dataset.field = "assignmentId";
  itemSelect.dataset.lmsGradebookItemSelect = "";
  const stateSelect = new FakeSelect();
  stateSelect.dataset.lmsWorkflowStateSelect = "";
  const status = new FakeElement("P");
  status.setAttribute("data-lms-gradebook-status", "");
  status.hidden = true;
  card.append(courseSelect, itemSelect, stateSelect, status);
  return { card, itemSelect, status };
};

describe("rule-builder LMS course picker", () => {
  it("keeps an unfinished course requirement empty instead of inventing a course ID", () => {
    const harness = loadPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("not called"))) as typeof fetch,
    });
    const card = new FakeElement();
    card.className = "ct-admin__condition-card";
    const typeSelect = new FakeSelect();
    typeSelect.className = "ct-admin__condition-type";
    typeSelect.value = "course_completion";
    const negate = new FakeInput();
    negate.dataset.field = "negate";
    const fields = new FakeElement();
    fields.className = "ct-admin__condition-fields";
    const summary = new FakeElement();
    summary.className = "ct-admin__condition-summary";
    card.append(typeSelect, negate, fields, summary);

    harness.renderConditionFields(card, {
      type: "course_completion",
      courseId: "",
      minCompletionPercent: 100,
    });

    const select = card.querySelector('[data-field="courseId"]');

    expect(select).toBeInstanceOf(FakeSelect);
    expect(
      select instanceof FakeSelect ? select.options.map((option) => option.value) : [],
    ).toEqual([""]);
    expect(harness.readConditionFromCard(card, false)).toEqual({
      type: "course_completion",
      courseId: "",
      minCompletionPercent: 100,
    });
  });

  it("makes restored single- and multi-course selections available before hydration", () => {
    const harness = loadPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("not called"))) as typeof fetch,
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

  it("renders separate polite status regions for course and gradebook lookups", () => {
    const harness = loadPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("not called"))) as typeof fetch,
    });
    const card = new FakeElement();
    card.className = "ct-admin__condition-card";
    const typeSelect = new FakeSelect();
    typeSelect.className = "ct-admin__condition-type";
    typeSelect.value = "assignment_submission";
    const fields = new FakeElement();
    fields.className = "ct-admin__condition-fields";
    const summary = new FakeElement();
    summary.className = "ct-admin__condition-summary";
    card.append(typeSelect, fields, summary);

    harness.renderConditionFields(card, {
      type: "assignment_submission",
      courseId: "",
      assignmentId: "",
      workflowStates: [],
    });

    const courseStatus = card.querySelector('[data-lms-course-status="courseId"]');
    const gradebookStatus = card.querySelector("[data-lms-gradebook-status]");

    expect(courseStatus?.hidden).toBe(true);
    expect(courseStatus?.getAttribute("aria-live")).toBe("polite");
    expect(courseStatus?.getAttribute("aria-atomic")).toBe("true");
    expect(gradebookStatus?.hidden).toBe(true);
    expect(gradebookStatus?.getAttribute("aria-live")).toBe("polite");
    expect(gradebookStatus?.getAttribute("aria-atomic")).toBe("true");
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
    const harness = loadPickerHarness({ fetchImpl });
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
    const harness = loadPickerHarness({ fetchImpl });
    const card = new FakeElement();
    const status = new FakeElement("P");
    status.setAttribute("data-lms-course-status", "courseId");
    status.hidden = true;
    const staleSelect = new FakeSelect();
    staleSelect.dataset.field = "courseId";
    const currentSelect = new FakeSelect();
    currentSelect.dataset.field = "courseId";
    card.append(status);

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
    expect(status.textContent).toBe("");
  });

  it("keeps loading in the select and reports the actual truncated result count locally", async () => {
    let resolveCourses: (response: Response) => void = () => {
      throw new Error("Course request did not start");
    };
    const fetchImpl = (() =>
      new Promise<Response>((resolve) => {
        resolveCourses = resolve;
      })) as typeof fetch;
    const harness = loadPickerHarness({ fetchImpl });
    const { card, select, status } = createCourseLookupFixture();

    const request = harness.hydrateCourseSelect(card, select, "");

    expect(select.disabled).toBe(true);
    expect(select.options.map((option) => option.textContent)).toEqual(["Loading courses..."]);
    expect(status.hidden).toBe(true);

    resolveCourses(
      Response.json({
        courses: [
          { courseId: "course-101", title: "Course 101" },
          { courseId: "course-202", title: "Course 202" },
        ],
        hasMore: true,
      }),
    );

    await expect(request).resolves.toBe(true);
    expect(status.hidden).toBe(false);
    expect(status.dataset.tone).toBe("info");
    expect(status.textContent).toBe(
      "Showing 2 courses. Search by title, code, or ID to narrow the list.",
    );
  });

  it("uses quiet local empty states for the initial course list and filtered results", async () => {
    const fetchImpl = (() =>
      Promise.resolve(Response.json({ courses: [], hasMore: false }))) as typeof fetch;
    const harness = loadPickerHarness({ fetchImpl });
    const { card, select, status } = createCourseLookupFixture();

    await expect(harness.hydrateCourseSelect(card, select, "")).resolves.toBe(true);
    expect(status.dataset.tone).toBe("info");
    expect(status.textContent).toBe("No courses are available through this LMS connection.");

    await expect(harness.hydrateCourseSelect(card, select, "calculus")).resolves.toBe(true);
    expect(status.dataset.tone).toBe("info");
    expect(status.textContent).toBe("No courses match this search.");
  });

  it("keeps course lookup feedback independent across requirement cards", async () => {
    const fetchImpl = ((input: RequestInfo | URL): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;
      const isFirstCard = url.includes("q=first");
      return Promise.resolve(
        Response.json({
          courses: isFirstCard
            ? []
            : [
                { courseId: "course-202", title: "Course 202" },
                { courseId: "course-303", title: "Course 303" },
              ],
          hasMore: !isFirstCard,
        }),
      );
    }) as typeof fetch;
    const harness = loadPickerHarness({ fetchImpl });
    const first = createCourseLookupFixture();
    const second = createCourseLookupFixture();

    await Promise.all([
      harness.hydrateCourseSelect(first.card, first.select, "first"),
      harness.hydrateCourseSelect(second.card, second.select, "second"),
    ]);

    expect(first.status.textContent).toBe("No courses match this search.");
    expect(second.status.textContent).toBe(
      "Showing 2 matches. Refine your search to narrow the list.",
    );
  });

  it("reports course lookup failures beside the owning picker", async () => {
    const harness = loadPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("Canvas token expired."))) as typeof fetch,
    });
    const { card, select, status } = createCourseLookupFixture();

    await expect(harness.hydrateCourseSelect(card, select, "biology")).resolves.toBe(false);
    expect(select.disabled).toBe(false);
    expect(status.hidden).toBe(false);
    expect(status.dataset.tone).toBe("error");
    expect(status.textContent).toBe("Canvas token expired.");
  });

  it("reports gradebook lookup failures beside the assignment picker", async () => {
    const harness = loadPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("Gradebook access denied."))) as typeof fetch,
    });
    const { card, itemSelect, status } = createAssignmentLookupFixture();

    await expect(harness.hydrateGradebookItemsForCard(card, "essay")).resolves.toBe(false);
    expect(itemSelect.disabled).toBe(false);
    expect(itemSelect.options.map((option) => option.textContent)).toEqual([
      "Gradebook items unavailable",
    ]);
    expect(status.hidden).toBe(false);
    expect(status.dataset.tone).toBe("error");
    expect(status.textContent).toBe("Gradebook access denied.");
  });

  it("preserves an existing selection that is absent from refreshed results", async () => {
    const fetchImpl = (() =>
      Promise.resolve(
        Response.json({
          courses: [{ courseId: "other-course", title: "Other course" }],
          hasMore: false,
        }),
      )) as typeof fetch;
    const harness = loadPickerHarness({ fetchImpl });
    const select = new FakeSelect();
    const selectedOption = new FakeOption();
    selectedOption.value = "selected-course";
    selectedOption.textContent = "Selected course";
    selectedOption.selected = true;
    select.append(selectedOption);

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
    const harness = loadPickerHarness({ fetchImpl });
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
    const harness = loadPickerHarness({ fetchImpl });
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

    await expect(clearedRequest).resolves.toBe(true);
    await expect(staleRequest).resolves.toBe(false);
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
    const harness = loadPickerHarness({ fetchImpl });
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
    const harness = loadPickerHarness({ fetchImpl });
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
    await expect(currentItemRequest).resolves.toBe(true);
  });
});
