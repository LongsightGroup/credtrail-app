import { describe, expect, it } from "vitest";
import {
  FakeElement,
  FakeInput,
  FakeOption,
  FakeSelect,
  FakeTimers,
  waitForBrowserCondition,
} from "./test-support/browser-page-asset-harness";
import {
  createAssignmentLookupFixture,
  createCourseLookupFixture,
  createRuleBuilderConditionCard,
  loadRuleBuilderLmsPickerHarness,
} from "./test-support/rule-builder-lms-picker-harness";

describe("rule-builder LMS course picker", () => {
  it("projects issuance timing and missing-fact review through one builder definition", () => {
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("not called"))) as typeof fetch,
    });
    const timings = ["immediate", "manual", "end_of_term"] as const;

    for (const issuanceTiming of timings) {
      for (const reviewOnMissingFacts of [false, true]) {
        const { card } = createRuleBuilderConditionCard("course_completion");
        harness.renderConditionFields(card, {
          type: "course_completion",
          courseId: "course-101",
          minCompletionPercent: 100,
        });

        expect(
          harness.readDefinitionFromCards([card], {
            issuanceTiming,
            reviewOnMissingFacts,
          }),
        ).toEqual({
          conditions: {
            all: [
              {
                type: "course_completion",
                courseId: "course-101",
                minCompletionPercent: 100,
              },
            ],
          },
          options: { issuanceTiming, reviewOnMissingFacts },
        });
      }
    }
  });

  it("preserves valid serialized definition options when applying advanced JSON", () => {
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("not called"))) as typeof fetch,
    });

    expect(
      harness.normalizeSerializedDefinitionOptions({
        conditions: { all: [{ type: "course_completion", courseId: "course-101" }] },
        options: { issuanceTiming: "manual", reviewOnMissingFacts: true },
      }),
    ).toEqual({
      conditions: { all: [{ type: "course_completion", courseId: "course-101" }] },
      options: { issuanceTiming: "manual", reviewOnMissingFacts: true },
    });
  });

  it("classifies only exact supported starter shapes and treats custom trees truthfully", () => {
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("not called"))) as typeof fetch,
    });
    const definitions = new Map<string, object>([
      [
        "course_completion",
        { conditions: { all: [{ type: "course_completion", courseId: "course-101" }] } },
      ],
      [
        "course_and_grade",
        {
          conditions: {
            all: [
              { type: "course_completion", courseId: "course-101" },
              { type: "grade_threshold", courseId: "course-101", minScore: 92 },
            ],
          },
        },
      ],
      [
        "program_completion",
        {
          conditions: {
            all: [
              {
                type: "program_completion",
                courseIds: ["course-101", "course-202"],
                minimumCompleted: 2,
              },
            ],
          },
        },
      ],
      [
        "assignment_submission",
        {
          conditions: {
            all: [
              {
                type: "assignment_submission",
                courseId: "course-101",
                assignmentId: "assignment-42",
                minScore: 90,
              },
            ],
          },
        },
      ],
      [
        "survey_completion",
        {
          conditions: {
            all: [{ type: "survey_completion", source: "qualtrics", surveyId: "survey-1" }],
          },
        },
      ],
      [
        "prerequisite_chain",
        {
          conditions: {
            all: [
              { type: "prerequisite_badge", badgeTemplateId: "badge-1" },
              { type: "course_completion", courseId: "course-202" },
            ],
          },
        },
      ],
      [
        "time_limited",
        {
          conditions: {
            all: [
              { type: "course_completion", courseId: "course-101" },
              { type: "time_window", notAfter: "2026-12-31T23:59:59.000Z" },
            ],
          },
        },
      ],
    ]);

    for (const [preset, definition] of definitions) {
      expect(harness.classifyStarterPreset(definition)).toBe(preset);
    }

    expect(
      harness.classifyStarterPreset({
        conditions: {
          any: [
            { type: "course_completion", courseId: "course-101" },
            { type: "survey_completion", surveyId: "survey-1" },
          ],
        },
      }),
    ).toBe("custom");
    expect(
      harness.classifyStarterPreset({
        conditions: {
          all: [{ type: "assignment_submission", courseId: "course-101", custom: true }],
        },
      }),
    ).toBe("custom");
  });

  it("keeps an unfinished course requirement empty instead of inventing a course ID", () => {
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("not called"))) as typeof fetch,
    });
    const { card } = createRuleBuilderConditionCard("course_completion");

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
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("not called"))) as typeof fetch,
    });
    const single = createRuleBuilderConditionCard("course_completion");
    const multiple = createRuleBuilderConditionCard("program_completion");
    harness.renderConditionFields(single.card, {
      type: "course_completion",
      courseId: "course-101",
      minCompletionPercent: 100,
    });
    harness.renderConditionFields(multiple.card, {
      type: "program_completion",
      courseIds: ["course-101", "course-202", "course-303"],
      minimumCompleted: 2,
    });
    const singleSelect = single.card.querySelector('[data-field="courseId"]');
    const multiSelect = multiple.card.querySelector('[data-field="courseIds"]');

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
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("not called"))) as typeof fetch,
    });
    const { card } = createRuleBuilderConditionCard("assignment_submission");

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
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
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

    await expect(currentRequest).resolves.toEqual({ status: "complete" });
    await expect(staleRequest).resolves.toEqual({ status: "superseded" });
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
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
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

    await expect(request).resolves.toEqual({ status: "complete" });
    expect(status.hidden).toBe(false);
    expect(status.dataset.tone).toBe("info");
    expect(status.textContent).toBe(
      "Showing 2 courses. Search by title, code, or ID to narrow the list.",
    );
  });

  it("uses quiet local empty states for the initial course list and filtered results", async () => {
    const fetchImpl = (() =>
      Promise.resolve(Response.json({ courses: [], hasMore: false }))) as typeof fetch;
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
    const { card, select, status } = createCourseLookupFixture();

    await expect(harness.hydrateCourseSelect(card, select, "")).resolves.toEqual({
      status: "complete",
    });
    expect(status.dataset.tone).toBe("info");
    expect(status.textContent).toBe("No courses are available through this LMS connection.");

    await expect(harness.hydrateCourseSelect(card, select, "calculus")).resolves.toEqual({
      status: "complete",
    });
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
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
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
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("Canvas token expired."))) as typeof fetch,
    });
    const { card, select, status } = createCourseLookupFixture();

    await expect(harness.hydrateCourseSelect(card, select, "biology")).resolves.toEqual({
      status: "failed",
      source: "courses",
      message: "Canvas token expired.",
    });
    expect(select.disabled).toBe(false);
    expect(status.hidden).toBe(false);
    expect(status.dataset.tone).toBe("error");
    expect(status.textContent).toBe("Canvas token expired.");
  });

  it("rejects malformed course payloads without leaving the picker loading", async () => {
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() =>
        Promise.resolve(Response.json({ courses: [null], hasMore: false }))) as typeof fetch,
    });
    const { card, select, status } = createCourseLookupFixture();

    await expect(harness.hydrateCourseSelect(card, select, "biology")).resolves.toEqual({
      status: "failed",
      source: "courses",
      message: "Unable to load LMS courses.",
    });
    expect(select.disabled).toBe(false);
    expect(select.options.map((option) => option.textContent)).toEqual(["Courses unavailable"]);
    expect(status.hidden).toBe(false);
    expect(status.dataset.tone).toBe("error");
    expect(status.textContent).toBe("Unable to load LMS courses.");
  });

  it("reports gradebook lookup failures beside the assignment picker", async () => {
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("Gradebook access denied."))) as typeof fetch,
    });
    const { card, itemSelect, status } = createAssignmentLookupFixture();

    await expect(harness.hydrateGradebookItemsForCard(card, "essay")).resolves.toEqual({
      status: "failed",
      source: "gradebook-items",
      message: "Gradebook access denied.",
    });
    expect(itemSelect.disabled).toBe(false);
    expect(itemSelect.options.map((option) => option.textContent)).toEqual([
      "Gradebook items unavailable",
    ]);
    expect(status.hidden).toBe(false);
    expect(status.dataset.tone).toBe("error");
    expect(status.textContent).toBe("Gradebook access denied.");
  });

  it("resolves and keeps a saved gradebook item omitted from discovery", async () => {
    const requests: Array<{
      readonly body: string | null;
      readonly method: string;
      readonly url: string;
    }> = [];
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;
      const method = init?.method ?? (input instanceof Request ? input.method : "GET");
      const body = typeof init?.body === "string" ? init.body : null;
      requests.push({ body, method, url });

      if (url.endsWith("/gradebook-items")) {
        return Response.json({ items: [{ assignmentId: "other-item", title: "Other item" }] });
      }

      if (url.endsWith("/gradebook-items/resolve")) {
        return Response.json({
          items: [{ assignmentId: "saved-item", title: "Saved capstone", pointsPossible: 100 }],
        });
      }

      if (url.endsWith("/gradebook-items/saved-item/workflow-states")) {
        return Response.json({ states: [] });
      }

      throw new Error(`Unexpected request: ${url}`);
    }) as typeof fetch;
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
    const { card, itemSelect, status } = createAssignmentLookupFixture();
    itemSelect.dataset.selectedValue = "saved-item";

    await expect(harness.hydrateGradebookItemsForCard(card, "")).resolves.toEqual({
      status: "complete",
    });
    expect(itemSelect.selectedOptions.map((option) => option.value)).toEqual(["saved-item"]);
    expect(itemSelect.options.map((option) => option.textContent)).toEqual([
      "Select gradebook item",
      "Saved capstone · 100 pts (saved-item)",
      "Other item (other-item)",
    ]);
    expect(status.hidden).toBe(true);
    expect(requests.map((request) => [request.method, request.url])).toEqual([
      ["GET", "/v1/lms/connections/connection-1/courses/course-101/gradebook-items"],
      ["POST", "/v1/lms/connections/connection-1/courses/course-101/gradebook-items/resolve"],
      [
        "GET",
        "/v1/lms/connections/connection-1/courses/course-101/gradebook-items/saved-item/workflow-states",
      ],
    ]);
    expect(JSON.parse(requests[1]?.body ?? "null") as unknown).toEqual({
      assignmentIds: ["saved-item"],
    });
  });

  it("keeps a stable saved gradebook ID when exact resolution cannot find it", async () => {
    const fetchImpl = ((input: RequestInfo | URL): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;

      if (url.endsWith("/gradebook-items") || url.endsWith("/gradebook-items/resolve")) {
        return Promise.resolve(Response.json({ items: [] }));
      }

      if (url.endsWith("/gradebook-items/saved-item/workflow-states")) {
        return Promise.resolve(Response.json({ states: [] }));
      }

      return Promise.reject(new Error(`Unexpected request: ${url}`));
    }) as typeof fetch;
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
    const { card, itemSelect, status } = createAssignmentLookupFixture();
    itemSelect.dataset.selectedValue = "saved-item";

    await expect(harness.hydrateGradebookItemsForCard(card, "")).resolves.toEqual({
      status: "complete",
      warningMessage:
        "The LMS no longer returns the saved gradebook item. Its saved ID remains selected.",
    });
    expect(itemSelect.selectedOptions.map((option) => option.value)).toEqual(["saved-item"]);
    expect(itemSelect.options.map((option) => option.textContent)).toEqual([
      "No matching gradebook items",
      "saved-item",
    ]);
    expect(status.dataset.tone).toBe("warning");
    expect(status.textContent).toContain("saved ID remains selected");
  });

  it("keeps the saved gradebook item selected when discovery fails", async () => {
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("Gradebook unavailable."))) as typeof fetch,
    });
    const { card, itemSelect, status } = createAssignmentLookupFixture();
    itemSelect.dataset.selectedValue = "saved-item";

    await expect(harness.hydrateGradebookItemsForCard(card, "")).resolves.toEqual({
      status: "failed",
      source: "gradebook-items",
      message: "Gradebook unavailable. The saved gradebook item remains selected.",
    });
    expect(itemSelect.selectedOptions.map((option) => option.value)).toEqual(["saved-item"]);
    expect(itemSelect.options.map((option) => option.textContent)).toEqual([
      "Gradebook items unavailable",
      "saved-item",
    ]);
    expect(status.textContent).toContain("saved gradebook item remains selected");
  });

  it("rejects malformed gradebook-item payloads at the response boundary", async () => {
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.resolve(Response.json({ items: [null] }))) as typeof fetch,
    });
    const select = new FakeSelect();

    await expect(
      harness.hydrateGradebookItemSelect({
        itemSelect: select,
        itemsUrl: "/course-101/items",
        query: "",
        fallbackMessage: "Unable to load gradebook items.",
      }),
    ).resolves.toEqual({
      status: "failed",
      source: "gradebook-items",
      message: "Unable to load gradebook items.",
    });
    expect(select.disabled).toBe(false);
    expect(select.options.map((option) => option.textContent)).toEqual([
      "Gradebook items unavailable",
    ]);
  });

  it("adds a search query without replacing existing resource parameters", async () => {
    const requestedUrls: string[] = [];
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: ((input: RequestInfo | URL): Promise<Response> => {
        requestedUrls.push(
          input instanceof Request ? input.url : input instanceof URL ? input.href : input,
        );
        return Promise.resolve(Response.json({ items: [] }));
      }) as typeof fetch,
    });

    await expect(
      harness.hydrateGradebookItemSelect({
        itemSelect: new FakeSelect(),
        itemsUrl: "/course-101/items?include=archived",
        query: " final essay ",
        fallbackMessage: "Unable to load gradebook items.",
      }),
    ).resolves.toEqual({ status: "complete" });
    expect(requestedUrls).toEqual(["/course-101/items?include=archived&q=final+essay"]);
  });

  it("rejects malformed workflow-state payloads at the response boundary", async () => {
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.resolve(Response.json({ states: [null] }))) as typeof fetch,
    });
    const select = new FakeSelect();

    await expect(
      harness.hydrateWorkflowStateSelect({
        stateSelect: select,
        workflowStatesUrl: "/assignment-1/workflow-states",
        fallbackMessage: "Unable to load workflow states.",
      }),
    ).resolves.toEqual({
      status: "failed",
      source: "workflow-states",
      message: "Unable to load workflow states.",
    });
    expect(select.disabled).toBe(false);
    expect(select.options.map((option) => option.textContent)).toEqual([
      "Workflow states unavailable",
    ]);
  });

  it("keeps hydrated gradebook items when the workflow-state stage fails", async () => {
    const fetchImpl = ((input: RequestInfo | URL): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;

      if (url.endsWith("/gradebook-items")) {
        return Promise.resolve(
          Response.json({ items: [{ assignmentId: "assignment-1", title: "Essay" }] }),
        );
      }

      if (url.endsWith("/gradebook-items/assignment-1/workflow-states")) {
        return Promise.reject(new Error("Workflow states denied."));
      }

      return Promise.reject(new Error(`Unexpected LMS request: ${url}`));
    }) as typeof fetch;
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
    const { card, itemSelect, stateSelect, status } = createAssignmentLookupFixture();
    itemSelect.dataset.selectedValue = "assignment-1";

    await expect(harness.hydrateGradebookItemsForCard(card, "")).resolves.toEqual({
      status: "failed",
      source: "workflow-states",
      message: "Workflow states denied.",
    });
    expect(itemSelect.disabled).toBe(false);
    expect(itemSelect.options.map((option) => option.value)).toEqual(["", "assignment-1"]);
    expect(itemSelect.options.map((option) => option.textContent)).toEqual([
      "Select gradebook item",
      "Essay (assignment-1)",
    ]);
    expect(stateSelect.disabled).toBe(false);
    expect(stateSelect.options.map((option) => option.textContent)).toEqual([
      "Workflow states unavailable",
    ]);
    expect(status.hidden).toBe(false);
    expect(status.dataset.tone).toBe("error");
    expect(status.textContent).toBe("Workflow states denied.");
  });

  it("reports rejected debounced work through the detached-work owner", async () => {
    const timers = new FakeTimers();
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() => Promise.reject(new Error("not called"))) as typeof fetch,
      timers,
    });
    const defect = new Error("Post-fetch rendering failed.");
    const schedule = harness.bindDebouncedSearch({
      debounceMs: 0,
      searchInput: new FakeInput(),
      onInput: () => Promise.reject(defect),
    });

    schedule();
    timers.runAll();
    await Promise.resolve();

    expect(harness.reportedErrors).toEqual([defect]);
  });

  it("preserves an existing selection that is absent from refreshed results", async () => {
    const fetchImpl = (() =>
      Promise.resolve(
        Response.json({
          courses: [{ courseId: "other-course", title: "Other course" }],
          hasMore: false,
        }),
      )) as typeof fetch;
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
    const select = new FakeSelect();
    const selectedOption = new FakeOption();
    selectedOption.value = "selected-course";
    selectedOption.textContent = "Selected course";
    selectedOption.selected = true;
    select.append(selectedOption);

    await expect(harness.hydrateCourseSelect({}, select, "other")).resolves.toEqual({
      status: "complete",
    });
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
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
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

    await expect(currentRequest).resolves.toEqual({ status: "complete" });
    await expect(staleRequest).resolves.toEqual({ status: "superseded" });
    expect(select.options.map((option) => option.value)).toEqual(["", "new-item"]);
    expect(requestCacheModes).toEqual(["no-store", "no-store"]);
  });

  it("ignores exact-item results superseded by an LMS connection switch", async () => {
    let exactRequestStarted = false;
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;

      if (url.includes("connection-1") && url.endsWith("/gradebook-items")) {
        return Promise.resolve(
          Response.json({ items: [{ assignmentId: "other-item", title: "Other item" }] }),
        );
      }

      if (url.includes("connection-1") && url.endsWith("/gradebook-items/resolve")) {
        exactRequestStarted = true;
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        });
      }

      if (url.includes("connection-2") && url.endsWith("/gradebook-items")) {
        return Promise.resolve(
          Response.json({ items: [{ assignmentId: "saved-item", title: "Current item" }] }),
        );
      }

      if (url.includes("connection-2") && url.endsWith("/workflow-states")) {
        return Promise.resolve(Response.json({ states: [] }));
      }

      return Promise.reject(new Error(`Unexpected request: ${url}`));
    }) as typeof fetch;
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
    const { card, itemSelect } = createAssignmentLookupFixture();
    itemSelect.dataset.selectedValue = "saved-item";

    const staleRequest = harness.hydrateGradebookItemsForCard(card, "");
    await waitForBrowserCondition(
      () => exactRequestStarted,
      "Exact gradebook-item request did not start",
    );
    harness.setSelectedLmsConnectionId("connection-2");
    const currentRequest = harness.hydrateGradebookItemsForCard(card, "");

    await expect(currentRequest).resolves.toEqual({ status: "complete" });
    await expect(staleRequest).resolves.toEqual({ status: "superseded" });
    expect(itemSelect.selectedOptions.map((option) => option.value)).toEqual(["saved-item"]);
    expect(itemSelect.options.map((option) => option.textContent)).toEqual([
      "Select gradebook item",
      "Current item (saved-item)",
    ]);
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
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
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

    await expect(clearedRequest).resolves.toEqual({ status: "complete" });
    await expect(staleRequest).resolves.toEqual({ status: "superseded" });
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
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
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

    await expect(currentRequest).resolves.toEqual({ status: "complete" });
    await expect(staleRequest).resolves.toEqual({ status: "superseded" });
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
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
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

    await expect(staleStateRequest).resolves.toEqual({ status: "superseded" });
    expect(stateSelect.options.map((option) => option.textContent)).toEqual([
      "Select gradebook item first",
    ]);
    expect(stateSelect.disabled).toBe(true);

    resolveItems(Response.json({ items: [] }));
    await expect(currentItemRequest).resolves.toEqual({ status: "complete" });
  });
});
