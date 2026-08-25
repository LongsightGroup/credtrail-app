import { describe, expect, it } from "vitest";
import {
  FakeOption,
  FakeSelect,
  waitForBrowserCondition,
} from "./test-support/browser-page-asset-harness";
import {
  createCourseLookupFixture,
  createRuleBuilderConditionCard,
  loadRuleBuilderLmsPickerHarness,
} from "./test-support/rule-builder-lms-picker-harness";

describe("rule-builder LMS course labels", () => {
  it("restores saved labels in one exact batch without changing the rule definition", async () => {
    const requests: Array<{ readonly init: RequestInit | undefined; readonly url: string }> = [];
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;
      requests.push({ init, url });

      if (url.includes("q=settle")) {
        return Promise.resolve(
          Response.json({
            courses: [
              {
                courseCode: "BIO-101",
                courseId: "course-101",
                title: "Foundations of Biology",
              },
            ],
            hasMore: false,
          }),
        );
      }

      if (url.endsWith("/courses/resolve")) {
        return Promise.resolve(
          Response.json({
            courses: [
              {
                courseCode: "CHEM-202",
                courseId: "course-202",
                title: "Organic Chemistry",
              },
              {
                courseCode: "PHYS-303",
                courseId: "course-303",
                title: "Advanced Mechanics",
              },
            ],
          }),
        );
      }

      return Promise.reject(new Error(`Unexpected LMS request: ${url}`));
    }) as typeof fetch;
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
    const { card, summary } = createRuleBuilderConditionCard("program_completion");
    const definition = {
      type: "program_completion",
      courseIds: ["course-101", "course-202", "course-303"],
      minimumCompleted: 2,
    };
    harness.renderConditionFields(card, definition);
    const select = card.querySelector('[data-field="courseIds"]');

    if (!(select instanceof FakeSelect)) {
      throw new Error("Course field did not render a native select");
    }

    expect(harness.readConditionFromCard(card, false)).toEqual(definition);
    await expect(harness.hydrateCourseSelect(card, select, "settle")).resolves.toEqual({
      status: "complete",
    });
    expect(select.selectedOptions.map((option) => option.value)).toEqual(definition.courseIds);
    expect(harness.readConditionFromCard(card, false)).toEqual(definition);
    expect(
      Object.fromEntries(select.options.map((option) => [option.value, option.textContent])),
    ).toMatchObject({
      "course-101": "Foundations of Biology · BIO-101 (course-101)",
      "course-202": "Organic Chemistry · CHEM-202 (course-202)",
      "course-303": "Advanced Mechanics · PHYS-303 (course-303)",
    });

    const resolutionRequest = requests.find((request) => request.url.endsWith("/courses/resolve"));
    expect(resolutionRequest?.init?.method).toBe("POST");
    expect(resolutionRequest?.init?.cache).toBe("no-store");
    const resolutionRequestBody = resolutionRequest?.init?.body;

    if (typeof resolutionRequestBody !== "string") {
      throw new TypeError("Expected exact course resolution to send a JSON string body");
    }

    const parsedResolutionRequest: unknown = JSON.parse(resolutionRequestBody);
    expect(parsedResolutionRequest).toEqual({ courseIds: ["course-202", "course-303"] });
    expect(requests.filter((request) => request.url.endsWith("/courses/resolve"))).toHaveLength(1);

    harness.renderConditionFields(card, definition);
    expect(harness.readConditionFromCard(card, false)).toEqual(definition);
    expect(summary.textContent).toBe(
      "Learner completes at least 2 of: Foundations of Biology · BIO-101 (course-101), Organic Chemistry · CHEM-202 (course-202), Advanced Mechanics · PHYS-303 (course-303)",
    );
  });

  it("keeps saved IDs usable when exact label restoration fails", async () => {
    const fetchImpl = ((input: RequestInfo | URL): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;

      if (url.endsWith("/courses/resolve")) {
        return Promise.resolve(
          Response.json({ error: "The LMS could not resolve saved courses." }, { status: 502 }),
        );
      }

      return Promise.resolve(
        Response.json({
          courses: [{ courseId: "other-course", title: "Other course" }],
          hasMore: false,
        }),
      );
    }) as typeof fetch;
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
    const { card, select, status } = createCourseLookupFixture();
    const selectedOption = new FakeOption();
    selectedOption.value = "saved-course";
    selectedOption.textContent = "saved-course";
    selectedOption.selected = true;
    select.append(selectedOption);

    await expect(harness.hydrateCourseSelect(card, select, "other")).resolves.toEqual({
      status: "complete",
    });
    expect(select.disabled).toBe(false);
    expect(select.selectedOptions.map((option) => option.value)).toEqual(["saved-course"]);
    expect(select.selectedOptions.map((option) => option.textContent)).toEqual(["saved-course"]);
    expect(status.hidden).toBe(false);
    expect(status.dataset.tone).toBe("error");
    expect(status.textContent).toBe(
      "The LMS could not resolve saved courses. Saved course IDs remain visible.",
    );
  });

  it("keeps labels isolated to the LMS connection that authorized them", async () => {
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() =>
        Promise.resolve(
          Response.json({
            courses: [
              {
                courseCode: "BIO-101",
                courseId: "course-101",
                title: "Connection one biology",
              },
            ],
            hasMore: false,
          }),
        )) as typeof fetch,
    });
    const lookup = createCourseLookupFixture();

    await expect(
      harness.hydrateCourseSelect(lookup.card, lookup.select, "biology"),
    ).resolves.toEqual({ status: "complete" });
    expect(lookup.select.options[1]?.textContent).toBe(
      "Connection one biology · BIO-101 (course-101)",
    );

    harness.setSelectedLmsConnectionId("connection-2");
    const restored = createRuleBuilderConditionCard("course_completion");
    harness.renderConditionFields(restored.card, {
      type: "course_completion",
      courseId: "course-101",
      minCompletionPercent: 100,
    });
    const restoredSelect = restored.card.querySelector('[data-field="courseId"]');
    expect(
      restoredSelect instanceof FakeSelect ? restoredSelect.options[1]?.textContent : null,
    ).toBe("course-101");
    expect(restored.summary.textContent).toContain("course-101");
    expect(restored.summary.textContent).not.toContain("Connection one biology");
  });

  it("projects authorized labels into rendered course and assignment summaries", async () => {
    const harness = loadRuleBuilderLmsPickerHarness({
      fetchImpl: (() =>
        Promise.resolve(
          Response.json({
            courses: [
              {
                courseCode: "BIO-101",
                courseId: "course-101",
                title: "Foundations of Biology",
              },
            ],
            hasMore: false,
          }),
        )) as typeof fetch,
    });
    const lookup = createCourseLookupFixture();
    await harness.hydrateCourseSelect(lookup.card, lookup.select, "biology");
    const cases = [
      {
        type: "course_completion",
        courseId: "course-101",
        minCompletionPercent: 80,
      },
      {
        type: "grade_threshold",
        courseId: "course-101",
        minScore: 70,
      },
      {
        type: "assignment_submission",
        courseId: "course-101",
        assignmentId: "essay-1",
      },
    ];

    for (const condition of cases) {
      const rendered = createRuleBuilderConditionCard(condition.type);
      harness.renderConditionFields(rendered.card, condition);
      expect(rendered.summary.textContent).toContain(
        "Foundations of Biology · BIO-101 (course-101)",
      );
    }
  });

  it("supersedes an exact-label request before a newer search can overwrite it", async () => {
    let exactRequestStarted = false;
    let exactRequestAborted = false;
    const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;

      if (url.includes("q=old")) {
        return Promise.resolve(
          Response.json({
            courses: [{ courseId: "other-course", title: "Old search result" }],
            hasMore: false,
          }),
        );
      }

      if (url.endsWith("/courses/resolve")) {
        exactRequestStarted = true;
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            exactRequestAborted = true;
            reject(new Error("aborted"));
          });
        });
      }

      return Promise.resolve(
        Response.json({
          courses: [
            {
              courseCode: "NEW-101",
              courseId: "selected-course",
              title: "Current course",
            },
          ],
          hasMore: false,
        }),
      );
    }) as typeof fetch;
    const harness = loadRuleBuilderLmsPickerHarness({ fetchImpl });
    const { card, select } = createCourseLookupFixture();
    const selectedOption = new FakeOption();
    selectedOption.value = "selected-course";
    selectedOption.textContent = "selected-course";
    selectedOption.selected = true;
    select.append(selectedOption);

    const staleRequest = harness.hydrateCourseSelect(card, select, "old");
    await waitForBrowserCondition(
      () => exactRequestStarted,
      "Expected the stale exact-label request to start",
    );
    const currentRequest = harness.hydrateCourseSelect(card, select, "new");

    await expect(currentRequest).resolves.toEqual({ status: "complete" });
    await expect(staleRequest).resolves.toEqual({ status: "superseded" });
    expect(exactRequestAborted).toBe(true);
    expect(select.selectedOptions.map((option) => option.textContent)).toEqual([
      "Current course · NEW-101 (selected-course)",
    ]);
  });
});
