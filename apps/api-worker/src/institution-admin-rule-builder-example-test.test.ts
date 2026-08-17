import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { FakeElement, FakeInput } from "./test-support/browser-page-asset-harness";

interface ExampleTestController {
  readonly sync: (conditions: readonly Readonly<Record<string, unknown>>[]) => void;
  readonly validationMessage: (values: {
    readonly completion: string;
    readonly score: string;
  }) => string | null;
}

interface ExampleTestHarness {
  readonly completionField: FakeElement;
  readonly completionHint: FakeElement;
  readonly completionInput: FakeInput;
  readonly controller: ExampleTestController;
  readonly emptyMessage: FakeElement;
  readonly guidance: FakeElement;
  readonly scoreField: FakeElement;
  readonly scoreHint: FakeElement;
  readonly scoreInput: FakeInput;
}

type CreateExampleTestController = (elements: {
  readonly completionField: FakeElement;
  readonly completionHint: FakeElement;
  readonly completionInput: FakeInput;
  readonly emptyMessage: FakeElement;
  readonly guidance: FakeElement;
  readonly scoreField: FakeElement;
  readonly scoreHint: FakeElement;
  readonly scoreInput: FakeInput;
}) => ExampleTestController;

const loadExampleTestController = (): CreateExampleTestController => {
  const source = readFileSync(
    new URL(
      "./ui/page-assets/content/js/institution-admin-rule-builder-example-test.js",
      import.meta.url,
    ),
    "utf8",
  );
  const context = createContext({ Array, Map, Number, Set, String });
  new Script(
    `${source}\nglobalThis.__createController = createRuleBuilderExampleTestController;`,
  ).runInContext(context);
  const createController = (context as { __createController?: unknown }).__createController;

  if (typeof createController !== "function") {
    throw new Error("Generated-example test controller did not load");
  }

  // SAFETY: The VM source defines this function, and the runtime guard verifies the boundary.
  return createController as CreateExampleTestController;
};

const createHarness = (): ExampleTestHarness => {
  const createController = loadExampleTestController();
  const elements = {
    completionField: new FakeElement(),
    completionHint: new FakeElement(),
    completionInput: new FakeInput(),
    emptyMessage: new FakeElement(),
    guidance: new FakeElement(),
    scoreField: new FakeElement(),
    scoreHint: new FakeElement(),
    scoreInput: new FakeInput(),
  };

  return {
    ...elements,
    controller: createController(elements),
  };
};

describe("rule-builder generated-example controls", () => {
  it("shows only score for a grade threshold and explains the configured boundary", () => {
    const harness = createHarness();

    harness.controller.sync([
      {
        type: "grade_threshold",
        courseId: "course-101",
        scoreField: "final_score",
        minScore: 80,
      },
    ]);

    expect(harness.scoreField.hidden).toBe(false);
    expect(harness.scoreInput.disabled).toBe(false);
    expect(harness.scoreInput.required).toBe(true);
    expect(harness.scoreHint.textContent).toBe("Configured requirement: final score at least 80%.");
    expect(harness.completionField.hidden).toBe(true);
    expect(harness.completionInput.disabled).toBe(true);
  });

  it("refreshes from score to completion when the rule definition changes", () => {
    const harness = createHarness();
    harness.controller.sync([
      { type: "grade_threshold", scoreField: "current_score", minScore: 70 },
    ]);
    expect(harness.scoreHint.textContent).toBe(
      "Configured requirement: current score at least 70%.",
    );

    harness.controller.sync([
      { type: "course_completion", courseId: "course-101", minCompletionPercent: 75 },
    ]);

    expect(harness.scoreField.hidden).toBe(true);
    expect(harness.scoreInput.disabled).toBe(true);
    expect(harness.completionField.hidden).toBe(false);
    expect(harness.completionInput.disabled).toBe(false);
    expect(harness.completionInput.required).toBe(true);
    expect(harness.completionHint.textContent).toBe(
      "Configured requirement: at least 75% of gradebook items complete.",
    );
    expect(harness.guidance.textContent).toBe("One generated value can affect this rule.");
  });

  it("validates only the generated values relevant to the current rule", () => {
    const harness = createHarness();
    harness.controller.sync([{ type: "grade_threshold", minScore: 70 }]);

    expect(harness.controller.validationMessage({ score: "", completion: "not-used" })).toBe(
      "Example score must be a number between 0 and 100.",
    );
    expect(harness.controller.validationMessage({ score: "70", completion: "not-used" })).toBe(
      null,
    );

    harness.controller.sync([{ type: "course_completion", minCompletionPercent: 75 }]);

    expect(harness.controller.validationMessage({ score: "not-used", completion: "101" })).toBe(
      "Example completion must be a number between 0 and 100.",
    );
    expect(harness.controller.validationMessage({ score: "not-used", completion: "75" })).toBe(
      null,
    );
  });

  it("shows each distinct variable once for a compound rule", () => {
    const harness = createHarness();

    harness.controller.sync([
      { type: "grade_threshold", scoreField: "final_score", minScore: 80 },
      { not: { type: "assignment_submission", minScore: 60 } },
      { type: "course_completion", minCompletionPercent: 90 },
      { type: "program_completion", courseIds: ["one", "two", "three"], minimumCompleted: 2 },
    ]);

    expect(harness.scoreField.hidden).toBe(false);
    expect(harness.completionField.hidden).toBe(false);
    expect(harness.scoreHint.textContent).toContain("final score at least 80%");
    expect(harness.scoreHint.textContent).toContain("gradebook item score of at least 60%");
    expect(harness.completionHint.textContent).toContain(
      "at least 90% of gradebook items complete",
    );
    expect(harness.completionHint.textContent).toContain("2 of 3 configured courses complete");
    expect(harness.guidance.textContent).toBe("Two generated values can affect this rule.");
    expect(harness.emptyMessage.hidden).toBe(true);
  });

  it("explains when configured requirements leave no values to adjust", () => {
    const harness = createHarness();

    harness.controller.sync([
      { type: "survey_completion", surveyId: "exit-survey", requireCompleted: true },
      { type: "assignment_submission", assignmentId: "essay", requireSubmitted: true },
      { type: "custom_field", fieldName: "standing", expectedValue: "eligible" },
    ]);

    expect(harness.scoreField.hidden).toBe(true);
    expect(harness.completionField.hidden).toBe(true);
    expect(harness.emptyMessage.hidden).toBe(false);
    expect(harness.guidance.textContent).toBe("No generated values need adjustment for this rule.");
  });
});
