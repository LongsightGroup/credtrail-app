import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { FakeElement, FakeInput } from "./test-support/browser-page-asset-harness";

type ExampleCondition = Readonly<Record<string, unknown>>;

interface ExampleTestController {
  readonly sync: (conditions: readonly ExampleCondition[]) => void;
  readonly validate: () => string | null;
}

type BuildSampleFacts = (
  conditions: readonly ExampleCondition[],
  learnerId: string,
) => {
  readonly completions: readonly Readonly<Record<string, unknown>>[];
  readonly grades: readonly Readonly<Record<string, unknown>>[];
};

interface ExampleTestHarness {
  readonly buildSampleFacts: BuildSampleFacts;
  readonly completionField: FakeElement;
  readonly completionHint: FakeElement;
  readonly completionInput: FakeInput;
  readonly controller: ExampleTestController;
  readonly guidance: FakeElement;
  readonly scoreField: FakeElement;
  readonly scoreHint: FakeElement;
  readonly scoreInput: FakeInput;
}

const createExampleControl = (
  key: "score" | "completion",
  name: "testScore" | "testCompletionPercent",
  value: string,
): { readonly field: FakeElement; readonly hint: FakeElement; readonly input: FakeInput } => {
  const field = new FakeElement();
  field.setAttribute("data-rule-builder-example-control", key);
  const input = new FakeInput();
  input.type = "number";
  input.value = value;
  input.setAttribute("name", name);
  input.setAttribute("min", "0");
  input.setAttribute("max", "100");
  const hint = new FakeElement();
  hint.className = "ct-field__hint";
  field.append(input, hint);
  return { field, hint, input };
};

const isExampleTestController = (candidate: unknown): candidate is ExampleTestController => {
  return (
    candidate !== null &&
    typeof candidate === "object" &&
    "sync" in candidate &&
    typeof candidate.sync === "function" &&
    "validate" in candidate &&
    typeof candidate.validate === "function"
  );
};

const createHarness = (): ExampleTestHarness => {
  const conditionModelSource = readFileSync(
    new URL(
      "./ui/page-assets/content/js/institution-admin-rule-builder-condition-model.js",
      import.meta.url,
    ),
    "utf8",
  );
  const exampleTestSource = readFileSync(
    new URL(
      "./ui/page-assets/content/js/institution-admin-rule-builder-example-test.js",
      import.meta.url,
    ),
    "utf8",
  );
  const root = new FakeElement();
  const guidance = new FakeElement();
  guidance.setAttribute("data-rule-builder-example-guidance", "");
  const score = createExampleControl("score", "testScore", "92");
  const completion = createExampleControl("completion", "testCompletionPercent", "100");
  root.append(guidance, score.field, completion.field);
  const context = createContext({
    Array,
    Error,
    HTMLInputElement: FakeInput,
    HTMLElement: FakeElement,
    Number,
    Set,
    String,
    getDefaultCourseId: (): string => "fallback-course",
    getTextFieldValue: (name: string): string => {
      if (name === "testScore") {
        return score.input.value;
      }

      if (name === "testCompletionPercent") {
        return completion.input.value;
      }

      return "";
    },
    ruleBuilderExampleTestFields: root,
  });

  new Script(
    `${conditionModelSource}\n${exampleTestSource}\nglobalThis.__exampleTestController = ruleBuilderExampleTestController; globalThis.__buildSampleFacts = buildSampleFactsFromConditions;`,
  ).runInContext(context);
  const controller = (context as { __exampleTestController?: unknown }).__exampleTestController;
  const buildSampleFacts = (context as { __buildSampleFacts?: unknown }).__buildSampleFacts;

  if (!isExampleTestController(controller)) {
    throw new Error("Generated-example test controller did not load");
  }

  if (typeof buildSampleFacts !== "function") {
    throw new Error("Generated-example fact builder did not load");
  }

  // SAFETY: The production script defines this function, and the runtime guard verifies its callable boundary.
  const verifiedFactBuilder = buildSampleFacts as BuildSampleFacts;
  return {
    buildSampleFacts: verifiedFactBuilder,
    completionField: completion.field,
    completionHint: completion.hint,
    completionInput: completion.input,
    controller,
    guidance,
    scoreField: score.field,
    scoreHint: score.hint,
    scoreInput: score.input,
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

  it("focuses and marks only an invalid relevant value", () => {
    const harness = createHarness();
    harness.controller.sync([{ type: "grade_threshold", minScore: 70 }]);
    harness.scoreInput.value = "";
    harness.completionInput.value = "not-used";

    expect(harness.controller.validate()).toBe("Example score must be a number between 0 and 100.");
    expect(harness.scoreInput.getAttribute("aria-invalid")).toBe("true");
    expect(harness.scoreInput.focusCount).toBe(1);

    harness.scoreInput.value = "70";
    harness.scoreInput.dispatch("input");

    expect(harness.scoreInput.getAttribute("aria-invalid")).toBeNull();
    expect(harness.controller.validate()).toBeNull();
  });

  it("uses both adjustable values in the shared fact-generation path", () => {
    const harness = createHarness();
    harness.scoreInput.value = "86";
    harness.completionInput.value = "73";

    const facts = harness.buildSampleFacts(
      [
        { type: "grade_threshold", courseId: "course-101", scoreField: "current_score" },
        { type: "course_completion", courseId: "course-202", minCompletionPercent: 70 },
      ],
      "learner-1",
    );

    expect(facts.grades).toEqual([
      {
        courseId: "course-101",
        learnerId: "learner-1",
        currentScore: 86,
        finalScore: 86,
      },
    ]);
    expect(facts.completions).toEqual([
      {
        courseId: "course-202",
        learnerId: "learner-1",
        completed: false,
        completionPercent: 73,
      },
    ]);
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
    expect(harness.guidance.textContent).toBe(
      "This rule's example facts come from its configured requirements. There are no values to adjust; run the test or use advanced facts.",
    );
  });
});
