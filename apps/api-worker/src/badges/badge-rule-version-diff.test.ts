import { describe, expect, it } from "vitest";
import {
  buildBadgeRuleVersionDefinitionDiff,
  describeRuleDefinitionDiff,
} from "./badge-rule-version-diff";

const gradeRuleJson = (minScore: number): string =>
  JSON.stringify({
    conditions: {
      type: "grade_threshold",
      courseId: "CS101",
      scoreField: "final_score",
      minScore,
    },
  });

describe("badge rule version diff descriptions", () => {
  it("describes lowered grade thresholds in reviewer-friendly language", () => {
    const diff = buildBadgeRuleVersionDefinitionDiff({
      baseRuleJson: gradeRuleJson(90),
      selectedRuleJson: gradeRuleJson(80),
    });

    expect(describeRuleDefinitionDiff(diff)).toContain("Minimum grade lowered from 90% to 80%.");
  });

  it("reports unchanged definitions clearly", () => {
    const diff = buildBadgeRuleVersionDefinitionDiff({
      baseRuleJson: gradeRuleJson(90),
      selectedRuleJson: gradeRuleJson(90),
    });

    expect(describeRuleDefinitionDiff(diff)).toEqual(["No rule definition changes detected."]);
  });

  it("uses the canonical stored JSON error for invalid rule JSON", () => {
    expect(() =>
      buildBadgeRuleVersionDefinitionDiff({
        baseRuleJson: "{invalid",
        selectedRuleJson: gradeRuleJson(90),
      }),
    ).toThrow("Stored rule JSON is invalid");
  });

  it("does not format generic numeric changes as percentages", () => {
    const baseRuleJson = JSON.stringify({
      conditions: {
        type: "program_completion",
        courseIds: ["CS101", "CS102", "CS103"],
        minimumCompleted: 2,
      },
    });
    const selectedRuleJson = JSON.stringify({
      conditions: {
        type: "program_completion",
        courseIds: ["CS101", "CS102", "CS103"],
        minimumCompleted: 3,
      },
    });
    const diff = buildBadgeRuleVersionDefinitionDiff({
      baseRuleJson,
      selectedRuleJson,
    });

    expect(describeRuleDefinitionDiff(diff)).toContain("minimum completed changed from 2 to 3.");
  });
});
