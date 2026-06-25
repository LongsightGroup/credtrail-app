import { describe, expect, it } from "vitest";
import { ltiRosterIssuanceBehaviorFromRuleDefinition } from "./issuance-behavior";

const ruleDefinition = (
  issuanceTiming?: "immediate" | "manual" | "end_of_term",
): Parameters<typeof ltiRosterIssuanceBehaviorFromRuleDefinition>[0] => ({
  conditions: {
    type: "grade_threshold",
    courseId: "course-123",
    scoreField: "final_score",
    minScore: 85,
  },
  ...(issuanceTiming === undefined
    ? {}
    : {
        options: {
          issuanceTiming,
        },
      }),
});

describe("LTI roster issuance behavior", () => {
  it("allows manual roster issuance for manual rules", () => {
    expect(ltiRosterIssuanceBehaviorFromRuleDefinition(ruleDefinition("manual"))).toMatchObject({
      key: "manual",
      label: "Instructor confirmation",
      manualIssuanceAllowed: true,
    });
  });

  it("defaults missing issuance timing to automatic behavior", () => {
    expect(ltiRosterIssuanceBehaviorFromRuleDefinition(ruleDefinition())).toMatchObject({
      key: "immediate",
      label: "Automatic",
      manualIssuanceAllowed: false,
    });
  });

  it("blocks manual roster issuance for end-of-term rules", () => {
    expect(
      ltiRosterIssuanceBehaviorFromRuleDefinition(ruleDefinition("end_of_term")),
    ).toMatchObject({
      key: "end_of_term",
      label: "End-of-term batch",
      manualIssuanceAllowed: false,
    });
  });
});
