import { describe, expect, it } from "vitest";
import { Script, createContext } from "node:vm";
import { describeBadgeRuleCondition } from "./badge-rule-description";
import { badgeRuleVersionDisplayFields } from "./badge-rule-presentation";
import { buildBadgeRuleVersionRecord } from "../test-support/badge-rule-version";
import { BADGE_RULE_DESCRIPTION_SCRIPT_SOURCE } from "../ui/page-assets/script-asset-fragments";

describe("requirement-based rule descriptions", () => {
  it("uses the course score, including both bounds", () => {
    expect(
      describeBadgeRuleCondition({
        type: "grade_threshold",
        courseId: "course_1",
        minScore: 80,
        maxScore: 95,
      }),
    ).toBe("Final course score between 80% and 95%");
  });

  it("uses the verified gradebook title within its course and does not invent score units", () => {
    expect(
      describeBadgeRuleCondition(
        { type: "assignment_submission", courseId: "biology", assignmentId: "exam", minScore: 80 },
        {
          courses: [],
          assignments: [
            { courseId: "chemistry", assignmentId: "exam", title: "Wrong exam" },
            { courseId: "biology", assignmentId: "exam", title: "Final Exam" },
          ],
        },
      ),
    ).toBe("Submit Final Exam with a score of at least 80");
  });

  it("distinguishes alternatives, combined requirements, and exclusions", () => {
    const first = { type: "survey_completion", surveyId: "survey" } as const;
    const second = { type: "prerequisite_badge", badgeTemplateId: "badge" } as const;
    expect(describeBadgeRuleCondition({ all: [first, second] })).toBe(
      "Complete the survey; Earn the prerequisite badge",
    );
    expect(describeBadgeRuleCondition({ any: [first, second] })).toBe("Meet any of 2 requirements");
    expect(describeBadgeRuleCondition({ not: first })).toBe("Exclude: Complete the survey");
  });

  it("derives descriptions from the saved requirements instead of old generated names", () => {
    const version = buildBadgeRuleVersionRecord();
    version.snapshot.name = "Final Exam badge, used by 1 other rule – Custom requirements";
    expect(badgeRuleVersionDisplayFields(version).displayName).toBe(
      "Final course score at least 80%",
    );
    expect(
      badgeRuleVersionDisplayFields({
        ...version,
        ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_1","minScore":90}}',
      }).displayName,
    ).toBe("Final course score at least 90%");
  });

  it("keeps the requirement description available with a custom label", () => {
    const version = buildBadgeRuleVersionRecord({
      ruleJson:
        '{"customLabel":"Honors pathway","conditions":{"type":"grade_threshold","courseId":"course_1","minScore":90}}',
    });
    expect(badgeRuleVersionDisplayFields(version)).toMatchObject({
      displayName: "Honors pathway",
      requirementSummary: "Final course score at least 90%",
    });
  });

  it("keeps malformed records readable without falling back to an inaccurate name", () => {
    const version = buildBadgeRuleVersionRecord();
    expect(badgeRuleVersionDisplayFields({ ...version, ruleJson: "invalid" }).displayName).toBe(
      "Requirements unavailable",
    );
  });

  it("runs the same description logic in the browser asset", () => {
    const context = createContext({ result: null });
    if (typeof BADGE_RULE_DESCRIPTION_SCRIPT_SOURCE === "string")
      throw new Error("Expected generated source");
    new Script(
      `${BADGE_RULE_DESCRIPTION_SCRIPT_SOURCE.body}\nresult = describeBadgeRuleCondition({type: "grade_threshold", courseId: "course", minScore: 85});`,
    ).runInContext(context);
    expect(context.result).toBe("Final course score at least 85%");
  });
});
