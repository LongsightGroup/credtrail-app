import { describe, expect, it } from "vitest";
import { sampleBadgeRuleVersionSnapshot } from "../test-support/badge-rule-version";
import {
  buildBadgeRuleVersionDefinitionDiff,
  buildBadgeRuleVersionSnapshotDiff,
} from "./badge-rule-version-diff";
import {
  badgeRuleVersionSnapshotDiffRows,
  describeRuleDefinitionDiffDetails,
} from "./badge-rule-version-diff-presentation";

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

    expect(describeRuleDefinitionDiffDetails(diff).map((change) => change.text)).toContain(
      "Minimum grade lowered from 90% to 80%.",
    );
  });

  it("reports unchanged definitions clearly", () => {
    const diff = buildBadgeRuleVersionDefinitionDiff({
      baseRuleJson: gradeRuleJson(90),
      selectedRuleJson: gradeRuleJson(90),
    });

    expect(describeRuleDefinitionDiffDetails(diff)).toEqual([]);
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
        type: "custom_field",
        fieldName: "portfolio_reviews",
        expectedValue: 1,
      },
    });
    const selectedRuleJson = JSON.stringify({
      conditions: {
        type: "custom_field",
        fieldName: "portfolio_reviews",
        expectedValue: 2,
      },
    });
    const diff = buildBadgeRuleVersionDefinitionDiff({
      baseRuleJson,
      selectedRuleJson,
    });

    expect(describeRuleDefinitionDiffDetails(diff).map((change) => change.text)).toContain(
      "expected value changed from 1 to 2.",
    );
  });

  it("flags broader reviewer-impacting loosenings", () => {
    const baseRuleJson = JSON.stringify({
      conditions: {
        all: [
          {
            type: "grade_threshold",
            courseId: "CS101",
            maxScore: 80,
          },
          {
            type: "course_completion",
            courseId: "CS101",
            minCompletionPercent: 90,
          },
          {
            type: "program_completion",
            courseIds: ["CS101", "CS102", "CS103"],
            minimumCompleted: 3,
          },
        ],
      },
    });
    const selectedRuleJson = JSON.stringify({
      conditions: {
        all: [
          {
            type: "grade_threshold",
            courseId: "CS101",
            maxScore: 95,
          },
          {
            type: "course_completion",
            courseId: "CS101",
            minCompletionPercent: 70,
          },
          {
            type: "program_completion",
            courseIds: ["CS101", "CS102"],
            minimumCompleted: 2,
          },
        ],
      },
    });
    const diff = buildBadgeRuleVersionDefinitionDiff({
      baseRuleJson,
      selectedRuleJson,
    });

    expect(describeRuleDefinitionDiffDetails(diff)).toEqual(
      expect.arrayContaining([
        {
          text: "Maximum grade cap raised from 80% to 95%.",
          reviewImpact: "loosening",
        },
        {
          text: "Completion requirement lowered from 90% to 70%.",
          reviewImpact: "loosening",
        },
        {
          text: "Listed course removed from program requirement: CS103.",
          reviewImpact: "loosening",
        },
        {
          text: "Required completed courses lowered from 3 to 2.",
          reviewImpact: "loosening",
        },
      ]),
    );
  });

  it("summarizes removed structured conditions without dumping JSON", () => {
    const baseRuleJson = JSON.stringify({
      conditions: {
        all: [
          {
            type: "grade_threshold",
            courseId: "CS101",
            minScore: 80,
          },
          {
            type: "assignment_submission",
            courseId: "CS101",
            assignmentId: "final-project",
            minScore: 90,
          },
        ],
      },
    });
    const selectedRuleJson = JSON.stringify({
      conditions: {
        all: [
          {
            type: "grade_threshold",
            courseId: "CS101",
            minScore: 80,
          },
        ],
      },
    });
    const diff = buildBadgeRuleVersionDefinitionDiff({
      baseRuleJson,
      selectedRuleJson,
    });

    expect(describeRuleDefinitionDiffDetails(diff)).toContainEqual({
      text: "Requirement removed: assignment submission for final-project.",
      reviewImpact: "loosening",
    });
    expect(
      describeRuleDefinitionDiffDetails(diff)
        .map((change) => change.text)
        .join("\n"),
    ).not.toContain('"assignmentId"');
  });
});

describe("badge rule version snapshot diff descriptions", () => {
  it("describes every immutable authoring metadata change", () => {
    const diff = buildBadgeRuleVersionSnapshotDiff(sampleBadgeRuleVersionSnapshot, {
      ...sampleBadgeRuleVersionSnapshot,
      name: "Revised badge rule",
      description: null,
      badgeTemplateId: "badge_template_002",
      badgeTemplateTitle: "Revised badge",
      badgeTemplateDescription: "Revised badge description",
      badgeTemplateCriteriaUri: "https://example.edu/criteria/revised-badge",
      badgeTemplateImageUri: "https://example.edu/revised-badge.png",
      badgeTemplateTrustedCredentialMetadataJson: '{"credentialType":"Certificate"}',
      orgUnitId: "tenant_123:org:registrar",
      ownerOrgUnitId: "tenant_123:org:academic-affairs",
      lmsProviderKind: "sakai",
      lmsConnectionId: null,
    });

    expect(diff.changeCount).toBe(11);
    expect(badgeRuleVersionSnapshotDiffRows(diff)).toEqual([
      { label: "Rule name", before: "Sample badge rule", after: "Revised badge rule" },
      {
        label: "Description",
        before: "Sample badge rule description",
        after: "Not set",
      },
      {
        label: "Badge template",
        before: "Sample badge (badge_template_001)",
        after: "Revised badge (badge_template_002)",
      },
      {
        label: "Badge description",
        before: "Sample badge description",
        after: "Revised badge description",
      },
      {
        label: "Badge criteria",
        before: "https://example.edu/criteria/sample-badge",
        after: "https://example.edu/criteria/revised-badge",
      },
      { label: "Badge artwork", before: "Not set", after: "New artwork" },
      {
        label: "Badge trust metadata",
        before: "Not set",
        after: "Updated trust metadata",
      },
      {
        label: "Organization scope",
        before: "tenant_123:org:institution",
        after: "tenant_123:org:registrar",
      },
      {
        label: "Badge template owner scope",
        before: "tenant_123:org:institution",
        after: "tenant_123:org:academic-affairs",
      },
      { label: "LMS provider", before: "Canvas", after: "Sakai" },
      { label: "LMS connection", before: "lms_123", after: "Not set" },
    ]);
  });

  it("reports unchanged immutable settings clearly", () => {
    const diff = buildBadgeRuleVersionSnapshotDiff(
      sampleBadgeRuleVersionSnapshot,
      sampleBadgeRuleVersionSnapshot,
    );

    expect(badgeRuleVersionSnapshotDiffRows(diff)).toEqual([]);
  });
});
