import { badgeRuleLmsProviderLabel } from "./badge-rule-lms-provider-label";
import type {
  BadgeRuleVersionDefinitionDiff,
  BadgeRuleVersionSnapshotDiff,
  BadgeRuleVersionSnapshotDiffField,
  RuleDefinitionDiffChange,
} from "./badge-rule-version-diff";

/** Reviewer-facing explanation of one structural rule-definition change. */
export interface RuleDefinitionDiffDescription {
  readonly text: string;
  readonly reviewImpact: "loosening" | "tightening" | "neutral";
}

/** One reviewer-facing before-and-after row for immutable version metadata. */
export interface BadgeRuleVersionSnapshotDiffRow {
  readonly label: string;
  readonly before: string;
  readonly after: string;
}

const isJsonRecord = (value: unknown): value is Record<string, unknown> => {
  return value !== null && typeof value === "object" && !Array.isArray(value);
};

const snapshotDiffFieldLabels = {
  name: "Rule name",
  description: "Description",
  badge_template: "Badge template",
  badge_description: "Badge description",
  badge_criteria: "Badge criteria",
  badge_artwork: "Badge artwork",
  badge_trust_metadata: "Badge trust metadata",
  organization_scope: "Organization scope",
  template_owner_scope: "Badge template owner scope",
  lms_provider: "LMS provider",
  lms_connection: "LMS connection",
} satisfies Readonly<Record<BadgeRuleVersionSnapshotDiffField, string>>;

const formatSnapshotDiffValue = (
  field: BadgeRuleVersionSnapshotDiffField,
  value: string | null,
  position: "before" | "after",
): string => {
  if (value === null) {
    return "Not set";
  }

  if (field === "badge_artwork") {
    return position === "before" ? "Previous artwork" : "New artwork";
  }

  if (field === "badge_trust_metadata") {
    return position === "before" ? "Previous trust metadata" : "Updated trust metadata";
  }

  if (field === "lms_provider") {
    switch (value) {
      case "canvas":
      case "moodle":
      case "blackboard_ultra":
      case "d2l_brightspace":
      case "sakai":
        return badgeRuleLmsProviderLabel(value);
      default:
        return value;
    }
  }

  return value;
};

/** Projects changed immutable metadata into scannable reviewer-facing rows. */
export const badgeRuleVersionSnapshotDiffRows = (
  diff: BadgeRuleVersionSnapshotDiff,
): readonly BadgeRuleVersionSnapshotDiffRow[] => {
  return diff.changes.map((change) => ({
    label: snapshotDiffFieldLabels[change.field],
    before: formatSnapshotDiffValue(change.field, change.before, "before"),
    after: formatSnapshotDiffValue(change.field, change.after, "after"),
  }));
};

const formatValue = (value: unknown): string => {
  if (typeof value === "number") {
    return String(value);
  }

  if (typeof value === "string") {
    return value;
  }

  if (value === null) {
    return "not set";
  }

  if (isJsonRecord(value)) {
    const conditionSummary = formatConditionSummary(value);

    if (conditionSummary !== null) {
      return conditionSummary;
    }
  }

  return "structured requirement";
};

const fieldLabelFromPath = (path: string): string => {
  const lastSegment = path.split(".").at(-1) ?? path;

  return lastSegment
    .replace(/\[\d+\]/g, "")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replaceAll("_", " ")
    .toLowerCase();
};

const formatConditionSummary = (value: Record<string, unknown>): string | null => {
  const type = typeof value.type === "string" ? value.type : null;

  switch (type) {
    case "grade_threshold": {
      const course = typeof value.courseId === "string" ? value.courseId : "the selected course";
      return `grade threshold for ${course}`;
    }
    case "course_completion": {
      const course = typeof value.courseId === "string" ? value.courseId : "the selected course";
      return `course completion for ${course}`;
    }
    case "program_completion":
      return "program completion requirement";
    case "assignment_submission": {
      const assignment =
        typeof value.assignmentId === "string" ? value.assignmentId : "the selected assignment";
      return `assignment submission for ${assignment}`;
    }
    case "survey_completion": {
      const survey = typeof value.surveyId === "string" ? value.surveyId : "the selected survey";
      return `survey completion for ${survey}`;
    }
    case "custom_field": {
      const field = typeof value.fieldName === "string" ? value.fieldName : "custom field";
      return `custom field requirement for ${field}`;
    }
    case "time_window":
      return "time window requirement";
    case "prerequisite_badge":
      return "prerequisite badge requirement";
    default:
      return null;
  }
};

const formatThresholdChange = (
  change: RuleDefinitionDiffChange,
): RuleDefinitionDiffDescription | null => {
  if (
    change.changeType !== "changed" ||
    typeof change.before !== "number" ||
    typeof change.after !== "number"
  ) {
    return null;
  }

  if (change.path.endsWith(".minScore")) {
    if (change.after < change.before) {
      return {
        text: `Minimum grade lowered from ${String(change.before)}% to ${String(change.after)}%.`,
        reviewImpact: "loosening",
      };
    }

    if (change.after > change.before) {
      return {
        text: `Minimum grade raised from ${String(change.before)}% to ${String(change.after)}%.`,
        reviewImpact: "tightening",
      };
    }
  }

  if (change.path.endsWith(".maxScore")) {
    if (change.after > change.before) {
      return {
        text: `Maximum grade cap raised from ${String(change.before)}% to ${String(change.after)}%.`,
        reviewImpact: "loosening",
      };
    }

    if (change.after < change.before) {
      return {
        text: `Maximum grade cap lowered from ${String(change.before)}% to ${String(change.after)}%.`,
        reviewImpact: "tightening",
      };
    }
  }

  return null;
};

const formatCompletionChange = (
  change: RuleDefinitionDiffChange,
): RuleDefinitionDiffDescription | null => {
  if (
    change.changeType !== "changed" ||
    typeof change.before !== "number" ||
    typeof change.after !== "number"
  ) {
    return null;
  }

  if (change.path.endsWith(".minCompletionPercent")) {
    if (change.after < change.before) {
      return {
        text: `Completion requirement lowered from ${String(change.before)}% to ${String(change.after)}%.`,
        reviewImpact: "loosening",
      };
    }

    if (change.after > change.before) {
      return {
        text: `Completion requirement raised from ${String(change.before)}% to ${String(change.after)}%.`,
        reviewImpact: "tightening",
      };
    }
  }

  if (change.path.endsWith(".minimumCompleted")) {
    if (change.after < change.before) {
      return {
        text: `Required completed courses lowered from ${String(change.before)} to ${String(change.after)}.`,
        reviewImpact: "loosening",
      };
    }

    if (change.after > change.before) {
      return {
        text: `Required completed courses raised from ${String(change.before)} to ${String(change.after)}.`,
        reviewImpact: "tightening",
      };
    }
  }

  return null;
};

const formatRemovedRequirement = (
  change: RuleDefinitionDiffChange,
): RuleDefinitionDiffDescription | null => {
  if (change.changeType !== "removed") {
    return null;
  }

  if (isJsonRecord(change.before) && formatConditionSummary(change.before) !== null) {
    return {
      text: `Requirement removed: ${formatConditionSummary(change.before)}.`,
      reviewImpact: "loosening",
    };
  }

  if (change.path.includes(".courseIds[")) {
    return {
      text: `Listed course removed from program requirement: ${formatValue(change.before)}.`,
      reviewImpact: "loosening",
    };
  }

  return null;
};

const describeRuleDefinitionDiffChangeDetailed = (
  change: RuleDefinitionDiffChange,
): RuleDefinitionDiffDescription => {
  const thresholdChange = formatThresholdChange(change);

  if (thresholdChange !== null) {
    return thresholdChange;
  }

  const completionChange = formatCompletionChange(change);

  if (completionChange !== null) {
    return completionChange;
  }

  const removedRequirement = formatRemovedRequirement(change);

  if (removedRequirement !== null) {
    return removedRequirement;
  }

  const fieldLabel = fieldLabelFromPath(change.path);

  switch (change.changeType) {
    case "added":
      return {
        text: `${fieldLabel} added: ${formatValue(change.after)}.`,
        reviewImpact: "neutral",
      };
    case "removed":
      return {
        text: `${fieldLabel} removed: ${formatValue(change.before)}.`,
        reviewImpact: "neutral",
      };
    case "changed":
      return {
        text: `${fieldLabel} changed from ${formatValue(change.before)} to ${formatValue(
          change.after,
        )}.`,
        reviewImpact: "neutral",
      };
  }
};

export const describeRuleDefinitionDiffDetails = (
  diff: BadgeRuleVersionDefinitionDiff,
): readonly RuleDefinitionDiffDescription[] => {
  if (!diff.changed) {
    return [];
  }

  return diff.changes.map(describeRuleDefinitionDiffChangeDetailed);
};
