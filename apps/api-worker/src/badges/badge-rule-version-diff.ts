import type { BadgeIssuanceRuleVersionSnapshot } from "@credtrail/db";
import { resolveRuleDefinition } from "../rules/badge-rule-definition-resolver";

export interface RuleDefinitionDiffChange {
  readonly path: string;
  readonly changeType: "added" | "removed" | "changed";
  readonly before: unknown;
  readonly after: unknown;
}

export interface RuleDefinitionDiffDescription {
  readonly text: string;
  readonly reviewImpact: "loosening" | "tightening" | "neutral";
}

export interface BadgeRuleVersionDefinitionDiff {
  readonly changed: boolean;
  readonly changeCount: number;
  readonly changes: readonly RuleDefinitionDiffChange[];
}

/** Reviewer-facing groups of immutable rule-version metadata. */
export type BadgeRuleVersionSnapshotDiffField =
  | "name"
  | "description"
  | "badge_template"
  | "badge_artwork"
  | "organization_scope"
  | "template_owner_scope"
  | "lms_provider"
  | "lms_connection";

/** One changed immutable metadata value between governed rule versions. */
export interface BadgeRuleVersionSnapshotDiffChange {
  readonly field: BadgeRuleVersionSnapshotDiffField;
  readonly before: string | null;
  readonly after: string | null;
}

/** Complete immutable metadata comparison between governed rule versions. */
export interface BadgeRuleVersionSnapshotDiff {
  readonly changed: boolean;
  readonly changeCount: number;
  readonly changes: readonly BadgeRuleVersionSnapshotDiffChange[];
}

const isJsonRecord = (value: unknown): value is Record<string, unknown> => {
  return value !== null && typeof value === "object" && !Array.isArray(value);
};

const areJsonValuesEqual = (left: unknown, right: unknown): boolean => {
  return JSON.stringify(left) === JSON.stringify(right);
};

const collectRuleDefinitionDiff = (
  baseValue: unknown,
  compareValue: unknown,
  path: string,
  changes: RuleDefinitionDiffChange[],
): void => {
  if (areJsonValuesEqual(baseValue, compareValue)) {
    return;
  }

  if (Array.isArray(baseValue) && Array.isArray(compareValue)) {
    const maxLength = Math.max(baseValue.length, compareValue.length);

    for (let index = 0; index < maxLength; index += 1) {
      const childPath = `${path}[${String(index)}]`;

      if (!(index in baseValue)) {
        changes.push({
          path: childPath,
          changeType: "added",
          before: null,
          after: compareValue[index],
        });
        continue;
      }

      if (!(index in compareValue)) {
        changes.push({
          path: childPath,
          changeType: "removed",
          before: baseValue[index],
          after: null,
        });
        continue;
      }

      collectRuleDefinitionDiff(baseValue[index], compareValue[index], childPath, changes);
    }

    return;
  }

  if (isJsonRecord(baseValue) && isJsonRecord(compareValue)) {
    const keySet = new Set<string>([...Object.keys(baseValue), ...Object.keys(compareValue)]);

    for (const key of keySet) {
      const childPath = path.length === 0 ? key : `${path}.${key}`;
      const baseHasKey = Object.prototype.hasOwnProperty.call(baseValue, key);
      const compareHasKey = Object.prototype.hasOwnProperty.call(compareValue, key);

      if (!baseHasKey) {
        changes.push({
          path: childPath,
          changeType: "added",
          before: null,
          after: compareValue[key],
        });
        continue;
      }

      if (!compareHasKey) {
        changes.push({
          path: childPath,
          changeType: "removed",
          before: baseValue[key],
          after: null,
        });
        continue;
      }

      collectRuleDefinitionDiff(baseValue[key], compareValue[key], childPath, changes);
    }

    return;
  }

  changes.push({
    path: path.length === 0 ? "$" : path,
    changeType: "changed",
    before: baseValue,
    after: compareValue,
  });
};

export const buildBadgeRuleVersionDefinitionDiff = (input: {
  readonly baseRuleJson: string;
  readonly selectedRuleJson: string;
}): BadgeRuleVersionDefinitionDiff => {
  const changes: RuleDefinitionDiffChange[] = [];

  collectRuleDefinitionDiff(
    resolveRuleDefinition(input.baseRuleJson),
    resolveRuleDefinition(input.selectedRuleJson),
    "definition",
    changes,
  );

  return {
    changed: changes.length > 0,
    changeCount: changes.length,
    changes,
  };
};

const badgeTemplateSnapshotLabel = (snapshot: BadgeIssuanceRuleVersionSnapshot): string => {
  return `${snapshot.badgeTemplateTitle} (${snapshot.badgeTemplateId})`;
};

/** Compares immutable authoring metadata between two governed rule versions. */
export const buildBadgeRuleVersionSnapshotDiff = (
  baseSnapshot: BadgeIssuanceRuleVersionSnapshot,
  selectedSnapshot: BadgeIssuanceRuleVersionSnapshot,
): BadgeRuleVersionSnapshotDiff => {
  const changes: BadgeRuleVersionSnapshotDiffChange[] = [];
  const addChange = (
    field: BadgeRuleVersionSnapshotDiffField,
    before: string | null,
    after: string | null,
  ): void => {
    if (before !== after) {
      changes.push({ field, before, after });
    }
  };

  addChange("name", baseSnapshot.name, selectedSnapshot.name);
  addChange("description", baseSnapshot.description, selectedSnapshot.description);
  addChange(
    "badge_template",
    badgeTemplateSnapshotLabel(baseSnapshot),
    badgeTemplateSnapshotLabel(selectedSnapshot),
  );
  addChange(
    "badge_artwork",
    baseSnapshot.badgeTemplateImageUri,
    selectedSnapshot.badgeTemplateImageUri,
  );
  addChange("organization_scope", baseSnapshot.orgUnitId, selectedSnapshot.orgUnitId);
  addChange("template_owner_scope", baseSnapshot.ownerOrgUnitId, selectedSnapshot.ownerOrgUnitId);
  addChange("lms_provider", baseSnapshot.lmsProviderKind, selectedSnapshot.lmsProviderKind);
  addChange("lms_connection", baseSnapshot.lmsConnectionId, selectedSnapshot.lmsConnectionId);

  return {
    changed: changes.length > 0,
    changeCount: changes.length,
    changes,
  };
};

const snapshotDiffFieldLabels = {
  name: "Rule name",
  description: "Description",
  badge_template: "Badge template",
  badge_artwork: "Badge artwork",
  organization_scope: "Organization scope",
  template_owner_scope: "Badge template owner scope",
  lms_provider: "LMS provider",
  lms_connection: "LMS connection",
} satisfies Readonly<Record<BadgeRuleVersionSnapshotDiffField, string>>;

const formatSnapshotDiffValue = (
  field: BadgeRuleVersionSnapshotDiffField,
  value: string,
): string => {
  if (field === "lms_provider") {
    switch (value) {
      case "canvas":
        return "Canvas";
      case "moodle":
        return "Moodle";
      case "blackboard_ultra":
        return "Blackboard Ultra";
      case "d2l_brightspace":
        return "D2L Brightspace";
      case "sakai":
        return "Sakai";
      default:
        return value;
    }
  }

  return `“${value}”`;
};

const describeSnapshotDiffChange = (change: BadgeRuleVersionSnapshotDiffChange): string => {
  if (change.field === "badge_artwork") {
    if (change.before === null) {
      return "Badge artwork was added.";
    }

    if (change.after === null) {
      return "Badge artwork was removed.";
    }

    return "Badge artwork changed.";
  }

  const label = snapshotDiffFieldLabels[change.field];

  if (change.before === null && change.after !== null) {
    return `${label} set to ${formatSnapshotDiffValue(change.field, change.after)}.`;
  }

  if (change.before !== null && change.after === null) {
    return `${label} removed; it was ${formatSnapshotDiffValue(change.field, change.before)}.`;
  }

  if (change.before === null || change.after === null) {
    return `${label} changed.`;
  }

  return `${label} changed from ${formatSnapshotDiffValue(
    change.field,
    change.before,
  )} to ${formatSnapshotDiffValue(change.field, change.after)}.`;
};

/** Describes immutable snapshot changes in reviewer-facing language. */
export const describeBadgeRuleVersionSnapshotDiff = (
  diff: BadgeRuleVersionSnapshotDiff,
): readonly string[] => {
  if (!diff.changed) {
    return ["No rule setting changes detected."];
  }

  return diff.changes.map(describeSnapshotDiffChange);
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

export const describeRuleDefinitionDiffChange = (change: RuleDefinitionDiffChange): string => {
  return describeRuleDefinitionDiffChangeDetailed(change).text;
};

export const describeRuleDefinitionDiff = (
  diff: BadgeRuleVersionDefinitionDiff,
): readonly string[] => {
  if (!diff.changed) {
    return ["No rule definition changes detected."];
  }

  return diff.changes.map(describeRuleDefinitionDiffChange);
};

export const describeRuleDefinitionDiffDetails = (
  diff: BadgeRuleVersionDefinitionDiff,
): readonly RuleDefinitionDiffDescription[] => {
  if (!diff.changed) {
    return [
      {
        text: "No rule definition changes detected.",
        reviewImpact: "neutral",
      },
    ];
  }

  return diff.changes.map(describeRuleDefinitionDiffChangeDetailed);
};
