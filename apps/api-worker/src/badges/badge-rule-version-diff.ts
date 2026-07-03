import { resolveRuleDefinition } from "../rules/badge-rule-definition-resolver";

export interface RuleDefinitionDiffChange {
  readonly path: string;
  readonly changeType: "added" | "removed" | "changed";
  readonly before: unknown;
  readonly after: unknown;
}

export interface BadgeRuleVersionDefinitionDiff {
  readonly changed: boolean;
  readonly changeCount: number;
  readonly changes: readonly RuleDefinitionDiffChange[];
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

  return JSON.stringify(value) ?? "unserializable value";
};

const fieldLabelFromPath = (path: string): string => {
  const lastSegment = path.split(".").at(-1) ?? path;

  return lastSegment
    .replace(/\[\d+\]/g, "")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replaceAll("_", " ")
    .toLowerCase();
};

const formatThresholdChange = (change: RuleDefinitionDiffChange): string | null => {
  if (
    change.changeType !== "changed" ||
    !change.path.endsWith(".minScore") ||
    typeof change.before !== "number" ||
    typeof change.after !== "number"
  ) {
    return null;
  }

  if (change.after < change.before) {
    return `Minimum grade lowered from ${String(change.before)}% to ${String(change.after)}%.`;
  }

  if (change.after > change.before) {
    return `Minimum grade raised from ${String(change.before)}% to ${String(change.after)}%.`;
  }

  return null;
};

export const describeRuleDefinitionDiffChange = (change: RuleDefinitionDiffChange): string => {
  const thresholdChange = formatThresholdChange(change);

  if (thresholdChange !== null) {
    return thresholdChange;
  }

  const fieldLabel = fieldLabelFromPath(change.path);

  switch (change.changeType) {
    case "added":
      return `${fieldLabel} added: ${formatValue(change.after)}.`;
    case "removed":
      return `${fieldLabel} removed: ${formatValue(change.before)}.`;
    case "changed":
      return `${fieldLabel} changed from ${formatValue(change.before)} to ${formatValue(
        change.after,
      )}.`;
  }
};

export const describeRuleDefinitionDiff = (
  diff: BadgeRuleVersionDefinitionDiff,
): readonly string[] => {
  if (!diff.changed) {
    return ["No rule definition changes detected."];
  }

  return diff.changes.map(describeRuleDefinitionDiffChange);
};
