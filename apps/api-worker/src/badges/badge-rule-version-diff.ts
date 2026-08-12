import type { BadgeIssuanceRuleVersionSnapshot } from "@credtrail/db";
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

/** Reviewer-facing groups of immutable rule-version metadata. */
export type BadgeRuleVersionSnapshotDiffField =
  | "name"
  | "description"
  | "badge_template"
  | "badge_description"
  | "badge_criteria"
  | "badge_artwork"
  | "badge_trust_metadata"
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
    "badge_description",
    baseSnapshot.badgeTemplateDescription,
    selectedSnapshot.badgeTemplateDescription,
  );
  addChange(
    "badge_criteria",
    baseSnapshot.badgeTemplateCriteriaUri,
    selectedSnapshot.badgeTemplateCriteriaUri,
  );
  addChange(
    "badge_artwork",
    baseSnapshot.badgeTemplateImageUri,
    selectedSnapshot.badgeTemplateImageUri,
  );
  addChange(
    "badge_trust_metadata",
    baseSnapshot.badgeTemplateTrustedCredentialMetadataJson,
    selectedSnapshot.badgeTemplateTrustedCredentialMetadataJson,
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
