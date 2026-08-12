import type { BadgeIssuanceRuleVersionRecord } from "@credtrail/db";
import {
  buildBadgeRuleVersionDefinitionDiff,
  buildBadgeRuleVersionSnapshotDiff,
} from "../badges/badge-rule-version-diff";
import {
  badgeRuleVersionSnapshotDiffRows,
  describeRuleDefinitionDiffDetails,
  type BadgeRuleVersionSnapshotDiffRow,
  type RuleDefinitionDiffDescription,
} from "../badges/badge-rule-version-diff-presentation";

/** Complete comparison state shown to a badge-rule reviewer. */
export type BadgeRuleReviewComparison =
  | { readonly kind: "unavailable" }
  | {
      readonly kind: "available";
      readonly baseVersionNumber: number;
      readonly settingRows: readonly BadgeRuleVersionSnapshotDiffRow[];
      readonly requirementChanges: readonly RuleDefinitionDiffDescription[];
      readonly changeCount: number;
    };

/** Exactly one action state supported by the approval review panel. */
export type BadgeRuleReviewAction =
  | { readonly kind: "decide" }
  | { readonly kind: "reopen" }
  | { readonly kind: "read_only" };

/** Builds a complete comparison with no partially populated diff state. */
export const buildBadgeRuleReviewComparison = (input: {
  readonly baseVersion: BadgeIssuanceRuleVersionRecord | null;
  readonly selectedVersion: BadgeIssuanceRuleVersionRecord;
}): BadgeRuleReviewComparison => {
  if (input.baseVersion === null) {
    return { kind: "unavailable" };
  }

  const settingRows = badgeRuleVersionSnapshotDiffRows(
    buildBadgeRuleVersionSnapshotDiff(input.baseVersion.snapshot, input.selectedVersion.snapshot),
  );
  const requirementChanges = describeRuleDefinitionDiffDetails(
    buildBadgeRuleVersionDefinitionDiff({
      baseRuleJson: input.baseVersion.ruleJson,
      selectedRuleJson: input.selectedVersion.ruleJson,
    }),
  );

  return {
    kind: "available",
    baseVersionNumber: input.baseVersion.versionNumber,
    settingRows,
    requirementChanges,
    changeCount: settingRows.length + requirementChanges.length,
  };
};

/** Resolves authorization facts into one valid review-panel action state. */
export const buildBadgeRuleReviewAction = (input: {
  readonly canDecide: boolean;
  readonly canReopen: boolean;
}): BadgeRuleReviewAction => {
  if (input.canDecide && input.canReopen) {
    throw new Error("Badge rule review cannot be both decidable and reopenable");
  }

  if (input.canReopen) {
    return { kind: "reopen" };
  }

  return input.canDecide ? { kind: "decide" } : { kind: "read_only" };
};
