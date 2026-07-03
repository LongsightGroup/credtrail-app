import type { BadgeIssuanceRuleEvidenceEvaluationNode } from "@credtrail/validation";

export type AssertionEvidenceEvaluationOutcomeKind =
  | "matched"
  | "failed_condition"
  | "missing_data"
  | "group";

export interface AssertionEvidenceEvaluationOutcomeRow {
  outcome: AssertionEvidenceEvaluationOutcomeKind;
  detail: string;
}

const outcomeKindFromNode = (
  node: BadgeIssuanceRuleEvidenceEvaluationNode,
): AssertionEvidenceEvaluationOutcomeKind => {
  if (node.children !== undefined && node.children.length > 0) {
    return "group";
  }

  if (node.resultKind === "missing_data") {
    return "missing_data";
  }

  if (node.resultKind === "failed_condition") {
    return "failed_condition";
  }

  return node.matched ? "matched" : "failed_condition";
};

const visitEvaluationNode = (
  node: BadgeIssuanceRuleEvidenceEvaluationNode,
  rows: AssertionEvidenceEvaluationOutcomeRow[],
): void => {
  if (node.children === undefined || node.children.length === 0) {
    rows.push({
      outcome: outcomeKindFromNode(node),
      detail: node.detail,
    });
    return;
  }

  rows.push({
    outcome: "group",
    detail: node.detail,
  });

  for (const child of node.children) {
    visitEvaluationNode(child, rows);
  }
};

export const flattenEvaluationTree = (
  tree: BadgeIssuanceRuleEvidenceEvaluationNode | null,
): AssertionEvidenceEvaluationOutcomeRow[] => {
  if (tree === null) {
    return [];
  }

  const rows: AssertionEvidenceEvaluationOutcomeRow[] = [];
  visitEvaluationNode(tree, rows);
  return rows;
};

export const summarizeEvaluationFacts = (facts: {
  grades: readonly unknown[];
  completions: readonly unknown[];
  submissions: readonly unknown[];
  surveyCompletions: readonly unknown[];
  customFields: readonly unknown[];
  earnedBadgeTemplateIds: readonly unknown[];
}): string[] => {
  const parts: string[] = [];

  if (facts.grades.length > 0) {
    parts.push(`${String(facts.grades.length)} grade fact${facts.grades.length === 1 ? "" : "s"}`);
  }

  if (facts.completions.length > 0) {
    parts.push(
      `${String(facts.completions.length)} completion fact${facts.completions.length === 1 ? "" : "s"}`,
    );
  }

  if (facts.submissions.length > 0) {
    parts.push(
      `${String(facts.submissions.length)} submission fact${facts.submissions.length === 1 ? "" : "s"}`,
    );
  }

  if (facts.surveyCompletions.length > 0) {
    parts.push(
      `${String(facts.surveyCompletions.length)} survey completion${facts.surveyCompletions.length === 1 ? "" : "s"}`,
    );
  }

  if (facts.customFields.length > 0) {
    parts.push(
      `${String(facts.customFields.length)} custom field fact${facts.customFields.length === 1 ? "" : "s"}`,
    );
  }

  if (facts.earnedBadgeTemplateIds.length > 0) {
    parts.push(
      `${String(facts.earnedBadgeTemplateIds.length)} prerequisite badge${facts.earnedBadgeTemplateIds.length === 1 ? "" : "s"}`,
    );
  }

  return parts;
};
