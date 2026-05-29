import type { BadgeIssuanceRuleEvaluationRecord } from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import {
  evaluateBadgeIssuanceRuleDefinition,
  summarizeBadgeIssuanceRuleEvaluation,
  type BadgeIssuanceRuleEvaluationFacts,
} from "../rules/engine";

export type BadgeRuleEvaluationOutcome = "matched" | "no_match" | "review_required";

export function badgeRuleEvaluationOutcome(
  definition: BadgeIssuanceRuleDefinition,
  evaluation: ReturnType<typeof evaluateBadgeIssuanceRuleDefinition>,
): BadgeRuleEvaluationOutcome {
  if (evaluation.matched) {
    return "matched";
  }

  const summary = summarizeBadgeIssuanceRuleEvaluation(evaluation);

  if (definition.options?.reviewOnMissingFacts === true && summary.missingDataCount > 0) {
    return "review_required";
  }

  return "no_match";
}

export function parseFactsFromEvaluationRecord(
  evaluationRecord: BadgeIssuanceRuleEvaluationRecord,
): BadgeIssuanceRuleEvaluationFacts | null {
  try {
    const parsed = JSON.parse(evaluationRecord.evaluationJson) as unknown;

    if (parsed === null || typeof parsed !== "object" || !("facts" in parsed)) {
      return null;
    }

    const facts = parsed.facts as Partial<BadgeIssuanceRuleEvaluationFacts>;

    if (typeof facts.learnerId !== "string" || typeof facts.nowIso !== "string") {
      return null;
    }

    return {
      learnerId: facts.learnerId,
      nowIso: facts.nowIso,
      grades: Array.isArray(facts.grades) ? facts.grades : [],
      completions: Array.isArray(facts.completions) ? facts.completions : [],
      submissions: Array.isArray(facts.submissions) ? facts.submissions : [],
      surveyCompletions: Array.isArray(facts.surveyCompletions) ? facts.surveyCompletions : [],
      customFields: Array.isArray(facts.customFields) ? facts.customFields : [],
      earnedBadgeTemplateIds: Array.isArray(facts.earnedBadgeTemplateIds)
        ? facts.earnedBadgeTemplateIds
        : [],
    };
  } catch {
    return null;
  }
}
