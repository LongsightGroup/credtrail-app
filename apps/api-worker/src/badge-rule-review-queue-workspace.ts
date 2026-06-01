import {
  findBadgeIssuanceRuleById,
  listBadgeIssuanceRuleEvaluations,
  type BadgeIssuanceRuleEvaluationRecord,
  type SqlDatabase,
} from "@credtrail/db";
import {
  evaluateBadgeIssuanceRuleDefinition,
  summarizeBadgeIssuanceRuleEvaluation,
  type BadgeIssuanceRuleEvaluationSummary,
} from "./rules/engine";
import { parseFactsFromEvaluationRecord } from "./routes/badge-rule-evaluation-helpers";

export interface BadgeRuleReviewQueueApiEntry extends BadgeIssuanceRuleEvaluationRecord {
  ruleName: string | null;
  badgeTemplateId: string | null;
  facts: ReturnType<typeof parseFactsFromEvaluationRecord>;
  evaluation: unknown;
  evaluationSummary: BadgeIssuanceRuleEvaluationSummary | null;
}

export interface BadgeRuleReviewQueueEntryView {
  evaluationId: string;
  evaluatedAt: string;
  recipientIdentity: string;
  ruleId: string;
  ruleName: string | null;
  evaluationSummary: BadgeIssuanceRuleEvaluationSummary | null;
  reviewStatus: string;
}

export const formatBadgeRuleReviewQueueSummary = (
  summary: BadgeIssuanceRuleEvaluationSummary | null,
): string => {
  if (summary === null) {
    return "Awaiting manual review";
  }

  const parts: string[] = [];

  if (summary.matchedLeafCount > 0) {
    parts.push(`${summary.matchedLeafCount} matched`);
  }

  if (summary.failedConditionCount > 0) {
    parts.push(`${summary.failedConditionCount} failed`);
  }

  if (summary.missingDataCount > 0) {
    parts.push(`${summary.missingDataCount} missing`);
  }

  if (parts.length === 0) {
    return "Awaiting manual review";
  }

  return parts.join(" · ");
};

const evaluationPayloadFromRecord = (
  evaluationRecord: BadgeIssuanceRuleEvaluationRecord,
): unknown => {
  try {
    const parsedPayload = JSON.parse(evaluationRecord.evaluationJson) as unknown;

    if (
      parsedPayload === null ||
      typeof parsedPayload !== "object" ||
      !("evaluation" in parsedPayload) ||
      parsedPayload.evaluation === null ||
      typeof parsedPayload.evaluation !== "object"
    ) {
      return null;
    }

    return parsedPayload.evaluation;
  } catch {
    return null;
  }
};

export const loadBadgeRuleReviewQueueForApi = async (
  db: SqlDatabase,
  tenantId: string,
  input?: {
    reviewStatus?: "pending" | "resolved";
    limit?: number;
  },
): Promise<BadgeRuleReviewQueueApiEntry[]> => {
  const reviewStatus = input?.reviewStatus ?? "pending";
  const evaluations =
    (await listBadgeIssuanceRuleEvaluations(db, {
      tenantId,
      issuanceStatus: "review_required",
      reviewStatus,
      limit: input?.limit ?? 50,
    })) ?? [];
  const ruleCache = new Map<string, Awaited<ReturnType<typeof findBadgeIssuanceRuleById>>>();

  return Promise.all(
    evaluations.map(async (evaluationRecord) => {
      let rule = ruleCache.get(evaluationRecord.ruleId);

      if (rule === undefined) {
        rule = await findBadgeIssuanceRuleById(db, tenantId, evaluationRecord.ruleId);
        ruleCache.set(evaluationRecord.ruleId, rule);
      }

      const evaluation = evaluationPayloadFromRecord(evaluationRecord);
      const evaluationSummary =
        evaluation !== null &&
        typeof evaluation === "object" &&
        "matched" in evaluation &&
        "tree" in evaluation &&
        typeof evaluation.matched === "boolean" &&
        evaluation.tree !== null &&
        typeof evaluation.tree === "object"
          ? summarizeBadgeIssuanceRuleEvaluation(
              evaluation as ReturnType<typeof evaluateBadgeIssuanceRuleDefinition>,
            )
          : null;

      return {
        ...evaluationRecord,
        ruleName: rule?.name ?? null,
        badgeTemplateId: rule?.badgeTemplateId ?? null,
        facts: parseFactsFromEvaluationRecord(evaluationRecord),
        evaluation,
        evaluationSummary,
      };
    }),
  );
};

export const loadBadgeRuleReviewQueueEntries = async (
  db: SqlDatabase,
  tenantId: string,
  input?: {
    reviewStatus?: "pending" | "resolved";
    limit?: number;
  },
): Promise<BadgeRuleReviewQueueEntryView[]> => {
  const queue = await loadBadgeRuleReviewQueueForApi(db, tenantId, input);

  return queue.map((entry) => ({
    evaluationId: entry.id,
    evaluatedAt: entry.evaluatedAt,
    recipientIdentity: entry.recipientIdentity,
    ruleId: entry.ruleId,
    ruleName: entry.ruleName,
    evaluationSummary: entry.evaluationSummary,
    reviewStatus: entry.reviewStatus ?? "pending",
  }));
};
