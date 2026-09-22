import { badgeRuleVersionDisplayFields } from "./badges/badge-rule-presentation";
import { z } from "zod";
import {
  findBadgeIssuanceRuleVersionById,
  findBadgeIssuanceRuleById,
  findUserById,
  listBadgeIssuanceRuleEvaluations,
  type BadgeIssuanceRuleEvaluationRecord,
  type ListBadgeIssuanceRuleEvaluationsInput,
  type SqlDatabase,
} from "@credtrail/db";
import {
  evaluateBadgeIssuanceRuleDefinition,
  summarizeBadgeIssuanceRuleEvaluation,
  type BadgeIssuanceRuleEvaluationSummary,
} from "./rules/engine";
import { parseFactsFromEvaluationRecord } from "./routes/badge-rule-evaluation-helpers";

export interface BadgeRuleReviewQueueApiEntry extends BadgeIssuanceRuleEvaluationRecord {
  badgeTitle?: string | null;
  missingInformation?: readonly string[];
  ruleName: string | null;
  badgeTemplateId: string | null;
  facts: ReturnType<typeof parseFactsFromEvaluationRecord>;
  evaluation: unknown;
  evaluationSummary: BadgeIssuanceRuleEvaluationSummary | null;
}

export interface BadgeRuleReviewQueueEntryView {
  versionId?: string;
  recipientIdentityType?: BadgeIssuanceRuleEvaluationRecord["recipientIdentityType"];
  assertionId?: string | null;
  decision?: string | null;
  decisionNote?: string | null;
  reviewedAt?: string | null;
  reviewerEmail?: string | null;
  evaluationId: string;
  evaluatedAt: string;
  recipientIdentity: string;
  ruleId: string;
  badgeTitle?: string | null;
  missingInformation?: readonly string[];
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

const reviewNodeSchema = z.object({
  detail: z.string(),
  resultKind: z.enum(["matched", "failed_condition", "missing_data"]).optional(),
  get children() {
    return z.array(reviewNodeSchema).optional();
  },
});

/** Reads missing-information explanations from a persisted evaluation without trusting its shape. */
export const reviewMissingInformation = (evaluation: unknown): readonly string[] => {
  const parsed = z.object({ tree: reviewNodeSchema }).safeParse(evaluation);
  if (!parsed.success) return [];
  const details: string[] = [];
  const visit = (node: z.infer<typeof reviewNodeSchema>): void => {
    if (node.children?.length) node.children.forEach(visit);
    else if (node.resultKind === "missing_data") details.push(node.detail);
  };
  visit(parsed.data.tree);
  return [...new Set(details)];
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
  input?: Omit<ListBadgeIssuanceRuleEvaluationsInput, "tenantId" | "issuanceStatus">,
): Promise<BadgeRuleReviewQueueApiEntry[]> => {
  const reviewStatus = input?.reviewStatus ?? "pending";
  const evaluations =
    (await listBadgeIssuanceRuleEvaluations(db, {
      ...input,
      tenantId,
      ...(reviewStatus === "pending" ? { issuanceStatus: "review_required" as const } : {}),
      reviewStatus,
      limit: input?.limit ?? 50,
    })) ?? [];
  const versionCache = new Map<
    string,
    Awaited<ReturnType<typeof findBadgeIssuanceRuleVersionById>>
  >();

  const ruleCache = new Map<string, ReturnType<typeof findBadgeIssuanceRuleById>>();
  return Promise.all(
    evaluations.map(async (evaluationRecord) => {
      let version = versionCache.get(evaluationRecord.versionId);

      if (version === undefined) {
        version = await findBadgeIssuanceRuleVersionById(db, {
          tenantId,
          ruleId: evaluationRecord.ruleId,
          versionId: evaluationRecord.versionId,
        });
        versionCache.set(evaluationRecord.versionId, version);
      }

      let rulePromise = ruleCache.get(evaluationRecord.ruleId);
      if (rulePromise === undefined) {
        rulePromise = findBadgeIssuanceRuleById(db, tenantId, evaluationRecord.ruleId);
        ruleCache.set(evaluationRecord.ruleId, rulePromise);
      }
      const rule = await rulePromise;
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
        ruleName:
          version === null || version === undefined
            ? null
            : badgeRuleVersionDisplayFields(version, rule ?? { customLabel: null }).displayName,
        badgeTitle: version?.snapshot.badgeTemplateTitle ?? null,
        missingInformation: reviewMissingInformation(evaluation),
        badgeTemplateId: version?.snapshot.badgeTemplateId ?? null,
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
  input?: Omit<ListBadgeIssuanceRuleEvaluationsInput, "tenantId" | "issuanceStatus">,
): Promise<BadgeRuleReviewQueueEntryView[]> => {
  const queue = await loadBadgeRuleReviewQueueForApi(db, tenantId, input);

  const reviewers = new Map(
    await Promise.all(
      [
        ...new Set(
          queue.flatMap((entry) => (entry.reviewedByUserId ? [entry.reviewedByUserId] : [])),
        ),
      ].map(async (userId) => [userId, (await findUserById(db, userId))?.email ?? null] as const),
    ),
  );
  return queue.map((entry) => ({
    versionId: entry.versionId,
    recipientIdentityType: entry.recipientIdentityType,
    assertionId: entry.assertionId,
    decision: entry.reviewDecision,
    decisionNote: entry.reviewComment,
    reviewedAt: entry.reviewedAt,
    reviewerEmail: entry.reviewedByUserId ? (reviewers.get(entry.reviewedByUserId) ?? null) : null,
    evaluationId: entry.id,
    evaluatedAt: entry.evaluatedAt,
    recipientIdentity: entry.recipientIdentity,
    ruleId: entry.ruleId,
    ruleName: entry.ruleName,
    badgeTitle: entry.badgeTitle ?? null,
    missingInformation: entry.missingInformation ?? [],
    evaluationSummary: entry.evaluationSummary,
    reviewStatus: entry.reviewStatus ?? "pending",
  }));
};
