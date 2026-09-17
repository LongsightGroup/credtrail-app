import {
  findBadgeIssuanceRuleEvaluationById,
  listBadgeIssuanceRuleEvaluations,
  type SqlDatabase,
} from "@credtrail/db";
import { reviewQueuePageUrl, type ReviewQueuePageQuery } from "./review-queue-page-query";

/** Offers the next pending match after a tenant-scoped completed decision. */
export const loadReviewQueueContinuation = async (
  db: SqlDatabase,
  tenantId: string,
  query: ReviewQueuePageQuery,
): Promise<{ href: string | null } | undefined> => {
  if (!query.completed) return undefined;
  const completed = await findBadgeIssuanceRuleEvaluationById(db, {
    tenantId,
    evaluationId: query.completed,
  });
  if (completed?.reviewStatus !== "resolved") return undefined;
  const [next] = await listBadgeIssuanceRuleEvaluations(db, {
    tenantId,
    reviewStatus: "pending",
    issuanceStatus: "review_required",
    search: query.q,
    cursor: {
      at: completed.evaluatedAt,
      id: completed.id,
      direction: query.sort === "oldest" ? "newer" : "older",
    },
    limit: 1,
  });
  return {
    href: next
      ? `${reviewQueuePageUrl(tenantId, { ...query, reviewStatus: "pending", decision: "all", completed: "", review: next.id })}#review-decision-panel`
      : null,
  };
};
