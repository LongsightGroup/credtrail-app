import { z } from "zod";
import type { BadgeRuleReviewQueueEntryView } from "../badge-rule-review-queue-workspace";
import { buildReviewQueuePagePath } from "./review-queue-admin-helpers";

const cursorSchema = z.object({
  at: z.iso.datetime({ offset: true }),
  id: z.string().min(1).max(256),
  direction: z.enum(["older", "newer"]),
});
const querySchema = z.object({
  completed: z.string().max(256).default(""),
  sort: z.enum(["oldest", "newest"]).default("newest"),
  decision: z.enum(["all", "issue", "dismiss"]).default("all"),
  q: z.string().trim().max(320).default(""),
  reviewStatus: z.enum(["pending", "resolved"]).default("pending"),
  review: z.string().max(256).default(""),
  cursor: z.string().max(1024).optional(),
});
export interface ReviewQueuePageQuery {
  completed?: string;
  sort: "oldest" | "newest";
  decision: "all" | "issue" | "dismiss";
  q: string;
  reviewStatus: "pending" | "resolved";
  review: string;
  cursor: z.infer<typeof cursorSchema> | undefined;
}
export interface ReviewQueueCorrection {
  query: ReviewQueuePageQuery;
  evaluationId: string;
  comment: string;
  message: string;
}
export const parseReviewQueuePageQuery = (value: unknown): ReviewQueuePageQuery => {
  const query = querySchema.parse(value);
  return {
    ...query,
    decision: query.reviewStatus === "resolved" ? query.decision : "all",
    cursor: query.cursor ? cursorSchema.parse(JSON.parse(query.cursor)) : undefined,
  };
};
export const reviewQueuePageUrl = (tenantId: string, query: ReviewQueuePageQuery): string => {
  const params = new URLSearchParams();
  if (query.reviewStatus === "resolved") params.set("reviewStatus", "resolved");
  if (query.sort === "oldest") params.set("sort", "oldest");
  if (query.reviewStatus === "resolved" && query.decision !== "all")
    params.set("decision", query.decision);
  if (query.q) params.set("q", query.q);
  if (query.review) params.set("review", query.review);
  else if (query.completed) params.set("completed", query.completed);
  if (query.cursor) params.set("cursor", JSON.stringify(query.cursor));
  return `${buildReviewQueuePagePath(tenantId)}${params.size ? `?${params}` : ""}`;
};
export const paginateReviewQueue = (
  rows: readonly BadgeRuleReviewQueueEntryView[],
  query: ReviewQueuePageQuery,
  limit: number,
): {
  entries: BadgeRuleReviewQueueEntryView[];
  older: ReviewQueuePageQuery["cursor"];
  newer: ReviewQueuePageQuery["cursor"];
} => {
  const entries = rows.slice(0, limit);
  if (query.cursor && (query.cursor.direction === "newer") !== (query.sort === "oldest"))
    entries.reverse();
  const newest = query.sort === "oldest" ? entries.at(-1) : entries[0];
  const oldest = query.sort === "oldest" ? entries[0] : entries.at(-1);
  const cursor = (
    entry: BadgeRuleReviewQueueEntryView,
    direction: "older" | "newer",
  ): NonNullable<ReviewQueuePageQuery["cursor"]> => ({
    at:
      query.reviewStatus === "resolved"
        ? (entry.reviewedAt ?? entry.evaluatedAt)
        : entry.evaluatedAt,
    id: entry.evaluationId,
    direction,
  });
  return {
    entries,
    older:
      oldest &&
      (query.cursor?.direction === "newer" ||
        (rows.length > limit &&
          (query.cursor?.direction === "older" || (!query.cursor && query.sort !== "oldest"))))
        ? cursor(oldest, "older")
        : undefined,
    newer:
      newest &&
      (query.cursor?.direction === "older" ||
        (rows.length > limit &&
          (query.cursor?.direction === "newer" || (!query.cursor && query.sort === "oldest"))))
        ? cursor(newest, "newer")
        : undefined,
  };
};
