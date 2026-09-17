import { z } from "zod";
import { badgeRecordsReturnHref } from "./learner-record-link";
import { parseReviewQueuePageQuery, reviewQueuePageUrl } from "./review-queue-page-query";

export const badgeRecordReturnLink = (
  tenantId: string,
  value: unknown,
): { href: string; label: string } | null => {
  const raw = z.string().max(8192).safeParse(value);
  if (!raw.success || !raw.data.startsWith("/")) return null;
  try {
    const url = new URL(raw.data, "https://return.invalid");
    const base = `/tenants/${encodeURIComponent(tenantId)}/admin/operations`;
    if (url.origin !== "https://return.invalid") return null;
    if (url.pathname === `${base}/review-queue`)
      return {
        href: reviewQueuePageUrl(
          tenantId,
          parseReviewQueuePageQuery(Object.fromEntries(url.searchParams)),
        ),
        label: "Back to review queue",
      };
    if (url.pathname !== `${base}/learner-records`) return null;
    const learner = z.string().trim().min(1).max(320).parse(url.searchParams.get("learner"));
    const params = new URLSearchParams({ learner });
    const returnTo = badgeRecordsReturnHref(tenantId, url.searchParams.get("returnTo"));
    if (returnTo) params.set("returnTo", returnTo);
    return { href: `${base}/learner-records?${params}`, label: "Back to learner record" };
  } catch {
    return null;
  }
};
