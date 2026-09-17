import { z } from "zod";
import type { AssertionRecord } from "@credtrail/db";
import {
  buildIssuedBadgesPagePath,
  issuedBadgesPageUrl,
  safeParseIssuedBadgesPageQuery,
} from "./issued-badges-admin-helpers";

/** Only return to this tenant's records list, with validated list filters. */
export const badgeRecordsReturnHref = (tenantId: string, value: unknown): string | null => {
  const parsed = z.string().max(8192).safeParse(value);
  if (!parsed.success || !parsed.data.startsWith("/")) return null;
  let url: URL;
  try {
    url = new URL(parsed.data, "https://return.invalid");
  } catch {
    return null;
  }
  if (
    url.origin !== "https://return.invalid" ||
    url.pathname !== buildIssuedBadgesPagePath(tenantId)
  )
    return null;
  const filters = safeParseIssuedBadgesPageQuery(Object.fromEntries(url.searchParams));
  return filters.ok
    ? issuedBadgesPageUrl(tenantId, filters.value.filters, {
        limit: String(filters.value.filters.limit),
      })
    : null;
};

/** Link only identities supported by the existing tenant-scoped learner lookup. */
export const learnerRecordLink = (
  tenantId: string,
  recipientIdentityType: AssertionRecord["recipientIdentityType"],
  recipientIdentity: string,
  returnHref?: string,
): string | null => {
  if (recipientIdentityType !== "email") return null;
  const query = new URLSearchParams({ learner: recipientIdentity });
  const safeReturn = badgeRecordsReturnHref(tenantId, returnHref);
  if (safeReturn) query.set("returnTo", safeReturn);
  return `/tenants/${encodeURIComponent(tenantId)}/admin/operations/learner-records?${query}`;
};
