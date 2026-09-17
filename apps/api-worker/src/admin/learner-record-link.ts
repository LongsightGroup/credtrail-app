import type { AssertionRecord } from "@credtrail/db";

/** Link only identities supported by the existing tenant-scoped learner lookup. */
export const learnerRecordLink = (
  tenantId: string,
  recipientIdentityType: AssertionRecord["recipientIdentityType"],
  recipientIdentity: string,
): string | null =>
  recipientIdentityType === "email"
    ? `/tenants/${encodeURIComponent(tenantId)}/admin/operations/learner-records?${new URLSearchParams({ learner: recipientIdentity })}`
    : null;
