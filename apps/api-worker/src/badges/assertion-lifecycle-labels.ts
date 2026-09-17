import type { AssertionLifecycleState } from "@credtrail/db";

export const assertionLifecycleLabels: Readonly<Record<AssertionLifecycleState, string>> = {
  active: "Active",
  suspended: "Suspended",
  revoked: "Revoked",
  expired: "Expired",
};
