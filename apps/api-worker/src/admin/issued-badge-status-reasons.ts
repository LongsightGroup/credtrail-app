import type { AssertionLifecycleState, AssertionLifecycleReasonCode } from "@credtrail/db";

export const statusReasonLabels: Readonly<Record<AssertionLifecycleReasonCode, string>> = {
  administrative_hold: "Administrative hold",
  policy_violation: "Policy violation",
  appeal_pending: "Appeal pending",
  appeal_resolved: "Appeal resolved",
  credential_expired: "Credential expired",
  issuer_requested: "Requested by issuer",
  other: "Other",
};

export const statusReasons: Readonly<
  Record<AssertionLifecycleState, readonly AssertionLifecycleReasonCode[]>
> = {
  active: ["appeal_resolved", "issuer_requested", "other"],
  suspended: [
    "administrative_hold",
    "policy_violation",
    "appeal_pending",
    "issuer_requested",
    "other",
  ],
  revoked: ["policy_violation", "issuer_requested", "other"],
  expired: ["credential_expired", "issuer_requested", "other"],
};
