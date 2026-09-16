import {
  ASSERTION_REASON_MAX_LENGTH,
  assertionLifecycleTransitionRequestSchema,
  assertionLifecycleStateSchema,
} from "@credtrail/validation";
import type { AssertionLifecycleState } from "@credtrail/db";
import { readOptionalFormField } from "./admin-form-helpers";
import type { IssuedBadgesPageFilterValues } from "./issued-badges-admin-helpers";

export interface IssuedBadgeStatusFormError {
  readonly targetState: AssertionLifecycleState | null;
  readonly reasonCode: string;
  readonly reason: string;
  readonly message: string;
}
export interface IssuedBadgeStatusCorrection {
  readonly assertionId: string;
  readonly filters: IssuedBadgesPageFilterValues;
  readonly form: IssuedBadgeStatusFormError;
}

export const parseIssuedBadgeStatusForm = (
  form: FormData,
):
  | {
      readonly ok: true;
      readonly value: ReturnType<typeof assertionLifecycleTransitionRequestSchema.parse>;
    }
  | { readonly ok: false; readonly error: IssuedBadgeStatusFormError } => {
  const reason = readOptionalFormField(form, "reason") ?? "";
  const reasonCode = readOptionalFormField(form, "reasonCode") ?? "";
  const target = assertionLifecycleStateSchema.safeParse(form.get("toState"));
  const parsed = assertionLifecycleTransitionRequestSchema.safeParse({
    toState: form.get("toState"),
    reasonCode,
    reason: reason || undefined,
    transitionSource: "manual",
  });
  const confirmed =
    target.success && (target.data !== "revoked" || form.get("confirmRevocation") === "yes");
  if (parsed.success && confirmed) return { ok: true, value: parsed.data };
  const message = !target.success
    ? "Choose an available status action."
    : reason.length > ASSERTION_REASON_MAX_LENGTH
      ? `Shorten the reason details to ${ASSERTION_REASON_MAX_LENGTH} characters or fewer.`
      : !parsed.success
        ? "Choose a reason for this status change."
        : "Confirm that revocation is permanent before revoking this badge.";
  return {
    ok: false,
    error: { targetState: target.success ? target.data : null, reason, reasonCode, message },
  };
};
