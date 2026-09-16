import { ASSERTION_REASON_MAX_LENGTH } from "@credtrail/validation";
import type { IssuedBadgeStatusFormError } from "./issued-badge-status-form";
import { allowedAssertionLifecycleTransitions, type AssertionLifecycleState } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminField,
  AdminForm,
  AdminStatusPill,
  AdminStatus,
} from "./components";
import { CtCheckboxField, CtInput, CtSelect } from "../ui/forms";
import { formatIsoTimestamp } from "../utils/display-format";
import {
  issuedBadgesAssertionPageUrl,
  issuedBadgesPageUrl,
  tenantIssuedBadgeAdminStatusPath,
  type IssuedBadgeLifecycleMode,
  type IssuedBadgesPageFilterValues,
} from "./issued-badges-admin-helpers";

export interface IssuedBadgeStatusSelection {
  readonly assertionId: string;
  readonly badgeTitle: string;
  readonly recipientIdentity: string;
  readonly issuedAt: string;
  readonly state: AssertionLifecycleState;
}

const statusActions = {
  active: {
    mode: "restore",
    label: "Restore badge",
    consequence: "This credential will be active again on its public verification page.",
  },
  suspended: {
    mode: "suspend",
    label: "Suspend badge",
    consequence:
      "The public record will show that this credential is suspended. You can restore it after the issue is resolved.",
  },
  revoked: {
    mode: "revoke",
    label: "Revoke badge",
    consequence:
      "Revocation is permanent. The public record will remain available and show that the credential is revoked.",
  },
  expired: {
    mode: "expire",
    label: "Mark badge expired",
    consequence:
      "The public record will show that this credential has expired. Its history will remain available.",
  },
} as const;

/** Shows the selected record and a bounded, server-submitted status change. */
export const IssuedBadgeStatusPanel = (input: {
  readonly tenantId: string;
  readonly badge: IssuedBadgeStatusSelection;
  readonly formError?: IssuedBadgeStatusFormError | undefined;
  readonly mode: IssuedBadgeLifecycleMode | null;
  readonly filters: IssuedBadgesPageFilterValues;
}): HtmlEscapedString | Promise<HtmlEscapedString> => {
  const { badge, filters, tenantId } = input;
  const allowed = allowedAssertionLifecycleTransitions(badge.state);
  const requestedTarget = input.formError?.targetState ?? null;
  const targetState = allowed.find((state) =>
    requestedTarget !== null ? state === requestedTarget : statusActions[state].mode === input.mode,
  );
  const action = targetState === undefined ? null : statusActions[targetState];
  const statusHref = issuedBadgesAssertionPageUrl(tenantId, filters, badge.assertionId, "status");
  return (
    <section
      id="issued-badge-lifecycle-panel"
      class="ct-admin__setup-panel ct-stack"
      aria-labelledby="issued-badge-lifecycle-title"
    >
      <h3 id="issued-badge-lifecycle-title">{badge.badgeTitle}</h3>
      <p>
        Issued to <strong>{badge.recipientIdentity}</strong> on {formatIsoTimestamp(badge.issuedAt)}{" "}
        UTC.
      </p>
      <p>
        Current status: <AdminStatusPill tone={badge.state}>{badge.state}</AdminStatusPill>
      </p>
      <AdminActions>
        <AdminButtonLink
          href={issuedBadgesAssertionPageUrl(tenantId, filters, badge.assertionId, "audit")}
          variant="secondary"
        >
          View badge record and history
        </AdminButtonLink>
        <AdminButtonLink href={issuedBadgesPageUrl(tenantId, filters)} variant="quiet">
          Close
        </AdminButtonLink>
      </AdminActions>
      {input.formError ? (
        <AdminStatus data-tone="error">{input.formError.message}</AdminStatus>
      ) : null}
      {action === null || targetState === undefined ? (
        allowed.length === 0 ? (
          <p>This badge is permanently revoked. Its record and history remain available.</p>
        ) : (
          <AdminActions>
            {allowed.map((state) => (
              <AdminButtonLink
                href={issuedBadgesAssertionPageUrl(
                  tenantId,
                  filters,
                  badge.assertionId,
                  statusActions[state].mode,
                )}
                variant="secondary"
              >
                {statusActions[state].label}
              </AdminButtonLink>
            ))}
          </AdminActions>
        )
      ) : (
        <AdminForm
          id="issued-badge-status-form"
          method="post"
          action={tenantIssuedBadgeAdminStatusPath(tenantId)}
          className="ct-admin__form ct-admin__setup-form ct-stack"
        >
          <h4>{action.label}</h4>
          <p>{action.consequence}</p>
          <CtInput type="hidden" name="assertionId" value={badge.assertionId} />
          <CtInput type="hidden" name="toState" value={targetState} />
          {Object.entries(filters).map(([name, value]) => (
            <CtInput type="hidden" name={name} value={String(value)} />
          ))}
          <AdminField label="Reason">
            <CtSelect name="reasonCode" required>
              {[
                ["", "Choose a reason"],
                ["administrative_hold", "Administrative hold"],
                ["policy_violation", "Policy violation"],
                ["appeal_pending", "Appeal pending"],
                ["appeal_resolved", "Appeal resolved"],
                ["credential_expired", "Credential expired"],
                ["issuer_requested", "Requested by issuer"],
                ["other", "Other"],
              ].map(([value, label]) => (
                <option value={value} selected={input.formError?.reasonCode === value}>
                  {label}
                </option>
              ))}
            </CtSelect>
          </AdminField>
          <AdminField label="Reason details (optional)">
            <CtInput
              name="reason"
              type="text"
              maxlength={ASSERTION_REASON_MAX_LENGTH}
              value={input.formError?.reason ?? ""}
            />
          </AdminField>
          {targetState === "revoked" ? (
            <CtCheckboxField
              label="I understand this badge cannot be restored"
              name="confirmRevocation"
              value="yes"
              required
            />
          ) : null}
          <AdminActions>
            <AdminButton type="submit" variant={targetState === "revoked" ? "danger" : "primary"}>
              {action.label}
            </AdminButton>
            <AdminButtonLink href={statusHref} variant="quiet">
              Cancel
            </AdminButtonLink>
          </AdminActions>
        </AdminForm>
      )}
    </section>
  );
};
