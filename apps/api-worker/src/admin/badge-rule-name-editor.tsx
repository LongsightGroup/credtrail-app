import type { BadgeIssuanceRuleRecord, BadgeIssuanceRuleVersionRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { badgeRuleVersionDisplayFields } from "../badges/badge-rule-presentation";
import { CtInput } from "../ui/forms";
import { AdminActions, AdminButton, AdminForm } from "./components";

/** Inline metadata editor shared by the rule list and version page. */
export const BadgeRuleNameEditor = (input: {
  readonly rule?: BadgeIssuanceRuleRecord;
  readonly version?: BadgeIssuanceRuleVersionRecord;
  readonly returnTo?: string;
}): HtmlEscapedString | Promise<HtmlEscapedString> => {
  const display =
    input.rule === undefined || input.version === undefined
      ? null
      : badgeRuleVersionDisplayFields(input.version, input.rule);
  return (
    <details
      id="rule-name-editor"
      class="ct-stack ct-admin__rule-name-editor"
      hidden={input.rule === undefined}
    >
      <summary>Rename</summary>
      <AdminForm
        method="post"
        action={
          input.rule === undefined
            ? ""
            : `/tenants/${encodeURIComponent(input.rule.tenantId)}/admin/rules/${encodeURIComponent(input.rule.id)}/name`
        }
      >
        <input type="hidden" name="returnTo" value={input.returnTo ?? ""} />
        <div class="ct-admin__field ct-field">
          <label class="ct-field__label" htmlFor="rule-name-input">
            Name
          </label>
          <CtInput
            id="rule-name-input"
            name="name"
            value={display?.displayName ?? ""}
            maxlength={200}
            required
            describedBy="rule-name-hint"
          />
          <p id="rule-name-hint" class="ct-field__hint">
            Choose a name your team recognizes. Requirements and approvals stay the same.
          </p>
        </div>
        <AdminActions>
          <AdminButton type="submit">Save</AdminButton>
          <button
            type="button"
            class="ct-admin__button ct-action ct-action--quiet ct-action--md"
            data-rule-name-cancel
          >
            Cancel
          </button>
        </AdminActions>
        <p role="status" aria-live="polite" data-rule-name-status />
      </AdminForm>
    </details>
  );
};
