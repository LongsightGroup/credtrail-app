import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminButton,
  AdminCheckboxRow,
  AdminField,
  AdminFieldset,
  AdminForm,
  AdminPanel,
  AdminStatus,
} from "../components";
import { CtInput, CtSelect } from "../../ui/forms";
import { tenantAccessDelegatedGrantCreatePath } from "../access-admin-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | readonly HonoElement[];

interface RenderDelegationSetupSectionInput {
  tenantId: string;
  tenantMemberSelectOptions: HonoElement;
  activeOrgUnitSelectOptions: HonoElement;
  optionalBadgeTemplateScopeOptions: HonoElement;
  listError?: string | null;
  listNotice?: string | null;
}

export const renderDelegationSetupSection = (
  input: RenderDelegationSetupSectionInput,
): HonoElement => {
  return (
    <AdminPanel id="delegation-setup-panel" className="ct-stack">
      {input.listError !== null && input.listError !== undefined && input.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.listError}</AdminStatus>
      ) : input.listNotice !== null &&
        input.listNotice !== undefined &&
        input.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.listNotice}</AdminStatus>
      ) : null}
      <AdminForm
        id="delegated-grant-form"
        method="post"
        action={tenantAccessDelegatedGrantCreatePath(input.tenantId)}
        className="ct-admin__form ct-admin__setup-form ct-grid"
      >
        <AdminField label="Delegate">
          <CtSelect name="delegateUserId" required>
            {input.tenantMemberSelectOptions}
          </CtSelect>
        </AdminField>
        <p class="ct-admin__hint">
          Choose the tenant member receiving the delegation. They must already belong to this
          tenant.
        </p>
        <AdminField label="Org unit">
          <CtSelect name="orgUnitId" required>
            {input.activeOrgUnitSelectOptions}
          </CtSelect>
        </AdminField>
        <AdminFieldset legend="Allowed badge actions">
          <AdminCheckboxRow name="allowedAction" value="issue_badge" label="Issue badges" checked />
          <AdminCheckboxRow name="allowedAction" value="revoke_badge" label="Revoke badges" />
          <AdminCheckboxRow
            name="allowedAction"
            value="manage_lifecycle"
            label="Change badge status"
          />
          <AdminCheckboxRow
            name="allowedAction"
            value="configure_course_rule"
            label="Set up LTI course badges"
          />
        </AdminFieldset>
        <p class="ct-admin__hint">
          Course badge setup grants let an LTI instructor place approved templates and submit course
          rules for review without becoming a tenant issuer.
        </p>
        <AdminField label="Limit to badge template (optional)">
          <CtSelect name="badgeTemplateIds">{input.optionalBadgeTemplateScopeOptions}</CtSelect>
        </AdminField>
        <p class="ct-admin__hint">
          Leave blank to allow all badge templates inside the selected org-unit scope.
        </p>
        <AdminField label="Ends at">
          <CtInput name="endsAt" type="datetime-local" required />
        </AdminField>
        <p class="ct-admin__hint">
          Delegations are time-boxed. Choose when this authority should expire.
        </p>
        <AdminField label="Reason (optional)">
          <CtInput name="reason" type="text" placeholder="Coverage for spring term operations." />
        </AdminField>
        <AdminButton type="submit">Save delegation</AdminButton>
      </AdminForm>
    </AdminPanel>
  );
};
