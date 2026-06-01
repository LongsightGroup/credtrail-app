import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminButton,
  AdminButtonLink,
  AdminCheckboxRow,
  AdminField,
  AdminFieldset,
  AdminForm,
  AdminPanel,
  AdminStatus,
} from "../components";
import {
  buildAccessGovernanceAdminPath,
  tenantAccessDelegatedGrantCreatePath,
} from "../access-admin-helpers";

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
  const governancePath = buildAccessGovernanceAdminPath(input.tenantId);

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
          <select name="delegateUserId" required>
            {input.tenantMemberSelectOptions}
          </select>
        </AdminField>
        <p class="ct-admin__hint">
          Choose the tenant member receiving the delegation. They must already belong to this
          tenant.
        </p>
        <AdminField label="Org unit">
          <select name="orgUnitId" required>
            {input.activeOrgUnitSelectOptions}
          </select>
        </AdminField>
        <AdminFieldset legend="Allowed badge actions">
          <AdminCheckboxRow>
            <input name="allowedAction" type="checkbox" value="issue_badge" checked />
            Issue badges
          </AdminCheckboxRow>
          <AdminCheckboxRow>
            <input name="allowedAction" type="checkbox" value="revoke_badge" />
            Revoke badges
          </AdminCheckboxRow>
          <AdminCheckboxRow>
            <input name="allowedAction" type="checkbox" value="manage_lifecycle" />
            Change badge status
          </AdminCheckboxRow>
        </AdminFieldset>
        <p class="ct-admin__hint">
          “Change badge status” covers non-revocation lifecycle changes such as suspend, expire, or
          restore.
        </p>
        <AdminField label="Limit to badge template (optional)">
          <select name="badgeTemplateIds">{input.optionalBadgeTemplateScopeOptions}</select>
        </AdminField>
        <p class="ct-admin__hint">
          Leave blank to allow all badge templates inside the selected org-unit scope.
        </p>
        <AdminField label="Ends at">
          <input name="endsAt" type="datetime-local" required />
        </AdminField>
        <p class="ct-admin__hint">
          Delegations are time-boxed. Choose when this authority should expire.
        </p>
        <AdminField label="Reason (optional)">
          <input name="reason" type="text" placeholder="Coverage for spring term operations." />
        </AdminField>
        <div class="ct-cluster">
          <AdminButton type="submit">Save delegation</AdminButton>
          <AdminButtonLink href={governancePath} variant="secondary">
            Back to governance
          </AdminButtonLink>
        </div>
      </AdminForm>
    </AdminPanel>
  );
};
