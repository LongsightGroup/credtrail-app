import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminButton,
  AdminCheckboxRow,
  AdminField,
  AdminFieldset,
  AdminForm,
  AdminPanel,
  AdminStatus,
  AdminStatusPill,
  AdminTable,
  AdminWorkspaceCard,
} from "../components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | HonoElement[];

interface RenderInstitutionAdminAccessSectionsInput {
  accessMembersPath: string;
  accessGovernancePath: string;
  accessApiKeysPath: string;
  accessOrgUnitsPath: string;
  tenantMemberCount: string;
  scopedRoleCount: string;
  delegatedAuthorityGrantCount: string;
  activeApiKeyCount: string;
  revokedApiKeyCount: string;
  orgUnitCount: string;
  tenantMemberRoleSelectOptions: HonoElement;
  tenantMemberRows: HonoElement;
  orgUnitParentOptions: HonoElement;
  tenantMemberSelectOptions: HonoElement;
  activeOrgUnitSelectOptions: HonoElement;
  optionalBadgeTemplateScopeOptions: HonoElement;
  membershipScopeRows: HonoElement;
  delegatedGrantRows: HonoElement;
}

interface InstitutionAdminAccessSections {
  apiKeyPanelMarkup: HonoElement;
  orgUnitPanelMarkup: HonoElement;
  governanceGuidePanelMarkup: HonoElement;
  tenantMembersPanelMarkup: HonoElement;
  tenantMembersTableMarkup: HonoElement;
  accessOverviewPanelMarkup: HonoElement;
  membershipScopePanelMarkup: HonoElement;
  membershipScopeTableMarkup: HonoElement;
  delegatedGrantPanelMarkup: HonoElement;
  delegatedGrantTableMarkup: HonoElement;
}

const addDisclosureControlMarkup = (
  <span class="ct-admin__add-disclosure-control">
    <span class="ct-admin__add-disclosure-control-open">Open form</span>
    <span class="ct-admin__add-disclosure-control-close">Hide form</span>
  </span>
);

export const renderInstitutionAdminAccessSections = (
  input: RenderInstitutionAdminAccessSectionsInput,
): InstitutionAdminAccessSections => {
  const apiKeyPanelMarkup = (
    <details id="api-key-panel" class="ct-admin__panel ct-admin__add-disclosure">
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Create API key</strong>
          <small>Create a scoped key and reveal the secret once.</small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      <AdminForm
        id="api-key-form"
        className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--api-key ct-grid"
      >
        <AdminField label="Label">
          <input name="label" type="text" required value="Institution integration key" />
        </AdminField>
        <AdminField label="Scopes (comma separated)">
          <input name="scopes" type="text" value="queue.issue, queue.revoke" />
        </AdminField>
        <AdminButton type="submit">Create API key</AdminButton>
      </AdminForm>
      <AdminStatus id="api-key-status"></AdminStatus>
      <pre id="api-key-secret" class="ct-admin__secret" hidden></pre>
    </details>
  );

  const orgUnitPanelMarkup = (
    <details id="org-unit-panel" class="ct-admin__panel ct-admin__add-disclosure">
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Create org unit</strong>
          <small>Add college, department, program, or institution hierarchy.</small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      <p class="ct-admin__hint">
        Hierarchy: college → institution, department → college, program → department.
      </p>
      <AdminForm
        id="org-unit-form"
        className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--org-unit ct-grid"
      >
        <AdminField label="Display name">
          <input name="displayName" type="text" required placeholder="College of Engineering" />
        </AdminField>
        <AdminField label="Unit type">
          <select name="unitType" required>
            <option value="college">College</option>
            <option value="department">Department</option>
            <option value="program">Program</option>
            <option value="institution">Institution</option>
          </select>
        </AdminField>
        <AdminField label="Parent org unit">
          <select name="parentOrgUnitId">
            <option value="">None</option>
            {input.orgUnitParentOptions}
          </select>
        </AdminField>
        <p class="ct-admin__hint">CredTrail creates the internal org key from the display name.</p>
        <AdminButton type="submit">Create org unit</AdminButton>
      </AdminForm>
      <AdminStatus id="org-unit-status"></AdminStatus>
    </details>
  );

  const governanceGuidePanelMarkup = (
    <AdminPanel id="governance-panel">
      <h2>Before you delegate</h2>
      <p>
        Use this page to give an existing tenant member limited access inside a selected org unit.
        Choosing a parent org unit also covers the child units beneath it.
      </p>
      <p class="ct-admin__hint">
        The selected member receives the access. This workflow does not create tenant membership, so
        the person must already exist in this tenant.
      </p>
      <ul>
        <li>Use a scoped role for standing access inside an org unit.</li>
        <li>Use delegated authority for temporary badge actions with an end date.</li>
        <li>
          Leave the badge template limit blank when the delegation should cover every template in
          scope.
        </li>
      </ul>
    </AdminPanel>
  );

  const tenantMembersPanelMarkup = (
    <details class="ct-admin__panel ct-admin__add-disclosure">
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Add member</strong>
          <small>Add a colleague by institution email and assign their tenant-level role.</small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      <AdminForm
        id="tenant-member-form"
        className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--member ct-grid"
      >
        <AdminField label="Institution email">
          <input name="email" type="email" required placeholder="colleague@institution.edu" />
        </AdminField>
        <AdminField label="Tenant role">
          <select name="role" required>
            {input.tenantMemberRoleSelectOptions}
          </select>
        </AdminField>
        <AdminCheckboxRow>
          <input name="sendInvite" type="checkbox" checked />
          Email sign-in invite now
        </AdminCheckboxRow>
        <AdminButton type="submit">Save member</AdminButton>
      </AdminForm>
      <AdminStatus id="tenant-member-status"></AdminStatus>
    </details>
  );

  const tenantMembersTableMarkup = (
    <AdminPanel variant="table" className="ct-admin__members-table">
      <h2>Current Members ({input.tenantMemberCount})</h2>
      <p>
        Review tenant-level access, resend invites, and remove members who no longer need this
        organization.
      </p>
      <AdminTable
        headers={["Member", "Tenant role", "Joined", "Updated", "Status", "Actions"]}
        tbodyId="tenant-member-body"
      >
        {input.tenantMemberRows}
      </AdminTable>
      <AdminStatus id="tenant-member-list-status"></AdminStatus>
    </AdminPanel>
  );

  const accessOverviewPanelMarkup = (
    <section class="ct-admin__workspace-grid ct-grid" aria-label="Access pages">
      <AdminWorkspaceCard href={input.accessMembersPath} ariaLabel="Open Members page">
        <p class="ct-admin__eyebrow">People</p>
        <h2>Members</h2>
        <p>
          Add colleagues by email, assign tenant roles, resend invites, and remove tenant access.
        </p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{input.tenantMemberCount} members</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard href={input.accessGovernancePath} ariaLabel="Open Governance page">
        <p class="ct-admin__eyebrow">Delegation</p>
        <h2>Governance</h2>
        <p>Grant org-unit scoped roles and time-boxed badge authority.</p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{input.scopedRoleCount} scoped roles</AdminStatusPill>
          <AdminStatusPill>{input.delegatedAuthorityGrantCount} delegations</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard href={input.accessApiKeysPath} ariaLabel="Open API Keys page">
        <p class="ct-admin__eyebrow">Integrations</p>
        <h2>API Keys</h2>
        <p>Create and revoke tenant API keys for trusted integrations.</p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{input.activeApiKeyCount} active</AdminStatusPill>
          <AdminStatusPill>{input.revokedApiKeyCount} revoked</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard href={input.accessOrgUnitsPath} ariaLabel="Open Org Units page">
        <p class="ct-admin__eyebrow">Structure</p>
        <h2>Org Units</h2>
        <p>Maintain institution, college, department, and program hierarchy.</p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{input.orgUnitCount} org units</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
    </section>
  );

  const membershipScopePanelMarkup = (
    <details id="membership-scope-panel" class="ct-admin__panel ct-admin__add-disclosure">
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Add scoped role</strong>
          <small>Assign standing access to one org unit.</small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      <AdminForm
        id="membership-scope-form"
        className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--governance ct-grid"
      >
        <AdminField label="Tenant member">
          <select name="userId" required>
            {input.tenantMemberSelectOptions}
          </select>
        </AdminField>
        <p class="ct-admin__hint">
          Choose the person receiving access. They must already belong to this tenant.
        </p>
        <AdminField label="Org unit">
          <select name="orgUnitId" required>
            {input.activeOrgUnitSelectOptions}
          </select>
        </AdminField>
        <AdminField label="Scoped role">
          <select name="role" required>
            <option value="viewer">viewer</option>
            <option value="issuer">issuer</option>
            <option value="admin">admin</option>
          </select>
        </AdminField>
        <ul>
          <li>
            <strong>viewer</strong> can view in-scope templates and governance context.
          </li>
          <li>
            <strong>issuer</strong> includes viewer access and issuer workflows inside the selected
            scope.
          </li>
          <li>
            <strong>admin</strong> is the highest org-unit role and covers issuer and viewer checks.
          </li>
        </ul>
        <AdminButton type="submit">Save scoped role</AdminButton>
      </AdminForm>
      <AdminStatus id="membership-scope-status"></AdminStatus>
    </details>
  );

  const membershipScopeTableMarkup = (
    <AdminPanel variant="table">
      <h2>Current Scoped Roles ({input.scopedRoleCount})</h2>
      <p>Remove access directly from the list instead of re-entering the same identifiers.</p>
      <AdminTable
        headers={["Member", "Org unit", "Role", "Updated", "Action"]}
        tbodyId="membership-scope-body"
      >
        {input.membershipScopeRows}
      </AdminTable>
      <AdminStatus id="membership-scope-list-status"></AdminStatus>
    </AdminPanel>
  );

  const delegatedGrantPanelMarkup = (
    <details id="delegated-grant-panel" class="ct-admin__panel ct-admin__add-disclosure">
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Add delegated authority</strong>
          <small>Grant temporary badge authority without changing standing access.</small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      <AdminForm
        id="delegated-grant-form"
        className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--governance ct-grid"
      >
        <AdminField label="Delegate">
          <select name="delegateUserId" required>
            {input.tenantMemberSelectOptions}
          </select>
        </AdminField>
        <p class="ct-admin__hint">Choose the tenant member receiving the delegation.</p>
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
        <AdminButton type="submit">Save delegation</AdminButton>
      </AdminForm>
      <AdminStatus id="delegated-grant-status"></AdminStatus>
    </details>
  );

  const delegatedGrantTableMarkup = (
    <AdminPanel variant="table">
      <h2>Current Delegations ({input.delegatedAuthorityGrantCount})</h2>
      <p>Remove active or scheduled delegations directly from the list.</p>
      <AdminTable
        headers={["Delegate", "Org unit", "Allowed actions", "Granted", "Status", "Action"]}
        tbodyId="delegated-grant-body"
      >
        {input.delegatedGrantRows}
      </AdminTable>
      <AdminStatus id="delegated-grant-list-status"></AdminStatus>
    </AdminPanel>
  );

  return {
    apiKeyPanelMarkup,
    orgUnitPanelMarkup,
    governanceGuidePanelMarkup,
    tenantMembersPanelMarkup,
    tenantMembersTableMarkup,
    accessOverviewPanelMarkup,
    membershipScopePanelMarkup,
    membershipScopeTableMarkup,
    delegatedGrantPanelMarkup,
    delegatedGrantTableMarkup,
  };
};
