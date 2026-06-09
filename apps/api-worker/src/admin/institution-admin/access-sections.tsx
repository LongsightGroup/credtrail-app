import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminButton,
  AdminButtonLink,
  AdminCheckboxRow,
  AdminField,
  AdminForm,
  AdminPanel,
  AdminStatus,
  AdminTable,
} from "../components";
import {
  buildAccessAuthenticationAdminPath,
  buildAccessGovernanceDelegationNewPath,
  tenantAccessMemberCreatePath,
  tenantAccessMembershipScopeSavePath,
  tenantAccessOrgUnitCreatePath,
} from "../access-admin-helpers";
import { tenantApiKeyAdminCreatePath } from "../api-key-admin-helpers";
import { buildLmsConnectionNewPath } from "../lms-connection-admin-helpers";
import type {
  InstitutionAdminAccessGovernanceWorkspace,
  InstitutionAdminAccessMembersWorkspace,
  InstitutionAdminAccessOrgUnitsWorkspace,
  InstitutionAdminApiKeysWorkspace,
  InstitutionAdminLmsConnectionsWorkspace,
} from "./page-types";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | HonoElement[];

interface RenderInstitutionAdminAccessSectionsInput {
  accessMembersPath: string;
  accessGovernancePath: string;
  accessAuthenticationPath: string;
  accessApiKeysPath: string;
  accessOrgUnitsPath: string;
  accessLmsConnectionsPath: string;
  planTier: string;
  tenantMemberCount: string;
  scopedRoleCount: string;
  delegatedAuthorityGrantCount: string;
  activeApiKeyCount: string;
  revokedApiKeyCount: string;
  orgUnitCount: string;
  lmsConnectionCount: string;
  tenantMemberRoleSelectOptions: HonoElement;
  tenantMemberRows: HonoElement;
  orgUnitParentOptions: HonoElement;
  tenantMemberSelectOptions: HonoElement;
  activeOrgUnitSelectOptions: HonoElement;
  optionalBadgeTemplateScopeOptions: HonoElement;
  membershipScopeRows: HonoElement;
  delegatedGrantRows: HonoElement;
  lmsConnectionRows: HonoElement;
  tenantId: string;
  apiKeysWorkspace?: InstitutionAdminApiKeysWorkspace;
  lmsConnectionsWorkspace?: InstitutionAdminLmsConnectionsWorkspace;
  accessMembersWorkspace?: InstitutionAdminAccessMembersWorkspace;
  accessGovernanceWorkspace?: InstitutionAdminAccessGovernanceWorkspace;
  accessOrgUnitsWorkspace?: InstitutionAdminAccessOrgUnitsWorkspace;
}

interface InstitutionAdminAccessSections {
  apiKeyPanelMarkup: HonoElement;
  lmsConnectionsActionsMarkup: HonoElement;
  lmsConnectionsTableMarkup: HonoElement;
  orgUnitPanelMarkup: HonoElement;
  governanceGuidePanelMarkup: HonoElement;
  governanceActionsMarkup: HonoElement;
  tenantMembersPanelMarkup: HonoElement;
  tenantMembersTableMarkup: HonoElement;
  membershipScopePanelMarkup: HonoElement;
  membershipScopeTableMarkup: HonoElement;
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
  const apiKeyFormOpen = input.apiKeysWorkspace?.openCreatePanel === true;
  const apiKeyRevealedSecret = input.apiKeysWorkspace?.revealedSecret ?? null;
  const lmsNewPath = buildLmsConnectionNewPath(input.tenantId);
  const delegationNewPath = buildAccessGovernanceDelegationNewPath(input.tenantId);
  const authenticationPath = buildAccessAuthenticationAdminPath(input.tenantId);

  const apiKeyPanelMarkup = (
    <details
      id="api-key-panel"
      class="ct-admin__panel ct-admin__add-disclosure"
      open={apiKeyFormOpen ? true : undefined}
    >
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong>Create API key</strong>
          <small>Create a scoped key and reveal the secret once.</small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      {input.apiKeysWorkspace?.listError !== null &&
      input.apiKeysWorkspace?.listError !== undefined &&
      input.apiKeysWorkspace.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.apiKeysWorkspace.listError}</AdminStatus>
      ) : input.apiKeysWorkspace?.listNotice !== null &&
        input.apiKeysWorkspace?.listNotice !== undefined &&
        input.apiKeysWorkspace.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.apiKeysWorkspace.listNotice}</AdminStatus>
      ) : null}
      <AdminForm
        id="api-key-form"
        method="post"
        action={tenantApiKeyAdminCreatePath(input.tenantId)}
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
      {apiKeyRevealedSecret !== null && apiKeyRevealedSecret.length > 0 ? (
        <pre id="api-key-secret" class="ct-admin__secret">
          {`Store this now. It is shown once:\n\n${apiKeyRevealedSecret}`}
        </pre>
      ) : null}
    </details>
  );

  const lmsConnectionsActionsMarkup = (
    <AdminPanel id="lms-connection-actions" className="ct-cluster">
      <div class="ct-stack">
        <p class="ct-admin__hint">
          Connect Canvas or Sakai gradebook accounts on a dedicated setup page with optional OAuth
          and LTI metadata.
        </p>
        <AdminButtonLink href={lmsNewPath} variant="secondary">
          Connect LMS
        </AdminButtonLink>
      </div>
    </AdminPanel>
  );

  const lmsConnectionsTableMarkup = (
    <AdminPanel variant="table">
      <h2 id="lms-connection-heading">Current LMS Connections ({input.lmsConnectionCount})</h2>
      <p>
        These tenant gradebook accounts appear in Rule Builder. Secrets are never shown after they
        are saved.
      </p>
      <AdminTable
        headers={[
          "Connection",
          "Provider",
          "API/server URL",
          "Status",
          "Last connected",
          "LTI metadata",
          "Action",
        ]}
        tbodyId="lms-connection-body"
      >
        {input.lmsConnectionRows}
      </AdminTable>
    </AdminPanel>
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
      {input.accessOrgUnitsWorkspace?.listError !== null &&
      input.accessOrgUnitsWorkspace?.listError !== undefined &&
      input.accessOrgUnitsWorkspace.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.accessOrgUnitsWorkspace.listError}</AdminStatus>
      ) : input.accessOrgUnitsWorkspace?.listNotice !== null &&
        input.accessOrgUnitsWorkspace?.listNotice !== undefined &&
        input.accessOrgUnitsWorkspace.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.accessOrgUnitsWorkspace.listNotice}</AdminStatus>
      ) : null}
      <AdminForm
        id="org-unit-form"
        method="post"
        action={tenantAccessOrgUnitCreatePath(input.tenantId)}
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
    </details>
  );

  const governanceGuidePanelMarkup = (
    <AdminPanel id="governance-panel">
      <h2>Before you delegate</h2>
      <p>
        Use this page to review standing org-unit roles and time-boxed delegations. Choosing a
        parent org unit also covers the child units beneath it.
      </p>
      <p class="ct-admin__hint">
        The selected member receives the access. This workflow does not create tenant membership, so
        the person must already exist in this tenant.
      </p>
      <ul>
        <li>Use a scoped role for standing access inside an org unit.</li>
        <li>
          Use <a href={delegationNewPath}>delegated authority</a> for temporary badge actions with
          an end date.
        </li>
        {input.planTier === "enterprise" ? (
          <li>
            Configure institution sign-in on the <a href={authenticationPath}>Authentication</a>{" "}
            page.
          </li>
        ) : null}
      </ul>
    </AdminPanel>
  );

  const governanceActionsMarkup = (
    <AdminPanel id="governance-actions" className="ct-cluster">
      <AdminButtonLink href={delegationNewPath} variant="secondary">
        Add delegated authority
      </AdminButtonLink>
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
      {input.accessMembersWorkspace?.listError !== null &&
      input.accessMembersWorkspace?.listError !== undefined &&
      input.accessMembersWorkspace.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.accessMembersWorkspace.listError}</AdminStatus>
      ) : input.accessMembersWorkspace?.listNotice !== null &&
        input.accessMembersWorkspace?.listNotice !== undefined &&
        input.accessMembersWorkspace.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.accessMembersWorkspace.listNotice}</AdminStatus>
      ) : null}
      <AdminForm
        id="tenant-member-form"
        method="post"
        action={tenantAccessMemberCreatePath(input.tenantId)}
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
        <AdminButton type="submit">Add member</AdminButton>
      </AdminForm>
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
    </AdminPanel>
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
        method="post"
        action={tenantAccessMembershipScopeSavePath(input.tenantId)}
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
    </AdminPanel>
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
    </AdminPanel>
  );

  return {
    apiKeyPanelMarkup,
    lmsConnectionsActionsMarkup,
    lmsConnectionsTableMarkup,
    orgUnitPanelMarkup,
    governanceGuidePanelMarkup,
    governanceActionsMarkup,
    tenantMembersPanelMarkup,
    tenantMembersTableMarkup,
    membershipScopePanelMarkup,
    membershipScopeTableMarkup,
    delegatedGrantTableMarkup,
  };
};
