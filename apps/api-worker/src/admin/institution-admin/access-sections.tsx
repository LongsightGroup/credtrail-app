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
  AdminTable,
} from "../components";
import { tenantApiKeyAdminCreatePath } from "../api-key-admin-helpers";
import { tenantLmsConnectionAdminSavePath } from "../lms-connection-admin-helpers";
import type {
  InstitutionAdminApiKeysWorkspace,
  InstitutionAdminLmsConnectionsWorkspace,
} from "./page-types";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | HonoElement[];

interface RenderInstitutionAdminAccessSectionsInput {
  accessMembersPath: string;
  accessGovernancePath: string;
  accessApiKeysPath: string;
  accessOrgUnitsPath: string;
  accessLmsConnectionsPath: string;
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
  lmsConnectionFormValues?: {
    connectionId: string;
    displayName: string;
    providerKind: "canvas" | "sakai";
    apiBaseUrl: string;
    ltiIssuer: string;
    ltiClientId: string;
    ltiDeploymentId: string;
  };
}

interface InstitutionAdminAccessSections {
  apiKeyPanelMarkup: HonoElement;
  lmsConnectionsPanelMarkup: HonoElement;
  lmsConnectionsTableMarkup: HonoElement;
  orgUnitPanelMarkup: HonoElement;
  governanceGuidePanelMarkup: HonoElement;
  tenantMembersPanelMarkup: HonoElement;
  tenantMembersTableMarkup: HonoElement;
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
  const apiKeyFormOpen = input.apiKeysWorkspace?.openCreatePanel === true;
  const apiKeyRevealedSecret = input.apiKeysWorkspace?.revealedSecret ?? null;
  const lmsFormValues = input.lmsConnectionFormValues;
  const lmsEditing = (lmsFormValues?.connectionId.length ?? 0) > 0;

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

  const lmsConnectionsPanelMarkup = (
    <details
      id="lms-connection-panel"
      class="ct-admin__panel ct-admin__add-disclosure"
      open={lmsEditing ? true : undefined}
    >
      <summary class="ct-admin__add-disclosure-summary">
        <span>
          <strong id="lms-connection-form-title">
            {lmsEditing ? "Edit LMS connection" : "Add LMS connection"}
          </strong>
          <small>Connect a tenant gradebook account for rule lookup.</small>
        </span>
        {addDisclosureControlMarkup}
      </summary>
      {input.lmsConnectionsWorkspace?.listError !== null &&
      input.lmsConnectionsWorkspace?.listError !== undefined &&
      input.lmsConnectionsWorkspace.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.lmsConnectionsWorkspace.listError}</AdminStatus>
      ) : input.lmsConnectionsWorkspace?.listNotice !== null &&
        input.lmsConnectionsWorkspace?.listNotice !== undefined &&
        input.lmsConnectionsWorkspace.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.lmsConnectionsWorkspace.listNotice}</AdminStatus>
      ) : null}
      <AdminForm
        id="lms-connection-form"
        method="post"
        action={tenantLmsConnectionAdminSavePath(input.tenantId)}
        className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--lms-connection ct-stack"
      >
        <input name="connectionId" type="hidden" value={lmsFormValues?.connectionId ?? ""} />
        <AdminField label="Connection name">
          <input
            name="displayName"
            type="text"
            required
            placeholder="TrySakai test server"
            value={lmsFormValues?.displayName ?? ""}
          />
        </AdminField>
        <AdminField label="Provider">
          <select name="providerKind" required>
            <option value="canvas" selected={lmsFormValues?.providerKind !== "sakai"}>
              Canvas
            </option>
            <option value="sakai" selected={lmsFormValues?.providerKind === "sakai"}>
              Sakai
            </option>
          </select>
        </AdminField>
        <AdminField label="API/server URL">
          <input
            name="apiBaseUrl"
            type="url"
            required
            placeholder="https://lms.example.edu"
            value={lmsFormValues?.apiBaseUrl ?? ""}
          />
        </AdminField>
        <AdminField label="Credential or session value">
          <input
            name="accessToken"
            type="password"
            autocomplete="off"
            placeholder={
              lmsEditing
                ? "Leave blank to keep existing credential"
                : lmsFormValues?.providerKind === "sakai"
                  ? "Paste Sakai SAKAIID session value"
                  : "Paste Canvas access token"
            }
          />
        </AdminField>
        <details class="ct-admin__advanced-tools">
          <summary>
            <span>Advanced OAuth and LTI metadata</span>
            <small>
              Add refresh credentials or LTI identifiers only when this connection needs them.
            </small>
          </summary>
          <div class="ct-admin__advanced-tools-body ct-grid">
            <AdminField label="Refresh token (optional)">
              <input name="refreshToken" type="password" autocomplete="off" />
            </AdminField>
            <AdminField label="Authorization endpoint (optional)">
              <input
                name="authorizationEndpoint"
                type="url"
                placeholder="https://lms.example.edu/login/oauth2/auth"
              />
            </AdminField>
            <AdminField label="Token endpoint (optional)">
              <input
                name="tokenEndpoint"
                type="url"
                placeholder="https://lms.example.edu/login/oauth2/token"
              />
            </AdminField>
            <AdminField label="OAuth client ID (optional)">
              <input name="clientId" type="text" autocomplete="off" />
            </AdminField>
            <AdminField label="OAuth client secret (optional)">
              <input name="clientSecret" type="password" autocomplete="off" />
            </AdminField>
            <AdminField label="LTI issuer (optional)">
              <input name="ltiIssuer" type="url" value={lmsFormValues?.ltiIssuer ?? ""} />
            </AdminField>
            <AdminField label="LTI client ID (optional)">
              <input name="ltiClientId" type="text" value={lmsFormValues?.ltiClientId ?? ""} />
            </AdminField>
            <AdminField label="LTI deployment ID (optional)">
              <input
                name="ltiDeploymentId"
                type="text"
                value={lmsFormValues?.ltiDeploymentId ?? ""}
              />
            </AdminField>
          </div>
        </details>
        <AdminButton type="submit">
          {lmsEditing ? "Save connection changes" : "Save and connect gradebook"}
        </AdminButton>
        {lmsEditing ? (
          <AdminButtonLink href={input.accessLmsConnectionsPath} variant="secondary">
            Cancel edit
          </AdminButtonLink>
        ) : null}
      </AdminForm>
      {lmsEditing ? (
        <p class="ct-admin__hint">
          Editing connection details. Leave credential fields blank to keep saved secrets.
        </p>
      ) : null}
    </details>
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
    lmsConnectionsPanelMarkup,
    lmsConnectionsTableMarkup,
    orgUnitPanelMarkup,
    governanceGuidePanelMarkup,
    tenantMembersPanelMarkup,
    tenantMembersTableMarkup,
    membershipScopePanelMarkup,
    membershipScopeTableMarkup,
    delegatedGrantPanelMarkup,
    delegatedGrantTableMarkup,
  };
};
