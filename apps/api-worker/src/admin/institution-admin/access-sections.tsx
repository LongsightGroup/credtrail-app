import type { HtmlEscapedString } from "hono/utils/html";
import type { BadgeRuleApprovalPolicyRecord, TenantMembershipRole } from "@credtrail/db";
import { describeBadgeRuleApprovalSummary } from "../../badges/badge-rule-approval-policy-summary";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminCheckboxRow,
  AdminField,
  AdminForm,
  AdminPanel,
  AdminStatus,
  AdminTable,
} from "../components";
import { CtInput, CtSelect } from "../../ui/forms";
import {
  buildAccessAuthenticationAdminPath,
  buildAccessGovernanceDelegationNewPath,
  tenantAccessBadgeRuleApprovalPolicyPath,
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
  badgeRuleApprovalPolicy?: BadgeRuleApprovalPolicyRecord | null;
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

const ruleApprovalPolicyRoleLabel = (role: TenantMembershipRole): string => {
  switch (role) {
    case "owner":
      return "Owner";
    case "admin":
      return "Admin";
    case "issuer":
      return "Issuer";
    case "viewer":
      return "Viewer";
  }
};

export const renderInstitutionAdminAccessSections = (
  input: RenderInstitutionAdminAccessSectionsInput,
): InstitutionAdminAccessSections => {
  const apiKeyFormOpen = input.apiKeysWorkspace?.openCreatePanel === true;
  const apiKeyRevealedSecret = input.apiKeysWorkspace?.revealedSecret ?? null;
  const lmsNewPath = buildLmsConnectionNewPath(input.tenantId);
  const ltiDynamicRegistrationUrl =
    input.lmsConnectionsWorkspace?.ltiDynamicRegistrationUrl ?? null;
  const delegationNewPath = buildAccessGovernanceDelegationNewPath(input.tenantId);
  const authenticationPath = buildAccessAuthenticationAdminPath(input.tenantId);
  const badgeRuleApprovalPolicyPath = tenantAccessBadgeRuleApprovalPolicyPath(input.tenantId);
  const badgeRuleApprovalPolicy = input.badgeRuleApprovalPolicy ?? null;
  const badgeRuleApprovalRequirement =
    badgeRuleApprovalPolicy?.approvalRequirement === "never" ? "never" : "always";
  const firstBadgeRuleApprovalStep = badgeRuleApprovalPolicy?.approvalSteps[0] ?? null;
  const badgeRuleApprovalRole =
    firstBadgeRuleApprovalStep?.targetType === "role_threshold"
      ? firstBadgeRuleApprovalStep.requiredRole
      : "admin";
  const badgeRuleApprovalSummary = describeBadgeRuleApprovalSummary(badgeRuleApprovalPolicy);

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
          <CtInput name="label" type="text" required value="Institution integration key" />
        </AdminField>
        <AdminField label="Scopes (comma separated)">
          <CtInput name="scopes" type="text" value="queue.issue, queue.revoke" />
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
    <AdminPanel id="lms-connection-actions">
      <div class="ct-stack">
        <p class="ct-admin__hint">
          Connect Canvas or Sakai gradebook accounts on a dedicated setup page with optional OAuth
          and LTI metadata.
        </p>
        {ltiDynamicRegistrationUrl !== null && ltiDynamicRegistrationUrl.length > 0 ? (
          <div class="ct-admin__form ct-stack">
            <AdminField label="LTI dynamic registration URL">
              <CtInput
                id="lti-dynamic-registration-url"
                type="url"
                value={ltiDynamicRegistrationUrl}
                readonly
                describedBy="lti-dynamic-registration-help"
              />
            </AdminField>
            <p id="lti-dynamic-registration-help" class="ct-admin__hint">
              Tenant-scoped registration link for Canvas and Sakai. Expires after 7 days.
            </p>
          </div>
        ) : (
          <p class="ct-admin__hint">
            LTI dynamic registration URL is unavailable until LTI signing is configured.
          </p>
        )}
        <AdminActions>
          <AdminButtonLink href={lmsNewPath} variant="secondary">
            Connect LMS
          </AdminButtonLink>
        </AdminActions>
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
          <CtInput name="displayName" type="text" required placeholder="College of Engineering" />
        </AdminField>
        <AdminField label="Unit type">
          <CtSelect name="unitType" required>
            <option value="college">College</option>
            <option value="department">Department</option>
            <option value="program">Program</option>
            <option value="institution">Institution</option>
          </CtSelect>
        </AdminField>
        <AdminField label="Parent org unit">
          <CtSelect name="parentOrgUnitId">
            <option value="">None</option>
            {input.orgUnitParentOptions}
          </CtSelect>
        </AdminField>
        <p class="ct-admin__hint">CredTrail creates the internal org key from the display name.</p>
        <AdminButton type="submit">Create org unit</AdminButton>
      </AdminForm>
    </details>
  );

  const governanceGuidePanelMarkup = (
    <AdminPanel id="governance-panel">
      <h2>Governance controls</h2>
      <p>
        Use this page to set badge rule approval policy, review standing org-unit roles, and manage
        time-boxed delegations. Choosing a parent org unit also covers the child units beneath it.
      </p>
      <p class="ct-admin__hint">
        Rule authors cannot edit approval steps on the rule draft. Institution policy decides what
        happens when a rule version is submitted.
      </p>
      <ul>
        <li>Set badge rule approval before instructors submit rules for activation.</li>
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
    <div id="governance-actions" class="ct-stack">
      <details id="rule-approval-policy-panel" class="ct-admin__panel ct-admin__add-disclosure">
        <summary class="ct-admin__add-disclosure-summary">
          <span>
            <strong>Set badge rule approval policy</strong>
            <small>{badgeRuleApprovalSummary}</small>
          </span>
          {addDisclosureControlMarkup}
        </summary>
        <AdminForm
          id="rule-approval-policy-form"
          method="post"
          action={badgeRuleApprovalPolicyPath}
          className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--governance ct-grid"
        >
          <AdminField label="Approval requirement">
            <CtSelect name="approvalRequirement" required>
              <option
                value="always"
                selected={badgeRuleApprovalRequirement === "always" ? true : undefined}
              >
                Require approval before activation
              </option>
              <option
                value="never"
                selected={badgeRuleApprovalRequirement === "never" ? true : undefined}
              >
                Approve submitted versions automatically
              </option>
            </CtSelect>
          </AdminField>
          <AdminField label="Reviewer role">
            <CtSelect name="requiredRole" required>
              {(["admin", "owner", "issuer", "viewer"] as const).map((role) => (
                <option value={role} selected={badgeRuleApprovalRole === role ? true : undefined}>
                  {ruleApprovalPolicyRoleLabel(role)}
                </option>
              ))}
            </CtSelect>
          </AdminField>
          <p class="ct-admin__hint">
            Reviewer role is used when approval is required. Rule authors cannot edit this policy
            from Rule Builder.
          </p>
          <AdminButton type="submit">Save approval policy</AdminButton>
        </AdminForm>
      </details>
      <AdminPanel>
        <AdminActions>
          <AdminButtonLink href={delegationNewPath} variant="secondary">
            Add delegated authority
          </AdminButtonLink>
        </AdminActions>
      </AdminPanel>
    </div>
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
          <CtInput name="email" type="email" required placeholder="colleague@institution.edu" />
        </AdminField>
        <AdminField label="Tenant role">
          <CtSelect name="role" required>
            {input.tenantMemberRoleSelectOptions}
          </CtSelect>
        </AdminField>
        <AdminCheckboxRow name="sendInvite" label="Email sign-in invite now" checked />
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
          <CtSelect name="userId" required>
            {input.tenantMemberSelectOptions}
          </CtSelect>
        </AdminField>
        <p class="ct-admin__hint">
          Choose the person receiving access. They must already belong to this tenant.
        </p>
        <AdminField label="Org unit">
          <CtSelect name="orgUnitId" required>
            {input.activeOrgUnitSelectOptions}
          </CtSelect>
        </AdminField>
        <AdminField label="Scoped role">
          <CtSelect name="role" required>
            <option value="viewer">viewer</option>
            <option value="issuer">issuer</option>
            <option value="admin">admin</option>
          </CtSelect>
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
