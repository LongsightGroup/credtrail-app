import type { HtmlEscapedString } from "hono/utils/html";
import type { BadgeRuleApprovalPolicyRecord } from "@credtrail/db";
import { tenantMembershipRoleLabel } from "../tenant-membership-role-labels";
import {
  badgeRuleApprovalPolicyFormState,
  describeBadgeRuleApprovalSummary,
} from "../../badges/badge-rule-approval-policy-summary";
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
  tenantAccessApproverGroupCreatePath,
  tenantAccessApproverGroupMemberAddPath,
  tenantAccessBadgeRuleApprovalPolicyPath,
  tenantAccessMemberCreatePath,
  tenantAccessMembershipScopeSavePath,
  tenantAccessOrgUnitCreatePath,
} from "../access-admin-helpers";
import { tenantApiKeyAdminCreatePath } from "../api-key-admin-helpers";
import { buildLmsConnectionNewPath } from "../lms-connection-admin-helpers";
import type {
  InstitutionAdminAccessGovernanceWorkspace,
  InstitutionAdminAccessDelegationsWorkspace,
  InstitutionAdminAccessMembersWorkspace,
  InstitutionAdminAccessOrgUnitAccessWorkspace,
  InstitutionAdminAccessOrgUnitsWorkspace,
  InstitutionAdminApiKeysWorkspace,
  InstitutionAdminLmsConnectionsWorkspace,
} from "./page-types";
import { formatIsoTimestamp } from "../../utils/display-format";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | HonoElement[];

interface RenderInstitutionAdminAccessSectionsInput {
  accessMembersPath: string;
  accessOrgUnitAccessPath: string;
  accessGovernancePath: string;
  accessDelegationsPath: string;
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
  badgeRuleApprovalTargetUserSelectOptions: HonoElement;
  approverGroupSelectOptions: HonoElement;
  badgeRuleApprovalTargetApproverGroupSelectOptions: HonoElement;
  activeOrgUnitSelectOptions: HonoElement;
  badgeRuleApprovalOrgUnitSelectOptions: HonoElement;
  optionalBadgeTemplateScopeOptions: HonoElement;
  membershipScopeRows: HonoElement;
  approverGroupRows: HonoElement;
  delegatedGrantRows: HonoElement;
  lmsConnectionRows: HonoElement;
  badgeRuleApprovalPolicy?: BadgeRuleApprovalPolicyRecord | null;
  tenantId: string;
  apiKeysWorkspace?: InstitutionAdminApiKeysWorkspace;
  lmsConnectionsWorkspace?: InstitutionAdminLmsConnectionsWorkspace;
  accessMembersWorkspace?: InstitutionAdminAccessMembersWorkspace;
  accessOrgUnitAccessWorkspace?: InstitutionAdminAccessOrgUnitAccessWorkspace;
  accessGovernanceWorkspace?: InstitutionAdminAccessGovernanceWorkspace;
  accessDelegationsWorkspace?: InstitutionAdminAccessDelegationsWorkspace;
  accessOrgUnitsWorkspace?: InstitutionAdminAccessOrgUnitsWorkspace;
}

interface InstitutionAdminAccessSections {
  apiKeyPanelMarkup: HonoElement;
  lmsConnectionsActionsMarkup: HonoElement;
  lmsConnectionsTableMarkup: HonoElement;
  orgUnitPanelMarkup: HonoElement;
  governanceGuidePanelMarkup: HonoElement;
  governanceActionsMarkup: HonoElement;
  ruleApprovalPolicySummaryMarkup: HonoElement;
  tenantMembersPanelMarkup: HonoElement;
  tenantMembersTableMarkup: HonoElement;
  membershipScopePanelMarkup: HonoElement;
  membershipScopeTableMarkup: HonoElement;
  approverGroupPanelMarkup: HonoElement;
  approverGroupTableMarkup: HonoElement;
  delegatedGrantTableMarkup: HonoElement;
  delegatedGrantActionsMarkup: HonoElement;
}

const addDisclosureControlMarkup = (
  <span class="ct-admin__add-disclosure-control">
    <span class="ct-admin__add-disclosure-control-open">Open form</span>
    <span class="ct-admin__add-disclosure-control-close">Hide form</span>
  </span>
);

const ruleApprovalPolicyRoleLabel = tenantMembershipRoleLabel;

const describeRuleApprovalRequirement = (policy: BadgeRuleApprovalPolicyRecord | null): string => {
  if (policy?.approvalRequirement === "never") {
    return policy.allowSelfCertification ? "Automatic approval" : "Automatic approval disabled";
  }

  return "Approval required";
};

const describeRuleApprovalReviewer = (policy: BadgeRuleApprovalPolicyRecord | null): string => {
  if (policy?.approvalRequirement === "never") {
    return policy.allowSelfCertification ? "Self-certification" : "No active approval path";
  }

  const firstStep = policy?.approvalSteps[0] ?? null;

  if (firstStep === null || firstStep.targetType === "role_threshold") {
    const requiredRole = firstStep?.requiredRole ?? "admin";
    return `${ruleApprovalPolicyRoleLabel(requiredRole)} role`;
  }

  if (firstStep.targetType === "user") {
    return "Named reviewer";
  }

  return "Approver group";
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
  const approverGroupCreatePath = tenantAccessApproverGroupCreatePath(input.tenantId);
  const approverGroupMemberAddPath = tenantAccessApproverGroupMemberAddPath(input.tenantId);
  const badgeRuleApprovalPolicy = input.badgeRuleApprovalPolicy ?? null;
  const badgeRuleApprovalFormState = badgeRuleApprovalPolicyFormState(badgeRuleApprovalPolicy);
  const badgeRuleApprovalSummary = describeBadgeRuleApprovalSummary(badgeRuleApprovalPolicy);
  const badgeRuleApprovalScopeLabel =
    badgeRuleApprovalPolicy?.orgUnitId === null || badgeRuleApprovalPolicy?.orgUnitId === undefined
      ? "Tenant default"
      : "Org-unit override";
  const badgeRuleApprovalUpdatedAt =
    badgeRuleApprovalPolicy?.updatedAt === undefined
      ? "Not saved"
      : formatIsoTimestamp(badgeRuleApprovalPolicy.updatedAt);

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
      <h2>Approval governance</h2>
      <p>
        Rule approval policy decides who reviews submitted badge rule versions before activation.
      </p>
      <p class="ct-admin__hint">
        Rule authors cannot edit approval steps on the rule draft. Institution policy decides what
        happens when a rule version is submitted.
      </p>
      {input.planTier === "enterprise" ? (
        <p class="ct-admin__hint">
          Institution sign-in settings remain on the <a href={authenticationPath}>Authentication</a>{" "}
          page.
        </p>
      ) : null}
    </AdminPanel>
  );

  const ruleApprovalPolicySummaryMarkup = (
    <AdminPanel variant="table">
      <h2>Approval Policy</h2>
      <p>Review the active approval path before changing who can approve submitted rules.</p>
      <AdminTable
        headers={["Scope", "Requirement", "Reviewer", "Updated", "Actions"]}
        tbodyId="rule-approval-policy-body"
      >
        <tr>
          <td>
            <strong>{badgeRuleApprovalScopeLabel}</strong>
            {badgeRuleApprovalPolicy?.orgUnitId === null ||
            badgeRuleApprovalPolicy?.orgUnitId === undefined ? null : (
              <div class="ct-admin__meta">{badgeRuleApprovalPolicy.orgUnitId}</div>
            )}
          </td>
          <td>{describeRuleApprovalRequirement(badgeRuleApprovalPolicy)}</td>
          <td>{describeRuleApprovalReviewer(badgeRuleApprovalPolicy)}</td>
          <td>{badgeRuleApprovalUpdatedAt}</td>
          <td>
            <AdminButtonLink href="#rule-approval-policy-panel" size="tiny" variant="secondary">
              Change policy
            </AdminButtonLink>
          </td>
        </tr>
      </AdminTable>
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
                selected={
                  badgeRuleApprovalFormState.approvalRequirement === "always" ? true : undefined
                }
              >
                Require approval before activation
              </option>
              <option
                value="never"
                selected={
                  badgeRuleApprovalFormState.approvalRequirement === "never" ? true : undefined
                }
              >
                Approve submitted versions automatically
              </option>
            </CtSelect>
          </AdminField>
          <AdminField label="Policy scope">
            <CtSelect name="orgUnitId">
              <option
                value=""
                selected={badgeRuleApprovalFormState.orgUnitId.length === 0 ? true : undefined}
              >
                Tenant default
              </option>
              {input.badgeRuleApprovalOrgUnitSelectOptions}
            </CtSelect>
          </AdminField>
          <p class="ct-admin__hint">
            Choose an org unit to override the tenant default for that unit and its children.
          </p>
          <AdminField label="Reviewer type">
            <CtSelect name="stepTargetType" required>
              <option
                value="role_threshold"
                selected={
                  badgeRuleApprovalFormState.stepTargetType === "role_threshold" ? true : undefined
                }
              >
                Any member with a role
              </option>
              <option
                value="user"
                selected={badgeRuleApprovalFormState.stepTargetType === "user" ? true : undefined}
              >
                Named person
              </option>
              <option
                value="approver_group"
                selected={
                  badgeRuleApprovalFormState.stepTargetType === "approver_group" ? true : undefined
                }
              >
                Approver group
              </option>
            </CtSelect>
          </AdminField>
          <AdminField label="Reviewer role">
            <CtSelect name="requiredRole">
              <option
                value=""
                selected={badgeRuleApprovalFormState.requiredRole.length === 0 ? true : undefined}
              >
                No minimum role
              </option>
              {(["admin", "owner", "issuer", "approver", "viewer"] as const).map((role) => (
                <option
                  value={role}
                  selected={badgeRuleApprovalFormState.requiredRole === role ? true : undefined}
                >
                  {ruleApprovalPolicyRoleLabel(role)}
                </option>
              ))}
            </CtSelect>
          </AdminField>
          <AdminField label="Named reviewer">
            <CtSelect name="targetUserId">
              <option value="">Choose only for named-person approval</option>
              {input.badgeRuleApprovalTargetUserSelectOptions}
            </CtSelect>
          </AdminField>
          <AdminField label="Approver group">
            <CtSelect name="targetApproverGroupId">
              <option value="">Choose only for approver-group approval</option>
              {input.badgeRuleApprovalTargetApproverGroupSelectOptions}
            </CtSelect>
          </AdminField>
          <p class="ct-admin__hint">
            Role approval uses reviewer role. Named-person and group approval use the selected
            reviewer, with reviewer role as an optional minimum.
          </p>
          <AdminField label="Recertification cadence">
            <CtInput
              name="recertificationIntervalMonths"
              type="number"
              min="1"
              max="120"
              step="1"
              value={
                badgeRuleApprovalFormState.recertificationIntervalMonths === null
                  ? undefined
                  : String(badgeRuleApprovalFormState.recertificationIntervalMonths)
              }
              placeholder="No periodic review"
            />
          </AdminField>
          <p class="ct-admin__hint">
            Leave blank if active rules do not need scheduled re-approval.
          </p>
          <AdminButton type="submit">Save approval policy</AdminButton>
        </AdminForm>
      </details>
      <details id="approver-group-panel" class="ct-admin__panel ct-admin__add-disclosure">
        <summary class="ct-admin__add-disclosure-summary">
          <span>
            <strong>Manage approver groups</strong>
            <small>Create a group and add tenant members who can review assigned steps.</small>
          </span>
          {addDisclosureControlMarkup}
        </summary>
        <AdminForm
          id="approver-group-form"
          method="post"
          action={approverGroupCreatePath}
          className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--governance ct-grid"
        >
          <AdminField label="Group name">
            <CtInput name="name" type="text" required placeholder="Registrar office" />
          </AdminField>
          <AdminField label="Org unit">
            <CtSelect name="orgUnitId">
              <option value="">Tenant-wide group</option>
              {input.activeOrgUnitSelectOptions}
            </CtSelect>
          </AdminField>
          <AdminButton type="submit">Create approver group</AdminButton>
        </AdminForm>
        <AdminForm
          id="approver-group-member-form"
          method="post"
          action={approverGroupMemberAddPath}
          className="ct-admin__form ct-admin__add-disclosure-form ct-admin__add-disclosure-form--governance ct-grid"
        >
          <AdminField label="Approver group">
            <CtSelect name="groupId" required>
              {input.approverGroupSelectOptions}
            </CtSelect>
          </AdminField>
          <AdminField label="Tenant member">
            <CtSelect name="userId" required>
              {input.tenantMemberSelectOptions}
            </CtSelect>
          </AdminField>
          <AdminButton type="submit">Add member to group</AdminButton>
        </AdminForm>
      </details>
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

  const approverGroupTableMarkup = (
    <AdminPanel variant="table">
      <h2>Approver Groups</h2>
      <p>Use groups when an office or committee, not any admin, owns an approval step.</p>
      <AdminTable
        headers={["Group", "Scope", "Members", "Updated", "Actions"]}
        tbodyId="approver-group-body"
      >
        {input.approverGroupRows}
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

  const delegatedGrantActionsMarkup = (
    <AdminPanel>
      <p class="ct-admin__hint">
        Add a temporary authority grant on a dedicated setup page so the scope, actions, and end
        date stay explicit.
      </p>
      <AdminActions>
        <AdminButtonLink href={delegationNewPath} variant="secondary">
          Add delegated authority
        </AdminButtonLink>
      </AdminActions>
    </AdminPanel>
  );

  return {
    apiKeyPanelMarkup,
    lmsConnectionsActionsMarkup,
    lmsConnectionsTableMarkup,
    orgUnitPanelMarkup,
    governanceGuidePanelMarkup,
    governanceActionsMarkup,
    ruleApprovalPolicySummaryMarkup,
    tenantMembersPanelMarkup,
    tenantMembersTableMarkup,
    membershipScopePanelMarkup,
    membershipScopeTableMarkup,
    approverGroupPanelMarkup: <></>,
    approverGroupTableMarkup,
    delegatedGrantTableMarkup,
    delegatedGrantActionsMarkup,
  };
};
