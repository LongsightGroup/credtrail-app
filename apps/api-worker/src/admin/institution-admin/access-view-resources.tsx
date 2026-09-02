import type { TenantLmsConnectionRecord, TenantMembershipRole } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../../utils/display-format";
import { CtInput, CtSelect } from "../../ui/forms";
import {
  tenantAccessApproverGroupMemberRemovePath,
  tenantAccessApproverGroupRemovePath,
  tenantAccessDelegatedGrantRevokePath,
  tenantAccessMemberInvitePath,
  tenantAccessMemberRemovePath,
  tenantAccessMemberRolePath,
  tenantAccessMembershipScopeRemovePath,
} from "../access-admin-helpers";
import { TenantApiKeyAdminTableRow } from "../api-key-table-row";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminEmptyTableRow,
  AdminForm,
  AdminMeta,
  AdminStatusPill,
} from "../components";
import { buildLmsConnectionEditPath, isLmsConnectionReady } from "../lms-connection-admin-helpers";
import { accessSectionKindsForDataNeeds } from "./access-section-kinds";
import { renderInstitutionAdminAccessSections } from "./access-sections";
import type { InstitutionAdminPageInput } from "./page-types";
import type {
  InstitutionAdminViewContentInput,
  InstitutionAdminViewDataNeeds,
} from "./view-content";
import type { buildInstitutionAdminViewPaths } from "./view-paths";
import type { InstitutionAdminViewOptionResources } from "./view-option-resources";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | HonoElement[];

const emptySectionMarkup = <></>;

const formatDelegatedIssuingActionLabel = (action: string): string => {
  switch (action) {
    case "issue_badge":
      return "Issue badges";
    case "revoke_badge":
      return "Revoke badges";
    case "manage_lifecycle":
      return "Change badge status";
    default:
      return action;
  }
};

const buildOrgUnitRows = (page: InstitutionAdminPageInput, enabled: boolean): HonoElement => {
  if (!enabled) {
    return emptySectionMarkup;
  }

  if (page.orgUnits.length === 0) {
    return <AdminEmptyTableRow colSpan={4}>No org units found.</AdminEmptyTableRow>;
  }

  return page.orgUnits.map((orgUnit) => (
    <tr>
      <td>{orgUnit.displayName}</td>
      <td>{orgUnit.unitType}</td>
      <td>{orgUnit.id}</td>
      <td>{orgUnit.isActive ? "Active" : "Inactive"}</td>
    </tr>
  ));
};

const buildApiKeyRows = (page: InstitutionAdminPageInput, enabled: boolean): HonoElement => {
  if (!enabled) {
    return emptySectionMarkup;
  }

  if (page.activeApiKeys.length === 0) {
    return <AdminEmptyTableRow colSpan={5}>No active API keys found.</AdminEmptyTableRow>;
  }

  return page.activeApiKeys.map((apiKey) => (
    <TenantApiKeyAdminTableRow tenantId={page.tenant.id} apiKey={apiKey} />
  ));
};

const formatNullableTimestamp = (timestampIso: string | null): string => {
  return timestampIso === null ? "Not connected" : formatIsoTimestamp(timestampIso);
};

const formatLmsProviderLabel = (
  providerKind: TenantLmsConnectionRecord["providerKind"],
): string => {
  return providerKind === "sakai" ? "Sakai" : "Canvas";
};

const buildLmsConnectionRows = (page: InstitutionAdminPageInput, enabled: boolean): HonoElement => {
  if (!enabled) {
    return emptySectionMarkup;
  }

  if (page.lmsConnections.length === 0) {
    return <AdminEmptyTableRow colSpan={7}>No LMS connections configured yet.</AdminEmptyTableRow>;
  }

  return page.lmsConnections.map((connection) => {
    const connected = isLmsConnectionReady(connection);
    const ltiDetails = [
      connection.ltiIssuer === null ? null : `Issuer: ${connection.ltiIssuer}`,
      connection.ltiClientId === null ? null : `Client: ${connection.ltiClientId}`,
      connection.ltiDeploymentId === null ? null : `Deployment: ${connection.ltiDeploymentId}`,
    ].filter((value): value is string => value !== null);

    return (
      <tr>
        <td>
          <strong>{connection.displayName}</strong>
          <AdminMeta>{connection.id}</AdminMeta>
        </td>
        <td>{formatLmsProviderLabel(connection.providerKind)}</td>
        <td>
          <span>{connection.apiBaseUrl}</span>
        </td>
        <td>
          <AdminStatusPill tone={connected ? "active" : "warning"}>
            {connected ? "Connected" : "Needs credentials"}
          </AdminStatusPill>
        </td>
        <td>{formatNullableTimestamp(connection.connectedAt)}</td>
        <td>
          {ltiDetails.length === 0 ? (
            <AdminMeta as="span">Not recorded</AdminMeta>
          ) : (
            ltiDetails.join(" · ")
          )}
        </td>
        <td>
          <AdminButtonLink
            href={buildLmsConnectionEditPath(page.tenant.id, connection.id)}
            size="tiny"
            variant="secondary"
          >
            Edit
          </AdminButtonLink>
        </td>
      </tr>
    );
  });
};

const tenantMemberRoleOptions = (
  page: InstitutionAdminPageInput,
  selectedRole: TenantMembershipRole,
): HonoElement => {
  const roles: readonly TenantMembershipRole[] =
    page.membershipRole === "owner"
      ? ["owner", "admin", "issuer", "approver", "viewer"]
      : ["admin", "issuer", "approver", "viewer"];

  return (
    <>
      {roles.map((role) => (
        <option value={role} selected={role === selectedRole}>
          {role}
        </option>
      ))}
    </>
  );
};

const buildTenantMemberRows = (page: InstitutionAdminPageInput, enabled: boolean): HonoElement => {
  if (!enabled) {
    return emptySectionMarkup;
  }

  if (page.tenantMembers.length === 0) {
    return <AdminEmptyTableRow colSpan={6}>No tenant members found.</AdminEmptyTableRow>;
  }

  return page.tenantMembers.map((member) => {
    const canManageMember =
      member.userId !== page.userId && (page.membershipRole === "owner" || member.role !== "owner");

    return (
      <tr>
        <td>
          <span class="ct-admin__member-identity">{member.email}</span>
          <AdminMeta>{member.userId}</AdminMeta>
        </td>
        <td>
          {canManageMember ? (
            <AdminForm
              method="post"
              action={tenantAccessMemberRolePath(page.tenant.id, member.userId)}
              className="ct-admin__inline-form"
              dataAttributes={{ "data-admin-role-form": "" }}
            >
              <AdminActions>
                <CtSelect
                  name="role"
                  ariaLabel={`Tenant role for ${member.email}`}
                  describedBy="tenant-role-auto-save-note"
                  dataAttributes={{ "data-current-role": member.role }}
                >
                  {tenantMemberRoleOptions(page, member.role)}
                </CtSelect>
                <AdminButton
                  type="submit"
                  size="tiny"
                  variant="secondary"
                  ariaLabel={`Save role for ${member.email}`}
                  dataAttributes={{ "data-admin-role-submit": "" }}
                >
                  Save role
                </AdminButton>
              </AdminActions>
            </AdminForm>
          ) : (
            <AdminStatusPill>{member.role}</AdminStatusPill>
          )}
        </td>
        <td>{formatIsoTimestamp(member.createdAt)}</td>
        <td>{formatIsoTimestamp(member.updatedAt)}</td>
        <td>{member.userId === page.userId ? "You" : "Member"}</td>
        <td>
          {canManageMember ? (
            <AdminActions>
              <AdminForm
                method="post"
                action={tenantAccessMemberInvitePath(page.tenant.id, member.userId)}
                className="ct-admin__inline-form"
              >
                <AdminButton type="submit" size="tiny" variant="secondary">
                  Resend invite
                </AdminButton>
              </AdminForm>
              <AdminForm
                method="post"
                action={tenantAccessMemberRemovePath(page.tenant.id, member.userId)}
                className="ct-admin__inline-form"
                dataAttributes={{
                  "data-confirm-message": `Remove tenant access for ${member.email}?`,
                }}
              >
                <AdminButton type="submit" size="tiny" variant="danger">
                  Remove
                </AdminButton>
              </AdminForm>
            </AdminActions>
          ) : (
            <AdminMeta as="span">
              {member.userId === page.userId ? "Current user" : "Owner action"}
            </AdminMeta>
          )}
        </td>
      </tr>
    );
  });
};

const buildMembershipScopeRows = (
  page: InstitutionAdminPageInput,
  enabled: boolean,
  orgUnitById: ReadonlyMap<string, InstitutionAdminPageInput["orgUnits"][number]>,
): HonoElement => {
  if (!enabled) {
    return emptySectionMarkup;
  }

  if (page.membershipOrgUnitScopes.length === 0) {
    return <AdminEmptyTableRow colSpan={5}>No scoped roles assigned yet.</AdminEmptyTableRow>;
  }

  return page.membershipOrgUnitScopes.map((scope) => {
    const orgUnit = orgUnitById.get(scope.orgUnitId);
    const scopeLabel = orgUnit?.displayName ?? scope.orgUnitId;
    const orgUnitMarkup =
      orgUnit === undefined ? (
        <strong>{scope.orgUnitId}</strong>
      ) : (
        <>
          <strong>{orgUnit.displayName}</strong>
          <div class="ct-admin__meta">{`${orgUnit.id} · ${orgUnit.unitType}`}</div>
        </>
      );

    return (
      <tr>
        <td>
          <strong>{scope.userId}</strong>
        </td>
        <td>{orgUnitMarkup}</td>
        <td>
          <AdminStatusPill>{scope.role}</AdminStatusPill>
        </td>
        <td>{formatIsoTimestamp(scope.updatedAt)}</td>
        <td>
          <AdminForm
            method="post"
            action={tenantAccessMembershipScopeRemovePath(page.tenant.id)}
            className="ct-admin__inline-form"
            dataAttributes={{
              "data-confirm-message": `Remove scoped role for ${scope.userId} · ${scopeLabel}?`,
            }}
          >
            <CtInput type="hidden" name="userId" value={scope.userId} />
            <CtInput type="hidden" name="orgUnitId" value={scope.orgUnitId} />
            <AdminButton type="submit" size="tiny" variant="danger">
              Remove
            </AdminButton>
          </AdminForm>
        </td>
      </tr>
    );
  });
};

const buildApproverGroupRows = (
  page: InstitutionAdminPageInput,
  enabled: boolean,
  orgUnitById: ReadonlyMap<string, InstitutionAdminPageInput["orgUnits"][number]>,
): HonoElement => {
  if (!enabled) {
    return emptySectionMarkup;
  }

  if (page.badgeRuleApproverGroups.length === 0) {
    return <AdminEmptyTableRow colSpan={5}>No approver groups created yet.</AdminEmptyTableRow>;
  }

  return page.badgeRuleApproverGroups.map((group) => {
    const orgUnitLabel =
      group.orgUnitId === null
        ? "Tenant-wide"
        : (orgUnitById.get(group.orgUnitId)?.displayName ?? group.orgUnitId);

    return (
      <tr>
        <td>
          <strong>{group.name}</strong>
          <AdminMeta>{group.id}</AdminMeta>
        </td>
        <td>{orgUnitLabel}</td>
        <td>
          {group.members.length === 0 ? (
            <AdminMeta as="span">No members</AdminMeta>
          ) : (
            group.members.map((member) => (
              <div class="ct-admin__stacked-line">
                <span>{member.email ?? member.userId}</span>
                <AdminMeta>{member.role ?? "member"}</AdminMeta>
              </div>
            ))
          )}
        </td>
        <td>{formatIsoTimestamp(group.updatedAt)}</td>
        <td>
          <AdminActions>
            {group.members.map((member) => (
              <AdminForm
                method="post"
                action={tenantAccessApproverGroupMemberRemovePath(page.tenant.id)}
                className="ct-admin__inline-form"
                dataAttributes={{
                  "data-confirm-message": `Remove ${member.email ?? member.userId} from ${group.name}?`,
                }}
              >
                <CtInput type="hidden" name="groupId" value={group.id} />
                <CtInput type="hidden" name="userId" value={member.userId} />
                <AdminButton type="submit" size="tiny" variant="secondary">
                  Remove member
                </AdminButton>
              </AdminForm>
            ))}
            <AdminForm
              method="post"
              action={tenantAccessApproverGroupRemovePath(page.tenant.id)}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Remove approver group ${group.name}?`,
              }}
            >
              <CtInput type="hidden" name="groupId" value={group.id} />
              <AdminButton type="submit" size="tiny" variant="danger">
                Remove group
              </AdminButton>
            </AdminForm>
          </AdminActions>
        </td>
      </tr>
    );
  });
};

const buildDelegatedGrantRows = (
  page: InstitutionAdminPageInput,
  enabled: boolean,
  orgUnitById: ReadonlyMap<string, InstitutionAdminPageInput["orgUnits"][number]>,
  templateById: ReadonlyMap<string, InstitutionAdminPageInput["badgeTemplates"][number]>,
): HonoElement => {
  if (!enabled) {
    return emptySectionMarkup;
  }

  if (page.delegatedIssuingAuthorityGrants.length === 0) {
    return (
      <AdminEmptyTableRow colSpan={6}>No delegated authority grants exist yet.</AdminEmptyTableRow>
    );
  }

  return page.delegatedIssuingAuthorityGrants.map((grant) => {
    const canRemove = grant.status === "active" || grant.status === "scheduled";
    const statusMeta =
      grant.status === "revoked"
        ? grant.revokedAt === null
          ? "Removed"
          : `Removed ${formatIsoTimestamp(grant.revokedAt)}`
        : `Ends ${formatIsoTimestamp(grant.endsAt)}`;
    const orgUnit = orgUnitById.get(grant.orgUnitId);
    const orgUnitMarkup =
      orgUnit === undefined ? (
        <strong>{grant.orgUnitId}</strong>
      ) : (
        <>
          <strong>{orgUnit.displayName}</strong>
          <div class="ct-admin__meta">{`${orgUnit.id} · ${orgUnit.unitType}`}</div>
        </>
      );
    const templateScopeSummary =
      grant.badgeTemplateIds.length === 0
        ? "All badge templates in scope"
        : grant.badgeTemplateIds
            .map((templateId) => templateById.get(templateId)?.title ?? templateId)
            .join(", ");

    return (
      <tr>
        <td>
          <strong>{grant.delegateUserId}</strong>
          <AdminMeta>{grant.id}</AdminMeta>
        </td>
        <td>{orgUnitMarkup}</td>
        <td>
          {grant.allowedActions.map(formatDelegatedIssuingActionLabel).join(", ")}
          <AdminMeta>{templateScopeSummary}</AdminMeta>
        </td>
        <td>
          <strong>{formatIsoTimestamp(grant.startsAt)}</strong>
          <AdminMeta>Starts</AdminMeta>
          <AdminMeta>Granted by {grant.delegatedByUserId ?? "system"}</AdminMeta>
        </td>
        <td>
          <AdminStatusPill tone={grant.status}>{grant.status}</AdminStatusPill>
          <AdminMeta>{statusMeta}</AdminMeta>
          {grant.revokedReason === null ? null : (
            <AdminMeta>Reason: {grant.revokedReason}</AdminMeta>
          )}
        </td>
        <td>
          {canRemove ? (
            <AdminForm
              method="post"
              action={tenantAccessDelegatedGrantRevokePath(page.tenant.id)}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Remove delegation for ${grant.delegateUserId} · ${grant.id}?`,
              }}
            >
              <CtInput type="hidden" name="delegateUserId" value={grant.delegateUserId} />
              <CtInput type="hidden" name="grantId" value={grant.id} />
              <AdminButton type="submit" size="tiny" variant="danger">
                Remove
              </AdminButton>
            </AdminForm>
          ) : (
            <AdminMeta as="span">No action</AdminMeta>
          )}
        </td>
      </tr>
    );
  });
};

const emptyAccessResources = (): InstitutionAdminViewContentInput["access"] => ({
  apiKeysTableMarkup: emptySectionMarkup,
  approverGroupTableMarkup: emptySectionMarkup,
  delegatedGrantTableMarkup: emptySectionMarkup,
  delegatedGrantActionsMarkup: emptySectionMarkup,
  governanceGuidePanelMarkup: emptySectionMarkup,
  lmsConnectionsActionsMarkup: emptySectionMarkup,
  lmsConnectionsTableMarkup: emptySectionMarkup,
  membershipScopeTableMarkup: emptySectionMarkup,
  orgUnitsTableMarkup: emptySectionMarkup,
  ruleApprovalPolicySummaryMarkup: emptySectionMarkup,
  tenantMembersTableMarkup: emptySectionMarkup,
});

export const buildInstitutionAdminAccessViewResources = (input: {
  page: InstitutionAdminPageInput;
  paths: ReturnType<typeof buildInstitutionAdminViewPaths>;
  dataNeeds: InstitutionAdminViewDataNeeds;
  options: InstitutionAdminViewOptionResources["access"];
}): InstitutionAdminViewContentInput["access"] => {
  if (!input.dataNeeds.accessSectionBundles) {
    return emptyAccessResources();
  }

  const { page, paths, dataNeeds, options } = input;
  const orgUnitById = new Map(page.orgUnits.map((orgUnit) => [orgUnit.id, orgUnit]));
  const templateById = new Map(page.badgeTemplates.map((template) => [template.id, template]));
  const sections = renderInstitutionAdminAccessSections({
    accessMembersPath: paths.accessMembersPath,
    accessOrgUnitAccessPath: paths.accessOrgUnitAccessPath,
    accessGovernancePath: paths.accessGovernancePath,
    accessDelegationsPath: paths.accessDelegationsPath,
    accessAuthenticationPath: paths.accessAuthenticationPath,
    accessApiKeysPath: paths.accessApiKeysPath,
    accessOrgUnitsPath: paths.accessOrgUnitsPath,
    accessLmsConnectionsPath: paths.accessLmsConnectionsPath,
    planTier: page.tenant.planTier,
    tenantId: page.tenant.id,
    tenantMemberCount: String(page.tenantMembers.length),
    scopedRoleCount: String(page.membershipOrgUnitScopes.length),
    delegatedAuthorityGrantCount: String(page.delegatedIssuingAuthorityGrants.length),
    activeApiKeyCount: String(page.activeApiKeys.length),
    revokedApiKeyCount: String(page.revokedApiKeyCount),
    orgUnitCount: String(page.orgUnits.length),
    lmsConnectionCount: String(page.lmsConnections.length),
    tenantMemberRoleSelectOptions: options.tenantMemberRoleSelectOptions,
    tenantMemberRows: buildTenantMemberRows(page, dataNeeds.tenantMemberRows),
    apiKeyRows: buildApiKeyRows(page, dataNeeds.apiKeyRows),
    orgUnitRows: buildOrgUnitRows(page, dataNeeds.orgUnitRows),
    orgUnitParentOptions: options.orgUnitParentOptions,
    tenantMemberSelectOptions: options.tenantMemberSelectOptions,
    badgeRuleApprovalTargetUserSelectOptions: options.badgeRuleApprovalTargetUserSelectOptions,
    approverGroupSelectOptions: options.approverGroupSelectOptions,
    badgeRuleApprovalTargetApproverGroupSelectOptions:
      options.badgeRuleApprovalTargetApproverGroupSelectOptions,
    activeOrgUnitSelectOptions: options.activeOrgUnitSelectOptions,
    badgeRuleApprovalOrgUnitSelectOptions: options.badgeRuleApprovalOrgUnitSelectOptions,
    optionalBadgeTemplateScopeOptions: options.optionalBadgeTemplateScopeOptions,
    membershipScopeRows: buildMembershipScopeRows(page, dataNeeds.scopedRoleRows, orgUnitById),
    approverGroupRows: buildApproverGroupRows(page, dataNeeds.governanceTableRows, orgUnitById),
    delegatedGrantRows: buildDelegatedGrantRows(
      page,
      dataNeeds.delegatedGrantRows,
      orgUnitById,
      templateById,
    ),
    lmsConnectionRows: buildLmsConnectionRows(page, dataNeeds.lmsConnectionRows),
    badgeRuleApprovalPolicy: page.badgeRuleApprovalPolicy ?? null,
    enabledSections: accessSectionKindsForDataNeeds(dataNeeds),
    ...(page.apiKeysWorkspace === undefined ? {} : { apiKeysWorkspace: page.apiKeysWorkspace }),
    ...(page.lmsConnectionsWorkspace === undefined
      ? {}
      : { lmsConnectionsWorkspace: page.lmsConnectionsWorkspace }),
    ...(page.accessMembersWorkspace === undefined
      ? {}
      : { accessMembersWorkspace: page.accessMembersWorkspace }),
    ...(page.accessOrgUnitAccessWorkspace === undefined
      ? {}
      : { accessOrgUnitAccessWorkspace: page.accessOrgUnitAccessWorkspace }),
    ...(page.accessGovernanceWorkspace === undefined
      ? {}
      : { accessGovernanceWorkspace: page.accessGovernanceWorkspace }),
    ...(page.accessDelegationsWorkspace === undefined
      ? {}
      : { accessDelegationsWorkspace: page.accessDelegationsWorkspace }),
    ...(page.accessOrgUnitsWorkspace === undefined
      ? {}
      : { accessOrgUnitsWorkspace: page.accessOrgUnitsWorkspace }),
  });

  return {
    apiKeysTableMarkup: sections.apiKeysTableMarkup,
    approverGroupTableMarkup: sections.approverGroupTableMarkup,
    delegatedGrantTableMarkup: sections.delegatedGrantTableMarkup,
    delegatedGrantActionsMarkup: sections.delegatedGrantActionsMarkup,
    governanceGuidePanelMarkup: sections.governanceGuidePanelMarkup,
    lmsConnectionsActionsMarkup: sections.lmsConnectionsActionsMarkup,
    lmsConnectionsTableMarkup: sections.lmsConnectionsTableMarkup,
    membershipScopeTableMarkup: sections.membershipScopeTableMarkup,
    orgUnitsTableMarkup: sections.orgUnitsTableMarkup,
    ruleApprovalPolicySummaryMarkup: sections.ruleApprovalPolicySummaryMarkup,
    tenantMembersTableMarkup: sections.tenantMembersTableMarkup,
  };
};
