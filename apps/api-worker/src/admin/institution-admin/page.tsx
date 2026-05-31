import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  TenantLmsConnectionRecord,
  TenantMembershipRole,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../../ui/render-page";
import type { PageAssetKey } from "../../ui/page-assets";
import { formatIsoTimestamp } from "../../utils/display-format";
import {
  AdminButton,
  AdminButtonLink,
  AdminActions,
  AdminEmptyTableRow,
  AdminMeta,
  AdminPageHeader,
  AdminShell,
  AdminSidebar,
  AdminStatusPill,
  AdminTopbar,
  AdminWorkspaceCard,
  type AdminSidebarFooterLink,
} from "../components";
import { buildInstitutionAdminSidebarSectionsForTenant } from "../institution-admin-sidebar";
import { lmsConnectionsPageUrl } from "../lms-connection-admin-helpers";
import { TenantApiKeyAdminTableRow } from "../api-key-table-row";
import { serializeJsonScriptContent } from "../institution-admin-shell";
import { renderInstitutionAdminAccessSections } from "./access-sections";
import { renderEnterpriseAuthSection } from "./enterprise-auth-section";
import { renderInstitutionAdminLearnerRecordSections } from "./learner-record-sections";
import { renderInstitutionAdminManagementSections } from "./management-sections";
import { renderInstitutionAdminOperationsSections } from "./operations-sections";
import {
  INSTITUTION_ADMIN_VIEW_CONFIG,
  type InstitutionAdminPageInput,
  type InstitutionAdminView,
} from "./page-types";
import { renderInstitutionAdminReportingSections } from "./reporting-sections";
export {
  institutionAdminRuleTemplateEditorPage,
  institutionAdminRuleTemplatesPage,
} from "../institution-admin-templates-page";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

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

const renderInstitutionAdminPage = (
  input: InstitutionAdminPageInput,
  view: InstitutionAdminView,
): AppPage => {
  const templateById = new Map(input.badgeTemplates.map((template) => [template.id, template]));
  const orgUnitById = new Map(input.orgUnits.map((orgUnit) => [orgUnit.id, orgUnit]));
  const versionsByRuleId = new Map<string, BadgeIssuanceRuleVersionRecord[]>();
  const tenantAdminPath = `/tenants/${encodeURIComponent(input.tenant.id)}/admin`;
  const operationsPath = `${tenantAdminPath}/operations`;
  const operationsLearnerRecordsPath = `${operationsPath}/learner-records`;
  const operationsLearnerRecordImportsPath = `${operationsPath}/learner-record-imports`;
  const reportingPath = `${tenantAdminPath}/reporting`;
  const reportingExplorePath = `${reportingPath}/explore`;
  const reportingTrendsPath = `${reportingPath}/trends`;
  const reportingReportsPath = `${reportingPath}/reports`;
  const rulesWorkspacePath = `${tenantAdminPath}/rules`;
  const rulesTemplatesPath = `${rulesWorkspacePath}/templates`;
  const accessPath = `${tenantAdminPath}/access`;
  const accessMembersPath = `${accessPath}/members`;
  const accessGovernancePath = `${accessPath}/governance`;
  const accessApiKeysPath = `${accessPath}/api-keys`;
  const accessOrgUnitsPath = `${accessPath}/org-units`;
  const accessLmsConnectionsPath = `${accessPath}/lms-connections`;
  const ruleBuilderPath = `${tenantAdminPath}/rules/new`;
  const badgeTemplateCount = String(input.badgeTemplates.length);
  const orgUnitCount = String(input.orgUnits.length);
  const lmsConnectionCount = String(input.lmsConnections.length);
  const activeApiKeyCount = String(input.activeApiKeys.length);
  const revokedApiKeyCount = String(input.revokedApiKeyCount);
  const ruleCount = String(input.badgeRules.length);
  const hasBadgeRules = input.badgeRules.length > 0;
  const tenantMemberCount = String(input.tenantMembers.length);
  const scopedRoleCount = String(input.membershipOrgUnitScopes.length);
  const delegatedAuthorityGrantCount = String(input.delegatedIssuingAuthorityGrants.length);
  const userLabel = input.userEmail ?? input.userId;
  const switchOrganizationPath = input.switchOrganizationPath?.trim() ?? "";
  const learnerRecordReview = input.learnerRecordReview ?? {
    lookup: {},
    learnerProfile: null,
    presentation: null,
    exportPath: null,
    standardsMappingPath: null,
    lookupState: "idle" as const,
  };
  const learnerRecordImportWorkflow = input.learnerRecordImportWorkflow ?? {
    templatePath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/learner-record-imports/template.csv`,
    previewPath: operationsLearnerRecordImportsPath,
    applyPath: operationsLearnerRecordImportsPath,
    defaults: {
      defaultTrustLevel: "issuer_verified" as const,
      defaultIssuerName: "",
    },
    submission: null,
    feedback: null,
    progress: {
      totals: {
        messages: 0,
        batches: 0,
        pendingRows: 0,
        processingRows: 0,
        completedRows: 0,
        failedRows: 0,
      },
      batches: [],
    },
  };
  const reportingOverview = input.reportingOverview ?? null;
  const renderOrgUnitSummary = (orgUnitId: string): HonoElement => {
    const orgUnit = orgUnitById.get(orgUnitId);

    if (orgUnit === undefined) {
      return <strong>{orgUnitId}</strong>;
    }

    return (
      <>
        <strong>{orgUnit.displayName}</strong>
        <div class="ct-admin__meta">{`${orgUnit.id} · ${orgUnit.unitType}`}</div>
      </>
    );
  };
  const renderBadgeTemplateScopeSummary = (badgeTemplateIds: readonly string[]): string => {
    if (badgeTemplateIds.length === 0) {
      return "All badge templates in scope";
    }

    return badgeTemplateIds
      .map((badgeTemplateId) => templateById.get(badgeTemplateId)?.title ?? badgeTemplateId)
      .join(", ");
  };
  for (const version of input.badgeRuleVersions) {
    const versions = versionsByRuleId.get(version.ruleId);

    if (versions === undefined) {
      versionsByRuleId.set(version.ruleId, [version]);
      continue;
    }

    versions.push(version);
  }

  for (const versions of versionsByRuleId.values()) {
    versions.sort((left, right) => right.versionNumber - left.versionNumber);
  }

  const orgUnitRows =
    input.orgUnits.length === 0 ? (
      <AdminEmptyTableRow colSpan={4}>No org units found.</AdminEmptyTableRow>
    ) : (
      input.orgUnits.map((orgUnit) => (
        <tr>
          <td>{orgUnit.displayName}</td>
          <td>{orgUnit.unitType}</td>
          <td>{orgUnit.id}</td>
          <td>{orgUnit.isActive ? "Active" : "Inactive"}</td>
        </tr>
      ))
    );

  const apiKeyRows =
    input.activeApiKeys.length === 0 ? (
      <AdminEmptyTableRow colSpan={5}>No active API keys found.</AdminEmptyTableRow>
    ) : (
      input.activeApiKeys.map((apiKey) => (
        <TenantApiKeyAdminTableRow tenantId={input.tenant.id} apiKey={apiKey} />
      ))
    );

  const formatNullableTimestamp = (timestampIso: string | null): string => {
    return timestampIso === null ? "Not connected" : formatIsoTimestamp(timestampIso);
  };

  const formatLmsProviderLabel = (
    providerKind: TenantLmsConnectionRecord["providerKind"],
  ): string => {
    return providerKind === "sakai" ? "Sakai" : "Canvas";
  };

  const lmsConnectionRows =
    input.lmsConnections.length === 0 ? (
      <AdminEmptyTableRow colSpan={7}>No LMS connections configured yet.</AdminEmptyTableRow>
    ) : (
      input.lmsConnections.map((connection) => {
        const connected = connection.accessToken !== null && connection.accessToken.length > 0;
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
                {connected ? "Connected" : "Needs token"}
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
                href={lmsConnectionsPageUrl(input.tenant.id, { edit: connection.id })}
                size="tiny"
                variant="secondary"
              >
                Edit
              </AdminButtonLink>
            </td>
          </tr>
        );
      })
    );

  const assignableTenantRoles: TenantMembershipRole[] =
    input.membershipRole === "owner"
      ? ["owner", "admin", "issuer", "viewer"]
      : ["admin", "issuer", "viewer"];
  const tenantMemberRoleOptions = (selectedRole: TenantMembershipRole): HonoElement => {
    const roles: readonly TenantMembershipRole[] =
      input.membershipRole === "owner" ? assignableTenantRoles : ["admin", "issuer", "viewer"];

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
  const tenantMemberRows =
    input.tenantMembers.length === 0 ? (
      <AdminEmptyTableRow colSpan={6}>No tenant members found.</AdminEmptyTableRow>
    ) : (
      input.tenantMembers.map((member) => {
        const canManageMember =
          member.userId !== input.userId &&
          (input.membershipRole === "owner" || member.role !== "owner");

        return (
          <tr>
            <td>
              <span class="ct-admin__member-identity">{member.email}</span>
              <AdminMeta>{member.userId}</AdminMeta>
            </td>
            <td>
              {canManageMember ? (
                <select
                  aria-label={`Tenant role for ${member.email}`}
                  data-tenant-member-role-user-id={member.userId}
                  data-tenant-member-current-role={member.role}
                >
                  {tenantMemberRoleOptions(member.role)}
                </select>
              ) : (
                <AdminStatusPill>{member.role}</AdminStatusPill>
              )}
            </td>
            <td>{formatIsoTimestamp(member.createdAt)}</td>
            <td>{formatIsoTimestamp(member.updatedAt)}</td>
            <td>{member.userId === input.userId ? "You" : "Member"}</td>
            <td>
              {canManageMember ? (
                <AdminActions>
                  <AdminButton
                    type="button"
                    size="tiny"
                    variant="secondary"
                    dataAttributes={{
                      "data-tenant-member-invite-user-id": member.userId,
                      "data-tenant-member-email": member.email,
                    }}
                  >
                    Resend invite
                  </AdminButton>
                  <AdminButton
                    type="button"
                    size="tiny"
                    variant="danger"
                    dataAttributes={{
                      "data-tenant-member-remove-user-id": member.userId,
                      "data-tenant-member-email": member.email,
                    }}
                  >
                    Remove
                  </AdminButton>
                </AdminActions>
              ) : (
                <AdminMeta as="span">
                  {member.userId === input.userId ? "Current user" : "Owner action"}
                </AdminMeta>
              )}
            </td>
          </tr>
        );
      })
    );

  const membershipScopeRows =
    input.membershipOrgUnitScopes.length === 0 ? (
      <AdminEmptyTableRow colSpan={5}>No scoped roles assigned yet.</AdminEmptyTableRow>
    ) : (
      input.membershipOrgUnitScopes.map((scope) => {
        const scopeLabel = orgUnitById.get(scope.orgUnitId)?.displayName ?? scope.orgUnitId;

        return (
          <tr>
            <td>
              <strong>{scope.userId}</strong>
            </td>
            <td>{renderOrgUnitSummary(scope.orgUnitId)}</td>
            <td>
              <AdminStatusPill>{scope.role}</AdminStatusPill>
            </td>
            <td>{formatIsoTimestamp(scope.updatedAt)}</td>
            <td>
              <AdminButton
                type="button"
                size="tiny"
                variant="danger"
                dataAttributes={{
                  "data-membership-scope-remove-user-id": scope.userId,
                  "data-membership-scope-remove-org-unit-id": scope.orgUnitId,
                  "data-membership-scope-remove-label": `${scope.userId} · ${scopeLabel}`,
                }}
              >
                Remove
              </AdminButton>
            </td>
          </tr>
        );
      })
    );

  const delegatedGrantRows =
    input.delegatedIssuingAuthorityGrants.length === 0 ? (
      <AdminEmptyTableRow colSpan={6}>No delegated authority grants exist yet.</AdminEmptyTableRow>
    ) : (
      input.delegatedIssuingAuthorityGrants.map((grant) => {
        const canRemove = grant.status === "active" || grant.status === "scheduled";
        const statusMeta =
          grant.status === "revoked"
            ? grant.revokedAt === null
              ? "Removed"
              : `Removed ${formatIsoTimestamp(grant.revokedAt)}`
            : `Ends ${formatIsoTimestamp(grant.endsAt)}`;
        return (
          <tr>
            <td>
              <strong>{grant.delegateUserId}</strong>
              <AdminMeta>{grant.id}</AdminMeta>
            </td>
            <td>{renderOrgUnitSummary(grant.orgUnitId)}</td>
            <td>
              {grant.allowedActions
                .map((action) => formatDelegatedIssuingActionLabel(action))
                .join(", ")}
              <AdminMeta>{renderBadgeTemplateScopeSummary(grant.badgeTemplateIds)}</AdminMeta>
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
                <AdminButton
                  type="button"
                  size="tiny"
                  variant="danger"
                  dataAttributes={{
                    "data-delegated-grant-remove-user-id": grant.delegateUserId,
                    "data-delegated-grant-remove-id": grant.id,
                    "data-delegated-grant-remove-label": `${grant.delegateUserId} · ${grant.id}`,
                  }}
                >
                  Remove
                </AdminButton>
              ) : (
                <AdminMeta as="span">No action</AdminMeta>
              )}
            </td>
          </tr>
        );
      })
    );

  const ruleRows =
    input.badgeRules.length === 0 ? (
      <AdminEmptyTableRow colSpan={8}>
        No badge rules found. <a href={ruleBuilderPath}>Create your first rule</a>.
      </AdminEmptyTableRow>
    ) : (
      input.badgeRules.map((rule) => {
        const templateTitle = templateById.get(rule.badgeTemplateId)?.title ?? rule.badgeTemplateId;
        const versions = versionsByRuleId.get(rule.id) ?? [];
        const latestVersion = versions[0] ?? null;
        const submitApprovalPath =
          latestVersion === null
            ? null
            : `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules/${encodeURIComponent(
                rule.id,
              )}/versions/${encodeURIComponent(latestVersion.id)}/submit-approval`;
        const approvePath =
          latestVersion === null
            ? null
            : `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules/${encodeURIComponent(
                rule.id,
              )}/versions/${encodeURIComponent(latestVersion.id)}/decision`;
        const activatePath =
          latestVersion === null
            ? null
            : `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules/${encodeURIComponent(
                rule.id,
              )}/versions/${encodeURIComponent(latestVersion.id)}/activate`;
        const actionButtons: HonoElement[] = [];

        if (latestVersion !== null) {
          if (latestVersion.status === "draft" || latestVersion.status === "rejected") {
            actionButtons.push(
              <AdminButton
                type="button"
                size="tiny"
                dataAttributes={{
                  "data-rule-submit-path": submitApprovalPath ?? "",
                  "data-rule-label": rule.name,
                }}
              >
                Mark ready
              </AdminButton>,
            );
          }

          if (latestVersion.status === "pending_approval") {
            actionButtons.push(
              <AdminButton
                type="button"
                size="tiny"
                dataAttributes={{
                  "data-rule-decision-path": approvePath ?? "",
                  "data-rule-decision": "approved",
                  "data-rule-label": rule.name,
                }}
              >
                Approve
              </AdminButton>,
            );
            actionButtons.push(
              <AdminButton
                type="button"
                size="tiny"
                variant="danger"
                dataAttributes={{
                  "data-rule-decision-path": approvePath ?? "",
                  "data-rule-decision": "rejected",
                  "data-rule-label": rule.name,
                }}
              >
                Reject
              </AdminButton>,
            );
          }

          if (latestVersion.status === "approved" || latestVersion.status === "active") {
            actionButtons.push(
              <AdminButton
                type="button"
                size="tiny"
                dataAttributes={{
                  "data-rule-activate-path": activatePath ?? "",
                  "data-rule-label": rule.name,
                }}
              >
                Activate
              </AdminButton>,
            );
          }
        }

        return (
          <tr>
            <td>
              <strong>{rule.name}</strong>
              <AdminMeta>{rule.id}</AdminMeta>
            </td>
            <td>{templateTitle}</td>
            <td>{rule.lmsProviderKind}</td>
            <td>{rule.activeVersionId ?? "none"}</td>
            <td>
              {latestVersion === null ? (
                "none"
              ) : (
                <>
                  <strong>Version {String(latestVersion.versionNumber)}</strong>
                  <AdminMeta>Version ID: {latestVersion.id}</AdminMeta>
                </>
              )}
            </td>
            <td>
              <AdminStatusPill tone={latestVersion?.status ?? "none"}>
                {latestVersion?.status ?? "none"}
              </AdminStatusPill>
            </td>
            <td>{formatIsoTimestamp(rule.updatedAt)}</td>
            <td>
              {actionButtons.length > 0 ? (
                <AdminActions>{actionButtons}</AdminActions>
              ) : (
                <AdminMeta as="span">No actions</AdminMeta>
              )}
            </td>
          </tr>
        );
      })
    );

  const manualIssueApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/assertions/manual-issue`;
  const createApiKeyPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/api-keys`;
  const createOrgUnitPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/org-units`;
  const lmsConnectionsApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/lms/connections`;
  const badgeRuleApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules`;
  const badgeRulePreviewSimulationApiPath = `${badgeRuleApiPath}/preview-simulate`;
  const assertionsApiPathPrefix = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/assertions`;
  const tenantUsersApiPathPrefix = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/users`;
  const showcasePath = `/showcase/${encodeURIComponent(input.tenant.id)}`;
  const orgUnitParentOptions = input.orgUnits
    .filter((orgUnit) => orgUnit.isActive)
    .map((orgUnit) => {
      return (
        <option value={orgUnit.id} data-unit-type={orgUnit.unitType}>
          {`${orgUnit.displayName} (${orgUnit.unitType})`}
        </option>
      );
    });
  const activeOrgUnitOptions = input.orgUnits
    .filter((orgUnit) => orgUnit.isActive)
    .map((orgUnit) => {
      return <option value={orgUnit.id}>{`${orgUnit.displayName} (${orgUnit.unitType})`}</option>;
    });
  const tenantMemberOptions = input.tenantMembers.map((member) => {
    return <option value={member.userId}>{`${member.email} (${member.role})`}</option>;
  });
  const templateOptions = input.badgeTemplates.map((template, index) => {
    return (
      <option value={template.id} selected={index === 0}>
        {`${template.title} (${template.id})`}
      </option>
    );
  });
  const selectedBadgeTemplateFilterId = input.issuedBadgesWorkspace?.filters.badgeTemplateId ?? "";
  const templateFilterOptions = (
    <>
      <option value="" selected={selectedBadgeTemplateFilterId.length === 0}>
        All templates
      </option>
      {input.badgeTemplates.map((template) => (
        <option value={template.id} selected={template.id === selectedBadgeTemplateFilterId}>
          {template.title}
        </option>
      ))}
    </>
  );
  const lmsEditConnectionId = input.lmsConnectionsWorkspace?.editConnectionId ?? null;
  const lmsEditConnection =
    lmsEditConnectionId === null
      ? null
      : (input.lmsConnections.find((connection) => connection.id === lmsEditConnectionId) ?? null);
  const lmsConnectionFormValues =
    lmsEditConnection === null
      ? undefined
      : {
          connectionId: lmsEditConnection.id,
          displayName: lmsEditConnection.displayName,
          providerKind: lmsEditConnection.providerKind,
          apiBaseUrl: lmsEditConnection.apiBaseUrl,
          ltiIssuer: lmsEditConnection.ltiIssuer ?? "",
          ltiClientId: lmsEditConnection.ltiClientId ?? "",
          ltiDeploymentId: lmsEditConnection.ltiDeploymentId ?? "",
        };
  const formatRuleOption = (
    rule: BadgeIssuanceRuleRecord,
    includeSelected: boolean,
    index: number,
  ): HonoElement => {
    const versions = versionsByRuleId.get(rule.id) ?? [];
    const latestVersion = versions[0] ?? null;

    return (
      <option
        value={rule.id}
        selected={includeSelected && index === 0}
        data-version-id={latestVersion?.id ?? ""}
        data-version-status={latestVersion?.status ?? "none"}
        data-rule-label={rule.name}
      >
        {`${rule.name} (${rule.id}) · latest ${
          latestVersion === null
            ? "none"
            : `v${String(latestVersion.versionNumber)} ${latestVersion.status}`
        }`}
      </option>
    );
  };
  const ruleOptions = input.badgeRules.map((rule, index) => formatRuleOption(rule, true, index));
  const templateSelectOptions =
    templateOptions.length > 0 ? (
      templateOptions
    ) : (
      <option value="">No badge templates available</option>
    );
  const activeOrgUnitSelectOptions =
    activeOrgUnitOptions.length > 0 ? (
      activeOrgUnitOptions
    ) : (
      <option value="">No active org units available</option>
    );
  const tenantMemberSelectOptions =
    tenantMemberOptions.length > 0 ? (
      tenantMemberOptions
    ) : (
      <option value="">No tenant members available</option>
    );
  const optionalBadgeTemplateScopeOptions = (
    <>
      <option value="">All badge templates in the selected scope</option>
      {input.badgeTemplates.map((template) => (
        <option value={template.id}>{template.title}</option>
      ))}
    </>
  );
  const ruleSelectOptions =
    ruleOptions.length > 0 ? ruleOptions : <option value="">No rules available</option>;
  const authPolicyApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/auth-policy`;
  const authProvidersApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/auth-providers`;
  const enterpriseAuthPanelMarkup = renderEnterpriseAuthSection({
    tenant: input.tenant,
    enterpriseAuthPolicy: input.enterpriseAuthPolicy,
    enterpriseAuthProviders: input.enterpriseAuthProviders,
    breakGlassAccounts: input.breakGlassAccounts,
  });
  const tenantMemberEmailsByUserId = Object.fromEntries(
    input.tenantMembers.map((member) => [member.userId, member.email]),
  );
  const adminPageContextJson = serializeJsonScriptContent({
    tenantAdminPath,
    manualIssueApiPath,
    createApiKeyPath,
    createOrgUnitPath,
    lmsConnectionsApiPath,
    ruleBuilderPath,
    showcasePath,
    tenantMemberEmailsByUserId,
    badgeRuleApiPath,
    badgeRulePreviewSimulationApiPath,
    assertionsApiPathPrefix,
    tenantMembersApiPath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/members`,
    tenantUsersApiPathPrefix,
    reportingComparisonsApiPath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/comparisons`,
    reportingEngagementApiPath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/engagement`,
    reportingPagePath: reportingPath,
    reportingOverviewApiPath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/overview`,
    reportingTrendsApiPath: `/v1/tenants/${encodeURIComponent(input.tenant.id)}/reporting/trends`,
    authPolicyApiPath: input.tenant.planTier === "enterprise" ? authPolicyApiPath : "",
    authProvidersApiPath: input.tenant.planTier === "enterprise" ? authProvidersApiPath : "",
    breakGlassAccountsApiPath:
      input.tenant.planTier === "enterprise"
        ? `/v1/tenants/${encodeURIComponent(input.tenant.id)}/break-glass-accounts`
        : "",
  });
  const sidebarSections = buildInstitutionAdminSidebarSectionsForTenant(input.tenant.id, view);
  const sidebarFooterLinks: readonly AdminSidebarFooterLink[] = [
    {
      href: showcasePath,
      label: "Public showcase",
      isExternal: true,
      target: "_blank",
      rel: "noopener noreferrer",
    },
    ...(switchOrganizationPath.length > 0
      ? [{ href: switchOrganizationPath, label: "Switch organization" }]
      : []),
  ];

  const renderPageHeader = (
    title: string,
    description: string,
    noteMarkup: HonoElement | null = null,
  ): HonoElement => {
    return <AdminPageHeader title={title} description={description} note={noteMarkup} />;
  };

  const workspaceCardsMarkup = (
    <section class="ct-admin__workspace-grid ct-grid" aria-label="Institution admin workspaces">
      <AdminWorkspaceCard href={operationsPath} ariaLabel="Open Issue & Inspect workspace">
        <p class="ct-admin__eyebrow">Operations</p>
        <h2>Issue & Inspect</h2>
        <p>
          Issue badges, route manual review, inspect issued badges, and update badge status across
          focused pages.
        </p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{badgeTemplateCount} templates</AdminStatusPill>
          <AdminStatusPill>{ruleCount} rules</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard href={reportingPath} ariaLabel="Open Reporting workspace">
        <p class="ct-admin__eyebrow">Analytics</p>
        <h2>Reporting</h2>
        <p>
          Track issuance volume and badge status with filters, definitions, and clear source notes.
        </p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>Issued {reportingOverview?.counts.issued ?? 0}</AdminStatusPill>
          <AdminStatusPill>
            Pending review {reportingOverview?.counts.pendingReview ?? 0}
          </AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard href={rulesWorkspacePath} ariaLabel="Open Rules workspace">
        <p class="ct-admin__eyebrow">Management</p>
        <h2>Rules</h2>
        <p>
          Review awarding rules, maintain reusable lists, and open focused pages for builder and
          template maintenance.
        </p>
        {input.badgeRules.length === 0 ? (
          <p class="ct-admin__hint">No badge rules found. Create your first rule.</p>
        ) : null}
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{ruleCount} active rule records</AdminStatusPill>
          <AdminStatusPill>{badgeTemplateCount} templates</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard href={accessMembersPath} ariaLabel="Open Members workspace">
        <p class="ct-admin__eyebrow">Configuration</p>
        <h2>People &amp; Access</h2>
        <p>Manage members, governance delegation, API keys, LMS connections, and org structure.</p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{tenantMemberCount} members</AdminStatusPill>
          <AdminStatusPill>{activeApiKeyCount} active keys</AdminStatusPill>
          <AdminStatusPill>{orgUnitCount} org units</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
    </section>
  );

  const {
    manualIssuePanelMarkup,
    ruleValueListsPanelMarkup,
    evaluateRulePanelMarkup,
    badgeStatusPanelMarkup,
    ruleGovernancePanelMarkup,
    ruleReviewQueuePanelMarkup,
    issuedBadgesPanelMarkup,
  } = renderInstitutionAdminOperationsSections({
    tenantId: input.tenant.id,
    templateSelectOptions,
    ruleSelectOptions,
    templateFilterOptions,
    activeOrgUnitOptions,
    ...(input.issuedBadgesWorkspace === undefined
      ? {}
      : { issuedBadgesWorkspace: input.issuedBadgesWorkspace }),
    ...(input.reviewQueueWorkspace === undefined
      ? {}
      : { reviewQueueWorkspace: input.reviewQueueWorkspace }),
    ...(input.ruleValueListsWorkspace === undefined
      ? {}
      : { ruleValueListsWorkspace: input.ruleValueListsWorkspace }),
  });

  const tenantMemberRoleSelectOptions = assignableTenantRoles.map((role) => (
    <option value={role}>{role}</option>
  ));
  const {
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
  } = renderInstitutionAdminAccessSections({
    accessMembersPath,
    accessGovernancePath,
    accessApiKeysPath,
    accessOrgUnitsPath,
    accessLmsConnectionsPath,
    tenantId: input.tenant.id,
    tenantMemberCount,
    scopedRoleCount,
    delegatedAuthorityGrantCount,
    activeApiKeyCount,
    revokedApiKeyCount,
    orgUnitCount,
    lmsConnectionCount,
    tenantMemberRoleSelectOptions,
    tenantMemberRows,
    orgUnitParentOptions,
    tenantMemberSelectOptions,
    activeOrgUnitSelectOptions,
    optionalBadgeTemplateScopeOptions,
    membershipScopeRows,
    delegatedGrantRows,
    lmsConnectionRows,
    ...(input.apiKeysWorkspace === undefined ? {} : { apiKeysWorkspace: input.apiKeysWorkspace }),
    ...(input.lmsConnectionsWorkspace === undefined
      ? {}
      : { lmsConnectionsWorkspace: input.lmsConnectionsWorkspace }),
    ...(lmsConnectionFormValues === undefined ? {} : { lmsConnectionFormValues }),
  });

  const {
    reportingExecutiveSummaryMarkup,
    reportingFocusAreaPanelMarkup,
    reportingRankedChartsMarkup,
    reportingDeepLinksMarkup,
    reportingExploreSliceSummaryMarkup,
    reportingOverviewPanelMarkup,
    renderReportingTrendPanelMarkup,
    reportingEngagementPanelMarkup,
    reportingLowerStoryMarkup,
    reportingDefinitionsPanelMarkup,
    reportingDeferredPanelMarkup,
    reportingTrendFiltersPanelMarkup,
    reportingReportsLibraryMarkup,
    reportingExportFiltersPanelMarkup,
    reportingExportsPanelMarkup,
  } = renderInstitutionAdminReportingSections({
    input,
    reportingPath,
    reportingExplorePath,
    reportingTrendsPath,
    reportingReportsPath,
  });

  const {
    badgeRulesTableMarkup,
    ruleAdvancedToolsMarkup,
    orgUnitsTableMarkup,
    apiKeysTableMarkup,
  } = renderInstitutionAdminManagementSections({
    ruleCount,
    hasBadgeRules,
    ruleBuilderPath,
    rulesTemplatesPath,
    ruleRows,
    ruleValueListsPanelMarkup,
    evaluateRulePanelMarkup,
    ruleGovernancePanelMarkup,
    orgUnitCount,
    orgUnitRows,
    activeApiKeyCount,
    revokedApiKeyCount,
    apiKeyRows,
  });

  const {
    learnerRecordReviewPanelMarkup,
    renderLearnerRecordReviewSections,
    learnerRecordImportPanelMarkup,
    learnerRecordImportFeedbackMarkup,
    learnerRecordImportSubmissionMarkup,
    learnerRecordImportProgressMarkup,
  } = renderInstitutionAdminLearnerRecordSections({
    tenantDisplayName: input.tenant.displayName,
    operationsLearnerRecordsPath,
    operationsLearnerRecordImportsPath,
    learnerRecordReview,
    learnerRecordImportWorkflow,
  });

  const viewConfig = INSTITUTION_ADMIN_VIEW_CONFIG[view];
  const pageTitle = `${viewConfig.titlePrefix} · ${input.tenant.displayName}`;

  const viewContent = (() => {
    switch (view) {
      case "home":
        return (
          <>
            {renderPageHeader("Institution Admin", "Choose a workspace.")}
            <section class="ct-admin ct-stack">{workspaceCardsMarkup}</section>
          </>
        );
      case "operations":
        return (
          <>
            {renderPageHeader(
              "Issue & Inspect",
              "Issue badges here, then use dedicated pages for learner records, imports, review queue, issued badges, and badge status.",
            )}
            <section class="ct-admin ct-stack">{manualIssuePanelMarkup}</section>
          </>
        );
      case "operationsLearnerRecords":
        return (
          <>
            {renderPageHeader(
              "Learner Records",
              "Review one learner’s unified record without overloading operations with a broader learner-search or ingest surface.",
            )}
            <section class="ct-admin ct-stack">
              {learnerRecordReviewPanelMarkup}
              {renderLearnerRecordReviewSections()}
            </section>
          </>
        );
      case "operationsLearnerRecordImports":
        return (
          <>
            {renderPageHeader(
              "Learner Record Imports",
              "Import learner-record CSVs with one trust default, honest smart defaults, and queue-backed progress.",
            )}
            <section class="ct-admin ct-stack">
              {learnerRecordImportPanelMarkup}
              {learnerRecordImportFeedbackMarkup}
              {learnerRecordImportSubmissionMarkup}
              {learnerRecordImportProgressMarkup}
            </section>
          </>
        );
      case "operationsReviewQueue":
        return (
          <>
            {renderPageHeader(
              "Rule Review Queue",
              "Review pending badge decisions without mixing them into the rest of operations.",
            )}
            <section class="ct-admin ct-stack">{ruleReviewQueuePanelMarkup}</section>
          </>
        );
      case "operationsIssuedBadges":
        return (
          <>
            {renderPageHeader(
              "Issued Badges",
              "Search issued badges and take audit or revocation actions from one page.",
            )}
            <section class="ct-admin ct-stack">{issuedBadgesPanelMarkup}</section>
          </>
        );
      case "operationsBadgeStatus":
        return (
          <>
            {renderPageHeader(
              "Badge Status",
              "Look up a badge, inspect its current state, and apply status changes with a reason.",
            )}
            <section class="ct-admin ct-stack">{badgeStatusPanelMarkup}</section>
          </>
        );
      case "reporting":
        return (
          <>
            {renderPageHeader(
              "Reporting",
              "Start with the current view, then open detail only when you need it.",
            )}
            <section class="ct-admin ct-stack">
              <section class="ct-admin__reporting-presentation-shell ct-admin__reporting-presentation-shell--highlights ct-stack">
                <section class="ct-admin__reporting-primary-story ct-stack">
                  <section class="ct-admin__reporting-first-screen ct-stack">
                    {reportingExecutiveSummaryMarkup}
                  </section>
                  {reportingFocusAreaPanelMarkup}
                  {reportingRankedChartsMarkup}
                  {reportingDeepLinksMarkup}
                </section>
              </section>
            </section>
          </>
        );
      case "reportingExplore":
        return (
          <>
            {renderPageHeader(
              "Reporting Explore",
              "Filter the report, scan concise previews, and open exact detail only when needed.",
            )}
            <section class="ct-admin ct-stack">
              {reportingExploreSliceSummaryMarkup}
              <section class="ct-admin__reporting-explore-workspace ct-stack">
                {reportingOverviewPanelMarkup}
                {renderReportingTrendPanelMarkup({ includeDetailedTable: false })}
                {reportingEngagementPanelMarkup}
                {reportingLowerStoryMarkup}
                {reportingDefinitionsPanelMarkup}
                {reportingDeferredPanelMarkup}
              </section>
            </section>
          </>
        );
      case "reportingTrends":
        return (
          <>
            {renderPageHeader(
              "Trend Detail",
              "Use the focused trend page for exact daily counts behind the overview chart.",
            )}
            <section class="ct-admin ct-stack">
              {reportingTrendFiltersPanelMarkup}
              {renderReportingTrendPanelMarkup({ includeDetailedTable: true })}
            </section>
          </>
        );
      case "reportingReports":
        return (
          <>
            {renderPageHeader(
              "Report Library",
              "Use one focused page for saved report shortcuts, custom report setup, and CSV exports.",
            )}
            <section class="ct-admin ct-stack">
              {reportingReportsLibraryMarkup}
              {reportingExportFiltersPanelMarkup}
              {reportingExportsPanelMarkup}
            </section>
          </>
        );
      case "rules":
        return (
          <>
            {renderPageHeader(
              "Rules",
              "Review awarding rules and use focused tools for rule logic, reusable lists, and governance context.",
            )}
            <section class="ct-admin ct-stack">
              {badgeRulesTableMarkup}
              {ruleAdvancedToolsMarkup}
            </section>
          </>
        );
      case "accessMembers":
        return (
          <>
            {renderPageHeader(
              "Members",
              "Add colleagues, assign tenant roles, resend invites, and remove tenant access.",
              <aside class="ct-admin-page-header__note">
                <h2>Tenant-level access</h2>
                <p>
                  Use owner/admin roles for administration. Use issuer/viewer roles when someone
                  does not need full tenant control.
                </p>
              </aside>,
            )}
            <section class="ct-admin ct-stack">
              {tenantMembersPanelMarkup}
              {tenantMembersTableMarkup}
            </section>
          </>
        );
      case "accessGovernance":
        return (
          <>
            {renderPageHeader(
              "Governance Delegation",
              "Grant org-unit access and time-boxed badge authority with direct removal from the current assignments list.",
              <aside class="ct-admin-page-header__note">
                <h2>Choose the smallest access</h2>
                <p>
                  Use scoped roles for standing access. Use delegated authority when someone only
                  needs temporary badge operations.
                </p>
              </aside>,
            )}
            <section class="ct-admin ct-stack">
              {enterpriseAuthPanelMarkup}
              {governanceGuidePanelMarkup}
              {membershipScopeTableMarkup}
              {membershipScopePanelMarkup}
              {delegatedGrantTableMarkup}
              {delegatedGrantPanelMarkup}
            </section>
          </>
        );
      case "accessApiKeys":
        return (
          <>
            {renderPageHeader("API Keys", "Create, review, and revoke tenant API keys.")}
            <section class="ct-admin ct-stack">
              {apiKeyPanelMarkup}
              {apiKeysTableMarkup}
            </section>
          </>
        );
      case "accessLmsConnections":
        return (
          <>
            {renderPageHeader(
              "LMS Connections",
              "Manage connected Canvas and Sakai gradebook accounts used by badge awarding rules.",
            )}
            <section class="ct-admin ct-stack">
              {lmsConnectionsPanelMarkup}
              {lmsConnectionsTableMarkup}
            </section>
          </>
        );
      case "accessOrgUnits":
        return (
          <>
            {renderPageHeader("Org Units", "Create and review org structure.")}
            <section class="ct-admin ct-stack">
              {orgUnitPanelMarkup}
              {orgUnitsTableMarkup}
            </section>
          </>
        );
    }
  })();
  const pageAssets: PageAssetKey[] = [
    "institutionAdminCss",
    viewConfig.controller === "shared" ? "institutionAdminJs" : "institutionAdminShellJs",
    ...("extraAssets" in viewConfig ? viewConfig.extraAssets : []),
  ];

  return appPage({
    title: pageTitle,
    assets: pageAssets,
    variant: "admin",
    body: (
      <AdminShell
        sidebar={
          <AdminSidebar
            brandHref={tenantAdminPath}
            sections={sidebarSections}
            footerLinks={sidebarFooterLinks}
          />
        }
        topbar={
          <AdminTopbar
            title={input.tenant.displayName}
            chips={[{ label: input.membershipRole }, { label: input.tenant.planTier }]}
            userLabel={userLabel}
            userTitle={`User ID: ${input.userId}`}
          />
        }
      >
        {viewContent}
        <div id="ct-admin-context" hidden data-context-json={adminPageContextJson}></div>
      </AdminShell>
    ),
  });
};

export const institutionAdminDashboardPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "home");
};

export const institutionAdminOperationsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "operations");
};

export const institutionAdminLearnerRecordsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "operationsLearnerRecords");
};

export const institutionAdminLearnerRecordImportsPage = (
  input: InstitutionAdminPageInput,
): AppPage => {
  return renderInstitutionAdminPage(input, "operationsLearnerRecordImports");
};

export const institutionAdminOperationsReviewQueuePage = (
  input: InstitutionAdminPageInput,
): AppPage => {
  return renderInstitutionAdminPage(input, "operationsReviewQueue");
};

export const institutionAdminIssuedBadgesPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "operationsIssuedBadges");
};

export const institutionAdminBadgeStatusPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "operationsBadgeStatus");
};

export const institutionAdminReportingPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "reporting");
};

export const institutionAdminReportingExplorePage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "reportingExplore");
};

export const institutionAdminReportingTrendsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "reportingTrends");
};

export const institutionAdminReportingReportsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "reportingReports");
};

export const institutionAdminRulesPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "rules");
};

export const institutionAdminMembersPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessMembers");
};

export const institutionAdminGovernancePage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessGovernance");
};

export const institutionAdminApiKeysPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessApiKeys");
};

export const institutionAdminLmsConnectionsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessLmsConnections");
};

export const institutionAdminOrgUnitsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessOrgUnits");
};
