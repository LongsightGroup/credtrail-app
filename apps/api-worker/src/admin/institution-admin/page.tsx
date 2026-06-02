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
  tenantAccessDelegatedGrantRevokePath,
  tenantAccessMemberInvitePath,
  tenantAccessMemberRemovePath,
  tenantAccessMemberRolePath,
  tenantAccessMembershipScopeRemovePath,
  tenantBadgeRuleActivateAdminPath,
  tenantBadgeRuleDecisionAdminPath,
  tenantBadgeRuleSubmitApprovalAdminPath,
} from "../access-admin-helpers";
import {
  AdminButton,
  AdminButtonLink,
  AdminActions,
  AdminEmptyTableRow,
  AdminForm,
  AdminMeta,
  AdminPanel,
  AdminPageHeader,
  AdminShell,
  AdminSidebar,
  AdminStatus,
  AdminStatusPill,
  AdminTopbar,
  AdminWorkspaceCard,
  type AdminSidebarFooterLink,
} from "../components";
import { buildInstitutionAdminSidebarSectionsForTenant } from "../institution-admin-sidebar";
import { buildLmsConnectionEditPath } from "../lms-connection-admin-helpers";
import { renderDelegationSetupSection } from "./delegation-setup-section";
import {
  emptyLmsConnectionFormValues,
  renderLmsConnectionSetupSection,
} from "./lms-connection-setup-section";
import { renderManualIssueSection } from "./manual-issue-section";
import { TenantApiKeyAdminTableRow } from "../api-key-table-row";
import { serializeJsonScriptContent } from "../institution-admin-shell";
import { renderInstitutionAdminAccessSections } from "./access-sections";
import { renderEnterpriseAuthSection } from "./enterprise-auth-section";
import { renderInstitutionAdminLearnerRecordSections } from "./learner-record-sections";
import { renderInstitutionAdminManagementSections } from "./management-sections";
import { renderInstitutionAdminOperationsSections } from "./operations-sections";
import {
  INSTITUTION_ADMIN_VIEW_CONFIG,
  institutionAdminViewNeedsAccessSectionBundles,
  institutionAdminViewNeedsApiKeyRows,
  institutionAdminViewNeedsDelegationSelectOptions,
  institutionAdminViewNeedsGovernanceTableRows,
  institutionAdminViewNeedsLearnerRecordSectionBundles,
  institutionAdminViewNeedsLmsConnectionRows,
  institutionAdminViewNeedsManagementSectionBundles,
  institutionAdminViewNeedsOperationsSectionBundles,
  institutionAdminViewNeedsOrgUnitRows,
  institutionAdminViewNeedsReportingSectionBundles,
  institutionAdminViewNeedsRuleSelectOptions,
  institutionAdminViewNeedsRuleTableRows,
  institutionAdminViewNeedsRuleVersionIndexes,
  institutionAdminViewNeedsTemplateSelectOptions,
  institutionAdminViewNeedsTenantMemberRows,
  type InstitutionAdminPageInput,
  type InstitutionAdminView,
} from "./page-types";
import { renderInstitutionAdminReportingSections } from "./reporting-sections";
export {
  institutionAdminRuleTemplateEditorPage,
  institutionAdminRuleTemplatesPage,
} from "../institution-admin-templates-page";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

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

const renderInstitutionAdminPage = (
  input: InstitutionAdminPageInput,
  view: InstitutionAdminView,
): AppPage => {
  const templateById = new Map(input.badgeTemplates.map((template) => [template.id, template]));
  const orgUnitById = new Map(input.orgUnits.map((orgUnit) => [orgUnit.id, orgUnit]));
  const versionsByRuleId = new Map<string, BadgeIssuanceRuleVersionRecord[]>();
  const tenantAdminPath = `/tenants/${encodeURIComponent(input.tenant.id)}/admin`;
  const operationsPath = `${tenantAdminPath}/operations`;
  const operationsManualIssuePath = `${operationsPath}/issue`;
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
  const accessAuthenticationPath = `${accessPath}/authentication`;
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
  const needsAccessSectionBundles = institutionAdminViewNeedsAccessSectionBundles(view);
  const needsOperationsSectionBundles = institutionAdminViewNeedsOperationsSectionBundles(view);
  const needsReportingSectionBundles = institutionAdminViewNeedsReportingSectionBundles(view);
  const needsManagementSectionBundles = institutionAdminViewNeedsManagementSectionBundles(view);
  const needsLearnerRecordSectionBundles =
    institutionAdminViewNeedsLearnerRecordSectionBundles(view);
  const needsRuleTableRows = institutionAdminViewNeedsRuleTableRows(view);
  const needsLmsConnectionRows = institutionAdminViewNeedsLmsConnectionRows(view);
  const needsApiKeyRows = institutionAdminViewNeedsApiKeyRows(view);
  const needsOrgUnitRows = institutionAdminViewNeedsOrgUnitRows(view);
  const needsGovernanceTableRows = institutionAdminViewNeedsGovernanceTableRows(view);
  const needsTenantMemberRows = institutionAdminViewNeedsTenantMemberRows(view);
  const needsTemplateSelectOptions = institutionAdminViewNeedsTemplateSelectOptions(view);
  const needsDelegationSelectOptions = institutionAdminViewNeedsDelegationSelectOptions(view);
  const needsRuleSelectOptions = institutionAdminViewNeedsRuleSelectOptions(view);
  const needsRuleVersionIndexes = institutionAdminViewNeedsRuleVersionIndexes(view);
  const needsOrgUnitParentOptions = view === "accessOrgUnits";
  const needsIssuedBadgeFilters = view === "operationsIssuedBadges";
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
  if (needsRuleVersionIndexes) {
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
  }

  const orgUnitRows = !needsOrgUnitRows ? (
    emptySectionMarkup
  ) : input.orgUnits.length === 0 ? (
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

  const apiKeyRows = !needsApiKeyRows ? (
    emptySectionMarkup
  ) : input.activeApiKeys.length === 0 ? (
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

  const lmsConnectionRows = !needsLmsConnectionRows ? (
    emptySectionMarkup
  ) : input.lmsConnections.length === 0 ? (
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
              href={buildLmsConnectionEditPath(input.tenant.id, connection.id)}
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

  const assignableTenantRoles: TenantMembershipRole[] = needsTenantMemberRows
    ? input.membershipRole === "owner"
      ? ["owner", "admin", "issuer", "viewer"]
      : ["admin", "issuer", "viewer"]
    : [];
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
  const tenantMemberRows = !needsTenantMemberRows ? (
    emptySectionMarkup
  ) : input.tenantMembers.length === 0 ? (
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
              <AdminForm
                method="post"
                action={tenantAccessMemberRolePath(input.tenant.id, member.userId)}
                className="ct-admin__inline-form"
              >
                <select
                  name="role"
                  aria-label={`Tenant role for ${member.email}`}
                  data-current-role={member.role}
                  onchange="if(this.value!==this.dataset.currentRole)this.form.requestSubmit()"
                >
                  {tenantMemberRoleOptions(member.role)}
                </select>
              </AdminForm>
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
                <AdminForm
                  method="post"
                  action={tenantAccessMemberInvitePath(input.tenant.id, member.userId)}
                  className="ct-admin__inline-form"
                >
                  <AdminButton type="submit" size="tiny" variant="secondary">
                    Resend invite
                  </AdminButton>
                </AdminForm>
                <AdminForm
                  method="post"
                  action={tenantAccessMemberRemovePath(input.tenant.id, member.userId)}
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
                {member.userId === input.userId ? "Current user" : "Owner action"}
              </AdminMeta>
            )}
          </td>
        </tr>
      );
    })
  );

  const membershipScopeRows = !needsGovernanceTableRows ? (
    emptySectionMarkup
  ) : input.membershipOrgUnitScopes.length === 0 ? (
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
            <AdminForm
              method="post"
              action={tenantAccessMembershipScopeRemovePath(input.tenant.id)}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Remove scoped role for ${scope.userId} · ${scopeLabel}?`,
              }}
            >
              <input type="hidden" name="userId" value={scope.userId} />
              <input type="hidden" name="orgUnitId" value={scope.orgUnitId} />
              <AdminButton type="submit" size="tiny" variant="danger">
                Remove
              </AdminButton>
            </AdminForm>
          </td>
        </tr>
      );
    })
  );

  const delegatedGrantRows = !needsGovernanceTableRows ? (
    emptySectionMarkup
  ) : input.delegatedIssuingAuthorityGrants.length === 0 ? (
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
              <AdminForm
                method="post"
                action={tenantAccessDelegatedGrantRevokePath(input.tenant.id)}
                className="ct-admin__inline-form"
                dataAttributes={{
                  "data-confirm-message": `Remove delegation for ${grant.delegateUserId} · ${grant.id}?`,
                }}
              >
                <input type="hidden" name="delegateUserId" value={grant.delegateUserId} />
                <input type="hidden" name="grantId" value={grant.id} />
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
    })
  );

  const ruleRows = !needsRuleTableRows ? (
    emptySectionMarkup
  ) : input.badgeRules.length === 0 ? (
    <AdminEmptyTableRow colSpan={8}>
      No badge rules found. <a href={ruleBuilderPath}>Create your first rule</a>.
    </AdminEmptyTableRow>
  ) : (
    input.badgeRules.map((rule) => {
      const templateTitle = templateById.get(rule.badgeTemplateId)?.title ?? rule.badgeTemplateId;
      const versions = versionsByRuleId.get(rule.id) ?? [];
      const latestVersion = versions[0] ?? null;
      const actionButtons: HonoElement[] = [];

      if (latestVersion !== null) {
        if (latestVersion.status === "draft" || latestVersion.status === "rejected") {
          actionButtons.push(
            <AdminForm
              method="post"
              action={tenantBadgeRuleSubmitApprovalAdminPath(
                input.tenant.id,
                rule.id,
                latestVersion.id,
              )}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Mark draft version for "${rule.name}" ready for review? This does not activate the rule.`,
              }}
            >
              <AdminButton type="submit" size="tiny">
                Mark ready
              </AdminButton>
            </AdminForm>,
          );
        }

        if (latestVersion.status === "pending_approval") {
          actionButtons.push(
            <AdminForm
              method="post"
              action={tenantBadgeRuleDecisionAdminPath(input.tenant.id, rule.id, latestVersion.id)}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Approve latest version for "${rule.name}"?`,
              }}
            >
              <input type="hidden" name="decision" value="approved" />
              <AdminButton type="submit" size="tiny">
                Approve
              </AdminButton>
            </AdminForm>,
          );
          actionButtons.push(
            <AdminForm
              method="post"
              action={tenantBadgeRuleDecisionAdminPath(input.tenant.id, rule.id, latestVersion.id)}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Reject latest version for "${rule.name}"?`,
              }}
            >
              <input type="hidden" name="decision" value="rejected" />
              <AdminButton type="submit" size="tiny" variant="danger">
                Reject
              </AdminButton>
            </AdminForm>,
          );
        }

        if (latestVersion.status === "approved" || latestVersion.status === "active") {
          actionButtons.push(
            <AdminForm
              method="post"
              action={tenantBadgeRuleActivateAdminPath(input.tenant.id, rule.id, latestVersion.id)}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Activate latest version for "${rule.name}"?`,
              }}
            >
              <AdminButton type="submit" size="tiny">
                Activate
              </AdminButton>
            </AdminForm>,
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

  const badgeRuleApiPath = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/badge-rules`;
  const assertionsApiPathPrefix = `/v1/tenants/${encodeURIComponent(input.tenant.id)}/assertions`;
  const showcasePath = `/showcase/${encodeURIComponent(input.tenant.id)}`;
  const orgUnitParentOptions = needsOrgUnitParentOptions
    ? input.orgUnits
        .filter((orgUnit) => orgUnit.isActive)
        .map((orgUnit) => {
          return (
            <option value={orgUnit.id} data-unit-type={orgUnit.unitType}>
              {`${orgUnit.displayName} (${orgUnit.unitType})`}
            </option>
          );
        })
    : [];
  const activeOrgUnitOptions =
    needsOperationsSectionBundles || needsDelegationSelectOptions
      ? input.orgUnits
          .filter((orgUnit) => orgUnit.isActive)
          .map((orgUnit) => {
            return (
              <option value={orgUnit.id}>{`${orgUnit.displayName} (${orgUnit.unitType})`}</option>
            );
          })
      : [];
  const tenantMemberOptions = needsDelegationSelectOptions
    ? input.tenantMembers.map((member) => {
        return <option value={member.userId}>{`${member.email} (${member.role})`}</option>;
      })
    : [];
  const templateOptions = needsTemplateSelectOptions
    ? input.badgeTemplates.map((template, index) => {
        return (
          <option value={template.id} selected={index === 0}>
            {`${template.title} (${template.id})`}
          </option>
        );
      })
    : [];
  const selectedBadgeTemplateFilterId = input.issuedBadgesWorkspace?.filters.badgeTemplateId ?? "";
  const templateFilterOptions = needsIssuedBadgeFilters ? (
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
  ) : (
    emptySectionMarkup
  );
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
  const ruleOptions = needsRuleSelectOptions
    ? input.badgeRules.map((rule, index) => formatRuleOption(rule, true, index))
    : [];
  const templateSelectOptions = !needsTemplateSelectOptions ? (
    emptySectionMarkup
  ) : templateOptions.length > 0 ? (
    templateOptions
  ) : (
    <option value="">No badge templates available</option>
  );
  const activeOrgUnitSelectOptions = !needsDelegationSelectOptions ? (
    emptySectionMarkup
  ) : activeOrgUnitOptions.length > 0 ? (
    activeOrgUnitOptions
  ) : (
    <option value="">No active org units available</option>
  );
  const tenantMemberSelectOptions = !needsDelegationSelectOptions ? (
    emptySectionMarkup
  ) : tenantMemberOptions.length > 0 ? (
    tenantMemberOptions
  ) : (
    <option value="">No tenant members available</option>
  );
  const optionalBadgeTemplateScopeOptions = !needsDelegationSelectOptions ? (
    emptySectionMarkup
  ) : (
    <>
      <option value="">All badge templates in the selected scope</option>
      {input.badgeTemplates.map((template) => (
        <option value={template.id}>{template.title}</option>
      ))}
    </>
  );
  const ruleSelectOptions = !needsRuleSelectOptions ? (
    emptySectionMarkup
  ) : ruleOptions.length > 0 ? (
    ruleOptions
  ) : (
    <option value="">No rules available</option>
  );
  const adminPageContext = ((): Record<string, string> => {
    if (view === "rules" || view === "operationsBadgeStatus") {
      return {
        badgeRuleApiPath,
        assertionsApiPathPrefix,
      };
    }

    if (view === "operationsIssuedBadges") {
      return {
        assertionsApiPathPrefix,
      };
    }

    return {};
  })();
  const adminPageContextJson = serializeJsonScriptContent(adminPageContext);
  const sidebarSections = buildInstitutionAdminSidebarSectionsForTenant(
    input.tenant.id,
    view,
    input.tenant.planTier,
  );
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
      <AdminWorkspaceCard href={operationsManualIssuePath} ariaLabel="Open Issue Badge workspace">
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

  const operationsSections = needsOperationsSectionBundles
    ? renderInstitutionAdminOperationsSections({
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
        ...(input.operationsWorkspace === undefined
          ? {}
          : { operationsWorkspace: input.operationsWorkspace }),
      })
    : {
        ruleValueListsPanelMarkup: emptySectionMarkup,
        evaluateRulePanelMarkup: emptySectionMarkup,
        badgeStatusPanelMarkup: emptySectionMarkup,
        ruleGovernancePanelMarkup: emptySectionMarkup,
        ruleReviewQueuePanelMarkup: emptySectionMarkup,
        issuedBadgesPanelMarkup: emptySectionMarkup,
      };
  const {
    evaluateRulePanelMarkup,
    badgeStatusPanelMarkup,
    ruleReviewQueuePanelMarkup,
    issuedBadgesPanelMarkup,
  } = operationsSections;

  const tenantMemberRoleSelectOptions = needsTenantMemberRows
    ? assignableTenantRoles.map((role) => <option value={role}>{role}</option>)
    : [];
  const accessSections = needsAccessSectionBundles
    ? renderInstitutionAdminAccessSections({
        accessMembersPath,
        accessGovernancePath,
        accessAuthenticationPath,
        accessApiKeysPath,
        accessOrgUnitsPath,
        accessLmsConnectionsPath,
        planTier: input.tenant.planTier,
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
        ...(input.apiKeysWorkspace === undefined
          ? {}
          : { apiKeysWorkspace: input.apiKeysWorkspace }),
        ...(input.lmsConnectionsWorkspace === undefined
          ? {}
          : { lmsConnectionsWorkspace: input.lmsConnectionsWorkspace }),
        ...(input.accessMembersWorkspace === undefined
          ? {}
          : { accessMembersWorkspace: input.accessMembersWorkspace }),
        ...(input.accessGovernanceWorkspace === undefined
          ? {}
          : { accessGovernanceWorkspace: input.accessGovernanceWorkspace }),
        ...(input.accessOrgUnitsWorkspace === undefined
          ? {}
          : { accessOrgUnitsWorkspace: input.accessOrgUnitsWorkspace }),
      })
    : {
        apiKeyPanelMarkup: emptySectionMarkup,
        lmsConnectionsActionsMarkup: emptySectionMarkup,
        lmsConnectionsTableMarkup: emptySectionMarkup,
        orgUnitPanelMarkup: emptySectionMarkup,
        governanceGuidePanelMarkup: emptySectionMarkup,
        governanceActionsMarkup: emptySectionMarkup,
        tenantMembersPanelMarkup: emptySectionMarkup,
        tenantMembersTableMarkup: emptySectionMarkup,
        membershipScopePanelMarkup: emptySectionMarkup,
        membershipScopeTableMarkup: emptySectionMarkup,
        delegatedGrantTableMarkup: emptySectionMarkup,
      };
  const {
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
  } = accessSections;

  const reportingSections = needsReportingSectionBundles
    ? renderInstitutionAdminReportingSections({
        input,
        reportingPath,
        reportingExplorePath,
        reportingTrendsPath,
        reportingReportsPath,
      })
    : {
        reportingExecutiveSummaryMarkup: emptySectionMarkup,
        reportingFocusAreaPanelMarkup: emptySectionMarkup,
        reportingRankedChartsMarkup: emptySectionMarkup,
        reportingDeepLinksMarkup: emptySectionMarkup,
        reportingExploreSliceSummaryMarkup: emptySectionMarkup,
        reportingOverviewPanelMarkup: emptySectionMarkup,
        renderReportingTrendPanelMarkup: () => emptySectionMarkup,
        reportingEngagementPanelMarkup: emptySectionMarkup,
        reportingLowerStoryMarkup: emptySectionMarkup,
        reportingDefinitionsPanelMarkup: emptySectionMarkup,
        reportingDeferredPanelMarkup: emptySectionMarkup,
        reportingTrendFiltersPanelMarkup: emptySectionMarkup,
        reportingReportsLibraryMarkup: emptySectionMarkup,
        reportingExportFiltersPanelMarkup: emptySectionMarkup,
        reportingExportsPanelMarkup: emptySectionMarkup,
      };
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
  } = reportingSections;

  const managementSections = needsManagementSectionBundles
    ? renderInstitutionAdminManagementSections({
        ruleCount,
        hasBadgeRules,
        ruleBuilderPath,
        rulesTemplatesPath,
        ruleRows,
        evaluateRulePanelMarkup,
        orgUnitCount,
        orgUnitRows,
        activeApiKeyCount,
        revokedApiKeyCount,
        apiKeyRows,
      })
    : {
        badgeRulesTableMarkup: emptySectionMarkup,
        ruleAdvancedToolsMarkup: emptySectionMarkup,
        orgUnitsTableMarkup: emptySectionMarkup,
        apiKeysTableMarkup: emptySectionMarkup,
      };
  const {
    badgeRulesTableMarkup,
    ruleAdvancedToolsMarkup,
    orgUnitsTableMarkup,
    apiKeysTableMarkup,
  } = managementSections;

  const learnerRecordSections = needsLearnerRecordSectionBundles
    ? renderInstitutionAdminLearnerRecordSections({
        tenantDisplayName: input.tenant.displayName,
        operationsLearnerRecordsPath,
        operationsLearnerRecordImportsPath,
        learnerRecordReview,
        learnerRecordImportWorkflow,
      })
    : {
        learnerRecordReviewPanelMarkup: emptySectionMarkup,
        renderLearnerRecordReviewSections: () => emptySectionMarkup,
        learnerRecordImportPanelMarkup: emptySectionMarkup,
        learnerRecordImportFeedbackMarkup: emptySectionMarkup,
        learnerRecordImportSubmissionMarkup: emptySectionMarkup,
        learnerRecordImportProgressMarkup: emptySectionMarkup,
      };
  const {
    learnerRecordReviewPanelMarkup,
    renderLearnerRecordReviewSections,
    learnerRecordImportPanelMarkup,
    learnerRecordImportFeedbackMarkup,
    learnerRecordImportSubmissionMarkup,
    learnerRecordImportProgressMarkup,
  } = learnerRecordSections;

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
      case "operationsManualIssue":
        return (
          <>
            {renderPageHeader(
              "Issue Badge",
              "Issue a badge for one learner by choosing the template and recipient email.",
            )}
            <section class="ct-admin ct-stack">
              {renderManualIssueSection({
                tenantId: input.tenant.id,
                templateSelectOptions,
                listError: input.manualIssueWorkspace?.listError ?? null,
                listNotice: input.manualIssueWorkspace?.listNotice ?? null,
              })}
            </section>
          </>
        );
      case "operationsLearnerRecords":
        return (
          <>
            {renderPageHeader(
              "Learner Records",
              "Look up one learner by profile ID or email to review badges and record entries.",
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
              "Review awarding rules, create new rules, and test a rule before issuing when needed.",
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
              {input.accessGovernanceWorkspace?.listError !== null &&
              input.accessGovernanceWorkspace?.listError !== undefined &&
              input.accessGovernanceWorkspace.listError.length > 0 ? (
                <AdminStatus data-tone="error">
                  {input.accessGovernanceWorkspace.listError}
                </AdminStatus>
              ) : input.accessGovernanceWorkspace?.listNotice !== null &&
                input.accessGovernanceWorkspace?.listNotice !== undefined &&
                input.accessGovernanceWorkspace.listNotice.length > 0 ? (
                <AdminStatus data-tone="success">
                  {input.accessGovernanceWorkspace.listNotice}
                </AdminStatus>
              ) : null}
              {governanceGuidePanelMarkup}
              {governanceActionsMarkup}
              {membershipScopeTableMarkup}
              {membershipScopePanelMarkup}
              {delegatedGrantTableMarkup}
            </section>
          </>
        );
      case "accessGovernanceDelegationNew":
        return (
          <>
            {renderPageHeader(
              "Add Delegated Authority",
              "Grant temporary badge authority without changing standing org-unit access.",
            )}
            <section class="ct-admin ct-stack">
              {renderDelegationSetupSection({
                tenantId: input.tenant.id,
                tenantMemberSelectOptions,
                activeOrgUnitSelectOptions,
                optionalBadgeTemplateScopeOptions,
                listError: input.accessGovernanceDelegationWorkspace?.listError ?? null,
                listNotice: input.accessGovernanceDelegationWorkspace?.listNotice ?? null,
              })}
            </section>
          </>
        );
      case "accessAuthentication":
        return (
          <>
            {renderPageHeader(
              "Authentication",
              input.tenant.planTier === "enterprise"
                ? "Configure institution sign-in, OIDC providers, and break-glass local accounts."
                : "Enterprise authentication is available on the enterprise plan.",
            )}
            <section class="ct-admin ct-stack">
              {input.tenant.planTier === "enterprise" ? (
                <>
                  {input.accessAuthenticationWorkspace?.listError !== null &&
                  input.accessAuthenticationWorkspace?.listError !== undefined &&
                  input.accessAuthenticationWorkspace.listError.length > 0 ? (
                    <AdminStatus data-tone="error">
                      {input.accessAuthenticationWorkspace.listError}
                    </AdminStatus>
                  ) : input.accessAuthenticationWorkspace?.listNotice !== null &&
                    input.accessAuthenticationWorkspace?.listNotice !== undefined &&
                    input.accessAuthenticationWorkspace.listNotice.length > 0 ? (
                    <AdminStatus data-tone="success">
                      {input.accessAuthenticationWorkspace.listNotice}
                    </AdminStatus>
                  ) : null}
                  {renderEnterpriseAuthSection({
                    tenant: input.tenant,
                    enterpriseAuthPolicy: input.enterpriseAuthPolicy,
                    enterpriseAuthProviders: input.enterpriseAuthProviders,
                    breakGlassAccounts: input.breakGlassAccounts,
                    editProviderId: input.accessAuthenticationWorkspace?.editProviderId ?? null,
                  })}
                </>
              ) : (
                <AdminPanel>
                  <p>
                    Upgrade to the enterprise plan to configure OIDC sign-in and break-glass access.
                  </p>
                </AdminPanel>
              )}
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
              {input.lmsConnectionsWorkspace?.listError !== null &&
              input.lmsConnectionsWorkspace?.listError !== undefined &&
              input.lmsConnectionsWorkspace.listError.length > 0 ? (
                <AdminStatus data-tone="error">
                  {input.lmsConnectionsWorkspace.listError}
                </AdminStatus>
              ) : input.lmsConnectionsWorkspace?.listNotice !== null &&
                input.lmsConnectionsWorkspace?.listNotice !== undefined &&
                input.lmsConnectionsWorkspace.listNotice.length > 0 ? (
                <AdminStatus data-tone="success">
                  {input.lmsConnectionsWorkspace.listNotice}
                </AdminStatus>
              ) : null}
              {lmsConnectionsActionsMarkup}
              {lmsConnectionsTableMarkup}
            </section>
          </>
        );
      case "accessLmsConnectionNew":
        return (
          <>
            {renderPageHeader(
              "Connect LMS",
              "Add a Canvas or Sakai gradebook connection for rule lookup.",
            )}
            <section class="ct-admin ct-stack">
              {renderLmsConnectionSetupSection({
                tenantId: input.tenant.id,
                formValues: input.lmsConnectionSetupFormValues ?? emptyLmsConnectionFormValues(),
                listError: input.lmsConnectionSetupWorkspace?.listError ?? null,
                listNotice: input.lmsConnectionSetupWorkspace?.listNotice ?? null,
              })}
            </section>
          </>
        );
      case "accessLmsConnectionEdit":
        return (
          <>
            {renderPageHeader(
              "Edit LMS Connection",
              "Update connection details. Leave credential fields blank to keep saved secrets.",
            )}
            <section class="ct-admin ct-stack">
              {renderLmsConnectionSetupSection({
                tenantId: input.tenant.id,
                formValues: input.lmsConnectionSetupFormValues ?? emptyLmsConnectionFormValues(),
                listError: input.lmsConnectionSetupWorkspace?.listError ?? null,
                listNotice: input.lmsConnectionSetupWorkspace?.listNotice ?? null,
              })}
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

export const institutionAdminGovernanceDelegationNewPage = (
  input: InstitutionAdminPageInput,
): AppPage => {
  return renderInstitutionAdminPage(input, "accessGovernanceDelegationNew");
};

export const institutionAdminAuthenticationPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessAuthentication");
};

export const institutionAdminApiKeysPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessApiKeys");
};

export const institutionAdminLmsConnectionsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessLmsConnections");
};

export const institutionAdminLmsConnectionNewPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessLmsConnectionNew");
};

export const institutionAdminLmsConnectionEditPage = (
  input: InstitutionAdminPageInput,
): AppPage => {
  return renderInstitutionAdminPage(input, "accessLmsConnectionEdit");
};

export const institutionAdminManualIssuePage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "operationsManualIssue");
};

export const institutionAdminOrgUnitsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessOrgUnits");
};
