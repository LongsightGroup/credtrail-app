import {
  canDeleteBadgeIssuanceRuleDraft,
  canEditBadgeIssuanceRuleDraft,
  latestBadgeIssuanceRuleVersion,
  type BadgeIssuanceRuleRecord,
  type BadgeIssuanceRuleVersionRecord,
  type TenantLmsConnectionRecord,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { Child } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../../utils/display-format";
import {
  tenantAccessDelegatedGrantRevokePath,
  tenantAccessApproverGroupMemberRemovePath,
  tenantAccessApproverGroupRemovePath,
  tenantAccessMemberInvitePath,
  tenantAccessMemberRemovePath,
  tenantAccessMemberRolePath,
  tenantAccessMembershipScopeRemovePath,
  tenantBadgeRuleDecisionAdminPath,
  tenantBadgeRuleDeleteAdminPath,
  tenantBadgeRuleSubmitApprovalAdminPath,
} from "../access-admin-helpers";
import { buildBadgeRuleLifecycleMenuActions } from "./badge-rule-lifecycle-actions";
import {
  AdminActionMenu,
  AdminButton,
  AdminButtonLink,
  AdminActions,
  AdminEmptyTableRow,
  AdminForm,
  AdminMeta,
  AdminStatusPill,
  AdminWorkspaceCard,
} from "../components";
import { CtInput, CtSelect, CtTextarea } from "../../ui/forms";
import { buildLmsConnectionEditPath, isLmsConnectionReady } from "../lms-connection-admin-helpers";
import { TenantApiKeyAdminTableRow } from "../api-key-table-row";
import { badgeRuleApprovalPolicyFormState } from "../../badges/badge-rule-approval-policy-summary";
import { serializeJsonScriptContent } from "../institution-admin-shell";
import { renderInstitutionAdminAccessSections } from "./access-sections";
import { accessSectionKindsForDataNeeds } from "./access-section-kinds";
import { renderInstitutionAdminLearnerRecordSections } from "./learner-record-sections";
import { renderBadgeRulesTable } from "./badge-rules-table";
import { renderInstitutionAdminOperationsSections } from "./operations-sections";
import type { InstitutionAdminPageInput, InstitutionAdminView } from "./page-types";
import { renderInstitutionAdminReportingSections } from "./reporting-sections";
import {
  renderInstitutionAdminViewContent,
  type InstitutionAdminViewDefinition,
} from "./view-content";
import type { buildInstitutionAdminViewPaths } from "./view-paths";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const emptySectionMarkup = <></>;

const asChild = (node: unknown): Child => {
  return node as Child;
};

const formatDelegatedIssuingActionLabel = (action: string): string => {
  switch (action) {
    case "issue_badge":
      return "Issue badges";
    case "revoke_badge":
      return "Revoke badges";
    case "manage_lifecycle":
      return "Change badge status";
    case "configure_course_rule":
      return "Set up LTI course badges";
    default:
      return action;
  }
};

export interface BuildInstitutionAdminViewResourcesInput {
  input: InstitutionAdminPageInput;
  paths: ReturnType<typeof buildInstitutionAdminViewPaths>;
  view: InstitutionAdminView;
  viewDefinition: InstitutionAdminViewDefinition;
}

export interface InstitutionAdminViewResources {
  adminPageContextJson: string;
  viewContent: Child;
}

export const buildInstitutionAdminViewResources = (
  resourceInput: BuildInstitutionAdminViewResourcesInput,
): InstitutionAdminViewResources => {
  const { input, paths, view, viewDefinition } = resourceInput;
  const builtView = viewDefinition.build?.({ input, paths });

  if (builtView !== undefined) {
    return {
      adminPageContextJson: serializeJsonScriptContent(builtView.adminPageContext),
      viewContent: builtView.viewContent,
    };
  }

  const templateById = new Map(input.badgeTemplates.map((template) => [template.id, template]));
  const orgUnitById = new Map(input.orgUnits.map((orgUnit) => [orgUnit.id, orgUnit]));
  const versionsByRuleId = new Map<string, BadgeIssuanceRuleVersionRecord[]>();
  const {
    operationsManualIssuePath,
    operationsLearnerRecordsPath,
    operationsLearnerRecordImportsPath,
    reportingPath,
    reportingExplorePath,
    reportingTrendsPath,
    reportingReportsPath,
    rulesWorkspacePath,
    rulesTemplatesPath,
    accessMembersPath,
    accessOrgUnitAccessPath,
    accessGovernancePath,
    accessDelegationsPath,
    accessAuthenticationPath,
    accessApiKeysPath,
    accessOrgUnitsPath,
    accessLmsConnectionsPath,
    ruleBuilderPath,
    badgeRuleApiPath,
    assertionsApiPathPrefix,
  } = paths;
  const badgeTemplateCount = String(input.badgeTemplates.length);
  const orgUnitCount = String(input.orgUnits.length);
  const lmsConnectionCount = String(input.lmsConnections.length);
  const activeApiKeyCount = String(input.activeApiKeys.length);
  const revokedApiKeyCount = String(input.revokedApiKeyCount);
  const ruleCount = String(input.badgeRules.length);
  const tenantMemberCount = String(input.tenantMembers.length);
  const scopedRoleCount = String(input.membershipOrgUnitScopes.length);
  const delegatedAuthorityGrantCount = String(input.delegatedIssuingAuthorityGrants.length);
  const { dataNeeds } = viewDefinition;
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
  if (dataNeeds.ruleVersionIndexes) {
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

  const orgUnitRows = !dataNeeds.orgUnitRows ? (
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

  const apiKeyRows = !dataNeeds.apiKeyRows ? (
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

  const lmsConnectionRows = !dataNeeds.lmsConnectionRows ? (
    emptySectionMarkup
  ) : input.lmsConnections.length === 0 ? (
    <AdminEmptyTableRow colSpan={7}>No LMS connections configured yet.</AdminEmptyTableRow>
  ) : (
    input.lmsConnections.map((connection) => {
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

  const assignableTenantRoles: TenantMembershipRole[] = dataNeeds.tenantMemberRows
    ? input.membershipRole === "owner"
      ? ["owner", "admin", "issuer", "approver", "viewer"]
      : ["admin", "issuer", "approver", "viewer"]
    : [];
  const tenantMemberRoleOptions = (selectedRole: TenantMembershipRole): HonoElement => {
    const roles: readonly TenantMembershipRole[] =
      input.membershipRole === "owner"
        ? assignableTenantRoles
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
  const tenantMemberRows = !dataNeeds.tenantMemberRows ? (
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
                <CtSelect
                  name="role"
                  ariaLabel={`Tenant role for ${member.email}`}
                  onchange="if(this.value!==this.dataset.currentRole)this.form.requestSubmit()"
                  dataAttributes={{ "data-current-role": member.role }}
                >
                  {tenantMemberRoleOptions(member.role)}
                </CtSelect>
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

  const membershipScopeRows = !dataNeeds.scopedRoleRows ? (
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
              <CtInput type="hidden" name="userId" value={scope.userId} />
              <CtInput type="hidden" name="orgUnitId" value={scope.orgUnitId} />
              <AdminButton type="submit" size="tiny" variant="danger">
                Remove
              </AdminButton>
            </AdminForm>
          </td>
        </tr>
      );
    })
  );

  const approverGroupRows = !dataNeeds.governanceTableRows ? (
    emptySectionMarkup
  ) : input.badgeRuleApproverGroups.length === 0 ? (
    <AdminEmptyTableRow colSpan={5}>No approver groups created yet.</AdminEmptyTableRow>
  ) : (
    input.badgeRuleApproverGroups.map((group) => {
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
                  action={tenantAccessApproverGroupMemberRemovePath(input.tenant.id)}
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
                action={tenantAccessApproverGroupRemovePath(input.tenant.id)}
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
    })
  );

  const delegatedGrantRows = !dataNeeds.delegatedGrantRows ? (
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
    })
  );

  const ruleRows = !dataNeeds.ruleTableRows ? (
    emptySectionMarkup
  ) : input.badgeRules.length === 0 ? (
    <AdminEmptyTableRow colSpan={8}>
      No badge rules found. <a href={ruleBuilderPath}>Create your first rule</a>.
    </AdminEmptyTableRow>
  ) : (
    input.badgeRules.map((rule) => {
      const templateTitle = templateById.get(rule.badgeTemplateId)?.title ?? rule.badgeTemplateId;
      const versions = versionsByRuleId.get(rule.id) ?? [];
      const latestVersion = latestBadgeIssuanceRuleVersion(versions);
      const isEditableRule = canEditBadgeIssuanceRuleDraft(rule, versions);
      const canDeleteRule = canDeleteBadgeIssuanceRuleDraft(rule, versions);
      const editRulePath = `${rulesWorkspacePath}/${encodeURIComponent(rule.id)}/edit`;
      const menuActions: HonoElement[] = [];

      if (latestVersion !== null) {
        if (latestVersion.status === "draft" || latestVersion.status === "rejected") {
          menuActions.push(
            <AdminForm
              method="post"
              action={tenantBadgeRuleSubmitApprovalAdminPath(
                input.tenant.id,
                rule.id,
                latestVersion.id,
              )}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Submit draft version for "${rule.name}" for approval?`,
              }}
            >
              <button type="submit" class="ct-admin__action-menu-item">
                Submit for approval
              </button>
            </AdminForm>,
          );
        }

        if (latestVersion.status === "pending_approval") {
          menuActions.push(
            <AdminForm
              method="post"
              action={tenantBadgeRuleDecisionAdminPath(input.tenant.id, rule.id, latestVersion.id)}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Approve latest version for "${rule.name}"?`,
              }}
            >
              <CtInput type="hidden" name="decision" value="approved" />
              <button type="submit" class="ct-admin__action-menu-item">
                Approve
              </button>
            </AdminForm>,
          );
          menuActions.push(
            <AdminForm
              method="post"
              action={tenantBadgeRuleDecisionAdminPath(input.tenant.id, rule.id, latestVersion.id)}
              className="ct-admin__action-menu-form ct-admin__action-menu-form--stacked"
            >
              <CtInput type="hidden" name="decision" value="changes_requested" />
              <div class="ct-admin__action-menu-field">
                <label
                  class="ct-admin__action-menu-field-label"
                  htmlFor={`badge-rule-change-request-${rule.id}`}
                >
                  Request changes
                </label>
                <CtTextarea
                  id={`badge-rule-change-request-${rule.id}`}
                  name="comment"
                  rows={3}
                  required
                  placeholder="Explain what needs to change before this version can be approved."
                />
              </div>
              <button type="submit" class="ct-admin__action-menu-item">
                Send back to draft
              </button>
            </AdminForm>,
          );
          menuActions.push(
            <AdminForm
              method="post"
              action={tenantBadgeRuleDecisionAdminPath(input.tenant.id, rule.id, latestVersion.id)}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Reject latest version for "${rule.name}"?`,
              }}
            >
              <CtInput type="hidden" name="decision" value="rejected" />
              <button
                type="submit"
                class="ct-admin__action-menu-item ct-admin__action-menu-item--danger"
              >
                Reject
              </button>
            </AdminForm>,
          );
        }

        for (const action of buildBadgeRuleLifecycleMenuActions({
          tenantId: input.tenant.id,
          rule,
          latestVersion,
        })) {
          menuActions.push(action as HonoElement);
        }
      }

      if (canDeleteRule) {
        menuActions.push(
          <AdminForm
            method="post"
            action={tenantBadgeRuleDeleteAdminPath(input.tenant.id, rule.id)}
            className="ct-admin__action-menu-form"
            dataAttributes={{
              "data-confirm-message": `Delete draft rule "${rule.name}"? This removes its draft and rejected versions.`,
            }}
          >
            <button
              type="submit"
              class="ct-admin__action-menu-item ct-admin__action-menu-item--danger"
            >
              Delete
            </button>
          </AdminForm>,
        );
      }

      return (
        <tr>
          <td>
            {isEditableRule ? (
              <a class="ct-admin__rule-name-link" href={editRulePath}>
                <strong>{rule.name}</strong>
              </a>
            ) : (
              <strong>{rule.name}</strong>
            )}
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
                {latestVersion.recertificationDueAt === null ? null : (
                  <AdminMeta>
                    Recertification due {formatIsoTimestamp(latestVersion.recertificationDueAt)}
                  </AdminMeta>
                )}
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
            {isEditableRule || menuActions.length > 0 ? (
              <AdminActions>
                {isEditableRule ? (
                  <AdminButtonLink href={editRulePath} variant="secondary" size="tiny">
                    Edit
                  </AdminButtonLink>
                ) : null}
                {menuActions.length > 0 ? (
                  <AdminActionMenu
                    menuId={`badge-rule-action-menu-${rule.id}`}
                    ariaLabel={`More actions for ${rule.name}`}
                  >
                    {menuActions}
                  </AdminActionMenu>
                ) : null}
              </AdminActions>
            ) : (
              <AdminMeta as="span">No actions</AdminMeta>
            )}
          </td>
        </tr>
      );
    })
  );

  const orgUnitParentOptions = dataNeeds.orgUnitParentOptions
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
  const activeOrgUnitOptions = dataNeeds.accessOrgUnitSelectOptions
    ? input.orgUnits
        .filter((orgUnit) => orgUnit.isActive)
        .map((orgUnit) => {
          const selectedOrgUnitFilterId = input.issuedBadgesWorkspace?.filters.orgUnitId ?? "";

          return (
            <option value={orgUnit.id} selected={orgUnit.id === selectedOrgUnitFilterId}>
              {`${orgUnit.displayName} (${orgUnit.unitType})`}
            </option>
          );
        })
    : [];
  const tenantMemberOptions = dataNeeds.accessMemberSelectOptions
    ? input.tenantMembers.map((member) => {
        return <option value={member.userId}>{`${member.email} (${member.role})`}</option>;
      })
    : [];
  const templateOptions = dataNeeds.templateSelectOptions
    ? input.badgeTemplates.map((template, index) => {
        return (
          <option value={template.id} selected={index === 0}>
            {`${template.title} (${template.id})`}
          </option>
        );
      })
    : [];
  const selectedBadgeTemplateFilterId = input.issuedBadgesWorkspace?.filters.badgeTemplateId ?? "";
  const templateFilterOptions = dataNeeds.issuedBadgeFilters ? (
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
  const ruleOptions = dataNeeds.ruleSelectOptions
    ? input.badgeRules.map((rule, index) => formatRuleOption(rule, true, index))
    : [];
  const templateSelectOptions = !dataNeeds.templateSelectOptions ? (
    emptySectionMarkup
  ) : templateOptions.length > 0 ? (
    <>{templateOptions}</>
  ) : (
    <option value="">No badge templates available</option>
  );
  const activeOrgUnitSelectOptions = !dataNeeds.accessOrgUnitSelectOptions ? (
    emptySectionMarkup
  ) : activeOrgUnitOptions.length > 0 ? (
    <>{activeOrgUnitOptions}</>
  ) : (
    <option value="">No active org units available</option>
  );
  const approvalPolicyFormState = badgeRuleApprovalPolicyFormState(
    input.badgeRuleApprovalPolicy ?? null,
  );
  const selectedBadgeRuleApprovalOrgUnitId = approvalPolicyFormState.orgUnitId;
  const badgeRuleApprovalOrgUnitSelectOptions = !dataNeeds.governanceTableRows ? (
    emptySectionMarkup
  ) : (
    <>
      {input.orgUnits
        .filter((orgUnit) => orgUnit.isActive)
        .map((orgUnit) => (
          <option
            value={orgUnit.id}
            selected={orgUnit.id === selectedBadgeRuleApprovalOrgUnitId ? true : undefined}
          >
            {`${orgUnit.displayName} (${orgUnit.unitType})`}
          </option>
        ))}
    </>
  );
  const tenantMemberSelectOptions = !dataNeeds.accessMemberSelectOptions ? (
    emptySectionMarkup
  ) : tenantMemberOptions.length > 0 ? (
    <>{tenantMemberOptions}</>
  ) : (
    <option value="">No tenant members available</option>
  );
  const selectedBadgeRuleApprovalUserId = approvalPolicyFormState.targetUserId;
  const badgeRuleApprovalTargetUserSelectOptions = !dataNeeds.governanceTableRows ? (
    emptySectionMarkup
  ) : input.tenantMembers.length > 0 ? (
    <>
      {input.tenantMembers.map((member) => (
        <option
          value={member.userId}
          selected={member.userId === selectedBadgeRuleApprovalUserId ? true : undefined}
        >
          {`${member.email} (${member.role})`}
        </option>
      ))}
    </>
  ) : (
    <option value="">No tenant members available</option>
  );
  const approverGroupSelectOptions = !dataNeeds.governanceTableRows ? (
    emptySectionMarkup
  ) : input.badgeRuleApproverGroups.length > 0 ? (
    <>
      {input.badgeRuleApproverGroups.map((group) => (
        <option value={group.id}>{group.name}</option>
      ))}
    </>
  ) : (
    <option value="">No approver groups available</option>
  );
  const selectedBadgeRuleApprovalGroupId = approvalPolicyFormState.targetApproverGroupId;
  const badgeRuleApprovalTargetApproverGroupSelectOptions = !dataNeeds.governanceTableRows ? (
    emptySectionMarkup
  ) : input.badgeRuleApproverGroups.length > 0 ? (
    <>
      {input.badgeRuleApproverGroups.map((group) => (
        <option
          value={group.id}
          selected={group.id === selectedBadgeRuleApprovalGroupId ? true : undefined}
        >
          {group.name}
        </option>
      ))}
    </>
  ) : (
    <option value="">No approver groups available</option>
  );
  const optionalBadgeTemplateScopeOptions = !dataNeeds.delegationSelectOptions ? (
    emptySectionMarkup
  ) : (
    <>
      <option value="">All badge templates in the selected scope</option>
      {input.badgeTemplates.map((template) => (
        <option value={template.id}>{template.title}</option>
      ))}
    </>
  );
  const ruleSelectOptions = !dataNeeds.ruleSelectOptions ? (
    emptySectionMarkup
  ) : ruleOptions.length > 0 ? (
    <>{ruleOptions}</>
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
  const workspaceCardsMarkup = (
    <section class="ct-admin__workspace-grid ct-grid" aria-label="Institution admin workspaces">
      <AdminWorkspaceCard href={operationsManualIssuePath} ariaLabel="Open Issuance workspace">
        <h2>Issuance</h2>
        <p>
          Issue badges, route manual review, inspect issued badges, and update badge status across
          focused pages.
        </p>
        <div class="ct-admin__workspace-stats ct-cluster">
          <AdminStatusPill>{badgeTemplateCount} templates</AdminStatusPill>
          <AdminStatusPill>{ruleCount} rules</AdminStatusPill>
        </div>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard
        href={operationsLearnerRecordsPath}
        ariaLabel="Open Learner Records workspace"
      >
        <h2>Learner Records</h2>
        <p>View, import, and export learner records.</p>
      </AdminWorkspaceCard>
      <AdminWorkspaceCard href={rulesWorkspacePath} ariaLabel="Open Badge Program workspace">
        <h2>Badge Program</h2>
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
      <AdminWorkspaceCard href={reportingPath} ariaLabel="Open Reporting workspace">
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
      <AdminWorkspaceCard href={accessMembersPath} ariaLabel="Open People & Access workspace">
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

  const operationsSections = dataNeeds.operationsSectionBundles
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
        badgeStatusPanelMarkup: emptySectionMarkup,
        ruleGovernancePanelMarkup: emptySectionMarkup,
        ruleReviewQueuePanelMarkup: emptySectionMarkup,
        issuedBadgesPanelMarkup: emptySectionMarkup,
      };
  const { badgeStatusPanelMarkup, ruleReviewQueuePanelMarkup, issuedBadgesPanelMarkup } =
    operationsSections;

  const tenantMemberRoleSelectOptions = dataNeeds.tenantMemberRows
    ? assignableTenantRoles.map((role) => <option value={role}>{role}</option>)
    : [];
  const accessSections = dataNeeds.accessSectionBundles
    ? renderInstitutionAdminAccessSections({
        accessMembersPath,
        accessOrgUnitAccessPath,
        accessGovernancePath,
        accessDelegationsPath,
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
        apiKeyRows,
        orgUnitRows,
        orgUnitParentOptions,
        tenantMemberSelectOptions,
        badgeRuleApprovalTargetUserSelectOptions,
        approverGroupSelectOptions,
        badgeRuleApprovalTargetApproverGroupSelectOptions,
        activeOrgUnitSelectOptions,
        badgeRuleApprovalOrgUnitSelectOptions,
        optionalBadgeTemplateScopeOptions,
        membershipScopeRows,
        approverGroupRows,
        delegatedGrantRows,
        lmsConnectionRows,
        badgeRuleApprovalPolicy: input.badgeRuleApprovalPolicy ?? null,
        enabledSections: accessSectionKindsForDataNeeds(dataNeeds),
        ...(input.apiKeysWorkspace === undefined
          ? {}
          : { apiKeysWorkspace: input.apiKeysWorkspace }),
        ...(input.lmsConnectionsWorkspace === undefined
          ? {}
          : { lmsConnectionsWorkspace: input.lmsConnectionsWorkspace }),
        ...(input.accessMembersWorkspace === undefined
          ? {}
          : { accessMembersWorkspace: input.accessMembersWorkspace }),
        ...(input.accessOrgUnitAccessWorkspace === undefined
          ? {}
          : { accessOrgUnitAccessWorkspace: input.accessOrgUnitAccessWorkspace }),
        ...(input.accessGovernanceWorkspace === undefined
          ? {}
          : { accessGovernanceWorkspace: input.accessGovernanceWorkspace }),
        ...(input.accessDelegationsWorkspace === undefined
          ? {}
          : { accessDelegationsWorkspace: input.accessDelegationsWorkspace }),
        ...(input.accessOrgUnitsWorkspace === undefined
          ? {}
          : { accessOrgUnitsWorkspace: input.accessOrgUnitsWorkspace }),
      })
    : {
        apiKeysTableMarkup: emptySectionMarkup,
        lmsConnectionsActionsMarkup: emptySectionMarkup,
        lmsConnectionsTableMarkup: emptySectionMarkup,
        orgUnitsTableMarkup: emptySectionMarkup,
        governanceGuidePanelMarkup: emptySectionMarkup,
        ruleApprovalPolicySummaryMarkup: emptySectionMarkup,
        tenantMembersTableMarkup: emptySectionMarkup,
        membershipScopeTableMarkup: emptySectionMarkup,
        approverGroupTableMarkup: emptySectionMarkup,
        delegatedGrantTableMarkup: emptySectionMarkup,
        delegatedGrantActionsMarkup: emptySectionMarkup,
      };
  const {
    apiKeysTableMarkup,
    lmsConnectionsActionsMarkup,
    lmsConnectionsTableMarkup,
    orgUnitsTableMarkup,
    governanceGuidePanelMarkup,
    tenantMembersTableMarkup,
    membershipScopeTableMarkup,
    approverGroupTableMarkup,
    delegatedGrantTableMarkup,
    delegatedGrantActionsMarkup,
    ruleApprovalPolicySummaryMarkup,
  } = accessSections;

  const reportingSections = dataNeeds.reportingSectionBundles
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

  const badgeRulesTableMarkup = dataNeeds.badgeRulesTable
    ? renderBadgeRulesTable({
        ruleCount,
        ruleBuilderPath,
        rulesTemplatesPath,
        ruleRows,
      })
    : emptySectionMarkup;

  const learnerRecordSections = dataNeeds.learnerRecordSectionBundles
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

  const viewContent = renderInstitutionAdminViewContent({
    input,
    view,
    home: {
      workspaceCardsMarkup,
    },
    controls: {
      activeOrgUnitSelectOptions,
      optionalBadgeTemplateScopeOptions,
      templateSelectOptions,
      tenantMemberSelectOptions,
    },
    learnerRecords: {
      learnerRecordImportFeedbackMarkup,
      learnerRecordImportPanelMarkup,
      learnerRecordImportProgressMarkup,
      learnerRecordImportSubmissionMarkup,
      learnerRecordReviewPanelMarkup,
      renderLearnerRecordReviewSections,
    },
    operations: {
      badgeStatusPanelMarkup: asChild(badgeStatusPanelMarkup),
      issuedBadgesPanelMarkup: asChild(issuedBadgesPanelMarkup),
      ruleReviewQueuePanelMarkup: asChild(ruleReviewQueuePanelMarkup),
    },
    reporting: {
      renderReportingTrendPanelMarkup,
      reportingDeepLinksMarkup,
      reportingDeferredPanelMarkup,
      reportingDefinitionsPanelMarkup,
      reportingEngagementPanelMarkup,
      reportingExecutiveSummaryMarkup,
      reportingExportFiltersPanelMarkup,
      reportingExploreSliceSummaryMarkup,
      reportingExportsPanelMarkup,
      reportingFocusAreaPanelMarkup,
      reportingLowerStoryMarkup,
      reportingOverviewPanelMarkup,
      reportingRankedChartsMarkup,
      reportingReportsLibraryMarkup,
      reportingTrendFiltersPanelMarkup,
    },
    rules: {
      badgeRulesTableMarkup,
    },
    access: {
      apiKeysTableMarkup,
      approverGroupTableMarkup,
      delegatedGrantTableMarkup,
      delegatedGrantActionsMarkup,
      governanceGuidePanelMarkup,
      lmsConnectionsActionsMarkup,
      lmsConnectionsTableMarkup,
      membershipScopeTableMarkup,
      orgUnitsTableMarkup,
      ruleApprovalPolicySummaryMarkup,
      tenantMembersTableMarkup,
    },
  });

  return {
    adminPageContextJson,
    viewContent,
  };
};
