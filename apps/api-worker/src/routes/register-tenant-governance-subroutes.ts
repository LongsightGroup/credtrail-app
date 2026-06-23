import { registerBadgeTemplateEditorArtworkAdminRoutes } from "./badge-template-editor-artwork-admin-routes";
import { registerBadgeTemplateListAdminRoutes } from "./badge-template-list-admin-routes";
import { registerTenantAccessEnterpriseAdminRoutes } from "./tenant-access-enterprise-admin-routes";
import { registerTenantAccessGovernanceAdminRoutes } from "./tenant-access-governance-admin-routes";
import { registerTenantAccessMembersAdminRoutes } from "./tenant-access-members-admin-routes";
import { registerTenantAdminPageRoutes } from "./tenant-admin-page-routes";
import { registerTenantAdminReportingPageRoutes } from "./tenant-admin-reporting-page-routes";
import { registerTenantApiKeyAdminRoutes } from "./tenant-api-key-admin-routes";
import { registerTenantApiKeyRoutes } from "./tenant-api-key-routes";
import { registerTenantAuthManagementRoutes } from "./tenant-auth-management-routes";
import { registerTenantBadgeRuleActionsAdminRoutes } from "./tenant-badge-rule-actions-admin-routes";
import { registerTenantBreakGlassRoutes } from "./tenant-break-glass-routes";
import { registerTenantDelegatedAuthorityRoutes } from "./tenant-delegated-authority-routes";
import { registerTenantIssuedBadgesAdminRoutes } from "./tenant-issued-badges-admin-routes";
import { registerTenantLearnerRecordAdminRoutes } from "./tenant-learner-record-admin-routes";
import { registerTenantLmsConnectionAdminRoutes } from "./tenant-lms-connection-admin-routes";
import { registerTenantMemberManagementRoutes } from "./tenant-member-management-routes";
import { registerTenantMembershipScopeRoutes } from "./tenant-membership-scope-routes";
import { registerTenantOperationsAdminRoutes } from "./tenant-operations-admin-routes";
import { registerTenantOrgUnitRoutes } from "./tenant-org-unit-routes";
import { registerTenantOrgUnitsAdminRoutes } from "./tenant-org-units-admin-routes";
import { registerTenantReviewQueueAdminRoutes } from "./tenant-review-queue-admin-routes";
import { registerTenantRuleValueListsAdminRoutes } from "./tenant-rule-value-lists-admin-routes";
import {
  assertRoleChangeAllowed,
  canManageTenantRole,
  membershipAuditAction,
} from "./tenant-member-policy";
import type { TenantGovernanceAdminAuth } from "./tenant-governance-admin/auth";
import type { TenantGovernanceInstitutionAdminWorkspaces } from "./tenant-governance-admin/institution-workspaces";
import type { TenantGovernanceLearnerRecordImportAdmin } from "./tenant-governance-admin/learner-record-import";
import type { TenantGovernanceReportingAdminWorkspaces } from "./tenant-governance-admin/reporting-workspaces";
import type { TenantGovernanceTemplateAdminWorkspaces } from "./tenant-governance-admin/template-workspaces";
import { adminRoleRequiredPage } from "./tenant-governance-shared-pages";
import type { RegisterTenantGovernanceRoutesInput } from "./tenant-governance-routes.types";

export interface RegisterTenantGovernanceSubroutesInput {
  auth: TenantGovernanceAdminAuth;
  templateWorkspaces: TenantGovernanceTemplateAdminWorkspaces;
  institutionWorkspaces: TenantGovernanceInstitutionAdminWorkspaces;
  learnerRecordImport: TenantGovernanceLearnerRecordImportAdmin;
  reportingWorkspaces: TenantGovernanceReportingAdminWorkspaces;
}

export const registerTenantGovernanceSubroutes = (
  input: RegisterTenantGovernanceRoutesInput,
  workflows: RegisterTenantGovernanceSubroutesInput,
): void => {
  const {
    app,
    resolveDatabase,
    defaultInstitutionOrgUnitId,
    generateOpaqueToken,
    sha256Hex,
    requireTenantRole,
    requireScopedOrgUnitPermission,
    requireDelegatedIssuingAuthorityPermission,
    assertionBelongsToTenant,
    issueBadgeForTenant,
    requestBreakGlassPasswordReset,
    ADMIN_ROLES,
    ISSUER_ROLES,
  } = input;
  const {
    auth: {
      requireEnterpriseTenant,
      requestInviteForTenantMember,
      resolveInstitutionAdminAdminRole,
      redirectToTenantLogin,
    },
    templateWorkspaces: {
      renderInstitutionAdminTemplatesWorkspace,
      renderInstitutionAdminTemplateEditorWorkspace,
    },
    institutionWorkspaces: {
      renderInstitutionAdminWorkspace,
      renderInstitutionAdminApiKeysWorkspace,
      renderInstitutionAdminIssuedBadgesWorkspace,
      renderRulesWorkspace,
      renderReviewQueueWorkspace,
      renderLmsConnectionsWorkspace,
      renderLmsConnectionNewWorkspace,
      renderLmsConnectionEditWorkspace,
      renderAuthenticationWorkspace,
      renderGovernanceDelegationNewWorkspace,
      renderManualIssueWorkspace,
      renderMembersWorkspace,
      renderGovernanceWorkspace,
      renderOrgUnitsWorkspace,
    },
    learnerRecordImport: {
      handleLearnerRecordImportUpload,
      loadLearnerRecordReviewPageData,
      renderLearnerRecordImportWorkspace,
    },
    reportingWorkspaces: { renderReportingWorkspace },
  } = workflows;

  registerBadgeTemplateEditorArtworkAdminRoutes({
    app,
    resolveDatabase,
    requireScopedOrgUnitPermission,
    resolveInstitutionAdminAdminRole,
  });

  registerBadgeTemplateListAdminRoutes({
    app,
    resolveDatabase,
    defaultInstitutionOrgUnitId,
    requireScopedOrgUnitPermission,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantApiKeyAdminRoutes({
    app,
    generateOpaqueToken,
    resolveDatabase,
    sha256Hex,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantLmsConnectionAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantIssuedBadgesAdminRoutes({
    app,
    resolveDatabase,
    requireDelegatedIssuingAuthorityPermission,
    assertionBelongsToTenant,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantReviewQueueAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
    issueBadgeForTenant,
  });

  registerTenantRuleValueListsAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantAccessMembersAdminRoutes({
    app,
    assertRoleChangeAllowed,
    canManageTenantRole,
    membershipAuditAction,
    requestInviteForTenantMember,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantAccessGovernanceAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantAccessEnterpriseAdminRoutes({
    app,
    resolveDatabase,
    requireEnterpriseTenant,
    ...(requestBreakGlassPasswordReset === undefined
      ? {}
      : {
          requestBreakGlassPasswordReset: async (c, input) => {
            const status = await requestBreakGlassPasswordReset(c, input);

            if (status === "unavailable") {
              return "failed";
            }

            return status;
          },
        }),
    resolveInstitutionAdminAdminRole,
  });

  registerTenantOrgUnitsAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantBadgeRuleActionsAdminRoutes({
    app,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantOperationsAdminRoutes({
    app,
    issueBadgeForTenant,
    requireDelegatedIssuingAuthorityPermission,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantAdminPageRoutes({
    app,
    ADMIN_ROLES,
    adminRoleRequiredPage,
    requireTenantRole,
    redirectToTenantLogin,
    renderInstitutionAdminWorkspace,
    renderInstitutionAdminMembersWorkspace: renderMembersWorkspace,
    renderInstitutionAdminGovernanceWorkspace: renderGovernanceWorkspace,
    renderInstitutionAdminOrgUnitsWorkspace: renderOrgUnitsWorkspace,
    renderInstitutionAdminApiKeysWorkspace,
    renderInstitutionAdminIssuedBadgesWorkspace,
    renderInstitutionAdminReviewQueueWorkspace: renderReviewQueueWorkspace,
    renderInstitutionAdminRulesWorkspace: renderRulesWorkspace,
    renderInstitutionAdminLmsConnectionsWorkspace: renderLmsConnectionsWorkspace,
    renderInstitutionAdminLmsConnectionNewWorkspace: renderLmsConnectionNewWorkspace,
    renderInstitutionAdminLmsConnectionEditWorkspace: renderLmsConnectionEditWorkspace,
    renderInstitutionAdminAuthenticationWorkspace: renderAuthenticationWorkspace,
    renderInstitutionAdminGovernanceDelegationNewWorkspace: renderGovernanceDelegationNewWorkspace,
    renderInstitutionAdminManualIssueWorkspace: renderManualIssueWorkspace,
    renderInstitutionAdminTemplatesWorkspace,
    renderInstitutionAdminTemplateEditorWorkspace,
    resolveDatabase,
    resolveInstitutionAdminAdminRole,
  });

  registerTenantLearnerRecordAdminRoutes({
    app,
    ADMIN_ROLES,
    adminRoleRequiredPage,
    handleLearnerRecordImportUpload,
    loadLearnerRecordReviewPageData,
    redirectToTenantLogin,
    renderLearnerRecordImportWorkspace,
    resolveDatabase,
    requireTenantRole,
  });

  registerTenantAdminReportingPageRoutes({
    app,
    renderReportingWorkspace,
  });

  registerTenantAuthManagementRoutes({
    app,
    resolveDatabase,
    requireEnterpriseTenant,
    requireTenantRole,
    ADMIN_ROLES,
  });

  registerTenantMemberManagementRoutes({
    app,
    assertRoleChangeAllowed,
    canManageTenantRole,
    membershipAuditAction,
    requestInviteForTenantMember,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
  });

  registerTenantBreakGlassRoutes({
    app,
    requestBreakGlassPasswordReset,
    requireEnterpriseTenant,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
  });

  registerTenantApiKeyRoutes({
    app,
    generateOpaqueToken,
    resolveDatabase,
    sha256Hex,
    requireTenantRole,
    ADMIN_ROLES,
  });

  registerTenantOrgUnitRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
    ISSUER_ROLES,
  });

  registerTenantMembershipScopeRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
  });

  registerTenantDelegatedAuthorityRoutes({
    app,
    resolveDatabase,
    requireTenantRole,
    ADMIN_ROLES,
  });
};
