import { registerBadgeTemplateEditorArtworkAdminRoutes } from "./badge-template-editor-artwork-admin-routes";
import { registerBadgeTemplateListAdminRoutes } from "./badge-template-list-admin-routes";
import { registerTenantAccessDelegationsAdminRoutes } from "./tenant-access-delegations-admin-routes";
import { registerTenantAccessEnterpriseAdminRoutes } from "./tenant-access-enterprise-admin-routes";
import { registerTenantAccessMembersAdminRoutes } from "./tenant-access-members-admin-routes";
import { registerTenantAccessOrgUnitAccessAdminRoutes } from "./tenant-access-org-unit-access-admin-routes";
import { registerTenantAccessRuleApprovalAdminRoutes } from "./tenant-access-rule-approval-admin-routes";
import { registerTenantAdminPageRoutes } from "./tenant-admin-page-routes";
import { registerTenantAdminReportingPageRoutes } from "./tenant-admin-reporting-page-routes";
import { registerTenantApiKeyAdminRoutes } from "./tenant-api-key-admin-routes";
import { registerTenantApiKeyRoutes } from "./tenant-api-key-routes";
import { registerTenantAuthManagementRoutes } from "./tenant-auth-management-routes";
import { registerTenantBadgeRuleActionsAdminRoutes } from "./tenant-badge-rule-actions-admin-routes";
import { registerTenantBadgeRuleApprovalWorkspaceAdminRoutes } from "./tenant-badge-rule-approval-workspace-admin-routes";
import { registerTenantBreakGlassRoutes } from "./tenant-break-glass-routes";
import { registerTenantDelegatedAuthorityRoutes } from "./tenant-delegated-authority-routes";
import { createTenantGovernanceAdminAuth } from "./tenant-governance-admin/auth";
import { createTenantGovernanceInstitutionAdminWorkspaces } from "./tenant-governance-admin/institution-workspaces";
import { createTenantGovernanceLearnerRecordImportAdmin } from "./tenant-governance-admin/learner-record-import";
import { createTenantGovernanceLearnerRecordReviewAdmin } from "./tenant-governance-admin/learner-record-review";
import { createTenantGovernanceAdminPageDataLoaders } from "./tenant-governance-admin/page-data";
import { createTenantGovernanceReportingAdminWorkspaces } from "./tenant-governance-admin/reporting-workspaces";
import { createTenantGovernanceTemplateAdminWorkspaces } from "./tenant-governance-admin/template-workspaces";
import type { RegisterTenantGovernanceRoutesInput } from "./tenant-governance-routes.types";
import { adminRoleRequiredPage } from "./tenant-governance-shared-pages";
import { registerTenantIssuedBadgesAdminRoutes } from "./tenant-issued-badges-admin-routes";
import { registerTenantLearnerRecordAdminRoutes } from "./tenant-learner-record-admin-routes";
import { registerTenantLmsConnectionAdminRoutes } from "./tenant-lms-connection-admin-routes";
import { registerTenantMemberManagementRoutes } from "./tenant-member-management-routes";
import {
  assertRoleChangeAllowed,
  canManageTenantRole,
  membershipAuditAction,
} from "./tenant-member-policy";
import { registerTenantMembershipScopeRoutes } from "./tenant-membership-scope-routes";
import { registerTenantOperationsAdminRoutes } from "./tenant-operations-admin-routes";
import { registerTenantOrgUnitRoutes } from "./tenant-org-unit-routes";
import { registerTenantOrgUnitsAdminRoutes } from "./tenant-org-units-admin-routes";
import { registerTenantReviewQueueAdminRoutes } from "./tenant-review-queue-admin-routes";
import { registerTenantRuleValueListsAdminRoutes } from "./tenant-rule-value-lists-admin-routes";

export type { RegisterTenantGovernanceRoutesInput } from "./tenant-governance-routes.types";
export {
  adminRoleRequiredPage,
  reportingAccessRequiredPage,
} from "./tenant-governance-shared-pages";

export const registerTenantGovernanceRoutes = (
  input: RegisterTenantGovernanceRoutesInput,
): void => {
  const auth = createTenantGovernanceAdminAuth(input);
  const pageData = createTenantGovernanceAdminPageDataLoaders(input);
  const templateWorkspaces = createTenantGovernanceTemplateAdminWorkspaces({
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
    loadInstitutionAdminShellData: pageData.loadInstitutionAdminShellData,
  });
  const institutionWorkspaces = createTenantGovernanceInstitutionAdminWorkspaces({
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
    resolveInstitutionAdminEvidenceRole: auth.resolveInstitutionAdminEvidenceRole,
    loadInstitutionAdminPageData: pageData.loadInstitutionAdminPageData,
  });
  const learnerRecordImport = createTenantGovernanceLearnerRecordImportAdmin({
    resolveDatabase: input.resolveDatabase,
    loadInstitutionAdminPageData: pageData.loadInstitutionAdminPageData,
  });
  const learnerRecordReview = createTenantGovernanceLearnerRecordReviewAdmin({
    resolveDatabase: input.resolveDatabase,
    loadInstitutionAdminPageData: pageData.loadInstitutionAdminPageData,
  });
  const reportingWorkspaces = createTenantGovernanceReportingAdminWorkspaces({
    requireTenantRole: input.requireTenantRole,
    ISSUER_ROLES: input.ISSUER_ROLES,
    redirectToTenantLogin: auth.redirectToTenantLogin,
    loadReportingPageData: pageData.loadReportingPageData,
  });

  registerBadgeTemplateEditorArtworkAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    requireScopedOrgUnitPermission: input.requireScopedOrgUnitPermission,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerBadgeTemplateListAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    defaultInstitutionOrgUnitId: input.defaultInstitutionOrgUnitId,
    requireScopedOrgUnitPermission: input.requireScopedOrgUnitPermission,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantApiKeyAdminRoutes({
    app: input.app,
    generateOpaqueToken: input.generateOpaqueToken,
    resolveDatabase: input.resolveDatabase,
    sha256Hex: input.sha256Hex,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantLmsConnectionAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantIssuedBadgesAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    requireDelegatedIssuingAuthorityPermission: input.requireDelegatedIssuingAuthorityPermission,
    assertionBelongsToTenant: input.assertionBelongsToTenant,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantReviewQueueAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
    issueBadgeForTenant: input.issueBadgeForTenant,
  });

  registerTenantRuleValueListsAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantAccessMembersAdminRoutes({
    app: input.app,
    assertRoleChangeAllowed,
    canManageTenantRole,
    membershipAuditAction,
    requestInviteForTenantMember: auth.requestInviteForTenantMember,
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantAccessRuleApprovalAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantAccessOrgUnitAccessAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantAccessDelegationsAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantAccessEnterpriseAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    requireEnterpriseTenant: auth.requireEnterpriseTenant,
    ...(input.requestBreakGlassPasswordReset === undefined
      ? {}
      : { requestBreakGlassPasswordReset: input.requestBreakGlassPasswordReset }),
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantOrgUnitsAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantBadgeRuleActionsAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    resolveBadgeRuleApprovalWorkspaceRole: auth.resolveBadgeRuleApprovalWorkspaceRole,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantBadgeRuleApprovalWorkspaceAdminRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    sha256Hex: input.sha256Hex,
    resolveBadgeRuleApprovalWorkspaceRole: auth.resolveBadgeRuleApprovalWorkspaceRole,
  });

  registerTenantOperationsAdminRoutes({
    app: input.app,
    issueBadgeForTenant: input.issueBadgeForTenant,
    requireDelegatedIssuingAuthorityPermission: input.requireDelegatedIssuingAuthorityPermission,
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantAdminPageRoutes({
    app: input.app,
    ADMIN_ROLES: input.ADMIN_ROLES,
    adminRoleRequiredPage,
    requireTenantRole: input.requireTenantRole,
    redirectToTenantLogin: auth.redirectToTenantLogin,
    renderInstitutionAdminWorkspace: institutionWorkspaces.renderInstitutionAdminWorkspace,
    renderInstitutionAdminMembersWorkspace: institutionWorkspaces.renderMembersWorkspace,
    renderInstitutionAdminOrgUnitAccessWorkspace:
      institutionWorkspaces.renderOrgUnitAccessWorkspace,
    renderInstitutionAdminGovernanceWorkspace: institutionWorkspaces.renderGovernanceWorkspace,
    renderInstitutionAdminDelegationsWorkspace: institutionWorkspaces.renderDelegationsWorkspace,
    renderInstitutionAdminOrgUnitsWorkspace: institutionWorkspaces.renderOrgUnitsWorkspace,
    renderInstitutionAdminApiKeysWorkspace:
      institutionWorkspaces.renderInstitutionAdminApiKeysWorkspace,
    renderInstitutionAdminIssuedBadgesWorkspace:
      institutionWorkspaces.renderInstitutionAdminIssuedBadgesWorkspace,
    renderInstitutionAdminAssertionEvidenceWorkspace:
      institutionWorkspaces.renderInstitutionAdminAssertionEvidenceWorkspace,
    renderInstitutionAdminReviewQueueWorkspace: institutionWorkspaces.renderReviewQueueWorkspace,
    renderInstitutionAdminRulesWorkspace: institutionWorkspaces.renderRulesWorkspace,
    renderInstitutionAdminLmsConnectionsWorkspace:
      institutionWorkspaces.renderLmsConnectionsWorkspace,
    renderInstitutionAdminLmsConnectionNewWorkspace:
      institutionWorkspaces.renderLmsConnectionNewWorkspace,
    renderInstitutionAdminLmsConnectionEditWorkspace:
      institutionWorkspaces.renderLmsConnectionEditWorkspace,
    renderInstitutionAdminAuthenticationWorkspace:
      institutionWorkspaces.renderAuthenticationWorkspace,
    renderInstitutionAdminDelegationsNewWorkspace:
      institutionWorkspaces.renderDelegationsNewWorkspace,
    renderInstitutionAdminManualIssueWorkspace: institutionWorkspaces.renderManualIssueWorkspace,
    renderInstitutionAdminTemplatesWorkspace:
      templateWorkspaces.renderInstitutionAdminTemplatesWorkspace,
    renderInstitutionAdminTemplateEditorWorkspace:
      templateWorkspaces.renderInstitutionAdminTemplateEditorWorkspace,
    resolveDatabase: input.resolveDatabase,
    resolveInstitutionAdminAdminRole: auth.resolveInstitutionAdminAdminRole,
  });

  registerTenantLearnerRecordAdminRoutes({
    app: input.app,
    ADMIN_ROLES: input.ADMIN_ROLES,
    adminRoleRequiredPage,
    handleLearnerRecordImportUpload: learnerRecordImport.handleLearnerRecordImportUpload,
    loadLearnerRecordReviewPageData: learnerRecordReview.loadLearnerRecordReviewPageData,
    redirectToTenantLogin: auth.redirectToTenantLogin,
    renderLearnerRecordImportWorkspace: learnerRecordImport.renderLearnerRecordImportWorkspace,
    resolveDatabase: input.resolveDatabase,
    requireTenantRole: input.requireTenantRole,
  });

  registerTenantAdminReportingPageRoutes({
    app: input.app,
    renderReportingWorkspace: reportingWorkspaces.renderReportingWorkspace,
  });

  registerTenantAuthManagementRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    requireEnterpriseTenant: auth.requireEnterpriseTenant,
    requireTenantRole: input.requireTenantRole,
    ADMIN_ROLES: input.ADMIN_ROLES,
  });

  registerTenantMemberManagementRoutes({
    app: input.app,
    assertRoleChangeAllowed,
    canManageTenantRole,
    membershipAuditAction,
    requestInviteForTenantMember: auth.requestInviteForTenantMember,
    resolveDatabase: input.resolveDatabase,
    requireTenantRole: input.requireTenantRole,
    ADMIN_ROLES: input.ADMIN_ROLES,
  });

  registerTenantBreakGlassRoutes({
    app: input.app,
    requestBreakGlassPasswordReset: input.requestBreakGlassPasswordReset,
    requireEnterpriseTenant: auth.requireEnterpriseTenant,
    resolveDatabase: input.resolveDatabase,
    requireTenantRole: input.requireTenantRole,
    ADMIN_ROLES: input.ADMIN_ROLES,
  });

  registerTenantApiKeyRoutes({
    app: input.app,
    generateOpaqueToken: input.generateOpaqueToken,
    resolveDatabase: input.resolveDatabase,
    sha256Hex: input.sha256Hex,
    requireTenantRole: input.requireTenantRole,
    ADMIN_ROLES: input.ADMIN_ROLES,
  });

  registerTenantOrgUnitRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    requireTenantRole: input.requireTenantRole,
    ADMIN_ROLES: input.ADMIN_ROLES,
    ISSUER_ROLES: input.ISSUER_ROLES,
  });

  registerTenantMembershipScopeRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    requireTenantRole: input.requireTenantRole,
    ADMIN_ROLES: input.ADMIN_ROLES,
  });

  registerTenantDelegatedAuthorityRoutes({
    app: input.app,
    resolveDatabase: input.resolveDatabase,
    requireTenantRole: input.requireTenantRole,
    ADMIN_ROLES: input.ADMIN_ROLES,
  });
};
