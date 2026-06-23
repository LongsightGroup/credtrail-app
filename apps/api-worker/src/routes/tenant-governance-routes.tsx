import { registerTenantGovernanceSubroutes } from "./register-tenant-governance-subroutes";
import type { RegisterTenantGovernanceRoutesInput } from "./tenant-governance-routes.types";
import { createTenantGovernanceAdminAuth } from "./tenant-governance-admin/auth";
import { createTenantGovernanceInstitutionAdminWorkspaces } from "./tenant-governance-admin/institution-workspaces";
import { createTenantGovernanceLearnerRecordImportAdmin } from "./tenant-governance-admin/learner-record-import";
import { createTenantGovernanceAdminPageDataLoaders } from "./tenant-governance-admin/page-data";
import { createTenantGovernanceReportingAdminWorkspaces } from "./tenant-governance-admin/reporting-workspaces";
import { createTenantGovernanceTemplateAdminWorkspaces } from "./tenant-governance-admin/template-workspaces";

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
    loadInstitutionAdminPageData: pageData.loadInstitutionAdminPageData,
  });
  const learnerRecordImport = createTenantGovernanceLearnerRecordImportAdmin({
    resolveDatabase: input.resolveDatabase,
    loadInstitutionAdminPageData: pageData.loadInstitutionAdminPageData,
  });
  const reportingWorkspaces = createTenantGovernanceReportingAdminWorkspaces({
    requireTenantRole: input.requireTenantRole,
    ISSUER_ROLES: input.ISSUER_ROLES,
    redirectToTenantLogin: auth.redirectToTenantLogin,
    loadReportingPageData: pageData.loadReportingPageData,
  });

  registerTenantGovernanceSubroutes(input, {
    auth,
    templateWorkspaces,
    institutionWorkspaces,
    learnerRecordImport,
    reportingWorkspaces,
  });
};
