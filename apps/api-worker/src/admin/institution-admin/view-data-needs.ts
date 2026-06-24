import type { InstitutionAdminView } from "./page-types";

const DEDICATED_ACCESS_SETUP_VIEWS: ReadonlySet<InstitutionAdminView> = new Set([
  "accessGovernanceDelegationNew",
  "accessAuthentication",
  "accessLmsConnectionNew",
  "accessLmsConnectionEdit",
]);

export interface InstitutionAdminViewDataNeeds {
  accessSectionBundles: boolean;
  operationsSectionBundles: boolean;
  reportingSectionBundles: boolean;
  managementSectionBundles: boolean;
  learnerRecordSectionBundles: boolean;
  ruleTableRows: boolean;
  lmsConnectionRows: boolean;
  apiKeyRows: boolean;
  orgUnitRows: boolean;
  governanceTableRows: boolean;
  tenantMemberRows: boolean;
  templateSelectOptions: boolean;
  delegationSelectOptions: boolean;
  ruleSelectOptions: boolean;
  ruleVersionIndexes: boolean;
  orgUnitParentOptions: boolean;
  issuedBadgeFilters: boolean;
}

export const institutionAdminViewNeedsAccessSectionBundles = (
  view: InstitutionAdminView,
): boolean => {
  return view.startsWith("access") && !DEDICATED_ACCESS_SETUP_VIEWS.has(view);
};

export const institutionAdminViewNeedsOperationsSectionBundles = (
  view: InstitutionAdminView,
): boolean => {
  if (view === "operationsManualIssue") {
    return false;
  }

  return view === "rules" || view.startsWith("operations");
};

export const institutionAdminViewNeedsReportingSectionBundles = (
  view: InstitutionAdminView,
): boolean => {
  return view.startsWith("reporting");
};

export const institutionAdminViewNeedsManagementSectionBundles = (
  view: InstitutionAdminView,
): boolean => {
  return view === "rules" || view === "accessOrgUnits" || view === "accessApiKeys";
};

export const institutionAdminViewNeedsLearnerRecordSectionBundles = (
  view: InstitutionAdminView,
): boolean => {
  return view === "operationsLearnerRecords" || view === "operationsLearnerRecordImports";
};

export const institutionAdminViewNeedsRuleTableRows = (view: InstitutionAdminView): boolean => {
  return view === "rules";
};

export const institutionAdminViewNeedsLmsConnectionRows = (view: InstitutionAdminView): boolean => {
  return view === "accessLmsConnections";
};

export const institutionAdminViewNeedsApiKeyRows = (view: InstitutionAdminView): boolean => {
  return view === "accessApiKeys";
};

export const institutionAdminViewNeedsOrgUnitRows = (view: InstitutionAdminView): boolean => {
  return view === "accessOrgUnits";
};

export const institutionAdminViewNeedsGovernanceTableRows = (
  view: InstitutionAdminView,
): boolean => {
  return view === "accessGovernance";
};

export const institutionAdminViewNeedsTenantMemberRows = (view: InstitutionAdminView): boolean => {
  return view === "accessMembers";
};

export const institutionAdminViewNeedsTemplateSelectOptions = (
  view: InstitutionAdminView,
): boolean => {
  return (
    view === "operationsManualIssue" || institutionAdminViewNeedsOperationsSectionBundles(view)
  );
};

export const institutionAdminViewNeedsDelegationSelectOptions = (
  view: InstitutionAdminView,
): boolean => {
  return view === "accessGovernanceDelegationNew" || view === "accessGovernance";
};

export const institutionAdminViewNeedsRuleSelectOptions = (view: InstitutionAdminView): boolean => {
  return institutionAdminViewNeedsOperationsSectionBundles(view) || view === "rules";
};

export const institutionAdminViewNeedsRuleVersionIndexes = (
  view: InstitutionAdminView,
): boolean => {
  return institutionAdminViewNeedsRuleSelectOptions(view) || view === "rules";
};

export const institutionAdminViewDataNeeds = (
  view: InstitutionAdminView,
): InstitutionAdminViewDataNeeds => {
  const operationsSectionBundles = institutionAdminViewNeedsOperationsSectionBundles(view);
  const ruleSelectOptions = operationsSectionBundles || view === "rules";

  return {
    accessSectionBundles: institutionAdminViewNeedsAccessSectionBundles(view),
    operationsSectionBundles,
    reportingSectionBundles: institutionAdminViewNeedsReportingSectionBundles(view),
    managementSectionBundles: institutionAdminViewNeedsManagementSectionBundles(view),
    learnerRecordSectionBundles: institutionAdminViewNeedsLearnerRecordSectionBundles(view),
    ruleTableRows: institutionAdminViewNeedsRuleTableRows(view),
    lmsConnectionRows: institutionAdminViewNeedsLmsConnectionRows(view),
    apiKeyRows: institutionAdminViewNeedsApiKeyRows(view),
    orgUnitRows: institutionAdminViewNeedsOrgUnitRows(view),
    governanceTableRows: institutionAdminViewNeedsGovernanceTableRows(view),
    tenantMemberRows: institutionAdminViewNeedsTenantMemberRows(view),
    templateSelectOptions: view === "operationsManualIssue" || operationsSectionBundles,
    delegationSelectOptions: institutionAdminViewNeedsDelegationSelectOptions(view),
    ruleSelectOptions,
    ruleVersionIndexes: ruleSelectOptions,
    orgUnitParentOptions: view === "accessOrgUnits",
    issuedBadgeFilters: view === "operationsIssuedBadges",
  };
};
