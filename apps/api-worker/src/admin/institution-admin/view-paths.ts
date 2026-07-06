export interface InstitutionAdminViewPaths {
  tenantAdminPath: string;
  operationsPath: string;
  operationsManualIssuePath: string;
  operationsLearnerRecordsPath: string;
  operationsLearnerRecordImportsPath: string;
  reportingPath: string;
  reportingExplorePath: string;
  reportingTrendsPath: string;
  reportingReportsPath: string;
  rulesWorkspacePath: string;
  rulesApprovalsPath: string;
  rulesTemplatesPath: string;
  accessPath: string;
  accessMembersPath: string;
  accessOrgUnitAccessPath: string;
  accessGovernancePath: string;
  accessDelegationsPath: string;
  accessAuthenticationPath: string;
  accessApiKeysPath: string;
  accessOrgUnitsPath: string;
  accessLmsConnectionsPath: string;
  ruleBuilderPath: string;
  badgeRuleApiPath: string;
  assertionsApiPathPrefix: string;
  showcasePath: string;
}

export const buildInstitutionAdminViewPaths = (tenantId: string): InstitutionAdminViewPaths => {
  const encodedTenantId = encodeURIComponent(tenantId);
  const tenantAdminPath = `/tenants/${encodedTenantId}/admin`;
  const operationsPath = `${tenantAdminPath}/operations`;
  const reportingPath = `${tenantAdminPath}/reporting`;
  const rulesWorkspacePath = `${tenantAdminPath}/rules`;
  const accessPath = `${tenantAdminPath}/access`;

  return {
    tenantAdminPath,
    operationsPath,
    operationsManualIssuePath: `${operationsPath}/issue`,
    operationsLearnerRecordsPath: `${operationsPath}/learner-records`,
    operationsLearnerRecordImportsPath: `${operationsPath}/learner-record-imports`,
    reportingPath,
    reportingExplorePath: `${reportingPath}/explore`,
    reportingTrendsPath: `${reportingPath}/trends`,
    reportingReportsPath: `${reportingPath}/reports`,
    rulesWorkspacePath,
    rulesApprovalsPath: `${rulesWorkspacePath}/approvals`,
    rulesTemplatesPath: `${rulesWorkspacePath}/templates`,
    accessPath,
    accessMembersPath: `${accessPath}/members`,
    accessOrgUnitAccessPath: `${accessPath}/org-unit-access`,
    accessGovernancePath: `${accessPath}/governance`,
    accessDelegationsPath: `${accessPath}/delegations`,
    accessAuthenticationPath: `${accessPath}/authentication`,
    accessApiKeysPath: `${accessPath}/api-keys`,
    accessOrgUnitsPath: `${accessPath}/org-units`,
    accessLmsConnectionsPath: `${accessPath}/lms-connections`,
    ruleBuilderPath: `${tenantAdminPath}/rules/new`,
    badgeRuleApiPath: `/v1/tenants/${encodedTenantId}/badge-rules`,
    assertionsApiPathPrefix: `/v1/tenants/${encodedTenantId}/assertions`,
    showcasePath: `/showcase/${encodedTenantId}`,
  };
};
