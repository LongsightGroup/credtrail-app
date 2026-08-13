import type { AdminSidebarSection } from "./sidebar";

export type InstitutionAdminSidebarView =
  | "home"
  | "operationsLearnerRecords"
  | "operationsLearnerRecordImports"
  | "operationsPathways"
  | "operationsReviewQueue"
  | "operationsIssuedBadges"
  | "operationsBadgeStatus"
  | "reporting"
  | "reportingExplore"
  | "reportingTrends"
  | "reportingReports"
  | "rules"
  | "rulesApprovals"
  | "rulesTemplates"
  | "rulesBuilder"
  | "accessMembers"
  | "accessOrgUnitAccess"
  | "accessGovernance"
  | "accessDelegations"
  | "accessDelegationsNew"
  | "accessAuthentication"
  | "accessApiKeys"
  | "accessLmsConnections"
  | "accessLmsConnectionNew"
  | "accessLmsConnectionEdit"
  | "accessOrgUnits"
  | "operationsManualIssue";

export interface InstitutionAdminSidebarPaths {
  tenantAdminPath: string;
  operationsPath: string;
  operationsLearnerRecordsPath: string;
  operationsLearnerRecordImportsPath: string;
  operationsPathwaysPath: string;
  operationsReviewQueuePath: string;
  operationsIssuedBadgesPath: string;
  operationsBadgeStatusPath: string;
  reportingPath: string;
  reportingExplorePath: string;
  reportingTrendsPath: string;
  reportingReportsPath: string;
  rulesWorkspacePath: string;
  rulesApprovalsPath: string;
  rulesTemplatesPath: string;
  ruleBuilderPath: string;
  accessPath: string;
  accessMembersPath: string;
  accessOrgUnitAccessPath: string;
  accessGovernancePath: string;
  accessDelegationsPath: string;
  accessAuthenticationPath: string;
  accessApiKeysPath: string;
  accessLmsConnectionsPath: string;
  accessOrgUnitsPath: string;
  operationsManualIssuePath: string;
}

export const buildInstitutionAdminSidebarPaths = (
  tenantId: string,
): InstitutionAdminSidebarPaths => {
  const tenantAdminPath = `/tenants/${encodeURIComponent(tenantId)}/admin`;
  const operationsPath = `${tenantAdminPath}/operations`;
  const reportingPath = `${tenantAdminPath}/reporting`;
  const rulesWorkspacePath = `${tenantAdminPath}/rules`;
  const accessPath = `${tenantAdminPath}/access`;

  return {
    tenantAdminPath,
    operationsPath,
    operationsLearnerRecordsPath: `${operationsPath}/learner-records`,
    operationsLearnerRecordImportsPath: `${operationsPath}/learner-record-imports`,
    operationsPathwaysPath: `${operationsPath}/pathways`,
    operationsReviewQueuePath: `${operationsPath}/review-queue`,
    operationsIssuedBadgesPath: `${operationsPath}/issued-badges`,
    operationsBadgeStatusPath: `${operationsPath}/badge-status`,
    reportingPath,
    reportingExplorePath: `${reportingPath}/explore`,
    reportingTrendsPath: `${reportingPath}/trends`,
    reportingReportsPath: `${reportingPath}/reports`,
    rulesWorkspacePath,
    rulesApprovalsPath: `${rulesWorkspacePath}/approvals`,
    rulesTemplatesPath: `${rulesWorkspacePath}/templates`,
    ruleBuilderPath: `${tenantAdminPath}/rules/new`,
    accessPath,
    accessMembersPath: `${accessPath}/members`,
    accessOrgUnitAccessPath: `${accessPath}/org-unit-access`,
    accessGovernancePath: `${accessPath}/governance`,
    accessDelegationsPath: `${accessPath}/delegations`,
    accessAuthenticationPath: `${accessPath}/authentication`,
    accessApiKeysPath: `${accessPath}/api-keys`,
    accessLmsConnectionsPath: `${accessPath}/lms-connections`,
    accessOrgUnitsPath: `${accessPath}/org-units`,
    operationsManualIssuePath: `${operationsPath}/issue`,
  };
};

export const buildInstitutionAdminSidebarSections = (
  paths: InstitutionAdminSidebarPaths,
  view: InstitutionAdminSidebarView,
  options?: { showEnterpriseAuthentication?: boolean },
): readonly AdminSidebarSection[] => {
  const showEnterpriseAuthentication = options?.showEnterpriseAuthentication ?? false;
  const peopleAndAccessLinks = [
    { href: paths.accessMembersPath, label: "Members", isCurrent: view === "accessMembers" },
    {
      href: paths.accessOrgUnitAccessPath,
      label: "Org-unit Access",
      isCurrent: view === "accessOrgUnitAccess",
    },
    {
      href: paths.accessGovernancePath,
      label: "Rule Approval",
      isCurrent: view === "accessGovernance",
    },
    {
      href: paths.accessDelegationsPath,
      label: "Delegated Authority",
      isCurrent: view === "accessDelegations" || view === "accessDelegationsNew",
    },
    ...(showEnterpriseAuthentication
      ? [
          {
            href: paths.accessAuthenticationPath,
            label: "Authentication",
            isCurrent: view === "accessAuthentication",
          },
        ]
      : []),
    {
      href: paths.accessLmsConnectionsPath,
      label: "LMS Connections",
      isCurrent:
        view === "accessLmsConnections" ||
        view === "accessLmsConnectionNew" ||
        view === "accessLmsConnectionEdit",
    },
    { href: paths.accessApiKeysPath, label: "API Keys", isCurrent: view === "accessApiKeys" },
    {
      href: paths.accessOrgUnitsPath,
      label: "Org Units",
      isCurrent: view === "accessOrgUnits",
    },
  ];

  return [
    {
      kind: "links",
      links: [
        {
          href: paths.tenantAdminPath,
          label: "Home",
          icon: "home",
          isCurrent: view === "home",
        },
      ],
    },
    {
      kind: "groups",
      groups: [
        {
          label: "Issuance",
          icon: "issuance",
          links: [
            {
              href: paths.operationsManualIssuePath,
              label: "Issue Badge",
              isCurrent: view === "operationsManualIssue",
            },
            {
              href: paths.operationsReviewQueuePath,
              label: "Review Queue",
              isCurrent: view === "operationsReviewQueue",
            },
            {
              href: paths.operationsIssuedBadgesPath,
              label: "Badge Records",
              isCurrent: view === "operationsIssuedBadges",
            },
            {
              href: paths.operationsBadgeStatusPath,
              label: "Badge Status",
              isCurrent: view === "operationsBadgeStatus",
            },
          ],
        },
        {
          label: "Learner Records",
          icon: "learnerRecords",
          links: [
            {
              href: paths.operationsLearnerRecordsPath,
              label: "Records",
              isCurrent: view === "operationsLearnerRecords",
            },
            {
              href: paths.operationsLearnerRecordImportsPath,
              label: "Imports",
              isCurrent: view === "operationsLearnerRecordImports",
            },
            {
              href: paths.operationsPathwaysPath,
              label: "Pathways",
              isCurrent: view === "operationsPathways",
            },
          ],
        },
      ],
    },
    {
      kind: "groups",
      groups: [
        {
          label: "Badge Program",
          icon: "badgeProgram",
          defaultOpen: view === "rulesBuilder" || view === "rulesApprovals",
          links: [
            {
              href: paths.rulesTemplatesPath,
              label: "Templates",
              isCurrent: view === "rulesTemplates",
            },
            { href: paths.rulesWorkspacePath, label: "Rules", isCurrent: view === "rules" },
            {
              href: paths.rulesApprovalsPath,
              label: "Approvals",
              isCurrent: view === "rulesApprovals",
            },
          ],
        },
      ],
    },
    {
      kind: "groups",
      groups: [
        {
          label: "Reporting",
          icon: "reporting",
          links: [
            { href: paths.reportingPath, label: "Overview", isCurrent: view === "reporting" },
            {
              href: paths.reportingExplorePath,
              label: "Explore",
              isCurrent: view === "reportingExplore",
            },
            {
              href: paths.reportingTrendsPath,
              label: "Trends",
              isCurrent: view === "reportingTrends",
            },
            {
              href: paths.reportingReportsPath,
              label: "Reports",
              isCurrent: view === "reportingReports",
            },
          ],
        },
      ],
    },
    {
      kind: "groups",
      groups: [
        {
          label: "People & Access",
          icon: "peopleAccess",
          links: peopleAndAccessLinks,
        },
      ],
    },
  ];
};

export const buildInstitutionAdminSidebarSectionsForTenant = (
  tenantId: string,
  view: InstitutionAdminSidebarView,
  planTier?: string,
): readonly AdminSidebarSection[] => {
  return buildInstitutionAdminSidebarSections(buildInstitutionAdminSidebarPaths(tenantId), view, {
    showEnterpriseAuthentication: planTier === "enterprise",
  });
};
