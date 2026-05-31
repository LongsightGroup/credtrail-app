import type { AdminSidebarSection } from "./sidebar";

export type InstitutionAdminSidebarView =
  | "home"
  | "operations"
  | "operationsLearnerRecords"
  | "operationsLearnerRecordImports"
  | "operationsReviewQueue"
  | "operationsIssuedBadges"
  | "operationsBadgeStatus"
  | "reporting"
  | "reportingExplore"
  | "reportingTrends"
  | "reportingReports"
  | "rules"
  | "rulesTemplates"
  | "rulesBuilder"
  | "access"
  | "accessMembers"
  | "accessGovernance"
  | "accessApiKeys"
  | "accessLmsConnections"
  | "accessOrgUnits";

export interface InstitutionAdminSidebarPaths {
  tenantAdminPath: string;
  operationsPath: string;
  operationsLearnerRecordsPath: string;
  operationsLearnerRecordImportsPath: string;
  operationsReviewQueuePath: string;
  operationsIssuedBadgesPath: string;
  operationsBadgeStatusPath: string;
  reportingPath: string;
  reportingExplorePath: string;
  reportingTrendsPath: string;
  reportingReportsPath: string;
  rulesWorkspacePath: string;
  rulesTemplatesPath: string;
  ruleBuilderPath: string;
  accessPath: string;
  accessMembersPath: string;
  accessGovernancePath: string;
  accessApiKeysPath: string;
  accessLmsConnectionsPath: string;
  accessOrgUnitsPath: string;
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
    operationsReviewQueuePath: `${operationsPath}/review-queue`,
    operationsIssuedBadgesPath: `${operationsPath}/issued-badges`,
    operationsBadgeStatusPath: `${operationsPath}/badge-status`,
    reportingPath,
    reportingExplorePath: `${reportingPath}/explore`,
    reportingTrendsPath: `${reportingPath}/trends`,
    reportingReportsPath: `${reportingPath}/reports`,
    rulesWorkspacePath,
    rulesTemplatesPath: `${rulesWorkspacePath}/templates`,
    ruleBuilderPath: `${tenantAdminPath}/rules/new`,
    accessPath,
    accessMembersPath: `${accessPath}/members`,
    accessGovernancePath: `${accessPath}/governance`,
    accessApiKeysPath: `${accessPath}/api-keys`,
    accessLmsConnectionsPath: `${accessPath}/lms-connections`,
    accessOrgUnitsPath: `${accessPath}/org-units`,
  };
};

export const buildInstitutionAdminSidebarSections = (
  paths: InstitutionAdminSidebarPaths,
  view: InstitutionAdminSidebarView,
): readonly AdminSidebarSection[] => [
  {
    kind: "links",
    links: [{ href: paths.tenantAdminPath, label: "Home", isCurrent: view === "home" }],
  },
  {
    kind: "groups",
    label: "Credential Operations",
    icon: "operations",
    groups: [
      {
        label: "Issuance",
        links: [
          {
            href: paths.operationsPath,
            label: "Issue & Inspect",
            isCurrent: view === "operations",
          },
          {
            href: paths.operationsReviewQueuePath,
            label: "Review Queue",
            isCurrent: view === "operationsReviewQueue",
          },
          {
            href: paths.operationsIssuedBadgesPath,
            label: "Issued Badges",
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
        ],
      },
    ],
  },
  {
    kind: "groups",
    label: "Credential Program",
    icon: "credential",
    groups: [
      {
        label: "Badge Templates",
        links: [
          {
            href: paths.rulesTemplatesPath,
            label: "Templates",
            isCurrent: view === "rulesTemplates",
          },
        ],
      },
      {
        label: "Rules",
        links: [
          { href: paths.rulesWorkspacePath, label: "Rules Workspace", isCurrent: view === "rules" },
          {
            href: paths.ruleBuilderPath,
            label: "Rule Builder",
            isCurrent: view === "rulesBuilder",
          },
        ],
      },
    ],
  },
  {
    kind: "flat",
    label: "Reporting",
    icon: "analytics",
    links: [
      { href: paths.reportingPath, label: "Overview", isCurrent: view === "reporting" },
      {
        href: paths.reportingExplorePath,
        label: "Explore",
        isCurrent: view === "reportingExplore",
      },
      { href: paths.reportingTrendsPath, label: "Trends", isCurrent: view === "reportingTrends" },
      {
        href: paths.reportingReportsPath,
        label: "Reports",
        isCurrent: view === "reportingReports",
      },
    ],
  },
  {
    kind: "groups",
    label: "Institution Setup",
    icon: "configuration",
    groups: [
      {
        label: "People & Access",
        links: [
          { href: paths.accessPath, label: "Access", isCurrent: view === "access" },
          { href: paths.accessMembersPath, label: "Members", isCurrent: view === "accessMembers" },
          {
            href: paths.accessGovernancePath,
            label: "Governance",
            isCurrent: view === "accessGovernance",
          },
          { href: paths.accessApiKeysPath, label: "API Keys", isCurrent: view === "accessApiKeys" },
        ],
      },
      {
        label: "Integrations",
        links: [
          {
            href: paths.accessLmsConnectionsPath,
            label: "LMS Connections",
            isCurrent: view === "accessLmsConnections",
          },
        ],
      },
      {
        label: "Organization",
        links: [
          {
            href: paths.accessOrgUnitsPath,
            label: "Org Units",
            isCurrent: view === "accessOrgUnits",
          },
        ],
      },
    ],
  },
];

export const buildInstitutionAdminSidebarSectionsForTenant = (
  tenantId: string,
  view: InstitutionAdminSidebarView,
): readonly AdminSidebarSection[] => {
  return buildInstitutionAdminSidebarSections(buildInstitutionAdminSidebarPaths(tenantId), view);
};
