import type { TenantMembershipRole, TenantRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";
import type { PageAssetKey } from "../ui/page-assets";
import {
  AdminPageHeader,
  AdminShell,
  AdminSidebar,
  AdminTopbar,
  type AdminSidebarFooterLink,
  type AdminSidebarSection,
} from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type InstitutionAdminShellView =
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
  | "access"
  | "accessMembers"
  | "accessGovernance"
  | "accessApiKeys"
  | "accessOrgUnits";

export interface InstitutionAdminShellPaths {
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
  accessOrgUnitsPath: string;
  adminAuditLogPath: string;
  showcasePath: string;
}

export const serializeJsonScriptContent = (value: unknown): string => {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
};

export const buildInstitutionAdminShellPaths = (tenantId: string): InstitutionAdminShellPaths => {
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
    accessOrgUnitsPath: `${accessPath}/org-units`,
    adminAuditLogPath: `/admin/audit-logs?tenantId=${encodeURIComponent(tenantId)}`,
    showcasePath: `/showcase/${encodeURIComponent(tenantId)}`,
  };
};

const buildSidebarSections = (
  paths: InstitutionAdminShellPaths,
  view: InstitutionAdminShellView,
): readonly AdminSidebarSection[] => [
  {
    links: [{ href: paths.tenantAdminPath, label: "Home", isCurrent: view === "home" }],
  },
  {
    label: "Operations",
    icon: "operations",
    links: [
      { href: paths.operationsPath, label: "Issue & Inspect", isCurrent: view === "operations" },
      {
        href: paths.operationsLearnerRecordsPath,
        label: "Learner Records",
        isCurrent: view === "operationsLearnerRecords",
        isSub: true,
      },
      {
        href: paths.operationsLearnerRecordImportsPath,
        label: "Learner Record Imports",
        isCurrent: view === "operationsLearnerRecordImports",
        isSub: true,
      },
      {
        href: paths.operationsReviewQueuePath,
        label: "Review Queue",
        isCurrent: view === "operationsReviewQueue",
        isSub: true,
      },
      {
        href: paths.operationsIssuedBadgesPath,
        label: "Issued Badges",
        isCurrent: view === "operationsIssuedBadges",
        isSub: true,
      },
      {
        href: paths.operationsBadgeStatusPath,
        label: "Badge Status",
        isCurrent: view === "operationsBadgeStatus",
        isSub: true,
      },
    ],
  },
  {
    label: "Analytics",
    icon: "analytics",
    links: [
      { href: paths.reportingPath, label: "Reporting", isCurrent: view === "reporting" },
      {
        href: paths.reportingExplorePath,
        label: "Explore",
        isCurrent: view === "reportingExplore",
        isSub: true,
      },
      {
        href: paths.reportingTrendsPath,
        label: "Trends",
        isCurrent: view === "reportingTrends",
        isSub: true,
      },
      {
        href: paths.reportingReportsPath,
        label: "Reports",
        isCurrent: view === "reportingReports",
        isSub: true,
      },
    ],
  },
  {
    label: "Management",
    icon: "management",
    links: [
      { href: paths.rulesWorkspacePath, label: "Rules", isCurrent: view === "rules" },
      {
        href: paths.rulesTemplatesPath,
        label: "Badge Templates",
        isCurrent: view === "rulesTemplates",
        isSub: true,
      },
      { href: paths.ruleBuilderPath, label: "Rule Builder", isSub: true },
    ],
  },
  {
    label: "Configuration",
    icon: "configuration",
    links: [
      { href: paths.accessPath, label: "Access", isCurrent: view === "access" },
      {
        href: paths.accessMembersPath,
        label: "Members",
        isCurrent: view === "accessMembers",
        isSub: true,
      },
      {
        href: paths.accessGovernancePath,
        label: "Governance",
        isCurrent: view === "accessGovernance",
        isSub: true,
      },
      {
        href: paths.accessApiKeysPath,
        label: "API Keys",
        isCurrent: view === "accessApiKeys",
        isSub: true,
      },
      {
        href: paths.accessOrgUnitsPath,
        label: "Org Units",
        isCurrent: view === "accessOrgUnits",
        isSub: true,
      },
    ],
  },
];

const buildSidebarFooterLinks = (input: {
  paths: InstitutionAdminShellPaths;
  switchOrganizationPath?: string | null;
}): readonly AdminSidebarFooterLink[] => {
  const switchOrganizationPath = input.switchOrganizationPath?.trim() ?? "";

  return [
    { href: input.paths.adminAuditLogPath, label: "Audit logs", isExternal: true },
    {
      href: input.paths.showcasePath,
      label: "Public showcase",
      isExternal: true,
      target: "_blank",
      rel: "noopener noreferrer",
    },
    ...(switchOrganizationPath.length > 0
      ? [{ href: switchOrganizationPath, label: "Switch organization" }]
      : []),
  ];
};

export const renderInstitutionAdminPageHeader = (
  title: string,
  description: string,
  noteMarkup: HonoElement | null = null,
): HonoElement => {
  return <AdminPageHeader title={title} description={description} note={noteMarkup} />;
};

export const renderInstitutionAdminShellPage = (input: {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string | undefined;
  membershipRole: TenantMembershipRole;
  view: InstitutionAdminShellView;
  title: string;
  assets: PageAssetKey[];
  contextJson: unknown;
  switchOrganizationPath?: string | null;
  children: HonoElement;
}): AppPage => {
  const paths = buildInstitutionAdminShellPaths(input.tenant.id);
  const userLabel = input.userEmail ?? input.userId;

  return appPage({
    title: input.title,
    assets: input.assets,
    variant: "admin",
    body: (
      <AdminShell
        sidebar={
          <AdminSidebar
            brandHref={paths.tenantAdminPath}
            sections={buildSidebarSections(paths, input.view)}
            footerLinks={buildSidebarFooterLinks({
              paths,
              ...(input.switchOrganizationPath === undefined
                ? {}
                : { switchOrganizationPath: input.switchOrganizationPath }),
            })}
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
        {input.children}
        <div
          id="ct-admin-context"
          hidden
          data-context-json={serializeJsonScriptContent(input.contextJson)}
        ></div>
      </AdminShell>
    ),
  });
};
