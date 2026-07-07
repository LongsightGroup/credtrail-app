import { appPage, type AppPage } from "../../ui/render-page";
import type { PageAssetKey } from "../../ui/page-assets";
import { AdminShell, AdminSidebar, AdminTopbar, type AdminSidebarFooterLink } from "../components";
import { buildInstitutionAdminSidebarSectionsForTenant } from "../institution-admin-sidebar";
import type { InstitutionAdminPageInput, InstitutionAdminView } from "./page-types";
import {
  INSTITUTION_ADMIN_VIEW_REGISTRY,
  type InstitutionAdminViewDefinition,
} from "./view-content";
import { buildInstitutionAdminViewPaths } from "./view-paths";
import { buildInstitutionAdminViewResources } from "./view-resources";
export {
  institutionAdminRuleTemplateEditorPage,
  institutionAdminRuleTemplatesPage,
} from "../institution-admin-templates-page";

const renderInstitutionAdminPage = (
  input: InstitutionAdminPageInput,
  view: InstitutionAdminView,
): AppPage => {
  const paths = buildInstitutionAdminViewPaths(input.tenant.id);
  const { tenantAdminPath, showcasePath } = paths;
  const viewDefinition: InstitutionAdminViewDefinition = INSTITUTION_ADMIN_VIEW_REGISTRY[view];
  const userLabel = input.userEmail ?? input.userId;
  const switchOrganizationPath = input.switchOrganizationPath?.trim() ?? "";
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

  const viewResources = buildInstitutionAdminViewResources({
    input,
    paths,
    view,
    viewDefinition,
  });
  const { adminPageContextJson, viewContent } = viewResources;

  const pageTitle = `${viewDefinition.titlePrefix} · ${input.tenant.displayName}`;

  const pageAssets: PageAssetKey[] = [
    "institutionAdminCss",
    viewDefinition.controller === "shared" ? "institutionAdminJs" : "institutionAdminShellJs",
    ...(viewDefinition.extraAssets ?? []),
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

export const institutionAdminOrgUnitAccessPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessOrgUnitAccess");
};

export const institutionAdminGovernancePage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessGovernance");
};

export const institutionAdminDelegationsPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessDelegations");
};

export const institutionAdminDelegationsNewPage = (input: InstitutionAdminPageInput): AppPage => {
  return renderInstitutionAdminPage(input, "accessDelegationsNew");
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
