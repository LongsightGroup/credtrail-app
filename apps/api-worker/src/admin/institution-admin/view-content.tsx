import type { Child } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import { AdminPageHeader, AdminPanel, AdminStatus } from "../components";
import { renderDelegationSetupSection } from "./delegation-setup-section";
import { renderEnterpriseAuthSection } from "./enterprise-auth-section";
import {
  emptyLmsConnectionFormValues,
  renderLmsConnectionSetupSection,
} from "./lms-connection-setup-section";
import { renderManualIssueSection } from "./manual-issue-section";
import type { InstitutionAdminPageInput, InstitutionAdminView } from "./page-types";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;
type RenderedNode = Child;

export interface InstitutionAdminViewContentInput {
  input: InstitutionAdminPageInput;
  view: InstitutionAdminView;
  home: {
    workspaceCardsMarkup: RenderedNode;
  };
  controls: {
    activeOrgUnitSelectOptions: HonoElement;
    optionalBadgeTemplateScopeOptions: HonoElement;
    templateSelectOptions: HonoElement;
    tenantMemberSelectOptions: HonoElement;
  };
  learnerRecords: {
    learnerRecordImportFeedbackMarkup: RenderedNode;
    learnerRecordImportPanelMarkup: RenderedNode;
    learnerRecordImportProgressMarkup: RenderedNode;
    learnerRecordImportSubmissionMarkup: RenderedNode;
    learnerRecordReviewPanelMarkup: RenderedNode;
    renderLearnerRecordReviewSections: () => RenderedNode;
  };
  operations: {
    badgeStatusPanelMarkup: RenderedNode;
    issuedBadgesPanelMarkup: RenderedNode;
    ruleReviewQueuePanelMarkup: RenderedNode;
  };
  reporting: {
    renderReportingTrendPanelMarkup: (input: { includeDetailedTable: boolean }) => RenderedNode;
    reportingDeepLinksMarkup: RenderedNode;
    reportingDeferredPanelMarkup: RenderedNode;
    reportingDefinitionsPanelMarkup: RenderedNode;
    reportingEngagementPanelMarkup: RenderedNode;
    reportingExecutiveSummaryMarkup: RenderedNode;
    reportingExportFiltersPanelMarkup: RenderedNode;
    reportingExploreSliceSummaryMarkup: RenderedNode;
    reportingExportsPanelMarkup: RenderedNode;
    reportingFocusAreaPanelMarkup: RenderedNode;
    reportingLowerStoryMarkup: RenderedNode;
    reportingOverviewPanelMarkup: RenderedNode;
    reportingRankedChartsMarkup: RenderedNode;
    reportingReportsLibraryMarkup: RenderedNode;
    reportingTrendFiltersPanelMarkup: RenderedNode;
  };
  rules: {
    badgeRulesTableMarkup: RenderedNode;
    ruleAdvancedToolsMarkup: RenderedNode;
  };
  access: {
    apiKeyPanelMarkup: RenderedNode;
    apiKeysTableMarkup: RenderedNode;
    delegatedGrantTableMarkup: RenderedNode;
    governanceActionsMarkup: RenderedNode;
    governanceGuidePanelMarkup: RenderedNode;
    lmsConnectionsActionsMarkup: RenderedNode;
    lmsConnectionsTableMarkup: RenderedNode;
    membershipScopePanelMarkup: RenderedNode;
    membershipScopeTableMarkup: RenderedNode;
    orgUnitPanelMarkup: RenderedNode;
    orgUnitsTableMarkup: RenderedNode;
    tenantMembersPanelMarkup: RenderedNode;
    tenantMembersTableMarkup: RenderedNode;
  };
}

const renderPageHeader = (
  title: string,
  description: string,
  noteMarkup: HonoElement | null = null,
): HonoElement => {
  return <AdminPageHeader title={title} description={description} note={noteMarkup} />;
};

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

export interface InstitutionAdminViewDefinition {
  controller: "shared" | "shell";
  dataNeeds: InstitutionAdminViewDataNeeds;
  extraAssets?: readonly import("../../ui/page-assets").PageAssetKey[];
  render: (content: InstitutionAdminViewContentInput) => RenderedNode;
  titlePrefix: string;
}

const DEFAULT_VIEW_DATA_NEEDS = {
  accessSectionBundles: false,
  operationsSectionBundles: false,
  reportingSectionBundles: false,
  managementSectionBundles: false,
  learnerRecordSectionBundles: false,
  ruleTableRows: false,
  lmsConnectionRows: false,
  apiKeyRows: false,
  orgUnitRows: false,
  governanceTableRows: false,
  tenantMemberRows: false,
  templateSelectOptions: false,
  delegationSelectOptions: false,
  ruleSelectOptions: false,
  ruleVersionIndexes: false,
  orgUnitParentOptions: false,
  issuedBadgeFilters: false,
} as const;

const viewDataNeeds = (
  overrides: Partial<InstitutionAdminViewDataNeeds>,
): InstitutionAdminViewDataNeeds => {
  return {
    ...DEFAULT_VIEW_DATA_NEEDS,
    ...overrides,
  };
};

export const INSTITUTION_ADMIN_VIEW_REGISTRY = {
  home: {
    titlePrefix: "Institution Admin",
    controller: "shell",
    dataNeeds: viewDataNeeds({}),
    render: (content) => {
      return (
        <>
          {renderPageHeader("Institution Admin", "Choose a workspace.")}
          <section class="ct-admin ct-stack">{content.home.workspaceCardsMarkup}</section>
        </>
      );
    },
  },
  operationsManualIssue: {
    titlePrefix: "Issue Badge · Institution Admin",
    controller: "shell",
    dataNeeds: viewDataNeeds({
      templateSelectOptions: true,
    }),
    render: (content) => {
      const { input } = content;
      return (
        <>
          {renderPageHeader(
            "Issue Badge",
            "Issue a badge for one learner by choosing the template and recipient email.",
          )}
          <section class="ct-admin ct-stack">
            {renderManualIssueSection({
              tenantId: input.tenant.id,
              templateSelectOptions: content.controls.templateSelectOptions,
              listError: input.manualIssueWorkspace?.listError ?? null,
              listNotice: input.manualIssueWorkspace?.listNotice ?? null,
              successLinks: input.manualIssueWorkspace?.successLinks ?? null,
            })}
          </section>
        </>
      );
    },
  },
  operationsLearnerRecords: {
    titlePrefix: "Learner Records · Institution Admin",
    controller: "shell",
    dataNeeds: viewDataNeeds({
      operationsSectionBundles: true,
      learnerRecordSectionBundles: true,
      templateSelectOptions: true,
      ruleSelectOptions: true,
      ruleVersionIndexes: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader(
            "Learner Records",
            "Look up one learner by profile ID or email to review badges and record entries.",
          )}
          <section class="ct-admin ct-stack">
            {content.learnerRecords.learnerRecordReviewPanelMarkup}
            {content.learnerRecords.renderLearnerRecordReviewSections()}
          </section>
        </>
      );
    },
  },
  operationsLearnerRecordImports: {
    titlePrefix: "Learner Record Imports · Institution Admin",
    controller: "shell",
    dataNeeds: viewDataNeeds({
      operationsSectionBundles: true,
      learnerRecordSectionBundles: true,
      templateSelectOptions: true,
      ruleSelectOptions: true,
      ruleVersionIndexes: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader(
            "Learner Record Imports",
            "Import learner-record CSVs with one trust default, honest smart defaults, and queue-backed progress.",
          )}
          <section class="ct-admin ct-stack">
            {content.learnerRecords.learnerRecordImportPanelMarkup}
            {content.learnerRecords.learnerRecordImportFeedbackMarkup}
            {content.learnerRecords.learnerRecordImportSubmissionMarkup}
            {content.learnerRecords.learnerRecordImportProgressMarkup}
          </section>
        </>
      );
    },
  },
  operationsReviewQueue: {
    titlePrefix: "Rule Review Queue · Institution Admin",
    controller: "shell",
    dataNeeds: viewDataNeeds({
      operationsSectionBundles: true,
      templateSelectOptions: true,
      ruleSelectOptions: true,
      ruleVersionIndexes: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader(
            "Rule Review Queue",
            "Review pending badge decisions without mixing them into the rest of operations.",
          )}
          <section class="ct-admin ct-stack">
            {content.operations.ruleReviewQueuePanelMarkup}
          </section>
        </>
      );
    },
  },
  operationsIssuedBadges: {
    titlePrefix: "Badge Records · Institution Admin",
    controller: "shell",
    extraAssets: ["institutionAdminIssuedBadgesJs"],
    dataNeeds: viewDataNeeds({
      operationsSectionBundles: true,
      templateSelectOptions: true,
      ruleSelectOptions: true,
      ruleVersionIndexes: true,
      issuedBadgeFilters: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader(
            "Badge Records",
            "Search issued badge records and take audit or revocation actions from one page.",
          )}
          <section class="ct-admin ct-stack">{content.operations.issuedBadgesPanelMarkup}</section>
        </>
      );
    },
  },
  operationsBadgeStatus: {
    titlePrefix: "Badge Status · Institution Admin",
    controller: "shared",
    dataNeeds: viewDataNeeds({
      operationsSectionBundles: true,
      templateSelectOptions: true,
      ruleSelectOptions: true,
      ruleVersionIndexes: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader(
            "Badge Status",
            "Look up a badge, inspect its current state, and apply status changes with a reason.",
          )}
          <section class="ct-admin ct-stack">{content.operations.badgeStatusPanelMarkup}</section>
        </>
      );
    },
  },
  reporting: {
    titlePrefix: "Reporting · Institution Admin",
    controller: "shared",
    dataNeeds: viewDataNeeds({
      reportingSectionBundles: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader(
            "Reporting",
            "Start with the current view, then open detail only when you need it.",
          )}
          <section class="ct-admin ct-stack">
            <section class="ct-admin__reporting-presentation-shell ct-admin__reporting-presentation-shell--highlights ct-stack">
              <section class="ct-admin__reporting-primary-story ct-stack">
                <section class="ct-admin__reporting-first-screen ct-stack">
                  {content.reporting.reportingExecutiveSummaryMarkup}
                </section>
                {content.reporting.reportingFocusAreaPanelMarkup}
                {content.reporting.reportingRankedChartsMarkup}
                {content.reporting.reportingDeepLinksMarkup}
              </section>
            </section>
          </section>
        </>
      );
    },
  },
  reportingExplore: {
    titlePrefix: "Reporting Explore · Institution Admin",
    controller: "shared",
    dataNeeds: viewDataNeeds({
      reportingSectionBundles: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader(
            "Reporting Explore",
            "Filter the report, scan concise previews, and open exact detail only when needed.",
          )}
          <section class="ct-admin ct-stack">
            {content.reporting.reportingExploreSliceSummaryMarkup}
            <section class="ct-admin__reporting-explore-workspace ct-stack">
              {content.reporting.reportingOverviewPanelMarkup}
              {content.reporting.renderReportingTrendPanelMarkup({ includeDetailedTable: false })}
              {content.reporting.reportingEngagementPanelMarkup}
              {content.reporting.reportingLowerStoryMarkup}
              {content.reporting.reportingDefinitionsPanelMarkup}
              {content.reporting.reportingDeferredPanelMarkup}
            </section>
          </section>
        </>
      );
    },
  },
  reportingTrends: {
    titlePrefix: "Trend Detail · Reporting · Institution Admin",
    controller: "shared",
    dataNeeds: viewDataNeeds({
      reportingSectionBundles: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader(
            "Trend Detail",
            "Use the focused trend page for exact daily counts behind the overview chart.",
          )}
          <section class="ct-admin ct-stack">
            {content.reporting.reportingTrendFiltersPanelMarkup}
            {content.reporting.renderReportingTrendPanelMarkup({ includeDetailedTable: true })}
          </section>
        </>
      );
    },
  },
  reportingReports: {
    titlePrefix: "Report Library · Reporting · Institution Admin",
    controller: "shared",
    dataNeeds: viewDataNeeds({
      reportingSectionBundles: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader(
            "Report Library",
            "Use one focused page for saved report shortcuts, custom report setup, and CSV exports.",
          )}
          <section class="ct-admin ct-stack">
            {content.reporting.reportingReportsLibraryMarkup}
            {content.reporting.reportingExportFiltersPanelMarkup}
            {content.reporting.reportingExportsPanelMarkup}
          </section>
        </>
      );
    },
  },
  rules: {
    titlePrefix: "Rules · Institution Admin",
    controller: "shared",
    dataNeeds: viewDataNeeds({
      operationsSectionBundles: true,
      managementSectionBundles: true,
      ruleTableRows: true,
      templateSelectOptions: true,
      ruleSelectOptions: true,
      ruleVersionIndexes: true,
    }),
    render: (content) => {
      const { input } = content;
      return (
        <>
          {renderPageHeader(
            "Rules",
            "Review awarding rules, create new rules, and test a rule before issuing when needed.",
          )}
          <section class="ct-admin ct-stack">
            {input.rulesWorkspace?.listError !== null &&
            input.rulesWorkspace?.listError !== undefined &&
            input.rulesWorkspace.listError.length > 0 ? (
              <AdminStatus tone="error">{input.rulesWorkspace.listError}</AdminStatus>
            ) : input.rulesWorkspace?.listNotice !== null &&
              input.rulesWorkspace?.listNotice !== undefined &&
              input.rulesWorkspace.listNotice.length > 0 ? (
              <AdminStatus tone="success">{input.rulesWorkspace.listNotice}</AdminStatus>
            ) : null}
            {content.rules.badgeRulesTableMarkup}
            {content.rules.ruleAdvancedToolsMarkup}
          </section>
        </>
      );
    },
  },
  accessMembers: {
    titlePrefix: "Members · Institution Admin",
    controller: "shared",
    dataNeeds: viewDataNeeds({
      accessSectionBundles: true,
      tenantMemberRows: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader(
            "Members",
            "Add colleagues, assign tenant roles, resend invites, and remove tenant access.",
            <aside class="ct-admin-page-header__note">
              <h2>Tenant-level access</h2>
              <p>
                Use owner/admin roles for administration. Use issuer/viewer roles when someone does
                not need full tenant control.
              </p>
            </aside>,
          )}
          <section class="ct-admin ct-stack">
            {content.access.tenantMembersPanelMarkup}
            {content.access.tenantMembersTableMarkup}
          </section>
        </>
      );
    },
  },
  accessGovernance: {
    titlePrefix: "Governance Delegation · Institution Admin",
    controller: "shared",
    dataNeeds: viewDataNeeds({
      accessSectionBundles: true,
      governanceTableRows: true,
      delegationSelectOptions: true,
    }),
    render: (content) => {
      const { input } = content;
      return (
        <>
          {renderPageHeader(
            "Governance Delegation",
            "Grant org-unit access and time-boxed badge authority with direct removal from the current assignments list.",
            <aside class="ct-admin-page-header__note">
              <h2>Choose the smallest access</h2>
              <p>
                Use scoped roles for standing access. Use delegated authority when someone only
                needs temporary badge operations.
              </p>
            </aside>,
          )}
          <section class="ct-admin ct-stack">
            {input.accessGovernanceWorkspace?.listError !== null &&
            input.accessGovernanceWorkspace?.listError !== undefined &&
            input.accessGovernanceWorkspace.listError.length > 0 ? (
              <AdminStatus data-tone="error">
                {input.accessGovernanceWorkspace.listError}
              </AdminStatus>
            ) : input.accessGovernanceWorkspace?.listNotice !== null &&
              input.accessGovernanceWorkspace?.listNotice !== undefined &&
              input.accessGovernanceWorkspace.listNotice.length > 0 ? (
              <AdminStatus data-tone="success">
                {input.accessGovernanceWorkspace.listNotice}
              </AdminStatus>
            ) : null}
            {content.access.governanceGuidePanelMarkup}
            {content.access.governanceActionsMarkup}
            {content.access.membershipScopeTableMarkup}
            {content.access.membershipScopePanelMarkup}
            {content.access.delegatedGrantTableMarkup}
          </section>
        </>
      );
    },
  },
  accessGovernanceDelegationNew: {
    titlePrefix: "Add Delegated Authority · Institution Admin",
    controller: "shell",
    dataNeeds: viewDataNeeds({
      delegationSelectOptions: true,
    }),
    render: (content) => {
      const { input } = content;
      return (
        <>
          {renderPageHeader(
            "Add Delegated Authority",
            "Grant temporary badge authority without changing standing org-unit access.",
          )}
          <section class="ct-admin ct-stack">
            {renderDelegationSetupSection({
              tenantId: input.tenant.id,
              tenantMemberSelectOptions: content.controls.tenantMemberSelectOptions,
              activeOrgUnitSelectOptions: content.controls.activeOrgUnitSelectOptions,
              optionalBadgeTemplateScopeOptions: content.controls.optionalBadgeTemplateScopeOptions,
              listError: input.accessGovernanceDelegationWorkspace?.listError ?? null,
              listNotice: input.accessGovernanceDelegationWorkspace?.listNotice ?? null,
            })}
          </section>
        </>
      );
    },
  },
  accessAuthentication: {
    titlePrefix: "Authentication · Institution Admin",
    controller: "shell",
    extraAssets: ["institutionAdminAccessJs"],
    dataNeeds: viewDataNeeds({}),
    render: (content) => {
      const { input } = content;
      return (
        <>
          {renderPageHeader(
            "Authentication",
            input.tenant.planTier === "enterprise"
              ? "Configure institution sign-in, OIDC providers, and break-glass local accounts."
              : "Enterprise authentication is available on the enterprise plan.",
          )}
          <section class="ct-admin ct-stack">
            {input.tenant.planTier === "enterprise" ? (
              <>
                {input.accessAuthenticationWorkspace?.listError !== null &&
                input.accessAuthenticationWorkspace?.listError !== undefined &&
                input.accessAuthenticationWorkspace.listError.length > 0 ? (
                  <AdminStatus data-tone="error">
                    {input.accessAuthenticationWorkspace.listError}
                  </AdminStatus>
                ) : input.accessAuthenticationWorkspace?.listNotice !== null &&
                  input.accessAuthenticationWorkspace?.listNotice !== undefined &&
                  input.accessAuthenticationWorkspace.listNotice.length > 0 ? (
                  <AdminStatus data-tone="success">
                    {input.accessAuthenticationWorkspace.listNotice}
                  </AdminStatus>
                ) : null}
                {renderEnterpriseAuthSection({
                  tenant: input.tenant,
                  enterpriseAuthPolicy: input.enterpriseAuthPolicy,
                  enterpriseAuthProviders: input.enterpriseAuthProviders,
                  breakGlassAccounts: input.breakGlassAccounts,
                  editProviderId: input.accessAuthenticationWorkspace?.editProviderId ?? null,
                })}
              </>
            ) : (
              <AdminPanel>
                <p>
                  Upgrade to the enterprise plan to configure OIDC sign-in and break-glass access.
                </p>
              </AdminPanel>
            )}
          </section>
        </>
      );
    },
  },
  accessApiKeys: {
    titlePrefix: "API Keys · Institution Admin",
    controller: "shell",
    extraAssets: ["institutionAdminAccessJs"],
    dataNeeds: viewDataNeeds({
      accessSectionBundles: true,
      managementSectionBundles: true,
      apiKeyRows: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader("API Keys", "Create, review, and revoke tenant API keys.")}
          <section class="ct-admin ct-stack">
            {content.access.apiKeyPanelMarkup}
            {content.access.apiKeysTableMarkup}
          </section>
        </>
      );
    },
  },
  accessLmsConnections: {
    titlePrefix: "LMS Connections · Institution Admin",
    controller: "shell",
    dataNeeds: viewDataNeeds({
      accessSectionBundles: true,
      lmsConnectionRows: true,
    }),
    render: (content) => {
      const { input } = content;
      return (
        <>
          {renderPageHeader(
            "LMS Connections",
            "Manage connected Canvas and Sakai gradebook accounts used by badge awarding rules.",
          )}
          <section class="ct-admin ct-stack">
            {input.lmsConnectionsWorkspace?.listError !== null &&
            input.lmsConnectionsWorkspace?.listError !== undefined &&
            input.lmsConnectionsWorkspace.listError.length > 0 ? (
              <AdminStatus data-tone="error">{input.lmsConnectionsWorkspace.listError}</AdminStatus>
            ) : input.lmsConnectionsWorkspace?.listNotice !== null &&
              input.lmsConnectionsWorkspace?.listNotice !== undefined &&
              input.lmsConnectionsWorkspace.listNotice.length > 0 ? (
              <AdminStatus data-tone="success">
                {input.lmsConnectionsWorkspace.listNotice}
              </AdminStatus>
            ) : null}
            {content.access.lmsConnectionsActionsMarkup}
            {content.access.lmsConnectionsTableMarkup}
          </section>
        </>
      );
    },
  },
  accessLmsConnectionNew: {
    titlePrefix: "Connect LMS · Institution Admin",
    controller: "shell",
    dataNeeds: viewDataNeeds({}),
    render: (content) => {
      const { input } = content;
      return (
        <>
          {renderPageHeader(
            "Connect LMS",
            "Add a Canvas or Sakai gradebook connection for rule lookup.",
          )}
          <section class="ct-admin ct-stack">
            {renderLmsConnectionSetupSection({
              tenantId: input.tenant.id,
              formValues: input.lmsConnectionSetupFormValues ?? emptyLmsConnectionFormValues(),
              listError: input.lmsConnectionSetupWorkspace?.listError ?? null,
              listNotice: input.lmsConnectionSetupWorkspace?.listNotice ?? null,
            })}
          </section>
        </>
      );
    },
  },
  accessLmsConnectionEdit: {
    titlePrefix: "Edit LMS Connection · Institution Admin",
    controller: "shell",
    dataNeeds: viewDataNeeds({}),
    render: (content) => {
      const { input } = content;
      return (
        <>
          {renderPageHeader(
            "Edit LMS Connection",
            "Update connection details. Leave credential fields blank to keep saved secrets.",
          )}
          <section class="ct-admin ct-stack">
            {renderLmsConnectionSetupSection({
              tenantId: input.tenant.id,
              formValues: input.lmsConnectionSetupFormValues ?? emptyLmsConnectionFormValues(),
              listError: input.lmsConnectionSetupWorkspace?.listError ?? null,
              listNotice: input.lmsConnectionSetupWorkspace?.listNotice ?? null,
            })}
          </section>
        </>
      );
    },
  },
  accessOrgUnits: {
    titlePrefix: "Org Units · Institution Admin",
    controller: "shell",
    dataNeeds: viewDataNeeds({
      accessSectionBundles: true,
      managementSectionBundles: true,
      orgUnitRows: true,
      orgUnitParentOptions: true,
    }),
    render: (content) => {
      return (
        <>
          {renderPageHeader("Org Units", "Create and review org structure.")}
          <section class="ct-admin ct-stack">
            {content.access.orgUnitPanelMarkup}
            {content.access.orgUnitsTableMarkup}
          </section>
        </>
      );
    },
  },
} as const satisfies Record<InstitutionAdminView, InstitutionAdminViewDefinition>;

export const renderInstitutionAdminViewContent = (
  content: InstitutionAdminViewContentInput,
): RenderedNode => {
  return INSTITUTION_ADMIN_VIEW_REGISTRY[content.view].render(content);
};
