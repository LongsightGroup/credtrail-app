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
  workspaceCardsMarkup: RenderedNode;
  templateSelectOptions: HonoElement;
  tenantMemberSelectOptions: HonoElement;
  activeOrgUnitSelectOptions: HonoElement;
  optionalBadgeTemplateScopeOptions: HonoElement;
  learnerRecordReviewPanelMarkup: RenderedNode;
  renderLearnerRecordReviewSections: () => RenderedNode;
  learnerRecordImportPanelMarkup: RenderedNode;
  learnerRecordImportFeedbackMarkup: RenderedNode;
  learnerRecordImportSubmissionMarkup: RenderedNode;
  learnerRecordImportProgressMarkup: RenderedNode;
  ruleReviewQueuePanelMarkup: RenderedNode;
  issuedBadgesPanelMarkup: RenderedNode;
  badgeStatusPanelMarkup: RenderedNode;
  reportingExecutiveSummaryMarkup: RenderedNode;
  reportingFocusAreaPanelMarkup: RenderedNode;
  reportingRankedChartsMarkup: RenderedNode;
  reportingDeepLinksMarkup: RenderedNode;
  reportingExploreSliceSummaryMarkup: RenderedNode;
  reportingOverviewPanelMarkup: RenderedNode;
  renderReportingTrendPanelMarkup: (input: { includeDetailedTable: boolean }) => RenderedNode;
  reportingEngagementPanelMarkup: RenderedNode;
  reportingLowerStoryMarkup: RenderedNode;
  reportingDefinitionsPanelMarkup: RenderedNode;
  reportingDeferredPanelMarkup: RenderedNode;
  reportingTrendFiltersPanelMarkup: RenderedNode;
  reportingReportsLibraryMarkup: RenderedNode;
  reportingExportFiltersPanelMarkup: RenderedNode;
  reportingExportsPanelMarkup: RenderedNode;
  badgeRulesTableMarkup: RenderedNode;
  ruleAdvancedToolsMarkup: RenderedNode;
  tenantMembersPanelMarkup: RenderedNode;
  tenantMembersTableMarkup: RenderedNode;
  governanceGuidePanelMarkup: RenderedNode;
  governanceActionsMarkup: RenderedNode;
  membershipScopeTableMarkup: RenderedNode;
  membershipScopePanelMarkup: RenderedNode;
  delegatedGrantTableMarkup: RenderedNode;
  apiKeyPanelMarkup: RenderedNode;
  apiKeysTableMarkup: RenderedNode;
  lmsConnectionsActionsMarkup: RenderedNode;
  lmsConnectionsTableMarkup: RenderedNode;
  orgUnitPanelMarkup: RenderedNode;
  orgUnitsTableMarkup: RenderedNode;
}

const renderPageHeader = (
  title: string,
  description: string,
  noteMarkup: HonoElement | null = null,
): HonoElement => {
  return <AdminPageHeader title={title} description={description} note={noteMarkup} />;
};

export const renderInstitutionAdminViewContent = (
  content: InstitutionAdminViewContentInput,
): RenderedNode => {
  const { input, view } = content;

  switch (view) {
    case "home":
      return (
        <>
          {renderPageHeader("Institution Admin", "Choose a workspace.")}
          <section class="ct-admin ct-stack">{content.workspaceCardsMarkup}</section>
        </>
      );
    case "operationsManualIssue":
      return (
        <>
          {renderPageHeader(
            "Issue Badge",
            "Issue a badge for one learner by choosing the template and recipient email.",
          )}
          <section class="ct-admin ct-stack">
            {renderManualIssueSection({
              tenantId: input.tenant.id,
              templateSelectOptions: content.templateSelectOptions,
              listError: input.manualIssueWorkspace?.listError ?? null,
              listNotice: input.manualIssueWorkspace?.listNotice ?? null,
              successLinks: input.manualIssueWorkspace?.successLinks ?? null,
            })}
          </section>
        </>
      );
    case "operationsLearnerRecords":
      return (
        <>
          {renderPageHeader(
            "Learner Records",
            "Look up one learner by profile ID or email to review badges and record entries.",
          )}
          <section class="ct-admin ct-stack">
            {content.learnerRecordReviewPanelMarkup}
            {content.renderLearnerRecordReviewSections()}
          </section>
        </>
      );
    case "operationsLearnerRecordImports":
      return (
        <>
          {renderPageHeader(
            "Learner Record Imports",
            "Import learner-record CSVs with one trust default, honest smart defaults, and queue-backed progress.",
          )}
          <section class="ct-admin ct-stack">
            {content.learnerRecordImportPanelMarkup}
            {content.learnerRecordImportFeedbackMarkup}
            {content.learnerRecordImportSubmissionMarkup}
            {content.learnerRecordImportProgressMarkup}
          </section>
        </>
      );
    case "operationsReviewQueue":
      return (
        <>
          {renderPageHeader(
            "Rule Review Queue",
            "Review pending badge decisions without mixing them into the rest of operations.",
          )}
          <section class="ct-admin ct-stack">{content.ruleReviewQueuePanelMarkup}</section>
        </>
      );
    case "operationsIssuedBadges":
      return (
        <>
          {renderPageHeader(
            "Badge Records",
            "Search issued badge records and take audit or revocation actions from one page.",
          )}
          <section class="ct-admin ct-stack">{content.issuedBadgesPanelMarkup}</section>
        </>
      );
    case "operationsBadgeStatus":
      return (
        <>
          {renderPageHeader(
            "Badge Status",
            "Look up a badge, inspect its current state, and apply status changes with a reason.",
          )}
          <section class="ct-admin ct-stack">{content.badgeStatusPanelMarkup}</section>
        </>
      );
    case "reporting":
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
                  {content.reportingExecutiveSummaryMarkup}
                </section>
                {content.reportingFocusAreaPanelMarkup}
                {content.reportingRankedChartsMarkup}
                {content.reportingDeepLinksMarkup}
              </section>
            </section>
          </section>
        </>
      );
    case "reportingExplore":
      return (
        <>
          {renderPageHeader(
            "Reporting Explore",
            "Filter the report, scan concise previews, and open exact detail only when needed.",
          )}
          <section class="ct-admin ct-stack">
            {content.reportingExploreSliceSummaryMarkup}
            <section class="ct-admin__reporting-explore-workspace ct-stack">
              {content.reportingOverviewPanelMarkup}
              {content.renderReportingTrendPanelMarkup({ includeDetailedTable: false })}
              {content.reportingEngagementPanelMarkup}
              {content.reportingLowerStoryMarkup}
              {content.reportingDefinitionsPanelMarkup}
              {content.reportingDeferredPanelMarkup}
            </section>
          </section>
        </>
      );
    case "reportingTrends":
      return (
        <>
          {renderPageHeader(
            "Trend Detail",
            "Use the focused trend page for exact daily counts behind the overview chart.",
          )}
          <section class="ct-admin ct-stack">
            {content.reportingTrendFiltersPanelMarkup}
            {content.renderReportingTrendPanelMarkup({ includeDetailedTable: true })}
          </section>
        </>
      );
    case "reportingReports":
      return (
        <>
          {renderPageHeader(
            "Report Library",
            "Use one focused page for saved report shortcuts, custom report setup, and CSV exports.",
          )}
          <section class="ct-admin ct-stack">
            {content.reportingReportsLibraryMarkup}
            {content.reportingExportFiltersPanelMarkup}
            {content.reportingExportsPanelMarkup}
          </section>
        </>
      );
    case "rules":
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
            {content.badgeRulesTableMarkup}
            {content.ruleAdvancedToolsMarkup}
          </section>
        </>
      );
    case "accessMembers":
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
            {content.tenantMembersPanelMarkup}
            {content.tenantMembersTableMarkup}
          </section>
        </>
      );
    case "accessGovernance":
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
            {content.governanceGuidePanelMarkup}
            {content.governanceActionsMarkup}
            {content.membershipScopeTableMarkup}
            {content.membershipScopePanelMarkup}
            {content.delegatedGrantTableMarkup}
          </section>
        </>
      );
    case "accessGovernanceDelegationNew":
      return (
        <>
          {renderPageHeader(
            "Add Delegated Authority",
            "Grant temporary badge authority without changing standing org-unit access.",
          )}
          <section class="ct-admin ct-stack">
            {renderDelegationSetupSection({
              tenantId: input.tenant.id,
              tenantMemberSelectOptions: content.tenantMemberSelectOptions,
              activeOrgUnitSelectOptions: content.activeOrgUnitSelectOptions,
              optionalBadgeTemplateScopeOptions: content.optionalBadgeTemplateScopeOptions,
              listError: input.accessGovernanceDelegationWorkspace?.listError ?? null,
              listNotice: input.accessGovernanceDelegationWorkspace?.listNotice ?? null,
            })}
          </section>
        </>
      );
    case "accessAuthentication":
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
    case "accessApiKeys":
      return (
        <>
          {renderPageHeader("API Keys", "Create, review, and revoke tenant API keys.")}
          <section class="ct-admin ct-stack">
            {content.apiKeyPanelMarkup}
            {content.apiKeysTableMarkup}
          </section>
        </>
      );
    case "accessLmsConnections":
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
            {content.lmsConnectionsActionsMarkup}
            {content.lmsConnectionsTableMarkup}
          </section>
        </>
      );
    case "accessLmsConnectionNew":
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
    case "accessLmsConnectionEdit":
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
    case "accessOrgUnits":
      return (
        <>
          {renderPageHeader("Org Units", "Create and review org structure.")}
          <section class="ct-admin ct-stack">
            {content.orgUnitPanelMarkup}
            {content.orgUnitsTableMarkup}
          </section>
        </>
      );
  }
};
