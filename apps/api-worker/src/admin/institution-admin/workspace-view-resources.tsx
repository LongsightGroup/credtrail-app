import { renderBadgeRuleBuilderDraftRows } from "./badge-rule-builder-draft-rows";
import { renderBadgeRulesTable } from "./badge-rules-table";
import { renderInstitutionAdminLearnerRecordSections } from "./learner-record-sections";
import { renderBadgeStatusPanel, renderRuleReviewQueuePanel } from "./operations-sections";
import type { InstitutionAdminPageInput, InstitutionAdminView } from "./page-types";
import {
  renderInstitutionAdminReportingReportsView,
  renderInstitutionAdminReportingTrendsView,
} from "./reporting-focused-sections";
import { renderInstitutionAdminReportingSections } from "./reporting-sections";
import type {
  InstitutionAdminViewContentInput,
  InstitutionAdminViewDataNeeds,
} from "./view-content";
import type { buildInstitutionAdminViewPaths } from "./view-paths";

const emptySectionMarkup = <></>;

export const buildInstitutionAdminOperationsViewResources = (input: {
  page: InstitutionAdminPageInput;
  dataNeeds: InstitutionAdminViewDataNeeds;
}): InstitutionAdminViewContentInput["operations"] => {
  return {
    badgeStatusPanelMarkup: input.dataNeeds.badgeStatusPanel
      ? renderBadgeStatusPanel()
      : emptySectionMarkup,
    ruleReviewQueuePanelMarkup: input.dataNeeds.reviewQueuePanel
      ? renderRuleReviewQueuePanel({
          tenantId: input.page.tenant.id,
          ...(input.page.reviewQueueWorkspace === undefined
            ? {}
            : { reviewQueueWorkspace: input.page.reviewQueueWorkspace }),
        })
      : emptySectionMarkup,
  };
};

export const buildInstitutionAdminReportingViewResources = (input: {
  page: InstitutionAdminPageInput;
  paths: ReturnType<typeof buildInstitutionAdminViewPaths>;
  view: InstitutionAdminView;
  dataNeeds: InstitutionAdminViewDataNeeds;
}): InstitutionAdminViewContentInput["reporting"] => {
  if (!input.dataNeeds.reportingSectionBundles) {
    return { viewMarkup: emptySectionMarkup };
  }

  const sectionInput = {
    input: input.page,
    reportingExplorePath: input.paths.reportingExplorePath,
    reportingTrendsPath: input.paths.reportingTrendsPath,
    reportingReportsPath: input.paths.reportingReportsPath,
  };

  if (input.view === "reportingTrends") {
    return {
      viewMarkup: renderInstitutionAdminReportingTrendsView({
        page: input.page,
        reportingExplorePath: input.paths.reportingExplorePath,
        reportingTrendsPath: input.paths.reportingTrendsPath,
      }),
    };
  }

  if (input.view === "reportingReports") {
    return {
      viewMarkup: renderInstitutionAdminReportingReportsView({
        page: input.page,
        reportingPath: input.paths.reportingPath,
        reportingExplorePath: input.paths.reportingExplorePath,
        reportingReportsPath: input.paths.reportingReportsPath,
      }),
    };
  }

  const sections = renderInstitutionAdminReportingSections(sectionInput);

  if (input.view === "reporting") {
    return {
      viewMarkup: (
        <section class="ct-admin__reporting-primary-story ct-stack">
          <section class="ct-admin__reporting-first-screen ct-stack">
            {sections.reportingExecutiveSummaryMarkup}
          </section>
          {sections.reportingFocusAreaPanelMarkup}
          {sections.reportingRankedChartsMarkup}
          {sections.reportingDeepLinksMarkup}
        </section>
      ),
    };
  }

  return {
    viewMarkup: (
      <>
        {sections.reportingExploreSliceSummaryMarkup}
        <section class="ct-admin__reporting-explore-workspace ct-stack">
          {sections.reportingOverviewPanelMarkup}
          {sections.renderReportingTrendPanelMarkup({ includeDetailedTable: false })}
          {sections.reportingEngagementPanelMarkup}
          {sections.reportingLowerStoryMarkup}
          {sections.reportingDefinitionsPanelMarkup}
          {sections.reportingDeferredPanelMarkup}
        </section>
      </>
    ),
  };
};

export const buildInstitutionAdminRulesViewResources = (input: {
  page: InstitutionAdminPageInput;
  paths: ReturnType<typeof buildInstitutionAdminViewPaths>;
  dataNeeds: InstitutionAdminViewDataNeeds;
}): InstitutionAdminViewContentInput["rules"] => {
  if (!input.dataNeeds.badgeRulesTable) {
    return { badgeRulesTableMarkup: emptySectionMarkup };
  }

  const builderDrafts = input.page.rulesWorkspace?.builderDrafts ?? [];
  const builderDraftRows = renderBadgeRuleBuilderDraftRows({
    tenantId: input.page.tenant.id,
    drafts: builderDrafts,
    badgeTemplates: input.page.badgeTemplates,
    lmsConnections: input.page.lmsConnections,
  });

  return {
    badgeRulesTableMarkup: renderBadgeRulesTable({
      tenantId: input.page.tenant.id,
      userId: input.page.userId,
      ruleBuilderPath: input.paths.ruleBuilderPath,
      rulesTemplatesPath: input.paths.rulesTemplatesPath,
      badgeRules: input.page.badgeRules,
      badgeRuleVersions: input.page.badgeRuleVersions,
      builderDraftRows,
      builderDraftCount: builderDrafts.length,
      registry: input.page.rulesWorkspace?.registry ?? {
        searchQuery: "",
        latestStatus: null,
        sort: "updated",
        direction: "desc",
        limit: 25,
        totalCount: input.page.badgeRules.length,
        previousPageHref: null,
        nextPageHref: null,
      },
    }),
  };
};

export const buildInstitutionAdminLearnerRecordViewResources = (input: {
  page: InstitutionAdminPageInput;
  paths: ReturnType<typeof buildInstitutionAdminViewPaths>;
  dataNeeds: InstitutionAdminViewDataNeeds;
}): InstitutionAdminViewContentInput["learnerRecords"] => {
  if (!input.dataNeeds.learnerRecordSectionBundles) {
    return {
      learnerRecordReviewPanelMarkup: emptySectionMarkup,
      renderLearnerRecordReviewSections: () => emptySectionMarkup,
      learnerRecordImportPanelMarkup: emptySectionMarkup,
      learnerRecordImportFeedbackMarkup: emptySectionMarkup,
      learnerRecordImportSubmissionMarkup: emptySectionMarkup,
      learnerRecordImportProgressMarkup: emptySectionMarkup,
    };
  }

  const learnerRecordReview = input.page.learnerRecordReview ?? {
    lookup: {},
    learnerProfile: null,
    presentation: null,
    exportPath: null,
    standardsMappingPath: null,
    lookupState: "idle" as const,
  };
  const learnerRecordImportWorkflow = input.page.learnerRecordImportWorkflow ?? {
    templatePath: `/v1/tenants/${encodeURIComponent(input.page.tenant.id)}/learner-record-imports/template.csv`,
    previewPath: input.paths.operationsLearnerRecordImportsPath,
    applyPath: input.paths.operationsLearnerRecordImportsPath,
    defaults: {
      defaultTrustLevel: "issuer_verified" as const,
      defaultIssuerName: "",
    },
    submission: null,
    feedback: null,
    progress: {
      totals: {
        messages: 0,
        batches: 0,
        pendingRows: 0,
        processingRows: 0,
        completedRows: 0,
        failedRows: 0,
      },
      batches: [],
    },
  };

  return renderInstitutionAdminLearnerRecordSections({
    tenantDisplayName: input.page.tenant.displayName,
    operationsLearnerRecordsPath: input.paths.operationsLearnerRecordsPath,
    operationsLearnerRecordImportsPath: input.paths.operationsLearnerRecordImportsPath,
    learnerRecordReview,
    learnerRecordImportWorkflow,
  });
};
