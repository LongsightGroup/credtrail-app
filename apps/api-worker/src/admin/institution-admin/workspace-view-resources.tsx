import type { Child } from "hono/jsx";
import { renderBadgeRuleBuilderDraftRows } from "./badge-rule-builder-draft-rows";
import { renderBadgeRulesTable } from "./badge-rules-table";
import { renderInstitutionAdminLearnerRecordSections } from "./learner-record-sections";
import { renderInstitutionAdminOperationsSections } from "./operations-sections";
import type { InstitutionAdminPageInput } from "./page-types";
import { renderInstitutionAdminReportingSections } from "./reporting-sections";
import type {
  InstitutionAdminViewContentInput,
  InstitutionAdminViewDataNeeds,
} from "./view-content";
import type { buildInstitutionAdminViewPaths } from "./view-paths";
import type { InstitutionAdminViewOptionResources } from "./view-option-resources";

const emptySectionMarkup = <></>;

const asChild = (node: unknown): Child => node as Child;

export const buildInstitutionAdminOperationsViewResources = (input: {
  page: InstitutionAdminPageInput;
  dataNeeds: InstitutionAdminViewDataNeeds;
  options: InstitutionAdminViewOptionResources["operations"];
}): InstitutionAdminViewContentInput["operations"] => {
  if (!input.dataNeeds.operationsSectionBundles) {
    return {
      badgeStatusPanelMarkup: emptySectionMarkup,
      issuedBadgesPanelMarkup: emptySectionMarkup,
      ruleReviewQueuePanelMarkup: emptySectionMarkup,
    };
  }

  const sections = renderInstitutionAdminOperationsSections({
    tenantId: input.page.tenant.id,
    templateSelectOptions: input.options.templateSelectOptions,
    ruleSelectOptions: input.options.ruleSelectOptions,
    templateFilterOptions: input.options.templateFilterOptions,
    activeOrgUnitOptions: input.options.activeOrgUnitOptions,
    ...(input.page.issuedBadgesWorkspace === undefined
      ? {}
      : { issuedBadgesWorkspace: input.page.issuedBadgesWorkspace }),
    ...(input.page.reviewQueueWorkspace === undefined
      ? {}
      : { reviewQueueWorkspace: input.page.reviewQueueWorkspace }),
    ...(input.page.ruleValueListsWorkspace === undefined
      ? {}
      : { ruleValueListsWorkspace: input.page.ruleValueListsWorkspace }),
    ...(input.page.operationsWorkspace === undefined
      ? {}
      : { operationsWorkspace: input.page.operationsWorkspace }),
  });

  return {
    badgeStatusPanelMarkup: asChild(sections.badgeStatusPanelMarkup),
    issuedBadgesPanelMarkup: asChild(sections.issuedBadgesPanelMarkup),
    ruleReviewQueuePanelMarkup: asChild(sections.ruleReviewQueuePanelMarkup),
  };
};

export const buildInstitutionAdminReportingViewResources = (input: {
  page: InstitutionAdminPageInput;
  paths: ReturnType<typeof buildInstitutionAdminViewPaths>;
  dataNeeds: InstitutionAdminViewDataNeeds;
}): InstitutionAdminViewContentInput["reporting"] => {
  if (!input.dataNeeds.reportingSectionBundles) {
    return {
      reportingExecutiveSummaryMarkup: emptySectionMarkup,
      reportingFocusAreaPanelMarkup: emptySectionMarkup,
      reportingRankedChartsMarkup: emptySectionMarkup,
      reportingDeepLinksMarkup: emptySectionMarkup,
      reportingExploreSliceSummaryMarkup: emptySectionMarkup,
      reportingOverviewPanelMarkup: emptySectionMarkup,
      renderReportingTrendPanelMarkup: () => emptySectionMarkup,
      reportingEngagementPanelMarkup: emptySectionMarkup,
      reportingLowerStoryMarkup: emptySectionMarkup,
      reportingDefinitionsPanelMarkup: emptySectionMarkup,
      reportingDeferredPanelMarkup: emptySectionMarkup,
      reportingTrendFiltersPanelMarkup: emptySectionMarkup,
      reportingReportsLibraryMarkup: emptySectionMarkup,
      reportingExportFiltersPanelMarkup: emptySectionMarkup,
      reportingExportsPanelMarkup: emptySectionMarkup,
    };
  }

  return renderInstitutionAdminReportingSections({
    input: input.page,
    reportingPath: input.paths.reportingPath,
    reportingExplorePath: input.paths.reportingExplorePath,
    reportingTrendsPath: input.paths.reportingTrendsPath,
    reportingReportsPath: input.paths.reportingReportsPath,
  });
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
