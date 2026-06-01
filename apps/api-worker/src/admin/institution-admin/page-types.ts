import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateRecord,
  LearnerRecordTrustLevel,
  TenantAssertionSummaryRecord,
  TenantApiKeyRecord,
  TenantAuthPolicyRecord,
  TenantAuthProviderRecord,
  TenantBreakGlassAccountRecord,
  TenantLmsConnectionRecord,
  TenantMemberRecord,
  TenantMembershipOrgUnitScopeRecord,
  TenantMembershipRole,
  TenantOrgUnitRecord,
  TenantRecord,
  TenantReportingComparisonRowRecord,
  TenantReportingEngagementCounts,
  TenantReportingOverviewRecord,
  TenantReportingTrendRecord,
  DelegatedIssuingAuthorityGrantRecord,
  BadgeIssuanceRuleValueListRecord,
} from "@credtrail/db";
import type {
  LearnerRecordImportBatchProgressSummary,
  LearnerRecordImportRowReport,
} from "../../learner-record/learner-record-import";
import type { LearnerRecordPresentationModel } from "../../learner-record/learner-record-presentation";
import type { ReportingMetricEntry } from "../../reporting/metric-definitions";
import type { BadgeRuleReviewQueueEntryView } from "../../badge-rule-review-queue-workspace";
import type { PageAssetKey } from "../../ui/page-assets";

export type InstitutionAdminView =
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
  | "accessMembers"
  | "accessGovernance"
  | "accessGovernanceDelegationNew"
  | "accessAuthentication"
  | "accessApiKeys"
  | "accessOrgUnits"
  | "accessLmsConnections"
  | "accessLmsConnectionNew"
  | "accessLmsConnectionEdit"
  | "operationsManualIssue";

const DEDICATED_ACCESS_SETUP_VIEWS: ReadonlySet<InstitutionAdminView> = new Set([
  "accessGovernanceDelegationNew",
  "accessAuthentication",
  "accessLmsConnectionNew",
  "accessLmsConnectionEdit",
]);

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

  return view === "rules" || view === "operations" || view.startsWith("operations");
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

export const INSTITUTION_ADMIN_VIEW_CONFIG = {
  home: {
    titlePrefix: "Institution Admin",
    controller: "shell",
  },
  operations: {
    titlePrefix: "Issue & Inspect · Institution Admin",
    controller: "shared",
  },
  operationsLearnerRecords: {
    titlePrefix: "Learner Records · Institution Admin",
    controller: "shell",
  },
  operationsLearnerRecordImports: {
    titlePrefix: "Learner Record Imports · Institution Admin",
    controller: "shell",
  },
  operationsReviewQueue: {
    titlePrefix: "Rule Review Queue · Institution Admin",
    controller: "shell",
  },
  operationsIssuedBadges: {
    titlePrefix: "Issued Badges · Institution Admin",
    controller: "shell",
    extraAssets: ["institutionAdminIssuedBadgesJs"],
  },
  operationsBadgeStatus: {
    titlePrefix: "Badge Status · Institution Admin",
    controller: "shared",
  },
  reporting: {
    titlePrefix: "Reporting · Institution Admin",
    controller: "shared",
  },
  reportingExplore: {
    titlePrefix: "Reporting Explore · Institution Admin",
    controller: "shared",
  },
  reportingTrends: {
    titlePrefix: "Trend Detail · Reporting · Institution Admin",
    controller: "shared",
  },
  reportingReports: {
    titlePrefix: "Report Library · Reporting · Institution Admin",
    controller: "shared",
  },
  rules: {
    titlePrefix: "Rules · Institution Admin",
    controller: "shared",
  },
  accessMembers: {
    titlePrefix: "Members · Institution Admin",
    controller: "shared",
  },
  accessGovernance: {
    titlePrefix: "Governance Delegation · Institution Admin",
    controller: "shared",
  },
  accessGovernanceDelegationNew: {
    titlePrefix: "Add Delegated Authority · Institution Admin",
    controller: "shell",
  },
  accessAuthentication: {
    titlePrefix: "Authentication · Institution Admin",
    controller: "shell",
    extraAssets: ["institutionAdminAccessJs"],
  },
  accessApiKeys: {
    titlePrefix: "API Keys · Institution Admin",
    controller: "shell",
    extraAssets: ["institutionAdminAccessJs"],
  },
  accessOrgUnits: {
    titlePrefix: "Org Units · Institution Admin",
    controller: "shell",
  },
  accessLmsConnections: {
    titlePrefix: "LMS Connections · Institution Admin",
    controller: "shell",
  },
  accessLmsConnectionNew: {
    titlePrefix: "Connect LMS · Institution Admin",
    controller: "shell",
  },
  accessLmsConnectionEdit: {
    titlePrefix: "Edit LMS Connection · Institution Admin",
    controller: "shell",
  },
  operationsManualIssue: {
    titlePrefix: "Issue Badge · Institution Admin",
    controller: "shell",
  },
} as const satisfies Record<
  InstitutionAdminView,
  {
    controller: "shared" | "shell";
    extraAssets?: readonly PageAssetKey[];
    titlePrefix: string;
  }
>;

export interface InstitutionAdminLearnerRecordReview {
  lookup: {
    learnerProfileId?: string;
    email?: string;
  };
  learnerProfile: {
    id: string;
    displayName: string | null;
    subjectId: string;
  } | null;
  presentation: LearnerRecordPresentationModel | null;
  exportPath: string | null;
  standardsMappingPath: string | null;
  lookupState: "idle" | "unresolved" | "loaded";
}

export interface InstitutionAdminApiKeysWorkspace {
  listNotice: string | null;
  listError: string | null;
  revealedSecret: string | null;
  openCreatePanel: boolean;
}

export interface InstitutionAdminIssuedBadgesWorkspace {
  filters: {
    recipientQuery: string;
    badgeTemplateId: string;
    state: string;
    limit: number;
  };
  assertions: readonly TenantAssertionSummaryRecord[];
  listNotice: string | null;
  listError: string | null;
  lifecycleAssertionId: string | null;
  lifecycleMode: "audit" | "revoke" | null;
}

export interface InstitutionAdminReviewQueueWorkspace {
  entries: readonly BadgeRuleReviewQueueEntryView[];
  listNotice: string | null;
  listError: string | null;
}

export interface InstitutionAdminRuleValueListsWorkspace {
  valueLists: readonly BadgeIssuanceRuleValueListRecord[];
  listNotice: string | null;
  listError: string | null;
}

export interface InstitutionAdminLmsConnectionsWorkspace {
  listNotice: string | null;
  listError: string | null;
}

export interface InstitutionAdminLmsConnectionSetupWorkspace {
  listNotice: string | null;
  listError: string | null;
}

export interface InstitutionAdminAccessMembersWorkspace {
  listNotice: string | null;
  listError: string | null;
}

export interface InstitutionAdminAccessGovernanceWorkspace {
  listNotice: string | null;
  listError: string | null;
}

export interface InstitutionAdminAccessAuthenticationWorkspace {
  listNotice: string | null;
  listError: string | null;
  editProviderId: string | null;
}

export interface InstitutionAdminAccessGovernanceDelegationWorkspace {
  listNotice: string | null;
  listError: string | null;
}

export interface InstitutionAdminAccessOrgUnitsWorkspace {
  listNotice: string | null;
  listError: string | null;
}

export interface InstitutionAdminOperationsWorkspace {
  listNotice: string | null;
  listError: string | null;
}

export interface InstitutionAdminManualIssueWorkspace {
  listNotice: string | null;
  listError: string | null;
}

export interface InstitutionAdminLearnerRecordImportWorkflow {
  templatePath: string;
  previewPath: string;
  applyPath: string;
  defaults: {
    defaultTrustLevel: LearnerRecordTrustLevel;
    defaultIssuerName: string;
  };
  submission: {
    mode: "preview" | "apply";
    batchId: string;
    fileName: string;
    totalRows: number;
    validRows: number;
    invalidRows: number;
    queuedRows: number;
    rows: readonly LearnerRecordImportRowReport[];
    queueForm: {
      batchId: string;
    } | null;
  } | null;
  feedback: {
    tone: "success" | "warning";
    title: string;
    detail: string;
  } | null;
  progress: {
    totals: {
      messages: number;
      batches: number;
      pendingRows: number;
      processingRows: number;
      completedRows: number;
      failedRows: number;
    };
    batches: readonly LearnerRecordImportBatchProgressSummary[];
  };
}

export interface InstitutionAdminPageInput {
  tenant: TenantRecord;
  userId: string;
  userEmail?: string;
  membershipRole: TenantMembershipRole;
  badgeTemplates: readonly BadgeTemplateRecord[];
  orgUnits: readonly TenantOrgUnitRecord[];
  tenantMembers: readonly TenantMemberRecord[];
  membershipOrgUnitScopes: readonly TenantMembershipOrgUnitScopeRecord[];
  delegatedIssuingAuthorityGrants: readonly DelegatedIssuingAuthorityGrantRecord[];
  lmsConnections: readonly TenantLmsConnectionRecord[];
  activeApiKeys: readonly TenantApiKeyRecord[];
  revokedApiKeyCount: number;
  badgeRules: readonly BadgeIssuanceRuleRecord[];
  badgeRuleVersions: readonly BadgeIssuanceRuleVersionRecord[];
  reportingEngagementCounts?: TenantReportingEngagementCounts | null;
  reportingOverview?: TenantReportingOverviewRecord | null;
  reportingMetrics?: readonly ReportingMetricEntry[];
  reportingOrgUnitComparisons?: readonly TenantReportingComparisonRowRecord[];
  reportingTemplateComparisons?: readonly TenantReportingComparisonRowRecord[];
  reportingTrends?: TenantReportingTrendRecord | null;
  enterpriseAuthPolicy?: TenantAuthPolicyRecord | null;
  enterpriseAuthProviders?: readonly TenantAuthProviderRecord[];
  breakGlassAccounts?: readonly TenantBreakGlassAccountRecord[];
  learnerRecordReview?: InstitutionAdminLearnerRecordReview;
  learnerRecordImportWorkflow?: InstitutionAdminLearnerRecordImportWorkflow;
  apiKeysWorkspace?: InstitutionAdminApiKeysWorkspace;
  issuedBadgesWorkspace?: InstitutionAdminIssuedBadgesWorkspace;
  reviewQueueWorkspace?: InstitutionAdminReviewQueueWorkspace;
  ruleValueListsWorkspace?: InstitutionAdminRuleValueListsWorkspace;
  lmsConnectionsWorkspace?: InstitutionAdminLmsConnectionsWorkspace;
  lmsConnectionSetupWorkspace?: InstitutionAdminLmsConnectionSetupWorkspace;
  lmsConnectionSetupFormValues?: {
    connectionId: string;
    displayName: string;
    providerKind: "canvas" | "sakai";
    apiBaseUrl: string;
    ltiIssuer: string;
    ltiClientId: string;
    ltiDeploymentId: string;
  };
  accessMembersWorkspace?: InstitutionAdminAccessMembersWorkspace;
  accessGovernanceWorkspace?: InstitutionAdminAccessGovernanceWorkspace;
  accessGovernanceDelegationWorkspace?: InstitutionAdminAccessGovernanceDelegationWorkspace;
  accessAuthenticationWorkspace?: InstitutionAdminAccessAuthenticationWorkspace;
  accessOrgUnitsWorkspace?: InstitutionAdminAccessOrgUnitsWorkspace;
  operationsWorkspace?: InstitutionAdminOperationsWorkspace;
  manualIssueWorkspace?: InstitutionAdminManualIssueWorkspace;
  switchOrganizationPath?: string | null;
}
