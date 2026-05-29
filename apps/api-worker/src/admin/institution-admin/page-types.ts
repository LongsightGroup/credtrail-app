import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateRecord,
  LearnerRecordTrustLevel,
  TenantApiKeyRecord,
  TenantAuthPolicyRecord,
  TenantAuthProviderRecord,
  TenantBreakGlassAccountRecord,
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
} from "@credtrail/db";
import type {
  LearnerRecordImportBatchProgressSummary,
  LearnerRecordImportRowReport,
} from "../../learner-record/learner-record-import";
import type { LearnerRecordPresentationModel } from "../../learner-record/learner-record-presentation";
import type { ReportingMetricEntry } from "../../reporting/metric-definitions";
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
  | "access"
  | "accessMembers"
  | "accessGovernance"
  | "accessApiKeys"
  | "accessOrgUnits";

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
    controller: "shared",
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
  access: {
    titlePrefix: "Access · Institution Admin",
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
  accessApiKeys: {
    titlePrefix: "API Keys · Institution Admin",
    controller: "shell",
    extraAssets: ["institutionAdminApiKeysJs"],
  },
  accessOrgUnits: {
    titlePrefix: "Org Units · Institution Admin",
    controller: "shell",
    extraAssets: ["institutionAdminOrgUnitsJs"],
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
  switchOrganizationPath?: string | null;
}
