import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeRuleApprovalPolicyRecord,
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
  BadgeRuleApproverGroupWithMembersRecord,
} from "@credtrail/db";
import type {
  LearnerRecordImportBatchProgressSummary,
  LearnerRecordImportRowReport,
} from "../../learner-record/learner-record-import";
import type { LearnerRecordPresentationModel } from "../../learner-record/learner-record-presentation";
import type { ReportingMetricEntry } from "../../reporting/metric-definitions";
import type { BadgeRuleReviewQueueEntryView } from "../../badge-rule-review-queue-workspace";
import type { AdminManualIssueSuccessLinks } from "../manual-issue-flash";

export type InstitutionAdminView =
  | "home"
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
    issuedFrom: string;
    issuedTo: string;
    recipientQuery: string;
    badgeTemplateId: string;
    orgUnitId: string;
    state: string;
    limit: number;
  };
  assertions: readonly TenantAssertionSummaryRecord[] | null;
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

export interface InstitutionAdminRulesWorkspace {
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
  ltiDynamicRegistrationUrl: string | null;
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
  successLinks: AdminManualIssueSuccessLinks | null;
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
  badgeRuleApproverGroups: readonly BadgeRuleApproverGroupWithMembersRecord[];
  delegatedIssuingAuthorityGrants: readonly DelegatedIssuingAuthorityGrantRecord[];
  lmsConnections: readonly TenantLmsConnectionRecord[];
  activeApiKeys: readonly TenantApiKeyRecord[];
  revokedApiKeyCount: number;
  badgeRules: readonly BadgeIssuanceRuleRecord[];
  badgeRuleVersions: readonly BadgeIssuanceRuleVersionRecord[];
  badgeRuleApprovalPolicy?: BadgeRuleApprovalPolicyRecord | null;
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
  rulesWorkspace?: InstitutionAdminRulesWorkspace;
  ruleValueListsWorkspace?: InstitutionAdminRuleValueListsWorkspace;
  lmsConnectionsWorkspace?: InstitutionAdminLmsConnectionsWorkspace;
  lmsConnectionSetupWorkspace?: InstitutionAdminLmsConnectionSetupWorkspace;
  lmsConnectionSetupFormValues?: {
    connectionId: string;
    displayName: string;
    providerKind: "canvas" | "sakai";
    apiBaseUrl: string;
    sakaiUsername: string;
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
