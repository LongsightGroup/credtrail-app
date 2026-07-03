import type { TenantMembershipRole } from "./tenant-memberships";

export type BadgeIssuanceRuleLmsProviderKind =
  | "canvas"
  | "moodle"
  | "blackboard_ultra"
  | "d2l_brightspace"
  | "sakai";

export type BadgeIssuanceRuleVersionStatus =
  | "draft"
  | "pending_approval"
  | "approved"
  | "active"
  | "rejected"
  | "deprecated";

export type BadgeIssuanceRuleApprovalStepStatus =
  | "queued"
  | "pending"
  | "approved"
  | "rejected"
  | "changes_requested";

export type BadgeIssuanceRuleApprovalStepTargetType = "role_threshold" | "user" | "approver_group";

export type BadgeIssuanceRuleApprovalDecision = "approved" | "rejected" | "changes_requested";

export type BadgeIssuanceRuleApprovalEventAction = "submitted" | BadgeIssuanceRuleApprovalDecision;

export interface BadgeIssuanceRuleRecord {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  badgeTemplateId: string;
  /**
   * Captured badge template owner scope at rule create or draft edit time.
   * Approval policy resolution uses this snapshot instead of live template ownership.
   */
  ownerOrgUnitId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId: string | null;
  activeVersionId: string | null;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BadgeIssuanceRuleVersionRecord {
  id: string;
  tenantId: string;
  ruleId: string;
  versionNumber: number;
  status: BadgeIssuanceRuleVersionStatus;
  ruleJson: string;
  changeSummary: string | null;
  createdByUserId: string | null;
  submittedByUserId: string | null;
  submittedAt: string | null;
  approvedByUserId: string | null;
  approvedAt: string | null;
  activatedByUserId: string | null;
  activatedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BadgeIssuanceRuleApprovalStepRecord {
  id: string;
  tenantId: string;
  versionId: string;
  stepNumber: number;
  targetType: BadgeIssuanceRuleApprovalStepTargetType;
  requiredRole: TenantMembershipRole | null;
  targetUserId: string | null;
  targetApproverGroupId: string | null;
  orgUnitId: string | null;
  label: string | null;
  status: BadgeIssuanceRuleApprovalStepStatus;
  decidedByUserId: string | null;
  decidedAt: string | null;
  decisionComment: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BadgeIssuanceRuleApprovalEventRecord {
  id: string;
  tenantId: string;
  versionId: string;
  stepNumber: number | null;
  action: BadgeIssuanceRuleApprovalEventAction;
  actorUserId: string | null;
  actorRole: TenantMembershipRole | null;
  comment: string | null;
  occurredAt: string;
  createdAt: string;
}

export interface CreateBadgeIssuanceRuleInput {
  tenantId: string;
  name: string;
  description?: string | undefined;
  badgeTemplateId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId: string;
  ruleJson: string;
  changeSummary?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface CreateBadgeIssuanceRuleVersionInput {
  tenantId: string;
  ruleId: string;
  ruleJson: string;
  changeSummary?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface UpdateBadgeIssuanceRuleDraftInput {
  tenantId: string;
  ruleId: string;
  name: string;
  description?: string | undefined;
  badgeTemplateId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId: string;
  ruleJson: string;
  changeSummary?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface ListBadgeIssuanceRulesInput {
  tenantId: string;
}

export interface ListBadgeIssuanceRuleVersionsInput {
  tenantId: string;
  ruleId: string;
}

export interface SubmitBadgeIssuanceRuleVersionForApprovalInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  actorUserId?: string | undefined;
  actorRole?: TenantMembershipRole | undefined;
  comment?: string | undefined;
  occurredAt?: string | undefined;
}

export interface DecideBadgeIssuanceRuleVersionInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  decision: BadgeIssuanceRuleApprovalDecision;
  actorUserId: string;
  actorRole: TenantMembershipRole;
  comment?: string | undefined;
  occurredAt?: string | undefined;
}

export interface ListBadgeIssuanceRuleVersionApprovalStepsInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
}

export interface ListBadgeIssuanceRuleVersionApprovalEventsInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
}

export interface ActivateBadgeIssuanceRuleVersionInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  actorUserId: string;
  activatedAt?: string | undefined;
}

export interface CreateBadgeIssuanceRuleResult {
  rule: BadgeIssuanceRuleRecord;
  version: BadgeIssuanceRuleVersionRecord;
}

export type UpdateBadgeIssuanceRuleDraftResult =
  | {
      status: "updated";
      rule: BadgeIssuanceRuleRecord;
      version: BadgeIssuanceRuleVersionRecord;
    }
  | {
      status: "not_found";
    }
  | {
      status: "not_editable";
      rule: BadgeIssuanceRuleRecord;
      versions: BadgeIssuanceRuleVersionRecord[];
    };

export type DeleteDraftBadgeIssuanceRuleResult =
  | {
      status: "deleted";
      rule: BadgeIssuanceRuleRecord;
      versions: BadgeIssuanceRuleVersionRecord[];
    }
  | {
      status: "not_found";
    }
  | {
      status: "not_deletable";
      rule: BadgeIssuanceRuleRecord;
      versions: BadgeIssuanceRuleVersionRecord[];
    };
