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
  | "suspended"
  | "expired"
  | "rejected"
  | "deprecated";

export type BadgeIssuanceRuleBuilderDraftStep = "metadata" | "conditions" | "test";

interface BadgeIssuanceRuleBuilderDraftRecordBase {
  readonly id: string;
  readonly tenantId: string;
  readonly userId: string;
  readonly currentStep: BadgeIssuanceRuleBuilderDraftStep;
  readonly draftJson: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/** Persisted builder progress with a valid unfinished or formal-rule target. */
export type BadgeIssuanceRuleBuilderDraftRecord = BadgeIssuanceRuleBuilderDraftRecordBase &
  (
    | {
        readonly targetKind: "unfinished";
        readonly ruleId: null;
        readonly versionId: null;
      }
    | {
        readonly targetKind: "formal_rule";
        readonly ruleId: string;
        readonly versionId: string;
      }
  );

interface SaveBadgeIssuanceRuleBuilderDraftInputBase {
  readonly id: string;
  readonly tenantId: string;
  readonly userId: string;
  readonly currentStep: BadgeIssuanceRuleBuilderDraftStep;
  readonly draftJson: string;
}

/** Input for saving builder progress against one explicit lifecycle target. */
export type SaveBadgeIssuanceRuleBuilderDraftInput = SaveBadgeIssuanceRuleBuilderDraftInputBase & {
  readonly target:
    | {
        readonly kind: "unfinished";
      }
    | {
        readonly kind: "formal_rule";
        readonly ruleId: string;
        readonly versionId: string;
      };
};

/** Outcome of saving builder progress without overwriting another lifecycle identity. */
export type SaveBadgeIssuanceRuleBuilderDraftResult =
  | {
      readonly status: "saved";
      readonly draft: BadgeIssuanceRuleBuilderDraftRecord;
    }
  | {
      readonly status: "unavailable";
    };

/** Outcome of idempotently promoting builder progress into a formal rule. */
export type PromoteBadgeIssuanceRuleBuilderDraftResult =
  | {
      readonly status: "created" | "replayed";
      readonly draft: CreateBadgeIssuanceRuleResult;
    }
  | {
      readonly status: "unavailable";
    };

export type BadgeIssuanceRuleApprovalStepStatus =
  | "queued"
  | "pending"
  | "approved"
  | "rejected"
  | "changes_requested";

export type BadgeIssuanceRuleApprovalStepTarget =
  | {
      targetType: "role_threshold";
      requiredRole: TenantMembershipRole;
      targetUserId: null;
      targetApproverGroupId: null;
    }
  | {
      targetType: "user";
      requiredRole: TenantMembershipRole | null;
      targetUserId: string;
      targetApproverGroupId: null;
    }
  | {
      targetType: "approver_group";
      requiredRole: TenantMembershipRole | null;
      targetUserId: null;
      targetApproverGroupId: string;
    };

export type BadgeIssuanceRuleApprovalStepTargetType =
  BadgeIssuanceRuleApprovalStepTarget["targetType"];

export type BadgeIssuanceRuleApprovalDecision = "approved" | "rejected" | "changes_requested";

export type BadgeIssuanceRuleApprovalEventAction =
  | "submitted"
  | "withdrawn"
  | "reopened"
  | BadgeIssuanceRuleApprovalDecision;

export interface BadgeIssuanceRuleRecord {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  badgeTemplateId: string;
  /**
   * Canonical org-unit scope for rule governance, delegated visibility, and reporting.
   * LTI-created course rules use a course org unit here.
   */
  orgUnitId: string;
  /**
   * Captured badge template owner scope at rule create or draft edit time.
   * This is template ownership metadata; rule governance uses orgUnitId.
   */
  ownerOrgUnitId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId: string | null;
  activeVersionId: string | null;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

/** Immutable authoring metadata captured with one governed rule version. */
export interface BadgeIssuanceRuleVersionSnapshot {
  name: string;
  description: string | null;
  badgeTemplateId: string;
  badgeTemplateTitle: string;
  badgeTemplateImageUri: string | null;
  orgUnitId: string;
  ownerOrgUnitId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId: string | null;
}

export interface BadgeIssuanceRuleVersionRecord {
  id: string;
  tenantId: string;
  ruleId: string;
  versionNumber: number;
  status: BadgeIssuanceRuleVersionStatus;
  ruleJson: string;
  snapshot: BadgeIssuanceRuleVersionSnapshot;
  changeSummary: string | null;
  createdByUserId: string | null;
  submittedByUserId: string | null;
  submittedAt: string | null;
  approvedByUserId: string | null;
  approvedAt: string | null;
  activatedByUserId: string | null;
  activatedAt: string | null;
  effectiveStartsAt: string | null;
  expiresAt: string | null;
  expiredAt: string | null;
  suspendedAt: string | null;
  suspendedByUserId: string | null;
  suspensionReason: string | null;
  recertifiedAt: string | null;
  recertificationDueAt: string | null;
  expiryReminderSentAt: string | null;
  recertificationReminderSentAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface BadgeIssuanceRuleApprovalStepBaseRecord {
  id: string;
  tenantId: string;
  versionId: string;
  stepNumber: number;
  orgUnitId: string | null;
  label: string | null;
  status: BadgeIssuanceRuleApprovalStepStatus;
  decidedByUserId: string | null;
  decidedAt: string | null;
  decisionComment: string | null;
  createdAt: string;
  updatedAt: string;
}

export type BadgeIssuanceRuleApprovalStepRecord = BadgeIssuanceRuleApprovalStepBaseRecord &
  BadgeIssuanceRuleApprovalStepTarget;

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
  orgUnitId?: string | undefined;
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
  orgUnitId?: string | undefined;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  lmsConnectionId: string;
  ruleJson: string;
  changeSummary?: string | undefined;
  createdByUserId?: string | undefined;
}

/** A formal rule-authoring action requested by a caller. */
export type BadgeIssuanceRuleAuthoringAction = "save_draft" | "submit_for_approval";

/** The persisted lifecycle outcome of a completed authoring action. */
export type BadgeIssuanceRuleAuthoringOutcome = "draft_saved" | "pending_approval" | "approved";

/** A stable reason why a badge-rule authoring command was rejected. */
export type BadgeIssuanceRuleAuthoringFailureReason =
  | "unavailable"
  | "replay_conflict"
  | "not_found"
  | "not_editable"
  | "self_certification_required"
  | "policy_missing_steps";

/** The completed authoring value or an expected authoring rejection. */
export type BadgeIssuanceRuleAuthoringResult =
  | {
      readonly status: "completed";
      readonly outcome: BadgeIssuanceRuleAuthoringOutcome;
      readonly writeStatus: "created" | "replayed" | "updated";
      readonly rule: BadgeIssuanceRuleRecord;
      readonly version: BadgeIssuanceRuleVersionRecord;
      readonly pendingStepNumber: number | null;
    }
  | {
      readonly status: "failed";
      readonly reason: BadgeIssuanceRuleAuthoringFailureReason;
    };

/** Input for creating and optionally submitting one rule version atomically. */
export type CreateBadgeIssuanceRuleAuthoringInput = Omit<
  CreateBadgeIssuanceRuleInput,
  "createdByUserId"
> & {
  readonly action: BadgeIssuanceRuleAuthoringAction;
  readonly actorUserId: string;
  readonly actorRole: TenantMembershipRole;
  readonly builderDraftId?: string | undefined;
};

/** Input for updating and optionally submitting one rule version atomically. */
export type UpdateBadgeIssuanceRuleAuthoringInput = Omit<
  UpdateBadgeIssuanceRuleDraftInput,
  "createdByUserId"
> & {
  readonly action: BadgeIssuanceRuleAuthoringAction;
  readonly actorUserId: string;
  readonly actorRole: TenantMembershipRole;
};

export type ListBadgeIssuanceRulesInput = {
  readonly tenantId: string;
  readonly scope?:
    | {
        readonly type: "org_unit";
        readonly orgUnitId: string;
      }
    | {
        readonly type: "descendants";
        readonly rootOrgUnitIds: readonly string[];
      };
};

export interface ListBadgeIssuanceRuleVersionsInput {
  readonly tenantId: string;
  readonly ruleId: string;
}

/** Input for loading every saved version for a bounded set of rules. */
export interface ListBadgeIssuanceRuleVersionsForRulesInput {
  readonly tenantId: string;
  readonly ruleIds: readonly string[];
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

/** Input for returning the actor's pending submission to an editable draft. */
export interface WithdrawBadgeIssuanceRuleVersionSubmissionInput {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly actorUserId: string;
  readonly actorRole: TenantMembershipRole;
  readonly occurredAt?: string | undefined;
}

/** Input for correcting an accidental final approval before activation. */
export interface ReopenApprovedBadgeIssuanceRuleVersionInput {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly actorUserId: string;
  readonly actorRole: TenantMembershipRole;
  readonly comment: string;
  readonly occurredAt?: string | undefined;
}

/** Input for activating an approved rule version with its effective issuance window. */
export interface ActivateBadgeIssuanceRuleVersionInput {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly actorUserId: string;
  readonly effectiveStartsAt?: string | undefined;
  readonly expiresAt?: string | undefined;
  readonly activatedAt?: string | undefined;
}

export interface SuspendBadgeIssuanceRuleVersionInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  actorUserId: string;
  reason: string;
  occurredAt?: string | undefined;
}

export interface ResumeBadgeIssuanceRuleVersionInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  actorUserId: string;
  occurredAt?: string | undefined;
}

export interface UpdateBadgeIssuanceRuleVersionLifecycleInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  actorUserId: string;
  effectiveStartsAt?: string | undefined;
  expiresAt?: string | undefined;
  occurredAt?: string | undefined;
}

export type DecideBadgeIssuanceRuleVersionForbiddenStep = Pick<
  BadgeIssuanceRuleApprovalStepRecord,
  "targetType" | "requiredRole"
>;

export type DecideBadgeIssuanceRuleVersionResult =
  | {
      status: "decided";
      version: BadgeIssuanceRuleVersionRecord;
      decidedStepNumber: number;
      nextStepNumber: number | null;
    }
  | {
      status: "not_found";
    }
  | {
      status: "not_pending";
    }
  | {
      status: "no_pending_step";
    }
  | {
      status: "stale";
    }
  | {
      status: "separation_of_duties";
    }
  | {
      status: "forbidden";
      step: DecideBadgeIssuanceRuleVersionForbiddenStep;
    }
  | {
      status: "comment_required";
    };

export type SubmitBadgeIssuanceRuleVersionForApprovalResult =
  | {
      status: "submitted";
      version: BadgeIssuanceRuleVersionRecord;
      pendingStepNumber: number | null;
    }
  | {
      status: "not_found";
    }
  | {
      status: "not_submittable";
    }
  | {
      status: "self_certification_required";
    }
  | {
      status: "policy_missing_steps";
    };

/** Outcome of withdrawing a pending badge-rule submission. */
export type WithdrawBadgeIssuanceRuleVersionSubmissionResult =
  | {
      readonly status: "withdrawn";
      readonly version: BadgeIssuanceRuleVersionRecord;
    }
  | {
      readonly status: "not_found" | "not_pending" | "forbidden" | "stale";
    };

/** Outcome of reopening an approved badge-rule version before activation. */
export type ReopenApprovedBadgeIssuanceRuleVersionResult =
  | {
      readonly status: "reopened";
      readonly version: BadgeIssuanceRuleVersionRecord;
    }
  | {
      readonly status: "not_found" | "not_approved" | "forbidden" | "comment_required" | "stale";
    };

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

/** Input for loading approval history for a bounded set of rule versions. */
export interface ListBadgeIssuanceRuleVersionApprovalHistoryForVersionsInput {
  readonly tenantId: string;
  readonly versionIds: readonly string[];
}

export interface ListPendingBadgeIssuanceRuleApprovalsForActorInput {
  tenantId: string;
  actorUserId: string;
  actorRole: TenantMembershipRole;
  limit?: number | undefined;
}

export interface PendingBadgeIssuanceRuleApprovalRecord {
  tenantId: string;
  ruleId: string;
  versionName: string;
  badgeTemplateId: string;
  badgeTemplateTitle: string;
  orgUnitId: string;
  orgUnitDisplayName: string | null;
  versionId: string;
  versionNumber: number;
  versionCreatedByUserId: string | null;
  submittedByUserId: string | null;
  submittedByEmail: string | null;
  submittedAt: string | null;
  currentStep: BadgeIssuanceRuleApprovalStepRecord;
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
