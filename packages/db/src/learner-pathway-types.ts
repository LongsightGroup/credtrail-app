export type LearnerPathwayStatus = "draft" | "published" | "retired";
export type LearnerPathwayVersionStatus = "draft" | "published" | "superseded";
export type LearnerPathwayCompletionBehavior =
  | "mark_complete"
  | "credential_eligible"
  | "review_required";
export type LearnerPathwayRequirementKind = "badge_template" | "learner_record";
export type LearnerPathwayRequirementState =
  | "met"
  | "not_recorded"
  | "in_review"
  | "waived"
  | "invalidated";
export type LearnerPathwayEvaluationResult =
  | "in_progress"
  | "needs_review"
  | "complete"
  | "invalidated";

export interface LearnerPathwayRequirementInput {
  title: string;
  description?: string | undefined;
  requirementKind: LearnerPathwayRequirementKind;
  badgeTemplateId?: string | undefined;
  learnerRecordType?: string | undefined;
}

export interface LearnerPathwayRequirementRecord {
  id: string;
  tenantId: string;
  pathwayVersionId: string;
  position: number;
  title: string;
  description: string | null;
  requirementKind: LearnerPathwayRequirementKind;
  badgeTemplateId: string | null;
  learnerRecordType: string | null;
}

export interface LearnerPathwayRecord {
  id: string;
  tenantId: string;
  ownerOrgUnitId: string;
  ownerOrgUnitName: string;
  status: LearnerPathwayStatus;
  currentPublishedVersionId: string | null;
  version: {
    id: string;
    number: number;
    status: LearnerPathwayVersionStatus;
    title: string;
    learnerDescription: string;
    completionBehavior: LearnerPathwayCompletionBehavior;
    finalBadgeTemplateId: string | null;
    publishedAt: string | null;
  };
  requirementCount: number;
  activeEnrollmentCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface LearnerPathwayRequirementEvaluation {
  requirementId: string;
  position: number;
  title: string;
  description: string | null;
  state: LearnerPathwayRequirementState;
  evidenceIds: readonly string[];
  rationale: string;
}

export interface LearnerPathwayEvaluationRecord {
  id: string;
  enrollmentId: string;
  pathwayVersionId: string;
  sequenceNumber: number;
  result: LearnerPathwayEvaluationResult;
  requirements: readonly LearnerPathwayRequirementEvaluation[];
  qualifyingEvidenceIds: readonly string[];
  rationale: string;
  evaluatedAt: string;
}

/** Canonical learner-facing progress state derived from evaluation and completion lifecycle. */
export type LearnerPathwayProgressState =
  | { readonly _tag: "in_progress" }
  | { readonly _tag: "invalidated" }
  | { readonly _tag: "complete" }
  | {
      readonly _tag: "eligible";
      readonly handoffId: string;
      readonly badgeTemplateId: string;
    }
  | {
      readonly _tag: "issued";
      readonly handoffId: string;
      readonly badgeTemplateId: string;
      readonly assertionPublicId: string;
    }
  | {
      readonly _tag: "needs_review";
      readonly handoffId: string;
      readonly badgeTemplateId: string;
    };

export interface LearnerPathwayProgressRecord {
  enrollmentId: string;
  pathwayId: string;
  pathwayVersionId: string;
  pathwayTitle: string;
  learnerDescription: string;
  ownerOrgUnitName: string;
  versionNumber: number;
  enrollmentStatus: "active" | "completed" | "withdrawn";
  completionBehavior: LearnerPathwayCompletionBehavior;
  evaluation: LearnerPathwayEvaluationRecord;
  evaluationHistory: readonly LearnerPathwayEvaluationRecord[];
  state: LearnerPathwayProgressState;
  nextRequirement: LearnerPathwayRequirementEvaluation | null;
  completedAt: string | null;
  enrolledAt: string;
}

export interface LearnerPathwayAdminProgressRecord extends LearnerPathwayProgressRecord {
  learnerProfileId: string;
  learnerDisplayName: string | null;
  learnerSubjectId: string;
}

export interface LearnerPathwayVersionSummaryRecord {
  id: string;
  number: number;
  status: LearnerPathwayVersionStatus;
  title: string;
  publishedAt: string | null;
  requirementCount: number;
}
