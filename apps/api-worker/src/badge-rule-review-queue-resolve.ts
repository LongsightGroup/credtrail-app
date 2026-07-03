import {
  createAuditLog,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleEvaluationById,
  resolveBadgeIssuanceRuleEvaluationReview,
  type BadgeIssuanceRuleEvaluationRecord,
  type SqlDatabase,
  type TenantMembershipRole,
} from "@credtrail/db";
import type { ResolveBadgeIssuanceRuleReviewRequest } from "@credtrail/validation";
import { buildIssuanceProvenanceSnapshotFromEvaluationJson } from "@credtrail/validation";
import type { AppContext } from "./app";
import { withIssuanceProvenance } from "./badges/issue-badge-provenance";
import {
  isIssueBadgeHttpError,
  type IssueBadgeForTenant,
} from "./routes/badge-rule-evaluation-types";

export type ResolveBadgeRuleReviewQueueResult =
  | {
      ok: true;
      review: NonNullable<Awaited<ReturnType<typeof resolveBadgeIssuanceRuleEvaluationReview>>>;
      issuance: Awaited<ReturnType<IssueBadgeForTenant>> | null;
    }
  | {
      ok: false;
      status: 400 | 404 | 409 | 422 | 500 | 502;
      error: string;
      payload?: { error: string; did?: string | undefined };
    };

const ISSUE_RESOLVE_FAILURE_MESSAGE =
  "Badge was issued but this review entry could not be marked resolved. Refresh the queue; if it stays pending, contact support with the evaluation ID.";

const resolveReviewRecord = async (input: {
  db: SqlDatabase;
  tenantId: string;
  evaluationId: string;
  request: ResolveBadgeIssuanceRuleReviewRequest;
  reviewedByUserId: string;
  issuance: Awaited<ReturnType<IssueBadgeForTenant>> | null;
}): Promise<BadgeIssuanceRuleEvaluationRecord | null> => {
  return resolveBadgeIssuanceRuleEvaluationReview(input.db, {
    tenantId: input.tenantId,
    evaluationId: input.evaluationId,
    reviewDecision: input.request.decision,
    reviewComment: input.request.comment,
    reviewedByUserId: input.reviewedByUserId,
    issuanceStatus:
      input.request.decision === "issue"
        ? (input.issuance?.status ?? "issued")
        : "review_dismissed",
    assertionId: input.request.decision === "issue" ? input.issuance?.assertionId : undefined,
  });
};

const loadCurrentEvaluation = async (
  db: SqlDatabase,
  tenantId: string,
  evaluationId: string,
): Promise<BadgeIssuanceRuleEvaluationRecord | null> => {
  return findBadgeIssuanceRuleEvaluationById(db, {
    tenantId,
    evaluationId,
  });
};

const finalizeResolvedReview = async (input: {
  db: SqlDatabase;
  tenantId: string;
  evaluationId: string;
  request: ResolveBadgeIssuanceRuleReviewRequest;
  sessionUserId: string;
  membershipRole: TenantMembershipRole;
  evaluationRecord: BadgeIssuanceRuleEvaluationRecord;
  issuance: Awaited<ReturnType<IssueBadgeForTenant>> | null;
  resolved: BadgeIssuanceRuleEvaluationRecord;
}): Promise<ResolveBadgeRuleReviewQueueResult> => {
  await createAuditLog(input.db, {
    tenantId: input.tenantId,
    actorUserId: input.sessionUserId,
    action: "badge_rule.review_resolved",
    targetType: "badge_rule_evaluation",
    targetId: input.evaluationRecord.id,
    metadata: {
      role: input.membershipRole,
      ruleId: input.evaluationRecord.ruleId,
      versionId: input.evaluationRecord.versionId,
      decision: input.request.decision,
      issuanceStatus: input.resolved.issuanceStatus,
    },
  });

  return {
    ok: true,
    review: input.resolved,
    issuance: input.issuance,
  };
};

export const resolveBadgeRuleReviewQueueEntry = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  evaluationId: string;
  request: ResolveBadgeIssuanceRuleReviewRequest;
  session: { userId: string };
  membershipRole: TenantMembershipRole;
  issueBadgeForTenant: IssueBadgeForTenant;
}): Promise<ResolveBadgeRuleReviewQueueResult> => {
  const evaluationRecord = await loadCurrentEvaluation(
    input.db,
    input.tenantId,
    input.evaluationId,
  );

  if (evaluationRecord === null) {
    return {
      ok: false,
      status: 404,
      error: "Review queue entry not found",
    };
  }

  if (evaluationRecord.reviewStatus !== "pending") {
    return {
      ok: false,
      status: 409,
      error: "Review queue entry is no longer pending",
    };
  }

  const rule = await findBadgeIssuanceRuleById(input.db, input.tenantId, evaluationRecord.ruleId);

  if (rule === null) {
    return {
      ok: false,
      status: 404,
      error: "Badge rule not found for review queue entry",
    };
  }

  let issuance: Awaited<ReturnType<IssueBadgeForTenant>> | null = null;

  if (input.request.decision === "issue") {
    try {
      issuance = await input.issueBadgeForTenant(
        input.c,
        input.tenantId,
        withIssuanceProvenance(
          {
            badgeTemplateId: rule.badgeTemplateId,
            recipientIdentity: evaluationRecord.recipientIdentity,
            recipientIdentityType: evaluationRecord.recipientIdentityType,
            idempotencyKey: `rule-review:${evaluationRecord.id}`,
          },
          {
            source: "rule_evaluate",
            ruleId: evaluationRecord.ruleId,
            versionId: evaluationRecord.versionId,
            provenanceJson: buildIssuanceProvenanceSnapshotFromEvaluationJson({
              matched: evaluationRecord.matched,
              evaluationJson: evaluationRecord.evaluationJson,
              learnerId: evaluationRecord.learnerId,
              evaluatedAt: evaluationRecord.evaluatedAt,
            }),
          },
        ),
        input.session.userId,
      );
    } catch (error) {
      if (isIssueBadgeHttpError(error)) {
        return {
          ok: false,
          status: error.statusCode,
          error: error.payload.error,
          payload: error.payload,
        };
      }

      return {
        ok: false,
        status: 502,
        error: error instanceof Error ? error.message : "Failed to issue badge from review queue",
      };
    }
  }

  let resolved = await resolveReviewRecord({
    db: input.db,
    tenantId: input.tenantId,
    evaluationId: evaluationRecord.id,
    request: input.request,
    reviewedByUserId: input.session.userId,
    issuance,
  });

  if (resolved === null) {
    const current = await loadCurrentEvaluation(input.db, input.tenantId, evaluationRecord.id);

    if (current !== null && current.reviewStatus === "resolved") {
      resolved = current;
    } else if (
      input.request.decision === "issue" &&
      issuance !== null &&
      current !== null &&
      current.reviewStatus === "pending"
    ) {
      resolved = await resolveReviewRecord({
        db: input.db,
        tenantId: input.tenantId,
        evaluationId: evaluationRecord.id,
        request: input.request,
        reviewedByUserId: input.session.userId,
        issuance,
      });
    }
  }

  if (resolved === null) {
    if (issuance !== null) {
      return {
        ok: false,
        status: 500,
        error: ISSUE_RESOLVE_FAILURE_MESSAGE,
      };
    }

    return {
      ok: false,
      status: 409,
      error: "Review queue entry is no longer pending",
    };
  }

  return finalizeResolvedReview({
    db: input.db,
    tenantId: input.tenantId,
    evaluationId: evaluationRecord.id,
    request: input.request,
    sessionUserId: input.session.userId,
    membershipRole: input.membershipRole,
    evaluationRecord,
    issuance,
    resolved,
  });
};
