import {
  mapLearnerPathwayEvaluationRow,
  type LearnerPathwayEvaluationRow,
} from "./learner-pathway-evaluation-codec.js";
import { groupLearnerPathwayValues } from "./learner-pathway-collections.js";
import type {
  LearnerPathwayAdminProgressRecord,
  LearnerPathwayCompletionBehavior,
  LearnerPathwayEvaluationRecord,
  LearnerPathwayEvaluationResult,
  LearnerPathwayProgressRecord,
  LearnerPathwayProgressState,
} from "./learner-pathway-types.js";
import type { SqlDatabase } from "./tenant-scope.js";

const EVALUATION_HISTORY_LIMIT = 20;

interface EnrollmentContextRow {
  enrollmentId: string;
  pathwayId: string;
  pathwayVersionId: string;
  learnerProfileId: string;
  enrollmentStatus: "active" | "completed" | "withdrawn";
  enrolledAt: string;
  completedAt: string | null;
  pathwayTitle: string;
  learnerDescription: string;
  ownerOrgUnitName: string;
  versionNumber: number;
  completionBehavior: LearnerPathwayCompletionBehavior;
  finalBadgeTemplateId: string | null;
}
interface CompletionHandoffRow {
  id: string;
  status: "recorded" | "eligible" | "review_pending" | "issued" | "cancelled";
  badgeTemplateId: string | null;
  assertionPublicId: string | null;
}

interface ProgressProjectionRow extends EnrollmentContextRow {
  evaluationId: string;
  sequenceNumber: number;
  result: LearnerPathwayEvaluationResult;
  requirementResultsJson: string;
  qualifyingEvidenceIdsJson: string;
  rationale: string;
  evaluatedAt: string;
  handoffId: string | null;
  handoffStatus: CompletionHandoffRow["status"] | null;
  handoffBadgeTemplateId: string | null;
  assertionPublicId: string | null;
  learnerDisplayName: string | null;
  learnerSubjectId: string;
}

const completionStateFromRow = (
  row: CompletionHandoffRow | null,
  evaluationResult: LearnerPathwayEvaluationResult,
): LearnerPathwayProgressState => {
  if (row === null || row.status === "cancelled") {
    switch (evaluationResult) {
      case "complete":
        return { _tag: "complete" };
      case "invalidated":
        return { _tag: "invalidated" };
      case "in_progress":
        return { _tag: "in_progress" };
      case "needs_review":
        throw new Error("Stored review-required evaluation is missing its completion handoff");
    }
  }

  switch (row.status) {
    case "recorded":
      return { _tag: "complete" };
    case "eligible": {
      if (row.badgeTemplateId === null) {
        throw new Error(`Stored ${row.status} pathway handoff is missing its badge template`);
      }

      return {
        _tag: "eligible",
        handoffId: row.id,
        badgeTemplateId: row.badgeTemplateId,
      };
    }
    case "review_pending": {
      if (row.badgeTemplateId === null) {
        throw new Error(`Stored ${row.status} pathway handoff is missing its badge template`);
      }

      return {
        _tag: "needs_review",
        handoffId: row.id,
        badgeTemplateId: row.badgeTemplateId,
      };
    }
    case "issued": {
      if (row.badgeTemplateId === null || row.assertionPublicId === null) {
        throw new Error("Stored issued pathway handoff is missing issuance data");
      }

      return {
        _tag: "issued",
        handoffId: row.id,
        badgeTemplateId: row.badgeTemplateId,
        assertionPublicId: row.assertionPublicId,
      };
    }
  }
};
const learnerPathwayProgressFromRow = (
  context: ProgressProjectionRow,
  evaluationHistory: readonly LearnerPathwayEvaluationRecord[],
): LearnerPathwayProgressRecord => {
  const evaluation = mapLearnerPathwayEvaluationRow({
    id: context.evaluationId,
    enrollmentId: context.enrollmentId,
    pathwayVersionId: context.pathwayVersionId,
    sequenceNumber: context.sequenceNumber,
    result: context.result,
    requirementResultsJson: context.requirementResultsJson,
    qualifyingEvidenceIdsJson: context.qualifyingEvidenceIdsJson,
    rationale: context.rationale,
    evaluatedAt: context.evaluatedAt,
  });
  const completionHandoff: CompletionHandoffRow | null =
    context.handoffId === null || context.handoffStatus === null
      ? null
      : {
          id: context.handoffId,
          status: context.handoffStatus,
          badgeTemplateId: context.handoffBadgeTemplateId,
          assertionPublicId: context.assertionPublicId,
        };

  return {
    enrollmentId: context.enrollmentId,
    pathwayId: context.pathwayId,
    pathwayVersionId: context.pathwayVersionId,
    pathwayTitle: context.pathwayTitle,
    learnerDescription: context.learnerDescription,
    ownerOrgUnitName: context.ownerOrgUnitName,
    versionNumber: Number(context.versionNumber),
    enrollmentStatus: evaluation.result === "complete" ? "completed" : context.enrollmentStatus,
    completionBehavior: context.completionBehavior,
    evaluation,
    evaluationHistory,
    state: completionStateFromRow(completionHandoff, evaluation.result),
    nextRequirement:
      evaluation.requirements.find(
        (requirement) => requirement.state !== "met" && requirement.state !== "waived",
      ) ?? null,
    completedAt:
      evaluation.result === "complete"
        ? (context.completedAt ?? evaluation.evaluatedAt)
        : context.completedAt,
    enrolledAt: context.enrolledAt,
  };
};

const listLearnerPathwayProgressRows = async (
  db: SqlDatabase,
  input:
    | { readonly tenantId: string; readonly learnerProfileId: string }
    | { readonly tenantId: string; readonly pathwayId: string },
): Promise<ProgressProjectionRow[]> => {
  const filterColumn =
    "learnerProfileId" in input ? "enrollments.learner_profile_id" : "enrollments.pathway_id";
  const filterValue = "learnerProfileId" in input ? input.learnerProfileId : input.pathwayId;
  const rows = await db
    .prepare(
      `SELECT enrollments.id AS enrollmentId, enrollments.pathway_id AS pathwayId,
        enrollments.pathway_version_id AS pathwayVersionId,
        enrollments.learner_profile_id AS learnerProfileId,
        enrollments.status AS enrollmentStatus, enrollments.enrolled_at AS enrolledAt,
        enrollments.completed_at AS completedAt, versions.title AS pathwayTitle,
        versions.learner_description AS learnerDescription,
        org_units.display_name AS ownerOrgUnitName, versions.version_number AS versionNumber,
        versions.completion_behavior AS completionBehavior,
        versions.final_badge_template_id AS finalBadgeTemplateId,
        evaluations.id AS evaluationId, evaluations.sequence_number AS sequenceNumber,
        evaluations.result, evaluations.requirement_results_json AS requirementResultsJson,
        evaluations.qualifying_evidence_ids_json AS qualifyingEvidenceIdsJson,
        evaluations.rationale, evaluations.evaluated_at AS evaluatedAt,
        handoffs.id AS handoffId, handoffs.status AS handoffStatus,
        handoffs.badge_template_id AS handoffBadgeTemplateId,
        issued_assertions.public_id AS assertionPublicId,
        profiles.display_name AS learnerDisplayName, profiles.subject_id AS learnerSubjectId
       FROM learner_pathway_enrollments enrollments
       INNER JOIN learner_pathway_versions versions
         ON versions.tenant_id = enrollments.tenant_id AND versions.id = enrollments.pathway_version_id
       INNER JOIN learner_pathways pathways
         ON pathways.tenant_id = enrollments.tenant_id AND pathways.id = enrollments.pathway_id
       INNER JOIN tenant_org_units org_units
         ON org_units.tenant_id = pathways.tenant_id AND org_units.id = pathways.owner_org_unit_id
       INNER JOIN learner_profiles profiles
         ON profiles.tenant_id = enrollments.tenant_id
         AND profiles.id = enrollments.learner_profile_id
       INNER JOIN LATERAL (
         SELECT pathway_evaluations.*
         FROM learner_pathway_evaluations pathway_evaluations
         WHERE pathway_evaluations.tenant_id = enrollments.tenant_id
           AND pathway_evaluations.enrollment_id = enrollments.id
         ORDER BY pathway_evaluations.sequence_number DESC
         LIMIT 1
       ) evaluations ON TRUE
       LEFT JOIN learner_pathway_completion_handoffs handoffs
         ON handoffs.tenant_id = enrollments.tenant_id
         AND handoffs.enrollment_id = enrollments.id
       LEFT JOIN assertions issued_assertions
         ON issued_assertions.tenant_id = handoffs.tenant_id
         AND issued_assertions.id = handoffs.issued_assertion_id
       WHERE enrollments.tenant_id = ? AND ${filterColumn} = ?
         AND enrollments.status <> 'withdrawn'
       ORDER BY enrollments.enrolled_at DESC`,
    )
    .bind(input.tenantId, filterValue)
    .all<ProgressProjectionRow>();
  return rows.results;
};

const evaluationHistoryByEnrollmentId = async (
  db: SqlDatabase,
  tenantId: string,
  enrollmentIds: readonly string[],
): Promise<ReadonlyMap<string, readonly LearnerPathwayEvaluationRecord[]>> => {
  if (enrollmentIds.length === 0) {
    return new Map();
  }

  const result = await db
    .prepare(
      `SELECT id, enrollmentId, pathwayVersionId, sequenceNumber, result,
        requirementResultsJson, qualifyingEvidenceIdsJson, rationale, evaluatedAt
       FROM (
         SELECT id, enrollment_id AS enrollmentId, pathway_version_id AS pathwayVersionId,
           sequence_number AS sequenceNumber, result,
           requirement_results_json AS requirementResultsJson,
           qualifying_evidence_ids_json AS qualifyingEvidenceIdsJson,
           rationale, evaluated_at AS evaluatedAt,
           ROW_NUMBER() OVER (
             PARTITION BY enrollment_id
             ORDER BY sequence_number DESC
           ) AS historyRank
         FROM learner_pathway_evaluations
         WHERE tenant_id = ?
           AND enrollment_id IN (${enrollmentIds.map(() => "?").join(", ")})
       ) AS evaluation_history
       WHERE historyRank <= ?
       ORDER BY enrollmentId, sequenceNumber DESC`,
    )
    .bind(tenantId, ...enrollmentIds, EVALUATION_HISTORY_LIMIT)
    .all<LearnerPathwayEvaluationRow>();
  return groupLearnerPathwayValues(
    result.results.map(mapLearnerPathwayEvaluationRow),
    (evaluation) => evaluation.enrollmentId,
  );
};

export const listLearnerPathwayProgress = async (
  db: SqlDatabase,
  input: { tenantId: string; learnerProfileId: string },
): Promise<LearnerPathwayProgressRecord[]> => {
  const rows = await listLearnerPathwayProgressRows(db, input);
  const historyByEnrollmentId = await evaluationHistoryByEnrollmentId(
    db,
    input.tenantId,
    rows.map((row) => row.enrollmentId),
  );
  return rows.map((row) =>
    learnerPathwayProgressFromRow(row, historyByEnrollmentId.get(row.enrollmentId) ?? []),
  );
};

export const listLearnerPathwayAdminProgress = async (
  db: SqlDatabase,
  input: { tenantId: string; pathwayId: string },
): Promise<LearnerPathwayAdminProgressRecord[]> => {
  const rows = await listLearnerPathwayProgressRows(db, {
    tenantId: input.tenantId,
    pathwayId: input.pathwayId,
  });
  const historyByEnrollmentId = await evaluationHistoryByEnrollmentId(
    db,
    input.tenantId,
    rows.map((row) => row.enrollmentId),
  );
  return rows.map((row) => ({
    ...learnerPathwayProgressFromRow(row, historyByEnrollmentId.get(row.enrollmentId) ?? []),
    learnerProfileId: row.learnerProfileId,
    learnerDisplayName: row.learnerDisplayName,
    learnerSubjectId: row.learnerSubjectId,
  }));
};
