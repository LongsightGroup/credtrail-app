import { createAuditLog } from "./audit-logs";
import { groupLearnerPathwayValues } from "./learner-pathway-collections.js";
import {
  findLearnerPathwayById,
  listLearnerPathwayRequirements,
} from "./learner-pathway-definitions.js";
import {
  mapLearnerPathwayEvaluationRow,
  type LearnerPathwayEvaluationRow,
} from "./learner-pathway-evaluation-codec.js";
import { LearnerPathwayCommandError } from "./learner-pathway-errors";
import type {
  LearnerPathwayCompletionBehavior,
  LearnerPathwayEvaluationRecord,
  LearnerPathwayEvaluationResult,
  LearnerPathwayRequirementEvaluation,
  LearnerPathwayRequirementRecord,
  LearnerPathwayRequirementState,
} from "./learner-pathway-types.js";
import { createPrefixedId } from "./shared-helpers";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope";

export * from "./learner-pathway-definitions.js";
export * from "./learner-pathway-progress.js";
export type * from "./learner-pathway-types.js";

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

interface EvidenceRow {
  evidenceId: string;
  state: "active" | "revoked" | "expired";
}

interface RequirementWaiverRow {
  requirementId: string;
  evidenceId: string;
  reason: string;
}

interface BadgeEvidenceRow extends EvidenceRow {
  badgeTemplateId: string;
}

interface LearnerRecordEvidenceRow extends EvidenceRow {
  learnerRecordType: string;
}

const requiredText = (value: string, label: string): string => {
  const normalized = value.trim();

  if (normalized.length === 0) {
    throw new LearnerPathwayCommandError("invalid", `${label} is required`);
  }

  return normalized;
};

export const enrollLearnerInPathway = async (
  db: SqlDatabase,
  input: { tenantId: string; pathwayId: string; learnerProfileId: string; actorUserId: string },
): Promise<string> => {
  const pathway = await findLearnerPathwayById(db, input.tenantId, input.pathwayId);

  if (pathway === null || pathway.status !== "published") {
    throw new LearnerPathwayCommandError(
      pathway === null ? "not_found" : "conflict",
      "Learners can only be enrolled in a published pathway",
    );
  }

  const enrollmentId = createPrefixedId("pthe");
  const now = new Date().toISOString();
  await runSqlTransaction(db, async (transaction) => {
    const inserted = await transaction
      .prepare(
        `INSERT INTO learner_pathway_enrollments (
          id, tenant_id, pathway_id, pathway_version_id, learner_profile_id, status,
          enrolled_by_user_id, enrolled_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)
        ON CONFLICT (tenant_id, pathway_id, learner_profile_id) DO NOTHING
        RETURNING id`,
      )
      .bind(
        enrollmentId,
        input.tenantId,
        input.pathwayId,
        pathway.version.id,
        input.learnerProfileId,
        input.actorUserId,
        now,
        now,
      )
      .first<{ id: string }>();

    if (inserted === null) {
      throw new LearnerPathwayCommandError(
        "conflict",
        "The learner is already enrolled in this pathway",
      );
    }
    await createAuditLog(transaction, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "learner_pathway.enrolled",
      targetType: "learner_pathway_enrollment",
      targetId: enrollmentId,
      metadata: {
        pathwayId: input.pathwayId,
        pathwayVersionId: pathway.version.id,
        learnerProfileId: input.learnerProfileId,
      },
      occurredAt: now,
    });
  });

  await evaluateLearnerPathwayEnrollment(db, {
    tenantId: input.tenantId,
    enrollmentId,
    trigger: "enrollment",
  });
  return enrollmentId;
};

export const waiveLearnerPathwayRequirement = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    pathwayId: string;
    enrollmentId: string;
    requirementId: string;
    reason: string;
    actorUserId: string;
  },
): Promise<void> => {
  const waiverId = createPrefixedId("pthw");
  const now = new Date().toISOString();
  const reason = requiredText(input.reason, "Waiver reason");
  await runSqlTransaction(db, async (transaction) => {
    await transaction
      .prepare(
        `INSERT INTO learner_pathway_waivers (
          id, tenant_id, enrollment_id, requirement_id, reason, approved_by_user_id, approved_at
        )
        SELECT ?, ?, enrollments.id, requirements.id, ?, ?, ?
        FROM learner_pathway_enrollments enrollments
        INNER JOIN learner_pathway_requirements requirements
          ON requirements.tenant_id = enrollments.tenant_id
          AND requirements.pathway_version_id = enrollments.pathway_version_id
        WHERE enrollments.tenant_id = ? AND enrollments.pathway_id = ?
          AND enrollments.id = ? AND requirements.id = ?`,
      )
      .bind(
        waiverId,
        input.tenantId,
        reason,
        input.actorUserId,
        now,
        input.tenantId,
        input.pathwayId,
        input.enrollmentId,
        input.requirementId,
      )
      .run();
    const inserted = await transaction
      .prepare(
        `SELECT id FROM learner_pathway_waivers
         WHERE tenant_id = ? AND id = ? LIMIT 1`,
      )
      .bind(input.tenantId, waiverId)
      .first<{ id: string }>();

    if (inserted === null) {
      throw new LearnerPathwayCommandError(
        "invalid",
        "The requirement does not belong to this pathway enrollment",
      );
    }
    await createAuditLog(transaction, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "learner_pathway.requirement_waived",
      targetType: "learner_pathway_enrollment",
      targetId: input.enrollmentId,
      metadata: { requirementId: input.requirementId, waiverId, reason },
      occurredAt: now,
    });
  });
  await evaluateLearnerPathwayEnrollment(db, {
    tenantId: input.tenantId,
    enrollmentId: input.enrollmentId,
    trigger: "waiver",
  });
};

export const revokeLearnerPathwayRequirementWaiver = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    pathwayId: string;
    enrollmentId: string;
    requirementId: string;
    actorUserId: string;
  },
): Promise<void> => {
  const now = new Date().toISOString();
  await runSqlTransaction(db, async (transaction) => {
    const waiver = await transaction
      .prepare(
        `SELECT waivers.id
         FROM learner_pathway_waivers waivers
         INNER JOIN learner_pathway_enrollments enrollments
           ON enrollments.tenant_id = waivers.tenant_id
           AND enrollments.id = waivers.enrollment_id
         INNER JOIN learner_pathway_requirements requirements
           ON requirements.tenant_id = enrollments.tenant_id
           AND requirements.pathway_version_id = enrollments.pathway_version_id
           AND requirements.id = waivers.requirement_id
         WHERE waivers.tenant_id = ? AND enrollments.pathway_id = ?
           AND waivers.enrollment_id = ? AND waivers.requirement_id = ?
           AND waivers.revoked_at IS NULL
         LIMIT 1
         FOR UPDATE OF waivers`,
      )
      .bind(input.tenantId, input.pathwayId, input.enrollmentId, input.requirementId)
      .first<{ id: string }>();

    if (waiver === null) {
      throw new LearnerPathwayCommandError(
        "conflict",
        "An active exception was not found for this pathway requirement",
      );
    }

    await transaction
      .prepare(
        `UPDATE learner_pathway_waivers
         SET revoked_by_user_id = ?, revoked_at = ?
         WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`,
      )
      .bind(input.actorUserId, now, input.tenantId, waiver.id)
      .run();
    await createAuditLog(transaction, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "learner_pathway.requirement_waiver_revoked",
      targetType: "learner_pathway_enrollment",
      targetId: input.enrollmentId,
      metadata: { requirementId: input.requirementId, waiverId: waiver.id },
      occurredAt: now,
    });
  });
  await evaluateLearnerPathwayEnrollment(db, {
    tenantId: input.tenantId,
    enrollmentId: input.enrollmentId,
    trigger: "waiver_revoked",
  });
};

export const approveLearnerPathwayCompletionReview = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    pathwayId: string;
    enrollmentId: string;
    actorUserId: string;
  },
): Promise<void> => {
  const now = new Date().toISOString();
  await runSqlTransaction(db, async (transaction) => {
    const handoff = await transaction
      .prepare(
        `SELECT handoffs.id
         FROM learner_pathway_completion_handoffs handoffs
         INNER JOIN learner_pathway_enrollments enrollments
           ON enrollments.tenant_id = handoffs.tenant_id
           AND enrollments.id = handoffs.enrollment_id
         WHERE handoffs.tenant_id = ? AND enrollments.pathway_id = ?
           AND handoffs.enrollment_id = ? AND handoffs.status = 'review_pending'
         ORDER BY handoffs.created_at DESC, handoffs.id DESC
         LIMIT 1
         FOR UPDATE OF handoffs`,
      )
      .bind(input.tenantId, input.pathwayId, input.enrollmentId)
      .first<{ id: string }>();

    if (handoff === null) {
      throw new LearnerPathwayCommandError(
        "conflict",
        "A pending pathway completion review was not found",
      );
    }

    await transaction
      .prepare(
        `UPDATE learner_pathway_completion_handoffs
         SET status = 'eligible', resolved_by_user_id = ?, resolved_at = ?
         WHERE tenant_id = ? AND id = ? AND status = 'review_pending'`,
      )
      .bind(input.actorUserId, now, input.tenantId, handoff.id)
      .run();
    await transaction
      .prepare(
        `UPDATE learner_pathway_enrollments
         SET status = 'completed', completed_at = COALESCE(completed_at, ?), updated_at = ?
         WHERE tenant_id = ? AND id = ? AND status <> 'withdrawn'`,
      )
      .bind(now, now, input.tenantId, input.enrollmentId)
      .run();
    await createAuditLog(transaction, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "learner_pathway.completion_review_approved",
      targetType: "learner_pathway_completion_handoff",
      targetId: handoff.id,
      metadata: { pathwayId: input.pathwayId, enrollmentId: input.enrollmentId },
      occurredAt: now,
    });
  });
};

interface LearnerPathwayFinalCredentialIssuanceTarget {
  readonly tenantId: string;
  readonly handoffId: string;
  readonly learnerProfileId: string;
  readonly badgeTemplateId: string;
}

/** Locks and verifies an exact eligible completion handoff before issuance mutates related state. */
export const lockEligibleLearnerPathwayCompletionHandoff = async (
  db: SqlDatabase,
  input: LearnerPathwayFinalCredentialIssuanceTarget,
): Promise<boolean> => {
  const handoff = await db
    .prepare(
      `SELECT handoffs.id
       FROM learner_pathway_completion_handoffs AS handoffs
       INNER JOIN learner_pathway_enrollments AS enrollments
         ON enrollments.tenant_id = handoffs.tenant_id
         AND enrollments.id = handoffs.enrollment_id
       WHERE handoffs.tenant_id = ?
         AND handoffs.id = ?
         AND enrollments.learner_profile_id = ?
         AND handoffs.badge_template_id = ?
         AND handoffs.status = 'eligible'
       LIMIT 1
       FOR UPDATE OF handoffs`,
    )
    .bind(input.tenantId, input.handoffId, input.learnerProfileId, input.badgeTemplateId)
    .first<{ id: string }>();

  return handoff !== null;
};

export const recordLearnerPathwayFinalCredentialIssuance = async (
  db: SqlDatabase,
  input: LearnerPathwayFinalCredentialIssuanceTarget & {
    assertionId: string;
    actorUserId?: string | undefined;
    issuedAt: string;
  },
): Promise<boolean> => {
  const handoff = await db
    .prepare(
      `WITH issued_handoff AS (
         UPDATE learner_pathway_completion_handoffs AS handoffs
         SET status = 'issued', issued_assertion_id = ?, issued_at = ?,
           resolved_by_user_id = COALESCE(resolved_by_user_id, ?),
           resolved_at = COALESCE(resolved_at, ?)
         FROM learner_pathway_enrollments AS enrollments
         WHERE enrollments.tenant_id = handoffs.tenant_id
           AND enrollments.id = handoffs.enrollment_id
           AND handoffs.tenant_id = ?
           AND handoffs.id = ?
           AND enrollments.learner_profile_id = ?
           AND handoffs.badge_template_id = ?
           AND handoffs.status = 'eligible'
         RETURNING handoffs.id, handoffs.enrollment_id
       ), completed_enrollment AS (
         UPDATE learner_pathway_enrollments AS enrollments
         SET status = 'completed',
           completed_at = COALESCE(enrollments.completed_at, ?),
           updated_at = ?
         FROM issued_handoff
         WHERE enrollments.tenant_id = ?
           AND enrollments.id = issued_handoff.enrollment_id
           AND enrollments.status <> 'withdrawn'
         RETURNING enrollments.id
       )
       SELECT id FROM issued_handoff`,
    )
    .bind(
      input.assertionId,
      input.issuedAt,
      input.actorUserId ?? null,
      input.issuedAt,
      input.tenantId,
      input.handoffId,
      input.learnerProfileId,
      input.badgeTemplateId,
      input.issuedAt,
      input.issuedAt,
      input.tenantId,
    )
    .first<{ id: string }>();

  if (handoff === null) {
    return false;
  }

  await createAuditLog(db, {
    tenantId: input.tenantId,
    actorUserId: input.actorUserId,
    action: "learner_pathway.final_credential_issued",
    targetType: "learner_pathway_completion_handoff",
    targetId: handoff.id,
    metadata: { assertionId: input.assertionId, badgeTemplateId: input.badgeTemplateId },
    occurredAt: input.issuedAt,
  });
  return true;
};

const findEnrollmentContext = async (
  db: SqlDatabase,
  tenantId: string,
  enrollmentId: string,
): Promise<EnrollmentContextRow | null> => {
  return db
    .prepare(
      `SELECT enrollments.id AS enrollmentId, enrollments.pathway_id AS pathwayId,
        enrollments.pathway_version_id AS pathwayVersionId,
        enrollments.learner_profile_id AS learnerProfileId,
        enrollments.status AS enrollmentStatus, enrollments.enrolled_at AS enrolledAt,
        enrollments.completed_at AS completedAt, versions.title AS pathwayTitle,
        versions.learner_description AS learnerDescription,
        org_units.display_name AS ownerOrgUnitName, versions.version_number AS versionNumber,
        versions.completion_behavior AS completionBehavior,
        versions.final_badge_template_id AS finalBadgeTemplateId
       FROM learner_pathway_enrollments enrollments
       INNER JOIN learner_pathway_versions versions
         ON versions.tenant_id = enrollments.tenant_id AND versions.id = enrollments.pathway_version_id
       INNER JOIN tenant_org_units org_units
         ON org_units.tenant_id = enrollments.tenant_id
       INNER JOIN learner_pathways pathways
         ON pathways.tenant_id = enrollments.tenant_id AND pathways.id = enrollments.pathway_id
         AND org_units.id = pathways.owner_org_unit_id
       WHERE enrollments.tenant_id = ? AND enrollments.id = ? LIMIT 1`,
    )
    .bind(tenantId, enrollmentId)
    .first<EnrollmentContextRow>();
};

const listRequirementEvidence = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    learnerProfileId: string;
    enrollmentId: string;
    requirements: readonly LearnerPathwayRequirementRecord[];
  },
): Promise<LearnerPathwayRequirementEvaluation[]> => {
  const requirementIds = input.requirements.map((requirement) => requirement.id);
  const badgeTemplateIds = Array.from(
    new Set(
      input.requirements.flatMap((requirement) =>
        requirement.requirementKind === "badge_template" && requirement.badgeTemplateId !== null
          ? [requirement.badgeTemplateId]
          : [],
      ),
    ),
  );
  const learnerRecordTypes = Array.from(
    new Set(
      input.requirements.flatMap((requirement) =>
        requirement.requirementKind === "learner_record" && requirement.learnerRecordType !== null
          ? [requirement.learnerRecordType]
          : [],
      ),
    ),
  );
  const waiverResult = await db
    .prepare(
      `SELECT requirement_id AS requirementId, id AS evidenceId, reason
       FROM learner_pathway_waivers
       WHERE tenant_id = ? AND enrollment_id = ?
         AND requirement_id IN (${requirementIds.map(() => "?").join(", ")})
         AND revoked_at IS NULL`,
    )
    .bind(input.tenantId, input.enrollmentId, ...requirementIds)
    .all<RequirementWaiverRow>();
  const badgeEvidence: readonly BadgeEvidenceRow[] =
    badgeTemplateIds.length === 0
      ? []
      : await db
          .prepare(
            `SELECT badge_template_id AS badgeTemplateId, id AS evidenceId,
              CASE WHEN revoked_at IS NULL THEN 'active' ELSE 'revoked' END AS state
             FROM assertions
             WHERE tenant_id = ? AND learner_profile_id = ?
               AND badge_template_id IN (${badgeTemplateIds.map(() => "?").join(", ")})
             ORDER BY issued_at DESC`,
          )
          .bind(input.tenantId, input.learnerProfileId, ...badgeTemplateIds)
          .all<BadgeEvidenceRow>()
          .then((result) => result.results);
  const learnerRecordEvidence: readonly LearnerRecordEvidenceRow[] =
    learnerRecordTypes.length === 0
      ? []
      : await db
          .prepare(
            `SELECT record_type AS learnerRecordType, id AS evidenceId, status AS state
             FROM learner_record_entries
             WHERE tenant_id = ? AND learner_profile_id = ? AND trust_level = 'issuer_verified'
               AND record_type IN (${learnerRecordTypes.map(() => "?").join(", ")})
             ORDER BY issued_at DESC`,
          )
          .bind(input.tenantId, input.learnerProfileId, ...learnerRecordTypes)
          .all<LearnerRecordEvidenceRow>()
          .then((result) => result.results);
  const waiversByRequirementId = new Map(
    waiverResult.results.map((waiver) => [waiver.requirementId, waiver]),
  );
  const evidenceByBadgeTemplateId = groupLearnerPathwayValues(
    badgeEvidence,
    (evidence) => evidence.badgeTemplateId,
  );
  const evidenceByLearnerRecordType = groupLearnerPathwayValues(
    learnerRecordEvidence,
    (evidence) => evidence.learnerRecordType,
  );

  return input.requirements.map((requirement) => {
    const waiver = waiversByRequirementId.get(requirement.id);

    if (waiver !== undefined) {
      return {
        requirementId: requirement.id,
        position: requirement.position,
        title: requirement.title,
        description: requirement.description,
        state: "waived",
        evidenceIds: [waiver.evidenceId],
        rationale: `Approved exception: ${waiver.reason}`,
      };
    }

    const evidence =
      requirement.requirementKind === "badge_template"
        ? (evidenceByBadgeTemplateId.get(requirement.badgeTemplateId ?? "") ?? [])
        : (evidenceByLearnerRecordType.get(requirement.learnerRecordType ?? "") ?? []);
    const activeEvidenceIds = evidence
      .filter((entry) => entry.state === "active")
      .map((entry) => entry.evidenceId);
    const state: LearnerPathwayRequirementState =
      activeEvidenceIds.length > 0 ? "met" : evidence.length > 0 ? "invalidated" : "not_recorded";

    return {
      requirementId: requirement.id,
      position: requirement.position,
      title: requirement.title,
      description: requirement.description,
      state,
      evidenceIds:
        activeEvidenceIds.length > 0
          ? activeEvidenceIds
          : evidence.map((entry) => entry.evidenceId),
      rationale:
        state === "met"
          ? "Institution-verified evidence is current"
          : state === "invalidated"
            ? "Previously recorded evidence is revoked or expired"
            : "No qualifying evidence recorded",
    };
  });
};

const findLatestEvaluation = async (
  db: SqlDatabase,
  tenantId: string,
  enrollmentId: string,
): Promise<LearnerPathwayEvaluationRecord | null> => {
  const row = await db
    .prepare(
      `SELECT id, enrollment_id AS enrollmentId, pathway_version_id AS pathwayVersionId,
        sequence_number AS sequenceNumber, result, requirement_results_json AS requirementResultsJson,
        qualifying_evidence_ids_json AS qualifyingEvidenceIdsJson, rationale, evaluated_at AS evaluatedAt
       FROM learner_pathway_evaluations
       WHERE tenant_id = ? AND enrollment_id = ?
       ORDER BY sequence_number DESC LIMIT 1`,
    )
    .bind(tenantId, enrollmentId)
    .first<LearnerPathwayEvaluationRow>();
  return row === null ? null : mapLearnerPathwayEvaluationRow(row);
};

interface EvaluateLearnerPathwayEnrollmentInput {
  readonly tenantId: string;
  readonly enrollmentId: string;
  readonly trigger: string;
}

const evaluateLearnerPathwayEnrollmentInTransaction = async (
  db: SqlDatabase,
  input: EvaluateLearnerPathwayEnrollmentInput,
): Promise<LearnerPathwayEvaluationRecord> => {
  await db
    .prepare("SELECT pg_advisory_xact_lock(hashtext(?))")
    .bind(`learner-pathway-evaluation:${input.tenantId}:${input.enrollmentId}`)
    .run();
  const context = await findEnrollmentContext(db, input.tenantId, input.enrollmentId);

  if (context === null) {
    throw new LearnerPathwayCommandError("not_found", "Pathway enrollment not found");
  }

  const requirements = await listLearnerPathwayRequirements(
    db,
    input.tenantId,
    context.pathwayVersionId,
  );
  const requirementResults = await listRequirementEvidence(db, {
    tenantId: input.tenantId,
    learnerProfileId: context.learnerProfileId,
    enrollmentId: context.enrollmentId,
    requirements,
  });

  const allSatisfied = requirementResults.every(
    (requirement) => requirement.state === "met" || requirement.state === "waived",
  );
  const hasInvalidatedEvidence = requirementResults.some(
    (requirement) => requirement.state === "invalidated",
  );
  const result: LearnerPathwayEvaluationResult = allSatisfied
    ? context.completionBehavior === "review_required"
      ? "needs_review"
      : "complete"
    : hasInvalidatedEvidence
      ? "invalidated"
      : "in_progress";
  const qualifyingEvidenceIds = Array.from(
    new Set(requirementResults.flatMap((requirement) => requirement.evidenceIds)),
  );
  const requirementResultsJson = JSON.stringify(requirementResults);
  const evidenceJson = JSON.stringify(qualifyingEvidenceIds);
  const rationale = allSatisfied
    ? context.completionBehavior === "review_required"
      ? "All requirements are satisfied; final credential review is required"
      : "All pathway requirements are satisfied"
    : hasInvalidatedEvidence
      ? "One or more prior evidence items are no longer current"
      : "One or more pathway requirements have no qualifying evidence";

  const latest = await findLatestEvaluation(db, input.tenantId, input.enrollmentId);

  if (
    latest !== null &&
    latest.result === result &&
    JSON.stringify(latest.requirements) === requirementResultsJson
  ) {
    return latest;
  }

  const evaluationId = createPrefixedId("pthev");
  const now = new Date().toISOString();
  const sequenceNumber = (latest?.sequenceNumber ?? 0) + 1;
  await db
    .prepare(
      `INSERT INTO learner_pathway_evaluations (
          id, tenant_id, enrollment_id, pathway_version_id, sequence_number, result,
          requirement_results_json, qualifying_evidence_ids_json, rationale, evaluated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      evaluationId,
      input.tenantId,
      input.enrollmentId,
      context.pathwayVersionId,
      sequenceNumber,
      result,
      requirementResultsJson,
      evidenceJson,
      rationale,
      now,
    )
    .run();

  if (result === "complete" || result === "needs_review") {
    const handoffStatus =
      context.completionBehavior === "mark_complete"
        ? "recorded"
        : context.completionBehavior === "credential_eligible"
          ? "eligible"
          : "review_pending";
    await db
      .prepare(
        `INSERT INTO learner_pathway_completion_handoffs (
            id, tenant_id, enrollment_id, evaluation_id, behavior, badge_template_id, status, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT (tenant_id, enrollment_id) DO UPDATE SET
            evaluation_id = EXCLUDED.evaluation_id,
            behavior = EXCLUDED.behavior,
            badge_template_id = EXCLUDED.badge_template_id,
            status = EXCLUDED.status,
            created_at = EXCLUDED.created_at,
            resolved_by_user_id = NULL,
            resolved_at = NULL,
            issued_assertion_id = NULL,
            issued_at = NULL
          WHERE learner_pathway_completion_handoffs.status <> 'issued'`,
      )
      .bind(
        createPrefixedId("pthh"),
        input.tenantId,
        input.enrollmentId,
        evaluationId,
        context.completionBehavior,
        context.finalBadgeTemplateId,
        handoffStatus,
        now,
      )
      .run();
  } else {
    await db
      .prepare(
        `UPDATE learner_pathway_completion_handoffs
           SET status = 'cancelled', evaluation_id = ?, badge_template_id = NULL,
             resolved_by_user_id = NULL, resolved_at = NULL
           WHERE tenant_id = ? AND enrollment_id = ? AND status <> 'issued'`,
      )
      .bind(evaluationId, input.tenantId, input.enrollmentId)
      .run();
  }

  const completed = result === "complete";
  await db
    .prepare(
      `UPDATE learner_pathway_enrollments AS enrollments
       SET status = ?, completed_at = ?, updated_at = ?
       WHERE tenant_id = ? AND id = ? AND status <> 'withdrawn'
         AND NOT EXISTS (
           SELECT 1
           FROM learner_pathway_completion_handoffs AS issued_handoffs
           WHERE issued_handoffs.tenant_id = enrollments.tenant_id
             AND issued_handoffs.enrollment_id = enrollments.id
             AND issued_handoffs.status = 'issued'
         )`,
    )
    .bind(
      completed ? "completed" : "active",
      completed ? (context.completedAt ?? now) : context.completedAt,
      now,
      input.tenantId,
      input.enrollmentId,
    )
    .run();
  await createAuditLog(db, {
    tenantId: input.tenantId,
    action: "learner_pathway.evaluated",
    targetType: "learner_pathway_enrollment",
    targetId: input.enrollmentId,
    metadata: {
      evaluationId,
      pathwayVersionId: context.pathwayVersionId,
      result,
      trigger: input.trigger,
      qualifyingEvidenceIds,
    },
    occurredAt: now,
  });

  return {
    id: evaluationId,
    enrollmentId: input.enrollmentId,
    pathwayVersionId: context.pathwayVersionId,
    sequenceNumber,
    result,
    requirements: requirementResults,
    qualifyingEvidenceIds,
    rationale,
    evaluatedAt: now,
  };
};

export const evaluateLearnerPathwayEnrollment = async (
  db: SqlDatabase,
  input: EvaluateLearnerPathwayEnrollmentInput,
): Promise<LearnerPathwayEvaluationRecord> => {
  return runSqlTransaction(db, (transaction) =>
    evaluateLearnerPathwayEnrollmentInTransaction(transaction, input),
  );
};

export const reevaluateLearnerPathwaysForLearner = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    learnerProfileId: string;
    trigger: string;
    afterEnrollmentId?: string | undefined;
    limit?: number | undefined;
  },
): Promise<{
  readonly evaluations: readonly LearnerPathwayEvaluationRecord[];
  readonly nextEnrollmentId: string | null;
}> => {
  const limit = input.limit ?? 25;

  if (!Number.isInteger(limit) || limit < 1 || limit > 50) {
    throw new Error("Learner pathway reevaluation limit must be between 1 and 50");
  }

  const enrollments = await db
    .prepare(
      `SELECT id FROM learner_pathway_enrollments
       WHERE tenant_id = ? AND learner_profile_id = ? AND status <> 'withdrawn'
         ${input.afterEnrollmentId === undefined ? "" : "AND id > ?"}
       ORDER BY id ASC
       LIMIT ?`,
    )
    .bind(
      input.tenantId,
      input.learnerProfileId,
      ...(input.afterEnrollmentId === undefined ? [] : [input.afterEnrollmentId]),
      limit + 1,
    )
    .all<{ id: string }>();
  const page = enrollments.results.slice(0, limit);
  const evaluations: LearnerPathwayEvaluationRecord[] = [];

  for (const enrollment of page) {
    evaluations.push(
      await evaluateLearnerPathwayEnrollment(db, {
        tenantId: input.tenantId,
        enrollmentId: enrollment.id,
        trigger: input.trigger,
      }),
    );
  }

  return {
    evaluations,
    nextEnrollmentId: enrollments.results.length > limit ? (page.at(-1)?.id ?? null) : null,
  };
};
