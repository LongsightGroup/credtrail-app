import { createAuditLog } from "./audit-logs";
import { findBadgeTemplateById } from "./badge-templates";
import { createPrefixedId } from "./shared-helpers";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope";
import { findTenantOrgUnitById } from "./tenant-org-units";

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
  completionHandoff: {
    id: string;
    status: "recorded" | "eligible" | "review_pending" | "issued" | "cancelled";
    badgeTemplateId: string | null;
    assertionPublicId: string | null;
  } | null;
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

interface PathwayRow {
  id: string;
  tenantId: string;
  ownerOrgUnitId: string;
  ownerOrgUnitName: string;
  status: LearnerPathwayStatus;
  currentPublishedVersionId: string | null;
  versionId: string;
  versionNumber: number;
  versionStatus: LearnerPathwayVersionStatus;
  title: string;
  learnerDescription: string;
  completionBehavior: LearnerPathwayCompletionBehavior;
  finalBadgeTemplateId: string | null;
  publishedAt: string | null;
  requirementCount: number;
  activeEnrollmentCount: number;
  createdAt: string;
  updatedAt: string;
}

interface RequirementRow {
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

interface EvaluationRow {
  id: string;
  enrollmentId: string;
  pathwayVersionId: string;
  sequenceNumber: number;
  result: LearnerPathwayEvaluationResult;
  requirementResultsJson: string;
  qualifyingEvidenceIdsJson: string;
  rationale: string;
  evaluatedAt: string;
}

interface VersionSummaryRow {
  id: string;
  number: number;
  status: LearnerPathwayVersionStatus;
  title: string;
  publishedAt: string | null;
  requirementCount: number;
}

interface CompletionHandoffRow {
  id: string;
  status: "recorded" | "eligible" | "review_pending" | "issued" | "cancelled";
  badgeTemplateId: string | null;
  assertionPublicId: string | null;
}

const requiredText = (value: string, label: string): string => {
  const normalized = value.trim();

  if (normalized.length === 0) {
    throw new Error(`${label} is required`);
  }

  return normalized;
};

const optionalText = (value: string | undefined): string | null => {
  const normalized = value?.trim() ?? "";
  return normalized.length === 0 ? null : normalized;
};

const assertPathwayReferencesAvailable = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ownerOrgUnitId: string;
    finalBadgeTemplateId?: string | undefined;
    requirements: readonly LearnerPathwayRequirementInput[];
  },
): Promise<void> => {
  if (
    input.finalBadgeTemplateId !== undefined &&
    input.requirements.some(
      (requirement) =>
        requirement.requirementKind === "badge_template" &&
        requirement.badgeTemplateId === input.finalBadgeTemplateId,
    )
  ) {
    throw new Error("The final credential cannot also be one of its pathway requirements");
  }

  const owner = await findTenantOrgUnitById(db, input.tenantId, input.ownerOrgUnitId);

  if (owner === null || !owner.isActive) {
    throw new Error("Pathway owner must be an active organization unit");
  }

  const badgeTemplateIds = new Set(
    input.requirements.flatMap((requirement) =>
      requirement.requirementKind === "badge_template" && requirement.badgeTemplateId !== undefined
        ? [requirement.badgeTemplateId]
        : [],
    ),
  );

  if (input.finalBadgeTemplateId !== undefined) {
    badgeTemplateIds.add(input.finalBadgeTemplateId);
  }

  for (const badgeTemplateId of badgeTemplateIds) {
    const template = await findBadgeTemplateById(db, input.tenantId, badgeTemplateId);

    if (template === null || template.isArchived) {
      throw new Error("Pathway credentials must use active badge templates from this organization");
    }
  }
};

const mapPathway = (row: PathwayRow): LearnerPathwayRecord => ({
  id: row.id,
  tenantId: row.tenantId,
  ownerOrgUnitId: row.ownerOrgUnitId,
  ownerOrgUnitName: row.ownerOrgUnitName,
  status: row.status,
  currentPublishedVersionId: row.currentPublishedVersionId,
  version: {
    id: row.versionId,
    number: row.versionNumber,
    status: row.versionStatus,
    title: row.title,
    learnerDescription: row.learnerDescription,
    completionBehavior: row.completionBehavior,
    finalBadgeTemplateId: row.finalBadgeTemplateId,
    publishedAt: row.publishedAt,
  },
  requirementCount: Number(row.requirementCount),
  activeEnrollmentCount: Number(row.activeEnrollmentCount),
  createdAt: row.createdAt,
  updatedAt: row.updatedAt,
});

const mapRequirement = (row: RequirementRow): LearnerPathwayRequirementRecord => ({
  ...row,
  position: Number(row.position),
});

const pathwaySelect = `
  SELECT
    pathways.id,
    pathways.tenant_id AS tenantId,
    pathways.owner_org_unit_id AS ownerOrgUnitId,
    org_units.display_name AS ownerOrgUnitName,
    pathways.status,
    pathways.current_published_version_id AS currentPublishedVersionId,
    versions.id AS versionId,
    versions.version_number AS versionNumber,
    versions.status AS versionStatus,
    versions.title,
    versions.learner_description AS learnerDescription,
    versions.completion_behavior AS completionBehavior,
    versions.final_badge_template_id AS finalBadgeTemplateId,
    versions.published_at AS publishedAt,
    (SELECT COUNT(*) FROM learner_pathway_requirements requirements
      WHERE requirements.tenant_id = pathways.tenant_id
        AND requirements.pathway_version_id = versions.id) AS requirementCount,
    (SELECT COUNT(*) FROM learner_pathway_enrollments enrollments
      WHERE enrollments.tenant_id = pathways.tenant_id
        AND enrollments.pathway_id = pathways.id
        AND enrollments.status = 'active') AS activeEnrollmentCount,
    pathways.created_at AS createdAt,
    pathways.updated_at AS updatedAt
  FROM learner_pathways pathways
  INNER JOIN tenant_org_units org_units
    ON org_units.tenant_id = pathways.tenant_id
    AND org_units.id = pathways.owner_org_unit_id
  INNER JOIN learner_pathway_versions versions
    ON versions.tenant_id = pathways.tenant_id
    AND versions.pathway_id = pathways.id
`;

export const createLearnerPathwayDraft = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ownerOrgUnitId: string;
    title: string;
    learnerDescription: string;
    completionBehavior: LearnerPathwayCompletionBehavior;
    finalBadgeTemplateId?: string | undefined;
    requirements: readonly LearnerPathwayRequirementInput[];
    actorUserId: string;
  },
): Promise<LearnerPathwayRecord> => {
  if (input.requirements.length === 0) {
    throw new Error("At least one pathway requirement is required");
  }

  const pathwayId = createPrefixedId("pth");
  const versionId = createPrefixedId("pthv");
  const now = new Date().toISOString();
  const title = requiredText(input.title, "Pathway title");
  const description = requiredText(input.learnerDescription, "Learner description");

  await assertPathwayReferencesAvailable(db, input);

  await runSqlTransaction(db, async (transaction) => {
    await transaction
      .prepare(
        `INSERT INTO learner_pathways (
          id, tenant_id, owner_org_unit_id, status, created_by_user_id, created_at, updated_at
        ) VALUES (?, ?, ?, 'draft', ?, ?, ?)`,
      )
      .bind(pathwayId, input.tenantId, input.ownerOrgUnitId, input.actorUserId, now, now)
      .run();
    await transaction
      .prepare(
        `INSERT INTO learner_pathway_versions (
          id, tenant_id, pathway_id, version_number, status, title, learner_description,
          completion_behavior, final_badge_template_id, created_by_user_id, created_at, updated_at
        ) VALUES (?, ?, ?, 1, 'draft', ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        versionId,
        input.tenantId,
        pathwayId,
        title,
        description,
        input.completionBehavior,
        input.finalBadgeTemplateId ?? null,
        input.actorUserId,
        now,
        now,
      )
      .run();

    for (const [index, requirement] of input.requirements.entries()) {
      await transaction
        .prepare(
          `INSERT INTO learner_pathway_requirements (
            id, tenant_id, pathway_version_id, position, title, description, requirement_kind,
            badge_template_id, learner_record_type, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          createPrefixedId("pthr"),
          input.tenantId,
          versionId,
          index + 1,
          requiredText(requirement.title, "Requirement title"),
          optionalText(requirement.description),
          requirement.requirementKind,
          requirement.badgeTemplateId ?? null,
          requirement.learnerRecordType ?? null,
          now,
        )
        .run();
    }

    await createAuditLog(transaction, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "learner_pathway.created",
      targetType: "learner_pathway",
      targetId: pathwayId,
      metadata: { versionId, requirementCount: input.requirements.length },
      occurredAt: now,
    });
  });

  const created = await findLearnerPathwayById(db, input.tenantId, pathwayId);

  if (created === null) {
    throw new Error(`Unable to load learner pathway "${pathwayId}"`);
  }

  return created;
};

export const listLearnerPathways = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<LearnerPathwayRecord[]> => {
  const result = await db
    .prepare(
      `${pathwaySelect}
       WHERE pathways.tenant_id = ?
         AND (versions.id = pathways.current_published_version_id OR versions.status = 'draft')
       ORDER BY pathways.updated_at DESC, pathways.id DESC,
         CASE WHEN versions.status = 'draft' THEN 0 ELSE 1 END`,
    )
    .bind(tenantId)
    .all<PathwayRow>();
  const seen = new Set<string>();
  return result.results.flatMap((row) => {
    if (seen.has(row.id)) {
      return [];
    }

    seen.add(row.id);
    return [mapPathway(row)];
  });
};

export const findLearnerPathwayById = async (
  db: SqlDatabase,
  tenantId: string,
  pathwayId: string,
): Promise<LearnerPathwayRecord | null> => {
  const row = await db
    .prepare(
      `${pathwaySelect}
       WHERE pathways.tenant_id = ? AND pathways.id = ?
       ORDER BY CASE WHEN versions.id = pathways.current_published_version_id THEN 0 ELSE 1 END,
         versions.version_number DESC
       LIMIT 1`,
    )
    .bind(tenantId, pathwayId)
    .first<PathwayRow>();
  return row === null ? null : mapPathway(row);
};

export const findLearnerPathwayDraft = async (
  db: SqlDatabase,
  tenantId: string,
  pathwayId: string,
): Promise<LearnerPathwayRecord | null> => {
  const row = await db
    .prepare(
      `${pathwaySelect}
       WHERE pathways.tenant_id = ? AND pathways.id = ? AND versions.status = 'draft'
       ORDER BY versions.version_number DESC LIMIT 1`,
    )
    .bind(tenantId, pathwayId)
    .first<PathwayRow>();
  return row === null ? null : mapPathway(row);
};

export const findLearnerPathwayVersion = async (
  db: SqlDatabase,
  input: { tenantId: string; pathwayId: string; pathwayVersionId: string },
): Promise<LearnerPathwayRecord | null> => {
  const row = await db
    .prepare(
      `${pathwaySelect}
       WHERE pathways.tenant_id = ? AND pathways.id = ? AND versions.id = ?
       LIMIT 1`,
    )
    .bind(input.tenantId, input.pathwayId, input.pathwayVersionId)
    .first<PathwayRow>();
  return row === null ? null : mapPathway(row);
};

export const updateLearnerPathwayDraft = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    pathwayId: string;
    ownerOrgUnitId: string;
    title: string;
    learnerDescription: string;
    completionBehavior: LearnerPathwayCompletionBehavior;
    finalBadgeTemplateId?: string | undefined;
    requirements: readonly LearnerPathwayRequirementInput[];
    actorUserId: string;
  },
): Promise<LearnerPathwayRecord> => {
  if (input.requirements.length === 0) {
    throw new Error("At least one pathway requirement is required");
  }

  const draft = await findLearnerPathwayDraft(db, input.tenantId, input.pathwayId);

  if (draft === null || draft.status === "retired") {
    throw new Error("Pathway draft not found");
  }

  await assertPathwayReferencesAvailable(db, input);

  const now = new Date().toISOString();
  await runSqlTransaction(db, async (transaction) => {
    await transaction
      .prepare(
        `UPDATE learner_pathways SET owner_org_unit_id = ?, updated_at = ?
         WHERE tenant_id = ? AND id = ? AND status <> 'retired'`,
      )
      .bind(input.ownerOrgUnitId, now, input.tenantId, input.pathwayId)
      .run();
    await transaction
      .prepare(
        `UPDATE learner_pathway_versions
         SET title = ?, learner_description = ?, completion_behavior = ?,
           final_badge_template_id = ?, updated_at = ?
         WHERE tenant_id = ? AND id = ? AND status = 'draft'`,
      )
      .bind(
        requiredText(input.title, "Pathway title"),
        requiredText(input.learnerDescription, "Learner description"),
        input.completionBehavior,
        input.finalBadgeTemplateId ?? null,
        now,
        input.tenantId,
        draft.version.id,
      )
      .run();
    await transaction
      .prepare(
        `DELETE FROM learner_pathway_requirements
         WHERE tenant_id = ? AND pathway_version_id = ?`,
      )
      .bind(input.tenantId, draft.version.id)
      .run();

    for (const [index, requirement] of input.requirements.entries()) {
      await transaction
        .prepare(
          `INSERT INTO learner_pathway_requirements (
            id, tenant_id, pathway_version_id, position, title, description, requirement_kind,
            badge_template_id, learner_record_type, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          createPrefixedId("pthr"),
          input.tenantId,
          draft.version.id,
          index + 1,
          requiredText(requirement.title, "Requirement title"),
          optionalText(requirement.description),
          requirement.requirementKind,
          requirement.badgeTemplateId ?? null,
          requirement.learnerRecordType ?? null,
          now,
        )
        .run();
    }

    await createAuditLog(transaction, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "learner_pathway.draft_updated",
      targetType: "learner_pathway",
      targetId: input.pathwayId,
      metadata: { pathwayVersionId: draft.version.id, requirementCount: input.requirements.length },
      occurredAt: now,
    });
  });

  const updated = await findLearnerPathwayDraft(db, input.tenantId, input.pathwayId);

  if (updated === null) {
    throw new Error("Updated pathway draft could not be loaded");
  }

  return updated;
};

export const listLearnerPathwayRequirements = async (
  db: SqlDatabase,
  tenantId: string,
  pathwayVersionId: string,
): Promise<LearnerPathwayRequirementRecord[]> => {
  const result = await db
    .prepare(
      `SELECT id, tenant_id AS tenantId, pathway_version_id AS pathwayVersionId, position,
        title, description, requirement_kind AS requirementKind,
        badge_template_id AS badgeTemplateId, learner_record_type AS learnerRecordType
       FROM learner_pathway_requirements
       WHERE tenant_id = ? AND pathway_version_id = ?
       ORDER BY position ASC`,
    )
    .bind(tenantId, pathwayVersionId)
    .all<RequirementRow>();
  return result.results.map(mapRequirement);
};

export const listLearnerPathwayVersions = async (
  db: SqlDatabase,
  input: { tenantId: string; pathwayId: string },
): Promise<LearnerPathwayVersionSummaryRecord[]> => {
  const result = await db
    .prepare(
      `SELECT versions.id, versions.version_number AS number, versions.status, versions.title,
        versions.published_at AS publishedAt,
        (SELECT COUNT(*) FROM learner_pathway_requirements requirements
          WHERE requirements.tenant_id = versions.tenant_id
            AND requirements.pathway_version_id = versions.id) AS requirementCount
       FROM learner_pathway_versions versions
       WHERE versions.tenant_id = ? AND versions.pathway_id = ?
       ORDER BY versions.version_number DESC`,
    )
    .bind(input.tenantId, input.pathwayId)
    .all<VersionSummaryRow>();
  return result.results.map((row) => ({
    ...row,
    number: Number(row.number),
    requirementCount: Number(row.requirementCount),
  }));
};

export const publishLearnerPathway = async (
  db: SqlDatabase,
  input: { tenantId: string; pathwayId: string; actorUserId: string },
): Promise<LearnerPathwayRecord> => {
  const pathway = await findLearnerPathwayDraft(db, input.tenantId, input.pathwayId);

  if (pathway === null || pathway.status === "retired" || pathway.version.status !== "draft") {
    throw new Error("A draft pathway version is required before publishing");
  }

  if (pathway.requirementCount === 0) {
    throw new Error("A pathway cannot be published without requirements");
  }

  const publishRequirements = await listLearnerPathwayRequirements(
    db,
    input.tenantId,
    pathway.version.id,
  );
  await assertPathwayReferencesAvailable(db, {
    tenantId: input.tenantId,
    ownerOrgUnitId: pathway.ownerOrgUnitId,
    ...(pathway.version.finalBadgeTemplateId === null
      ? {}
      : { finalBadgeTemplateId: pathway.version.finalBadgeTemplateId }),
    requirements: publishRequirements.map((requirement) => ({
      requirementKind: requirement.requirementKind,
      title: requirement.title,
      ...(requirement.description === null ? {} : { description: requirement.description }),
      ...(requirement.badgeTemplateId === null
        ? {}
        : { badgeTemplateId: requirement.badgeTemplateId }),
      ...(requirement.learnerRecordType === null
        ? {}
        : { learnerRecordType: requirement.learnerRecordType }),
    })),
  });

  const now = new Date().toISOString();
  await runSqlTransaction(db, async (transaction) => {
    if (pathway.currentPublishedVersionId !== null) {
      await transaction
        .prepare(
          `UPDATE learner_pathway_versions SET status = 'superseded', updated_at = ?
           WHERE tenant_id = ? AND id = ? AND status = 'published'`,
        )
        .bind(now, input.tenantId, pathway.currentPublishedVersionId)
        .run();
    }

    await transaction
      .prepare(
        `UPDATE learner_pathway_versions
         SET status = 'published', published_by_user_id = ?, published_at = ?, updated_at = ?
         WHERE tenant_id = ? AND id = ? AND status = 'draft'`,
      )
      .bind(input.actorUserId, now, now, input.tenantId, pathway.version.id)
      .run();
    await transaction
      .prepare(
        `UPDATE learner_pathways
         SET status = 'published', current_published_version_id = ?, updated_at = ?
         WHERE tenant_id = ? AND id = ? AND status <> 'retired'`,
      )
      .bind(pathway.version.id, now, input.tenantId, input.pathwayId)
      .run();
    await createAuditLog(transaction, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "learner_pathway.published",
      targetType: "learner_pathway",
      targetId: input.pathwayId,
      metadata: { pathwayVersionId: pathway.version.id, versionNumber: pathway.version.number },
      occurredAt: now,
    });
  });

  const published = await findLearnerPathwayById(db, input.tenantId, input.pathwayId);

  if (published === null) {
    throw new Error("Published pathway could not be loaded");
  }

  return published;
};

export const createNextLearnerPathwayDraft = async (
  db: SqlDatabase,
  input: { tenantId: string; pathwayId: string; actorUserId: string },
): Promise<LearnerPathwayRecord> => {
  const pathway = await findLearnerPathwayById(db, input.tenantId, input.pathwayId);
  const draft = await findLearnerPathwayDraft(db, input.tenantId, input.pathwayId);

  if (pathway === null || pathway.status !== "published" || draft !== null) {
    throw new Error("Only a published pathway can start a new version");
  }

  const existingDraft = await db
    .prepare(
      `SELECT id FROM learner_pathway_versions
       WHERE tenant_id = ? AND pathway_id = ? AND status = 'draft' LIMIT 1`,
    )
    .bind(input.tenantId, input.pathwayId)
    .first<{ id: string }>();

  if (existingDraft !== null) {
    throw new Error("This pathway already has a draft version");
  }

  const versionId = createPrefixedId("pthv");
  const now = new Date().toISOString();
  const requirements = await listLearnerPathwayRequirements(db, input.tenantId, pathway.version.id);

  await runSqlTransaction(db, async (transaction) => {
    await transaction
      .prepare(
        `INSERT INTO learner_pathway_versions (
          id, tenant_id, pathway_id, version_number, status, title, learner_description,
          completion_behavior, final_badge_template_id, created_by_user_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        versionId,
        input.tenantId,
        input.pathwayId,
        pathway.version.number + 1,
        pathway.version.title,
        pathway.version.learnerDescription,
        pathway.version.completionBehavior,
        pathway.version.finalBadgeTemplateId,
        input.actorUserId,
        now,
        now,
      )
      .run();

    for (const requirement of requirements) {
      await transaction
        .prepare(
          `INSERT INTO learner_pathway_requirements (
            id, tenant_id, pathway_version_id, position, title, description, requirement_kind,
            badge_template_id, learner_record_type, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          createPrefixedId("pthr"),
          input.tenantId,
          versionId,
          requirement.position,
          requirement.title,
          requirement.description,
          requirement.requirementKind,
          requirement.badgeTemplateId,
          requirement.learnerRecordType,
          now,
        )
        .run();
    }
    await createAuditLog(transaction, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "learner_pathway.version_drafted",
      targetType: "learner_pathway",
      targetId: input.pathwayId,
      metadata: { pathwayVersionId: versionId, versionNumber: pathway.version.number + 1 },
      occurredAt: now,
    });
  });

  const createdDraftRow = await db
    .prepare(`${pathwaySelect} WHERE pathways.tenant_id = ? AND versions.id = ? LIMIT 1`)
    .bind(input.tenantId, versionId)
    .first<PathwayRow>();

  if (createdDraftRow === null) {
    throw new Error("New pathway version could not be loaded");
  }

  return mapPathway(createdDraftRow);
};

export const retireLearnerPathway = async (
  db: SqlDatabase,
  input: { tenantId: string; pathwayId: string; actorUserId: string },
): Promise<void> => {
  const pathway = await findLearnerPathwayById(db, input.tenantId, input.pathwayId);
  const draft = await findLearnerPathwayDraft(db, input.tenantId, input.pathwayId);

  if (pathway === null || pathway.status !== "published" || draft !== null) {
    throw new Error("Only a published pathway can be retired");
  }

  const now = new Date().toISOString();
  await runSqlTransaction(db, async (transaction) => {
    await transaction
      .prepare(
        `UPDATE learner_pathways SET status = 'retired', retired_by_user_id = ?, retired_at = ?, updated_at = ?
         WHERE tenant_id = ? AND id = ? AND status = 'published'`,
      )
      .bind(input.actorUserId, now, now, input.tenantId, input.pathwayId)
      .run();
    await createAuditLog(transaction, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "learner_pathway.retired",
      targetType: "learner_pathway",
      targetId: input.pathwayId,
      occurredAt: now,
    });
  });
};

export const enrollLearnerInPathway = async (
  db: SqlDatabase,
  input: { tenantId: string; pathwayId: string; learnerProfileId: string; actorUserId: string },
): Promise<string> => {
  const pathway = await findLearnerPathwayById(db, input.tenantId, input.pathwayId);

  if (pathway === null || pathway.status !== "published") {
    throw new Error("Learners can only be enrolled in a published pathway");
  }

  const enrollmentId = createPrefixedId("pthe");
  const now = new Date().toISOString();
  await runSqlTransaction(db, async (transaction) => {
    await transaction
      .prepare(
        `INSERT INTO learner_pathway_enrollments (
          id, tenant_id, pathway_id, pathway_version_id, learner_profile_id, status,
          enrolled_by_user_id, enrolled_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
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
      .run();
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
      throw new Error("The requirement does not belong to this pathway enrollment");
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
      throw new Error("An active exception was not found for this pathway requirement");
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
      throw new Error("A pending pathway completion review was not found");
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

export const recordLearnerPathwayFinalCredentialIssuance = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    learnerProfileId: string;
    badgeTemplateId: string;
    assertionId: string;
    actorUserId?: string | undefined;
    issuedAt: string;
  },
): Promise<void> => {
  const handoffs = await db
    .prepare(
      `UPDATE learner_pathway_completion_handoffs AS handoffs
       SET status = 'issued', issued_assertion_id = ?, issued_at = ?,
         resolved_by_user_id = COALESCE(resolved_by_user_id, ?),
         resolved_at = COALESCE(resolved_at, ?)
       FROM learner_pathway_enrollments AS enrollments
       WHERE enrollments.tenant_id = handoffs.tenant_id
         AND enrollments.id = handoffs.enrollment_id
         AND handoffs.tenant_id = ?
         AND enrollments.learner_profile_id = ?
         AND handoffs.badge_template_id = ?
         AND handoffs.status = 'eligible'
       RETURNING handoffs.id`,
    )
    .bind(
      input.assertionId,
      input.issuedAt,
      input.actorUserId ?? null,
      input.issuedAt,
      input.tenantId,
      input.learnerProfileId,
      input.badgeTemplateId,
    )
    .all<{ id: string }>();

  for (const handoff of handoffs.results) {
    await createAuditLog(db, {
      tenantId: input.tenantId,
      actorUserId: input.actorUserId,
      action: "learner_pathway.final_credential_issued",
      targetType: "learner_pathway_completion_handoff",
      targetId: handoff.id,
      metadata: { assertionId: input.assertionId, badgeTemplateId: input.badgeTemplateId },
      occurredAt: input.issuedAt,
    });
  }
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
    requirement: LearnerPathwayRequirementRecord;
  },
): Promise<{ state: LearnerPathwayRequirementState; evidenceIds: string[]; rationale: string }> => {
  const waiver = await db
    .prepare(
      `SELECT id, reason FROM learner_pathway_waivers
       WHERE tenant_id = ? AND enrollment_id = ? AND requirement_id = ? AND revoked_at IS NULL
       LIMIT 1`,
    )
    .bind(input.tenantId, input.enrollmentId, input.requirement.id)
    .first<{ id: string; reason: string }>();

  if (waiver !== null) {
    return {
      state: "waived",
      evidenceIds: [waiver.id],
      rationale: `Approved exception: ${waiver.reason}`,
    };
  }

  const evidence =
    input.requirement.requirementKind === "badge_template"
      ? await db
          .prepare(
            `SELECT id AS evidenceId,
              CASE WHEN revoked_at IS NULL THEN 'active' ELSE 'revoked' END AS state
             FROM assertions
             WHERE tenant_id = ? AND learner_profile_id = ? AND badge_template_id = ?
             ORDER BY issued_at DESC`,
          )
          .bind(input.tenantId, input.learnerProfileId, input.requirement.badgeTemplateId)
          .all<EvidenceRow>()
      : await db
          .prepare(
            `SELECT id AS evidenceId, status AS state
             FROM learner_record_entries
             WHERE tenant_id = ? AND learner_profile_id = ? AND trust_level = 'issuer_verified'
               AND record_type = ?
             ORDER BY issued_at DESC`,
          )
          .bind(input.tenantId, input.learnerProfileId, input.requirement.learnerRecordType)
          .all<EvidenceRow>();
  const active = evidence.results.filter((row) => row.state === "active");

  if (active.length > 0) {
    return {
      state: "met",
      evidenceIds: active.map((row) => row.evidenceId),
      rationale: "Institution-verified evidence is current",
    };
  }

  if (evidence.results.length > 0) {
    return {
      state: "invalidated",
      evidenceIds: evidence.results.map((row) => row.evidenceId),
      rationale: "Previously recorded evidence is revoked or expired",
    };
  }

  return { state: "not_recorded", evidenceIds: [], rationale: "No qualifying evidence recorded" };
};

const mapEvaluation = (row: EvaluationRow): LearnerPathwayEvaluationRecord => ({
  id: row.id,
  enrollmentId: row.enrollmentId,
  pathwayVersionId: row.pathwayVersionId,
  sequenceNumber: Number(row.sequenceNumber),
  result: row.result,
  requirements: JSON.parse(row.requirementResultsJson) as LearnerPathwayRequirementEvaluation[],
  qualifyingEvidenceIds: JSON.parse(row.qualifyingEvidenceIdsJson) as string[],
  rationale: row.rationale,
  evaluatedAt: row.evaluatedAt,
});

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
    .first<EvaluationRow>();
  return row === null ? null : mapEvaluation(row);
};

export const listLearnerPathwayEvaluationHistory = async (
  db: SqlDatabase,
  input: { tenantId: string; enrollmentId: string },
): Promise<LearnerPathwayEvaluationRecord[]> => {
  const result = await db
    .prepare(
      `SELECT id, enrollment_id AS enrollmentId, pathway_version_id AS pathwayVersionId,
        sequence_number AS sequenceNumber, result, requirement_results_json AS requirementResultsJson,
        qualifying_evidence_ids_json AS qualifyingEvidenceIdsJson, rationale, evaluated_at AS evaluatedAt
       FROM learner_pathway_evaluations
       WHERE tenant_id = ? AND enrollment_id = ?
       ORDER BY sequence_number DESC`,
    )
    .bind(input.tenantId, input.enrollmentId)
    .all<EvaluationRow>();
  return result.results.map(mapEvaluation);
};

export const evaluateLearnerPathwayEnrollment = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    enrollmentId: string;
    trigger: string;
    inTransaction?: boolean | undefined;
  },
): Promise<LearnerPathwayEvaluationRecord> => {
  if (input.inTransaction !== true) {
    return runSqlTransaction(db, (transaction) =>
      evaluateLearnerPathwayEnrollment(transaction, { ...input, inTransaction: true }),
    );
  }

  await db
    .prepare("SELECT pg_advisory_xact_lock(hashtext(?))")
    .bind(`learner-pathway-evaluation:${input.tenantId}:${input.enrollmentId}`)
    .run();
  const context = await findEnrollmentContext(db, input.tenantId, input.enrollmentId);

  if (context === null) {
    throw new Error("Pathway enrollment not found");
  }

  const requirements = await listLearnerPathwayRequirements(
    db,
    input.tenantId,
    context.pathwayVersionId,
  );
  const requirementResults: LearnerPathwayRequirementEvaluation[] = [];

  for (const requirement of requirements) {
    const evidence = await listRequirementEvidence(db, {
      tenantId: input.tenantId,
      learnerProfileId: context.learnerProfileId,
      enrollmentId: context.enrollmentId,
      requirement,
    });
    requirementResults.push({
      requirementId: requirement.id,
      position: requirement.position,
      title: requirement.title,
      description: requirement.description,
      ...evidence,
    });
  }

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

  const persistEvaluation = async (
    transaction: SqlDatabase,
  ): Promise<LearnerPathwayEvaluationRecord> => {
    const latest = await findLatestEvaluation(transaction, input.tenantId, input.enrollmentId);

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
    await transaction
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
      await transaction
        .prepare(
          `INSERT INTO learner_pathway_completion_handoffs (
            id, tenant_id, enrollment_id, evaluation_id, behavior, badge_template_id, status, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
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
      await transaction
        .prepare(
          `UPDATE learner_pathway_completion_handoffs
           SET status = 'cancelled'
           WHERE tenant_id = ? AND enrollment_id = ? AND status IN ('eligible', 'review_pending')`,
        )
        .bind(input.tenantId, input.enrollmentId)
        .run();
    }

    const completed = result === "complete";
    await transaction
      .prepare(
        `UPDATE learner_pathway_enrollments
         SET status = ?, completed_at = ?, updated_at = ?
         WHERE tenant_id = ? AND id = ? AND status <> 'withdrawn'`,
      )
      .bind(
        completed ? "completed" : "active",
        completed ? (context.completedAt ?? now) : context.completedAt,
        now,
        input.tenantId,
        input.enrollmentId,
      )
      .run();
    await createAuditLog(transaction, {
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

  return persistEvaluation(db);
};

export const reevaluateLearnerPathwaysForLearner = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    learnerProfileId: string;
    trigger: string;
    inTransaction?: boolean | undefined;
  },
): Promise<LearnerPathwayEvaluationRecord[]> => {
  const enrollments = await db
    .prepare(
      `SELECT id FROM learner_pathway_enrollments
       WHERE tenant_id = ? AND learner_profile_id = ? AND status <> 'withdrawn'
       ORDER BY enrolled_at ASC`,
    )
    .bind(input.tenantId, input.learnerProfileId)
    .all<{ id: string }>();
  const evaluations: LearnerPathwayEvaluationRecord[] = [];

  for (const enrollment of enrollments.results) {
    evaluations.push(
      await evaluateLearnerPathwayEnrollment(db, {
        tenantId: input.tenantId,
        enrollmentId: enrollment.id,
        trigger: input.trigger,
        ...(input.inTransaction === undefined ? {} : { inTransaction: input.inTransaction }),
      }),
    );
  }

  return evaluations;
};

const loadLearnerPathwayProgress = async (
  db: SqlDatabase,
  input: { tenantId: string; context: EnrollmentContextRow; trigger: string },
): Promise<LearnerPathwayProgressRecord> => {
  const { context } = input;
  const evaluation = await evaluateLearnerPathwayEnrollment(db, {
    tenantId: input.tenantId,
    enrollmentId: context.enrollmentId,
    trigger: input.trigger,
  });
  const [evaluationHistory, completionHandoff] = await Promise.all([
    listLearnerPathwayEvaluationHistory(db, {
      tenantId: input.tenantId,
      enrollmentId: context.enrollmentId,
    }),
    db
      .prepare(
        `SELECT handoffs.id, handoffs.status, handoffs.badge_template_id AS badgeTemplateId,
           issued_assertions.public_id AS assertionPublicId
         FROM learner_pathway_completion_handoffs handoffs
         INNER JOIN learner_pathway_evaluations evaluations
           ON evaluations.tenant_id = handoffs.tenant_id
           AND evaluations.id = handoffs.evaluation_id
         LEFT JOIN assertions issued_assertions
           ON issued_assertions.tenant_id = handoffs.tenant_id
           AND issued_assertions.id = handoffs.issued_assertion_id
         WHERE handoffs.tenant_id = ? AND handoffs.enrollment_id = ?
         ORDER BY evaluations.sequence_number DESC LIMIT 1`,
      )
      .bind(input.tenantId, context.enrollmentId)
      .first<CompletionHandoffRow>(),
  ]);

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
    completionHandoff,
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

export const listLearnerPathwayProgress = async (
  db: SqlDatabase,
  input: { tenantId: string; learnerProfileId: string },
): Promise<LearnerPathwayProgressRecord[]> => {
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
        versions.final_badge_template_id AS finalBadgeTemplateId
       FROM learner_pathway_enrollments enrollments
       INNER JOIN learner_pathway_versions versions
         ON versions.tenant_id = enrollments.tenant_id AND versions.id = enrollments.pathway_version_id
       INNER JOIN learner_pathways pathways
         ON pathways.tenant_id = enrollments.tenant_id AND pathways.id = enrollments.pathway_id
       INNER JOIN tenant_org_units org_units
         ON org_units.tenant_id = pathways.tenant_id AND org_units.id = pathways.owner_org_unit_id
       WHERE enrollments.tenant_id = ? AND enrollments.learner_profile_id = ?
         AND enrollments.status <> 'withdrawn'
       ORDER BY enrollments.enrolled_at DESC`,
    )
    .bind(input.tenantId, input.learnerProfileId)
    .all<EnrollmentContextRow>();
  const progress: LearnerPathwayProgressRecord[] = [];

  for (const row of rows.results) {
    progress.push(
      await loadLearnerPathwayProgress(db, {
        tenantId: input.tenantId,
        context: row,
        trigger: "learner_view",
      }),
    );
  }

  return progress;
};

export const listLearnerPathwayAdminProgress = async (
  db: SqlDatabase,
  input: { tenantId: string; pathwayId: string },
): Promise<LearnerPathwayAdminProgressRecord[]> => {
  const learners = await db
    .prepare(
      `SELECT enrollments.id AS enrollmentId,
        enrollments.learner_profile_id AS learnerProfileId,
        profiles.display_name AS learnerDisplayName, profiles.subject_id AS learnerSubjectId
       FROM learner_pathway_enrollments enrollments
       INNER JOIN learner_profiles profiles
         ON profiles.tenant_id = enrollments.tenant_id
         AND profiles.id = enrollments.learner_profile_id
       WHERE enrollments.tenant_id = ? AND enrollments.pathway_id = ?
         AND enrollments.status <> 'withdrawn'
       ORDER BY enrollments.enrolled_at DESC`,
    )
    .bind(input.tenantId, input.pathwayId)
    .all<{
      enrollmentId: string;
      learnerProfileId: string;
      learnerDisplayName: string | null;
      learnerSubjectId: string;
    }>();
  const progress: LearnerPathwayAdminProgressRecord[] = [];

  for (const learner of learners.results) {
    const context = await findEnrollmentContext(db, input.tenantId, learner.enrollmentId);

    if (context !== null) {
      const pathwayProgress = await loadLearnerPathwayProgress(db, {
        tenantId: input.tenantId,
        context,
        trigger: "admin_view",
      });
      progress.push({
        ...pathwayProgress,
        learnerProfileId: learner.learnerProfileId,
        learnerDisplayName: learner.learnerDisplayName,
        learnerSubjectId: learner.learnerSubjectId,
      });
    }
  }

  return progress;
};
