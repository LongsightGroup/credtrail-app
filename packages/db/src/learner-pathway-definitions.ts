import { createAuditLog } from "./audit-logs.js";
import { findBadgeTemplateById } from "./badge-templates.js";
import { LearnerPathwayCommandError } from "./learner-pathway-errors.js";
import type {
  LearnerPathwayCompletionBehavior,
  LearnerPathwayRecord,
  LearnerPathwayRequirementInput,
  LearnerPathwayRequirementKind,
  LearnerPathwayRequirementRecord,
  LearnerPathwayStatus,
  LearnerPathwayVersionStatus,
  LearnerPathwayVersionSummaryRecord,
} from "./learner-pathway-types.js";
import { createPrefixedId } from "./shared-helpers.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";
import { findTenantOrgUnitById } from "./tenant-org-units.js";

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

interface VersionSummaryRow {
  id: string;
  number: number;
  status: LearnerPathwayVersionStatus;
  title: string;
  publishedAt: string | null;
  requirementCount: number;
}

const requiredText = (value: string, label: string): string => {
  const normalized = value.trim();

  if (normalized.length === 0) {
    throw new LearnerPathwayCommandError("invalid", `${label} is required`);
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
    throw new LearnerPathwayCommandError(
      "invalid",
      "The final credential cannot also be one of its pathway requirements",
    );
  }

  const owner = await findTenantOrgUnitById(db, input.tenantId, input.ownerOrgUnitId);

  if (owner === null || !owner.isActive) {
    throw new LearnerPathwayCommandError(
      "invalid",
      "Pathway owner must be an active organization unit",
    );
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

  const templates = await Promise.all(
    Array.from(badgeTemplateIds, (badgeTemplateId) =>
      findBadgeTemplateById(db, input.tenantId, badgeTemplateId),
    ),
  );

  if (templates.some((template) => template === null || template.isArchived)) {
    throw new LearnerPathwayCommandError(
      "invalid",
      "Pathway credentials must use active badge templates from this organization",
    );
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
    throw new LearnerPathwayCommandError(
      "not_ready",
      "At least one pathway requirement is required",
    );
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
    throw new LearnerPathwayCommandError(
      "not_ready",
      "At least one pathway requirement is required",
    );
  }

  const draft = await findLearnerPathwayDraft(db, input.tenantId, input.pathwayId);

  if (draft === null || draft.status === "retired") {
    throw new LearnerPathwayCommandError("not_found", "Pathway draft not found");
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
    throw new LearnerPathwayCommandError(
      "not_ready",
      "A draft pathway version is required before publishing",
    );
  }

  if (pathway.requirementCount === 0) {
    throw new LearnerPathwayCommandError(
      "not_ready",
      "A pathway cannot be published without requirements",
    );
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
  const [pathway, draft] = await Promise.all([
    findLearnerPathwayById(db, input.tenantId, input.pathwayId),
    findLearnerPathwayDraft(db, input.tenantId, input.pathwayId),
  ]);

  if (pathway === null || pathway.status !== "published") {
    throw new LearnerPathwayCommandError(
      "conflict",
      "Only a published pathway can start a new version",
    );
  }

  if (draft !== null) {
    throw new LearnerPathwayCommandError("conflict", "This pathway already has a draft version");
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
  const [pathway, draft] = await Promise.all([
    findLearnerPathwayById(db, input.tenantId, input.pathwayId),
    findLearnerPathwayDraft(db, input.tenantId, input.pathwayId),
  ]);

  if (pathway === null || pathway.status !== "published" || draft !== null) {
    throw new LearnerPathwayCommandError("conflict", "Only a published pathway can be retired");
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
