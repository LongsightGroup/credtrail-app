import { z } from "zod";
import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export interface BadgeIssuanceRuleEvaluationRecord {
  id: string;
  tenantId: string;
  ruleId: string;
  versionId: string;
  learnerId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  matched: boolean;
  issuanceStatus: string | null;
  assertionId: string | null;
  evaluationJson: string;
  reviewStatus: "pending" | "resolved" | null;
  reviewDecision: "issue" | "dismiss" | null;
  reviewComment: string | null;
  reviewedByUserId: string | null;
  reviewedAt: string | null;
  evaluatedAt: string;
  createdAt: string;
}

export interface CreateBadgeIssuanceRuleEvaluationInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  learnerId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  matched: boolean;
  issuanceStatus?: string | undefined;
  assertionId?: string | undefined;
  evaluationJson: string;
  reviewStatus?: "pending" | "resolved" | undefined;
  reviewDecision?: "issue" | "dismiss" | undefined;
  reviewComment?: string | undefined;
  reviewedByUserId?: string | undefined;
  reviewedAt?: string | undefined;
  evaluatedAt?: string | undefined;
}

export interface ListBadgeIssuanceRuleEvaluationsInput {
  sort?: "oldest" | "newest" | undefined;
  decision?: "issue" | "dismiss" | undefined;
  search?: string | undefined;
  evaluationId?: string | undefined;
  cursor?: { at: string; id: string; direction: "older" | "newer" } | undefined;
  includeLookahead?: boolean;
  tenantId: string;
  ruleId?: string | undefined;
  versionId?: string | undefined;
  badgeTemplateId?: string | undefined;
  issuanceStatus?: string | undefined;
  reviewStatus?: "pending" | "resolved" | undefined;
  limit?: number | undefined;
}

export interface ResolveBadgeIssuanceRuleEvaluationReviewInput {
  tenantId: string;
  evaluationId: string;
  reviewDecision: "issue" | "dismiss";
  reviewComment?: string | undefined;
  reviewedByUserId: string;
  reviewedAt?: string | undefined;
  issuanceStatus?: string | undefined;
  assertionId?: string | undefined;
}

export interface ListIssuedBadgeTemplateIdsForRecipientInput {
  tenantId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
}

interface BadgeIssuanceRuleEvaluationRow {
  id: string;
  tenantId: string;
  ruleId: string;
  versionId: string;
  learnerId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  matched: number | boolean;
  issuanceStatus: string | null;
  assertionId: string | null;
  evaluationJson: string;
  reviewStatus: "pending" | "resolved" | null;
  reviewDecision: "issue" | "dismiss" | null;
  reviewComment: string | null;
  reviewedByUserId: string | null;
  reviewedAt: string | null;
  evaluatedAt: string;
  createdAt: string;
}

interface BadgeTemplateIdRow {
  badgeTemplateId: string;
}

const mapBadgeIssuanceRuleEvaluationRow = (
  row: BadgeIssuanceRuleEvaluationRow,
): BadgeIssuanceRuleEvaluationRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    ruleId: row.ruleId,
    versionId: row.versionId,
    learnerId: row.learnerId,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    matched: row.matched === 1 || row.matched === true,
    issuanceStatus: row.issuanceStatus,
    assertionId: row.assertionId,
    evaluationJson: row.evaluationJson,
    reviewStatus: row.reviewStatus,
    reviewDecision: row.reviewDecision,
    reviewComment: row.reviewComment,
    reviewedByUserId: row.reviewedByUserId,
    reviewedAt: row.reviewedAt,
    evaluatedAt: row.evaluatedAt,
    createdAt: row.createdAt,
  };
};

export const createBadgeIssuanceRuleEvaluation = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleEvaluationInput,
): Promise<BadgeIssuanceRuleEvaluationRecord> => {
  const evaluationId = createPrefixedId("bre");
  const evaluatedAt = input.evaluatedAt ?? new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_evaluations (
          id,
          tenant_id,
          rule_id,
          version_id,
          learner_id,
          recipient_identity,
          recipient_identity_type,
          matched,
          issuance_status,
          assertion_id,
          evaluation_json,
          review_status,
          review_decision,
          review_comment,
          reviewed_by_user_id,
          reviewed_at,
          evaluated_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        evaluationId,
        input.tenantId,
        input.ruleId,
        input.versionId,
        input.learnerId,
        input.recipientIdentity,
        input.recipientIdentityType,
        input.matched ? 1 : 0,
        input.issuanceStatus ?? null,
        input.assertionId ?? null,
        input.evaluationJson,
        input.reviewStatus ?? null,
        input.reviewDecision ?? null,
        input.reviewComment ?? null,
        input.reviewedByUserId ?? null,
        input.reviewedAt ?? null,
        evaluatedAt,
        evaluatedAt,
      )
      .run();
  const lookupStatement = (): Promise<BadgeIssuanceRuleEvaluationRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          rule_id AS ruleId,
          version_id AS versionId,
          learner_id AS learnerId,
          recipient_identity AS recipientIdentity,
          recipient_identity_type AS recipientIdentityType,
          matched,
          issuance_status AS issuanceStatus,
          assertion_id AS assertionId,
          evaluation_json AS evaluationJson,
          review_status AS reviewStatus,
          review_decision AS reviewDecision,
          review_comment AS reviewComment,
          reviewed_by_user_id AS reviewedByUserId,
          reviewed_at AS reviewedAt,
          evaluated_at AS evaluatedAt,
          created_at AS createdAt
        FROM badge_issuance_rule_evaluations
        WHERE id = ?
        LIMIT 1
      `,
      )
      .bind(evaluationId)
      .first<BadgeIssuanceRuleEvaluationRow>();

  await insertStatement();

  const row = await lookupStatement();

  if (row === null) {
    throw new Error(`Unable to load badge issuance rule evaluation "${evaluationId}" after insert`);
  }

  return mapBadgeIssuanceRuleEvaluationRow(row);
};

export const findBadgeIssuanceRuleEvaluationByAssertionId = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    assertionId: string;
  },
): Promise<BadgeIssuanceRuleEvaluationRecord | null> => {
  const lookupStatement = (): Promise<BadgeIssuanceRuleEvaluationRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          rule_id AS ruleId,
          version_id AS versionId,
          learner_id AS learnerId,
          recipient_identity AS recipientIdentity,
          recipient_identity_type AS recipientIdentityType,
          matched,
          issuance_status AS issuanceStatus,
          assertion_id AS assertionId,
          evaluation_json AS evaluationJson,
          review_status AS reviewStatus,
          review_decision AS reviewDecision,
          review_comment AS reviewComment,
          reviewed_by_user_id AS reviewedByUserId,
          reviewed_at AS reviewedAt,
          evaluated_at AS evaluatedAt,
          created_at AS createdAt
        FROM badge_issuance_rule_evaluations
        WHERE tenant_id = ?
          AND assertion_id = ?
        ORDER BY evaluated_at DESC, created_at DESC, id DESC
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.assertionId)
      .first<BadgeIssuanceRuleEvaluationRow>();

  const row = await lookupStatement();

  return row === null ? null : mapBadgeIssuanceRuleEvaluationRow(row);
};

export const findBadgeIssuanceRuleEvaluationById = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    evaluationId: string;
  },
): Promise<BadgeIssuanceRuleEvaluationRecord | null> => {
  const lookupStatement = (): Promise<BadgeIssuanceRuleEvaluationRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          rule_id AS ruleId,
          version_id AS versionId,
          learner_id AS learnerId,
          recipient_identity AS recipientIdentity,
          recipient_identity_type AS recipientIdentityType,
          matched,
          issuance_status AS issuanceStatus,
          assertion_id AS assertionId,
          evaluation_json AS evaluationJson,
          review_status AS reviewStatus,
          review_decision AS reviewDecision,
          review_comment AS reviewComment,
          reviewed_by_user_id AS reviewedByUserId,
          reviewed_at AS reviewedAt,
          evaluated_at AS evaluatedAt,
          created_at AS createdAt
        FROM badge_issuance_rule_evaluations
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.evaluationId)
      .first<BadgeIssuanceRuleEvaluationRow>();

  const row = await lookupStatement();

  return row === null ? null : mapBadgeIssuanceRuleEvaluationRow(row);
};

export const listBadgeIssuanceRuleEvaluations = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleEvaluationsInput,
): Promise<BadgeIssuanceRuleEvaluationRecord[]> => {
  const limit = Math.min(500, Math.max(1, input.limit ?? 50));
  const at =
    input.reviewStatus === "resolved"
      ? "COALESCE(evaluations.reviewed_at, evaluations.evaluated_at)"
      : "evaluations.evaluated_at";
  const order = (input.cursor ? input.cursor.direction === "newer" : input.sort === "oldest")
    ? "ASC"
    : "DESC";
  const cursorSql = input.cursor
    ? `AND (${at}, evaluations.id) ${input.cursor.direction === "newer" ? ">" : "<"} (?, ?)`
    : "";
  const search = input.search?.trim()
    ? `%${input.search.trim().replace(/[\\%_]/g, "\\$&")}%`
    : null;
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleEvaluationRow>> =>
    db
      .prepare(
        `
        SELECT
          evaluations.id,
          evaluations.tenant_id AS tenantId,
          evaluations.rule_id AS ruleId,
          evaluations.version_id AS versionId,
          evaluations.learner_id AS learnerId,
          evaluations.recipient_identity AS recipientIdentity,
          evaluations.recipient_identity_type AS recipientIdentityType,
          evaluations.matched,
          evaluations.issuance_status AS issuanceStatus,
          evaluations.assertion_id AS assertionId,
          evaluations.evaluation_json AS evaluationJson,
          evaluations.review_status AS reviewStatus,
          evaluations.review_decision AS reviewDecision,
          evaluations.review_comment AS reviewComment,
          evaluations.reviewed_by_user_id AS reviewedByUserId,
          evaluations.reviewed_at AS reviewedAt,
          evaluations.evaluated_at AS evaluatedAt,
          evaluations.created_at AS createdAt
        FROM badge_issuance_rule_evaluations AS evaluations
        INNER JOIN badge_issuance_rules AS rules
          ON rules.id = evaluations.rule_id
          AND rules.tenant_id = evaluations.tenant_id
        INNER JOIN badge_issuance_rule_versions versions ON versions.id = evaluations.version_id AND versions.tenant_id = evaluations.tenant_id
        WHERE evaluations.tenant_id = ?
          AND (CAST(? AS TEXT) IS NULL OR evaluations.rule_id = ?)
          AND (CAST(? AS TEXT) IS NULL OR evaluations.version_id = ?)
          AND (CAST(? AS TEXT) IS NULL OR rules.badge_template_id = ?)
          AND (CAST(? AS TEXT) IS NULL OR evaluations.issuance_status = ?)
          AND (CAST(? AS TEXT) IS NULL OR evaluations.review_status = ?)
          AND (CAST(? AS TEXT) IS NULL OR evaluations.review_decision = ?)
          AND (CAST(? AS TEXT) IS NULL OR evaluations.id = ?)
          AND (CAST(? AS TEXT) IS NULL OR evaluations.recipient_identity ILIKE ? OR versions.snapshot_badge_template_title ILIKE ?)
          ${cursorSql}
        ORDER BY ${at} ${order}, evaluations.id ${order}
        LIMIT ?
      `,
      )
      .bind(
        input.tenantId,
        input.ruleId ?? null,
        input.ruleId ?? null,
        input.versionId ?? null,
        input.versionId ?? null,
        input.badgeTemplateId ?? null,
        input.badgeTemplateId ?? null,
        input.issuanceStatus ?? null,
        input.issuanceStatus ?? null,
        input.reviewStatus ?? null,
        input.reviewStatus ?? null,
        input.decision ?? null,
        input.decision ?? null,
        input.evaluationId ?? null,
        input.evaluationId ?? null,
        search,
        search,
        search,
        ...(input.cursor ? [input.cursor.at, input.cursor.id] : []),
        limit + (input.includeLookahead ? 1 : 0),
      )
      .all<BadgeIssuanceRuleEvaluationRow>();

  const result = await listStatement();

  return result.results.map((row) => mapBadgeIssuanceRuleEvaluationRow(row));
};

export const resolveBadgeIssuanceRuleEvaluationReview = async (
  db: SqlDatabase,
  input: ResolveBadgeIssuanceRuleEvaluationReviewInput,
): Promise<BadgeIssuanceRuleEvaluationRecord | null> => {
  const reviewedAt = input.reviewedAt ?? new Date().toISOString();
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_evaluations
        SET
          review_status = 'resolved',
          review_decision = ?,
          review_comment = ?,
          reviewed_by_user_id = ?,
          reviewed_at = ?,
          issuance_status = COALESCE(?, issuance_status),
          assertion_id = COALESCE(?, assertion_id)
        WHERE tenant_id = ?
          AND id = ?
          AND review_status = 'pending'
      `,
      )
      .bind(
        input.reviewDecision,
        input.reviewComment ?? null,
        input.reviewedByUserId,
        reviewedAt,
        input.issuanceStatus ?? null,
        input.assertionId ?? null,
        input.tenantId,
        input.evaluationId,
      )
      .run();

  const updated = await updateStatement();

  if ((updated.meta.rowsWritten ?? 0) === 0) {
    return null;
  }

  return findBadgeIssuanceRuleEvaluationById(db, {
    tenantId: input.tenantId,
    evaluationId: input.evaluationId,
  });
};

export const listIssuedBadgeTemplateIdsForRecipient = async (
  db: SqlDatabase,
  input: ListIssuedBadgeTemplateIdsForRecipientInput,
): Promise<string[]> => {
  const result = await db
    .prepare(
      `
      SELECT DISTINCT badge_template_id AS badgeTemplateId
      FROM assertions
      WHERE tenant_id = ?
        AND recipient_identity = ?
        AND recipient_identity_type = ?
        AND revoked_at IS NULL
      ORDER BY badge_template_id ASC
    `,
    )
    .bind(input.tenantId, input.recipientIdentity, input.recipientIdentityType)
    .all<BadgeTemplateIdRow>();

  return result.results.map((row) => row.badgeTemplateId);
};

/** Counts outstanding learner decisions without the review list's page limit. */
export const countPendingBadgeReviews = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<number> => {
  const row = await db
    .prepare(`SELECT COUNT(*) AS count FROM badge_issuance_rule_evaluations
    WHERE tenant_id = ? AND review_status = 'pending' AND issuance_status = 'review_required'`)
    .bind(tenantId)
    .first<{ count: unknown }>();
  return z.coerce.number().int().nonnegative().parse(row?.count);
};
