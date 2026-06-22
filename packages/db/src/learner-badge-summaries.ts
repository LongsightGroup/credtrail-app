import {
  assertionBadgeTemplateJoinSql,
  bindLearnerProfileOrEmailAccessParams,
  buildLearnerProfileOrEmailAccessFilter,
  buildLegacyLearnerEmailAccessFilter,
} from "./learner-assertion-access-sql";
import { findLearnerProfileByIdentity, listLearnerIdentitiesByProfile } from "./learner-profiles";
import type { SqlDatabase } from "./tenant-scope";
import { findUserById, normalizeEmail } from "./users";

export interface LearnerBadgeSummaryRecord {
  assertionId: string;
  assertionPublicId: string | null;
  tenantId: string;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  issuedAt: string;
  revokedAt: string | null;
}

export interface ListLearnerBadgeSummariesInput {
  tenantId: string;
  userId: string;
}

export interface FindClaimableLearnerBadgeSummaryInput extends ListLearnerBadgeSummariesInput {
  assertionId: string;
}

interface LearnerBadgeSummaryAccessContext {
  tenantId: string;
  learnerProfileId: string | null;
  emailAliases: readonly string[];
}

interface LearnerBadgeSummaryQuery {
  assertionId?: string | undefined;
  claimableOnly?: boolean | undefined;
}

const learnerBadgeSummarySelectClause = `
  SELECT
    assertions.id AS assertionId,
    assertions.public_id AS assertionPublicId,
    assertions.tenant_id AS tenantId,
    assertions.badge_template_id AS badgeTemplateId,
    badge_templates.title AS badgeTitle,
    badge_templates.description AS badgeDescription,
    assertions.issued_at AS issuedAt,
    assertions.revoked_at AS revokedAt
`;

const resolveLearnerBadgeSummaryAccessContext = async (
  db: SqlDatabase,
  input: ListLearnerBadgeSummariesInput,
): Promise<LearnerBadgeSummaryAccessContext | null> => {
  const user = await findUserById(db, input.userId);

  if (user === null) {
    return null;
  }

  const normalizedUserEmail = normalizeEmail(user.email);
  const learnerProfile = await findLearnerProfileByIdentity(db, {
    tenantId: input.tenantId,
    identityType: "email",
    identityValue: user.email,
  });

  if (learnerProfile === null) {
    return {
      tenantId: input.tenantId,
      learnerProfileId: null,
      emailAliases: [normalizedUserEmail],
    };
  }

  const identities = await listLearnerIdentitiesByProfile(db, input.tenantId, learnerProfile.id);
  const emailAliases = new Set<string>([normalizedUserEmail]);

  for (const identity of identities) {
    if (identity.identityType === "email") {
      emailAliases.add(normalizeEmail(identity.identityValue));
    }
  }

  return {
    tenantId: input.tenantId,
    learnerProfileId: learnerProfile.id,
    emailAliases: Array.from(emailAliases),
  };
};

const buildLearnerBadgeSummaryWhereClause = (
  access: LearnerBadgeSummaryAccessContext,
  query: LearnerBadgeSummaryQuery,
): { whereClause: string; params: unknown[] } | null => {
  const filters: string[] = ["assertions.tenant_id = ?"];
  const params: unknown[] = [access.tenantId];

  if (query.assertionId !== undefined) {
    filters.push("assertions.id = ?");
    params.push(query.assertionId);
  }

  if (query.claimableOnly === true) {
    filters.push("assertions.revoked_at IS NULL");
  }

  if (access.learnerProfileId === null) {
    // Legacy path: match only the user's primary normalized email, not every alias.
    const primaryEmail = access.emailAliases[0];

    if (primaryEmail === undefined) {
      return null;
    }

    filters.push(buildLegacyLearnerEmailAccessFilter());
    params.push(primaryEmail);
  } else {
    filters.push(buildLearnerProfileOrEmailAccessFilter(access.emailAliases));
    params.push(
      ...bindLearnerProfileOrEmailAccessParams(access.learnerProfileId, access.emailAliases),
    );
  }

  return {
    whereClause: filters.join("\n        AND "),
    params,
  };
};

const listLearnerBadgeSummariesForAccess = async (
  db: SqlDatabase,
  access: LearnerBadgeSummaryAccessContext,
): Promise<LearnerBadgeSummaryRecord[]> => {
  const where = buildLearnerBadgeSummaryWhereClause(access, {});

  if (where === null) {
    return [];
  }

  const result = await db
    .prepare(
      `
      ${learnerBadgeSummarySelectClause}
      ${assertionBadgeTemplateJoinSql}
      WHERE ${where.whereClause}
      ORDER BY assertions.issued_at DESC
    `,
    )
    .bind(...where.params)
    .all<LearnerBadgeSummaryRecord>();

  return result.results;
};

const findLearnerBadgeSummaryForAccess = async (
  db: SqlDatabase,
  access: LearnerBadgeSummaryAccessContext,
  query: Required<Pick<LearnerBadgeSummaryQuery, "assertionId">> &
    Pick<LearnerBadgeSummaryQuery, "claimableOnly">,
): Promise<LearnerBadgeSummaryRecord | null> => {
  const where = buildLearnerBadgeSummaryWhereClause(access, query);

  if (where === null) {
    return null;
  }

  const row = await db
    .prepare(
      `
      ${learnerBadgeSummarySelectClause}
      ${assertionBadgeTemplateJoinSql}
      WHERE ${where.whereClause}
    `,
    )
    .bind(...where.params)
    .first<LearnerBadgeSummaryRecord>();

  return row;
};

export const listLearnerBadgeSummaries = async (
  db: SqlDatabase,
  input: ListLearnerBadgeSummariesInput,
): Promise<LearnerBadgeSummaryRecord[]> => {
  const access = await resolveLearnerBadgeSummaryAccessContext(db, input);

  if (access === null) {
    return [];
  }

  return listLearnerBadgeSummariesForAccess(db, access);
};

export const findClaimableLearnerBadgeSummary = async (
  db: SqlDatabase,
  input: FindClaimableLearnerBadgeSummaryInput,
): Promise<LearnerBadgeSummaryRecord | null> => {
  const access = await resolveLearnerBadgeSummaryAccessContext(db, input);

  if (access === null) {
    return null;
  }

  return findLearnerBadgeSummaryForAccess(db, access, {
    assertionId: input.assertionId,
    claimableOnly: true,
  });
};
