import type { LearnerProfileRecord } from "./learner-profiles";
import { normalizeEmail } from "./users";
import type { SqlDatabase } from "./tenant-scope";

/** Connection-scoped provider identity attached during badge issuance. */
export interface EnsureLearnerLmsIdentityInput {
  readonly tenantId: string;
  readonly connectionId: string;
  readonly lmsLearnerId: string;
  readonly learnerProfileId: string;
  readonly linkedAt: string;
}

/** Result of idempotently linking a provider-local identity within one LMS connection. */
export type EnsureLearnerLmsIdentityResult =
  | { readonly status: "linked" }
  | {
      readonly status: "conflict";
      readonly reason: "lms_learner_id_in_use" | "learner_profile_in_use";
    };

interface LearnerLmsIdentityRow {
  learnerProfileId: string;
}

interface LearnerProfileRow {
  id: string;
  tenantId: string;
  subjectId: string;
  displayName: string | null;
  createdAt: string;
  updatedAt: string;
}

const mapLearnerProfileRow = (row: LearnerProfileRow): LearnerProfileRecord => ({
  id: row.id,
  tenantId: row.tenantId,
  subjectId: row.subjectId,
  displayName: row.displayName,
  createdAt: row.createdAt,
  updatedAt: row.updatedAt,
});

/** Idempotently links one provider-local learner ID to a profile within one LMS connection. */
export const ensureLearnerLmsIdentity = async (
  db: SqlDatabase,
  input: EnsureLearnerLmsIdentityInput,
): Promise<EnsureLearnerLmsIdentityResult> => {
  const lmsLearnerId = input.lmsLearnerId.trim();

  if (lmsLearnerId.length === 0) {
    throw new Error("LMS learner ID must not be empty");
  }

  await db
    .prepare(
      `
      INSERT INTO learner_lms_identities (
        tenant_id,
        connection_id,
        lms_learner_id,
        learner_profile_id,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT DO NOTHING
    `,
    )
    .bind(
      input.tenantId,
      input.connectionId,
      lmsLearnerId,
      input.learnerProfileId,
      input.linkedAt,
      input.linkedAt,
    )
    .run();

  const [identityByLearnerId, identityByProfile] = await Promise.all([
    db
      .prepare(
        `
        SELECT learner_profile_id AS learnerProfileId
        FROM learner_lms_identities
        WHERE tenant_id = ?
          AND connection_id = ?
          AND lms_learner_id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.connectionId, lmsLearnerId)
      .first<LearnerLmsIdentityRow>(),
    db
      .prepare(
        `
        SELECT learner_profile_id AS learnerProfileId
        FROM learner_lms_identities
        WHERE tenant_id = ?
          AND connection_id = ?
          AND learner_profile_id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.connectionId, input.learnerProfileId)
      .first<LearnerLmsIdentityRow>(),
  ]);

  if (
    identityByLearnerId !== null &&
    identityByLearnerId.learnerProfileId !== input.learnerProfileId
  ) {
    return { status: "conflict", reason: "lms_learner_id_in_use" };
  }

  if (identityByLearnerId === null && identityByProfile !== null) {
    return { status: "conflict", reason: "learner_profile_in_use" };
  }

  if (identityByLearnerId === null) {
    throw new Error("LMS learner identity insert did not produce a persisted record");
  }

  return { status: "linked" };
};

/** Lists at most two tenant learner profiles matching an LMS learner ID or email address. */
export const listLearnerProfilesForRecordLookup = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly lookupValue: string;
  },
): Promise<LearnerProfileRecord[]> => {
  const lookupValue = input.lookupValue.trim();
  const normalizedEmail = normalizeEmail(lookupValue);
  const result = await db
    .prepare(
      `
      SELECT DISTINCT
        learner_profiles.id AS id,
        learner_profiles.tenant_id AS tenantId,
        learner_profiles.subject_id AS subjectId,
        learner_profiles.display_name AS displayName,
        learner_profiles.created_at AS createdAt,
        learner_profiles.updated_at AS updatedAt
      FROM learner_profiles
      WHERE learner_profiles.tenant_id = ?
        AND (
          EXISTS (
            SELECT 1
            FROM learner_identities
            WHERE learner_identities.tenant_id = learner_profiles.tenant_id
              AND learner_identities.learner_profile_id = learner_profiles.id
              AND learner_identities.identity_type = 'email'
              AND learner_identities.identity_value = ?
          )
          OR EXISTS (
            SELECT 1
            FROM learner_lms_identities
            WHERE learner_lms_identities.tenant_id = learner_profiles.tenant_id
              AND learner_lms_identities.learner_profile_id = learner_profiles.id
              AND learner_lms_identities.lms_learner_id = ?
          )
        )
      ORDER BY learner_profiles.id ASC
      LIMIT 2
    `,
    )
    .bind(input.tenantId, normalizedEmail, lookupValue)
    .all<LearnerProfileRow>();

  return result.results.map(mapLearnerProfileRow);
};
