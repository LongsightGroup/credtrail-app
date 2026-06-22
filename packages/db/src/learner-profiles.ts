import { createPrefixedId } from "./shared-helpers";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope";
import { normalizeEmail } from "./users";

export type LearnerIdentityType =
  | "email"
  | "email_sha256"
  | "did"
  | "url"
  | "saml_subject"
  | "sourced_id";

export type RecipientIdentifierType =
  | "emailAddress"
  | "sourcedId"
  | "did"
  | "nationalIdentityNumber"
  | "studentId";

export interface RecipientIdentifierRecord {
  assertionId: string;
  identifierType: RecipientIdentifierType;
  identifierValue: string;
  createdAt: string;
}

export interface RecipientIdentifierInput {
  identifierType: RecipientIdentifierType;
  identifierValue: string;
}

export interface LearnerProfileRecord {
  id: string;
  tenantId: string;
  subjectId: string;
  displayName: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface LearnerIdentityRecord {
  id: string;
  tenantId: string;
  learnerProfileId: string;
  identityType: LearnerIdentityType;
  identityValue: string;
  isPrimary: boolean;
  isVerified: boolean;
  createdAt: string;
  updatedAt: string;
}
export interface CreateLearnerProfileInput {
  tenantId: string;
  subjectId?: string | undefined;
  displayName?: string | undefined;
  primaryIdentityType: LearnerIdentityType;
  primaryIdentityValue: string;
  primaryIdentityVerified?: boolean | undefined;
}

export interface AddLearnerIdentityAliasInput {
  tenantId: string;
  learnerProfileId: string;
  identityType: LearnerIdentityType;
  identityValue: string;
  isPrimary?: boolean | undefined;
  isVerified?: boolean | undefined;
}

export interface RemoveLearnerIdentityAliasesByTypeInput {
  tenantId: string;
  learnerProfileId: string;
  identityType: LearnerIdentityType;
}

export interface MoveLearnerIdentityAliasToProfileInput {
  tenantId: string;
  learnerProfileId: string;
  identityType: LearnerIdentityType;
  identityValue: string;
  isPrimary?: boolean | undefined;
  isVerified?: boolean | undefined;
}

export interface FindLearnerProfileByIdentityInput {
  tenantId: string;
  identityType: LearnerIdentityType;
  identityValue: string;
}

export interface ResolveLearnerProfileForIdentityInput {
  tenantId: string;
  identityType: LearnerIdentityType;
  identityValue: string;
  displayName?: string | undefined;
}

export interface ResolveLearnerProfileFromSamlInput {
  tenantId: string;
  samlSubject?: string | undefined;
  email?: string | undefined;
  displayName?: string | undefined;
}

export type LearnerProfileResolutionStrategy = "saml_subject" | "verified_email" | "created";

export interface ResolveLearnerProfileFromSamlResult {
  profile: LearnerProfileRecord;
  strategy: LearnerProfileResolutionStrategy;
}
interface LearnerProfileRow {
  id: string;
  tenantId: string;
  subjectId: string;
  displayName: string | null;
  createdAt: string;
  updatedAt: string;
}

interface LearnerIdentityRow {
  id: string;
  tenantId: string;
  learnerProfileId: string;
  identityType: LearnerIdentityType;
  identityValue: string;
  isPrimary: number;
  isVerified: number;
  createdAt: string;
  updatedAt: string;
}
const defaultLearnerSubjectId = (tenantId: string, learnerProfileId: string): string => {
  return `urn:credtrail:learner:${encodeURIComponent(tenantId)}:${encodeURIComponent(learnerProfileId)}`;
};
const mapLearnerProfileRow = (row: LearnerProfileRow): LearnerProfileRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    subjectId: row.subjectId,
    displayName: row.displayName,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLearnerIdentityRow = (row: LearnerIdentityRow): LearnerIdentityRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    learnerProfileId: row.learnerProfileId,
    identityType: row.identityType,
    identityValue: row.identityValue,
    isPrimary: row.isPrimary === 1,
    isVerified: row.isVerified === 1,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};
export const normalizeLearnerIdentityValue = (
  identityType: LearnerIdentityType,
  identityValue: string,
): string => {
  const trimmed = identityValue.trim();

  switch (identityType) {
    case "email":
      return normalizeEmail(trimmed);
    case "email_sha256":
      return trimmed.toLowerCase();
    case "did":
    case "url":
    case "saml_subject":
    case "sourced_id":
      return trimmed;
  }
};

export const findLearnerProfileById = async (
  db: SqlDatabase,
  tenantId: string,
  learnerProfileId: string,
): Promise<LearnerProfileRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        subject_id AS subjectId,
        display_name AS displayName,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM learner_profiles
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, learnerProfileId)
    .first<LearnerProfileRow>();

  return row === null ? null : mapLearnerProfileRow(row);
};

export const listLearnerIdentitiesByProfile = async (
  db: SqlDatabase,
  tenantId: string,
  learnerProfileId: string,
): Promise<LearnerIdentityRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        learner_profile_id AS learnerProfileId,
        identity_type AS identityType,
        identity_value AS identityValue,
        is_primary AS isPrimary,
        is_verified AS isVerified,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM learner_identities
      WHERE tenant_id = ?
        AND learner_profile_id = ?
      ORDER BY is_primary DESC, created_at ASC
    `,
    )
    .bind(tenantId, learnerProfileId)
    .all<LearnerIdentityRow>();

  return result.results.map((row) => mapLearnerIdentityRow(row));
};

export const addLearnerIdentityAlias = async (
  db: SqlDatabase,
  input: AddLearnerIdentityAliasInput,
): Promise<LearnerIdentityRecord> => {
  const identityId = createPrefixedId("lid");
  const nowIso = new Date().toISOString();
  const normalizedIdentityValue = normalizeLearnerIdentityValue(
    input.identityType,
    input.identityValue,
  );
  const isPrimary = input.isPrimary ?? false;
  const isVerified = input.isVerified ?? false;

  if (isPrimary) {
    await db
      .prepare(
        `
        UPDATE learner_identities
        SET is_primary = 0,
            updated_at = ?
        WHERE tenant_id = ?
          AND learner_profile_id = ?
      `,
      )
      .bind(nowIso, input.tenantId, input.learnerProfileId)
      .run();
  }

  await db
    .prepare(
      `
      INSERT INTO learner_identities (
        id,
        tenant_id,
        learner_profile_id,
        identity_type,
        identity_value,
        is_primary,
        is_verified,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      identityId,
      input.tenantId,
      input.learnerProfileId,
      input.identityType,
      normalizedIdentityValue,
      isPrimary ? 1 : 0,
      isVerified ? 1 : 0,
      nowIso,
      nowIso,
    )
    .run();

  const insertedRow = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        learner_profile_id AS learnerProfileId,
        identity_type AS identityType,
        identity_value AS identityValue,
        is_primary AS isPrimary,
        is_verified AS isVerified,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM learner_identities
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, identityId)
    .first<LearnerIdentityRow>();

  if (insertedRow === null) {
    throw new Error(`Failed to create learner identity alias "${identityId}"`);
  }

  return mapLearnerIdentityRow(insertedRow);
};

export const removeLearnerIdentityAliasesByType = async (
  db: SqlDatabase,
  input: RemoveLearnerIdentityAliasesByTypeInput,
): Promise<number> => {
  const result = await db
    .prepare(
      "DELETE FROM learner_identities WHERE tenant_id = ? AND learner_profile_id = ? AND identity_type = ?",
    )
    .bind(input.tenantId, input.learnerProfileId, input.identityType)
    .run();

  return result.meta.rowsWritten ?? 0;
};

interface FindLearnerIdentityByTypeValueInput {
  tenantId: string;
  identityType: LearnerIdentityType;
  identityValue: string;
}

const findLearnerIdentityByTypeValue = async (
  db: SqlDatabase,
  input: FindLearnerIdentityByTypeValueInput,
): Promise<LearnerIdentityRecord | null> => {
  const normalizedIdentityValue = normalizeLearnerIdentityValue(
    input.identityType,
    input.identityValue,
  );
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        learner_profile_id AS learnerProfileId,
        identity_type AS identityType,
        identity_value AS identityValue,
        is_primary AS isPrimary,
        is_verified AS isVerified,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM learner_identities
      WHERE tenant_id = ?
        AND identity_type = ?
        AND identity_value = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.identityType, normalizedIdentityValue)
    .first<LearnerIdentityRow>();

  return row === null ? null : mapLearnerIdentityRow(row);
};

const demotePrimaryIdentitiesOnProfile = async (
  db: SqlDatabase,
  tenantId: string,
  learnerProfileId: string,
  updatedAtIso: string,
): Promise<void> => {
  await db
    .prepare(
      `
      UPDATE learner_identities
      SET is_primary = 0,
          updated_at = ?
      WHERE tenant_id = ?
        AND learner_profile_id = ?
    `,
    )
    .bind(updatedAtIso, tenantId, learnerProfileId)
    .run();
};

const deleteOrphanLearnerProfileIfUnreferenced = async (
  db: SqlDatabase,
  tenantId: string,
  learnerProfileId: string,
): Promise<void> => {
  await db
    .prepare(
      `
      DELETE FROM learner_profiles
      WHERE tenant_id = ?
        AND id = ?
        AND NOT EXISTS (
          SELECT 1
          FROM learner_identities
          WHERE tenant_id = ?
            AND learner_profile_id = ?
        )
        AND NOT EXISTS (
          SELECT 1
          FROM assertions
          WHERE tenant_id = ?
            AND learner_profile_id = ?
        )
        AND NOT EXISTS (
          SELECT 1
          FROM learner_record_entries
          WHERE tenant_id = ?
            AND learner_profile_id = ?
        )
    `,
    )
    .bind(
      tenantId,
      learnerProfileId,
      tenantId,
      learnerProfileId,
      tenantId,
      learnerProfileId,
      tenantId,
      learnerProfileId,
    )
    .run();
};

export const moveLearnerIdentityAliasToProfile = async (
  db: SqlDatabase,
  input: MoveLearnerIdentityAliasToProfileInput,
): Promise<LearnerIdentityRecord> => {
  const normalizedIdentityValue = normalizeLearnerIdentityValue(
    input.identityType,
    input.identityValue,
  );
  const isPrimary = input.isPrimary ?? false;
  const isVerified = input.isVerified ?? true;

  return runSqlTransaction(db, async (transactionDb) => {
    const existingIdentity = await findLearnerIdentityByTypeValue(transactionDb, {
      tenantId: input.tenantId,
      identityType: input.identityType,
      identityValue: normalizedIdentityValue,
    });

    if (existingIdentity !== null) {
      if (existingIdentity.learnerProfileId === input.learnerProfileId) {
        return existingIdentity;
      }

      const previousProfileId = existingIdentity.learnerProfileId;
      const nowIso = new Date().toISOString();

      if (isPrimary) {
        await demotePrimaryIdentitiesOnProfile(
          transactionDb,
          input.tenantId,
          input.learnerProfileId,
          nowIso,
        );
      }

      await transactionDb
        .prepare(
          `
          UPDATE learner_identities
          SET learner_profile_id = ?,
              is_primary = ?,
              is_verified = ?,
              updated_at = ?
          WHERE tenant_id = ?
            AND identity_type = ?
            AND identity_value = ?
        `,
        )
        .bind(
          input.learnerProfileId,
          isPrimary ? 1 : 0,
          isVerified ? 1 : 0,
          nowIso,
          input.tenantId,
          input.identityType,
          normalizedIdentityValue,
        )
        .run();

      await deleteOrphanLearnerProfileIfUnreferenced(
        transactionDb,
        input.tenantId,
        previousProfileId,
      );

      const movedIdentity = await findLearnerIdentityByTypeValue(transactionDb, {
        tenantId: input.tenantId,
        identityType: input.identityType,
        identityValue: normalizedIdentityValue,
      });

      if (movedIdentity === null) {
        throw new Error("Failed to move learner identity alias to the requested profile");
      }

      return movedIdentity;
    }

    return addLearnerIdentityAlias(transactionDb, {
      tenantId: input.tenantId,
      learnerProfileId: input.learnerProfileId,
      identityType: input.identityType,
      identityValue: normalizedIdentityValue,
      isPrimary,
      isVerified,
    });
  });
};

export const createLearnerProfile = async (
  db: SqlDatabase,
  input: CreateLearnerProfileInput,
): Promise<LearnerProfileRecord> => {
  const learnerProfileId = createPrefixedId("lpr");
  const nowIso = new Date().toISOString();
  const subjectId =
    input.subjectId === undefined || input.subjectId.trim().length === 0
      ? defaultLearnerSubjectId(input.tenantId, learnerProfileId)
      : input.subjectId.trim();
  const displayName =
    input.displayName === undefined || input.displayName.trim().length === 0
      ? null
      : input.displayName.trim();

  await db
    .prepare(
      `
      INSERT INTO learner_profiles (
        id,
        tenant_id,
        subject_id,
        display_name,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(learnerProfileId, input.tenantId, subjectId, displayName, nowIso, nowIso)
    .run();

  await addLearnerIdentityAlias(db, {
    tenantId: input.tenantId,
    learnerProfileId,
    identityType: input.primaryIdentityType,
    identityValue: input.primaryIdentityValue,
    isPrimary: true,
    isVerified: input.primaryIdentityVerified ?? false,
  });

  const profile = await findLearnerProfileById(db, input.tenantId, learnerProfileId);

  if (profile === null) {
    throw new Error(`Failed to create learner profile "${learnerProfileId}"`);
  }

  return profile;
};

export const findLearnerProfileByIdentity = async (
  db: SqlDatabase,
  input: FindLearnerProfileByIdentityInput,
): Promise<LearnerProfileRecord | null> => {
  const normalizedIdentityValue = normalizeLearnerIdentityValue(
    input.identityType,
    input.identityValue,
  );
  const row = await db
    .prepare(
      `
      SELECT
        learner_profiles.id AS id,
        learner_profiles.tenant_id AS tenantId,
        learner_profiles.subject_id AS subjectId,
        learner_profiles.display_name AS displayName,
        learner_profiles.created_at AS createdAt,
        learner_profiles.updated_at AS updatedAt
      FROM learner_profiles
      INNER JOIN learner_identities
        ON learner_identities.tenant_id = learner_profiles.tenant_id
        AND learner_identities.learner_profile_id = learner_profiles.id
      WHERE learner_profiles.tenant_id = ?
        AND learner_identities.identity_type = ?
        AND learner_identities.identity_value = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.identityType, normalizedIdentityValue)
    .first<LearnerProfileRow>();

  return row === null ? null : mapLearnerProfileRow(row);
};

export const resolveLearnerProfileForIdentity = async (
  db: SqlDatabase,
  input: ResolveLearnerProfileForIdentityInput,
): Promise<LearnerProfileRecord> => {
  const existingProfile = await findLearnerProfileByIdentity(db, {
    tenantId: input.tenantId,
    identityType: input.identityType,
    identityValue: input.identityValue,
  });

  if (existingProfile !== null) {
    return existingProfile;
  }

  return createLearnerProfile(db, {
    tenantId: input.tenantId,
    displayName: input.displayName,
    primaryIdentityType: input.identityType,
    primaryIdentityValue: input.identityValue,
    primaryIdentityVerified: true,
  });
};

const findLearnerProfileByVerifiedIdentity = async (
  db: SqlDatabase,
  input: FindLearnerProfileByIdentityInput,
): Promise<LearnerProfileRecord | null> => {
  const normalizedIdentityValue = normalizeLearnerIdentityValue(
    input.identityType,
    input.identityValue,
  );
  const row = await db
    .prepare(
      `
      SELECT
        learner_profiles.id AS id,
        learner_profiles.tenant_id AS tenantId,
        learner_profiles.subject_id AS subjectId,
        learner_profiles.display_name AS displayName,
        learner_profiles.created_at AS createdAt,
        learner_profiles.updated_at AS updatedAt
      FROM learner_profiles
      INNER JOIN learner_identities
        ON learner_identities.tenant_id = learner_profiles.tenant_id
        AND learner_identities.learner_profile_id = learner_profiles.id
      WHERE learner_profiles.tenant_id = ?
        AND learner_identities.identity_type = ?
        AND learner_identities.identity_value = ?
        AND learner_identities.is_verified = 1
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.identityType, normalizedIdentityValue)
    .first<LearnerProfileRow>();

  return row === null ? null : mapLearnerProfileRow(row);
};

export const resolveLearnerProfileFromSaml = async (
  db: SqlDatabase,
  input: ResolveLearnerProfileFromSamlInput,
): Promise<ResolveLearnerProfileFromSamlResult> => {
  const samlSubject =
    input.samlSubject === undefined || input.samlSubject.trim().length === 0
      ? null
      : input.samlSubject.trim();
  const email =
    input.email === undefined || input.email.trim().length === 0
      ? null
      : normalizeEmail(input.email);
  const displayName =
    input.displayName === undefined || input.displayName.trim().length === 0
      ? undefined
      : input.displayName.trim();

  if (samlSubject !== null) {
    const profileBySamlSubject = await findLearnerProfileByIdentity(db, {
      tenantId: input.tenantId,
      identityType: "saml_subject",
      identityValue: samlSubject,
    });

    if (profileBySamlSubject !== null) {
      return {
        profile: profileBySamlSubject,
        strategy: "saml_subject",
      };
    }
  }

  if (email !== null) {
    const profileByVerifiedEmail = await findLearnerProfileByVerifiedIdentity(db, {
      tenantId: input.tenantId,
      identityType: "email",
      identityValue: email,
    });

    if (profileByVerifiedEmail !== null) {
      if (samlSubject !== null) {
        await moveLearnerIdentityAliasToProfile(db, {
          tenantId: input.tenantId,
          learnerProfileId: profileByVerifiedEmail.id,
          identityType: "saml_subject",
          identityValue: samlSubject,
          isPrimary: true,
          isVerified: true,
        });
      }

      return {
        profile: profileByVerifiedEmail,
        strategy: "verified_email",
      };
    }
  }

  if (samlSubject === null && email === null) {
    throw new Error("Cannot resolve learner profile without SAML subject or email");
  }

  const primaryIdentityType: LearnerIdentityType = samlSubject === null ? "email" : "saml_subject";
  const primaryIdentityValue = samlSubject ?? email;

  if (primaryIdentityValue === null) {
    throw new Error("Primary learner identity is required");
  }

  const createdProfile = await createLearnerProfile(db, {
    tenantId: input.tenantId,
    displayName,
    primaryIdentityType,
    primaryIdentityValue,
    primaryIdentityVerified: true,
  });

  if (samlSubject !== null && email !== null) {
    await moveLearnerIdentityAliasToProfile(db, {
      tenantId: input.tenantId,
      learnerProfileId: createdProfile.id,
      identityType: "email",
      identityValue: email,
      isPrimary: false,
      isVerified: true,
    });
  }

  return {
    profile: createdProfile,
    strategy: "created",
  };
};
