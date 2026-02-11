export interface TenantQueryContext {
  tenantId: string;
}

export interface TenantScopedQuery {
  sql: string;
  params: readonly string[];
}

export const withTenantScope = (sql: string, context: TenantQueryContext): TenantScopedQuery => {
  return {
    sql: `${sql} WHERE tenant_id = ?`,
    params: [context.tenantId],
  };
};

export interface UserRecord {
  id: string;
  email: string;
}

export interface MagicLinkTokenRecord {
  id: string;
  tenantId: string;
  userId: string;
  magicTokenHash: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

export interface SessionRecord {
  id: string;
  tenantId: string;
  userId: string;
  sessionTokenHash: string;
  expiresAt: string;
  lastSeenAt: string;
  revokedAt: string | null;
  createdAt: string;
}

export interface LearnerIdentityLinkProofRecord {
  id: string;
  tenantId: string;
  learnerProfileId: string;
  requestedByUserId: string;
  identityType: 'email';
  identityValue: string;
  tokenHash: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

export type LearnerIdentityType =
  | 'email'
  | 'email_sha256'
  | 'did'
  | 'url'
  | 'saml_subject';

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

export type LearnerProfileResolutionStrategy = 'saml_subject' | 'verified_email' | 'created';

export interface ResolveLearnerProfileFromSamlResult {
  profile: LearnerProfileRecord;
  strategy: LearnerProfileResolutionStrategy;
}

export interface CreateMagicLinkTokenInput {
  tenantId: string;
  userId: string;
  magicTokenHash: string;
  expiresAt: string;
}

export interface CreateSessionInput {
  tenantId: string;
  userId: string;
  sessionTokenHash: string;
  expiresAt: string;
}

export interface CreateLearnerIdentityLinkProofInput {
  tenantId: string;
  learnerProfileId: string;
  requestedByUserId: string;
  identityType: 'email';
  identityValue: string;
  tokenHash: string;
  expiresAt: string;
}

export interface BadgeTemplateRecord {
  id: string;
  tenantId: string;
  slug: string;
  title: string;
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
  createdByUserId: string | null;
  isArchived: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateBadgeTemplateInput {
  tenantId: string;
  slug: string;
  title: string;
  description?: string | undefined;
  criteriaUri?: string | undefined;
  imageUri?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface ListBadgeTemplatesInput {
  tenantId: string;
  includeArchived: boolean;
}

export interface UpdateBadgeTemplateInput {
  tenantId: string;
  id: string;
  slug?: string | undefined;
  title?: string | undefined;
  description?: string | null | undefined;
  criteriaUri?: string | null | undefined;
  imageUri?: string | null | undefined;
}

export interface SetBadgeTemplateArchiveStateInput {
  tenantId: string;
  id: string;
  isArchived: boolean;
}

export interface AssertionRecord {
  id: string;
  tenantId: string;
  publicId: string | null;
  learnerProfileId: string | null;
  badgeTemplateId: string;
  recipientIdentity: string;
  recipientIdentityType: 'email' | 'email_sha256' | 'did' | 'url';
  vcR2Key: string;
  statusListIndex: number | null;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

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

export interface CreateAssertionInput {
  id: string;
  tenantId: string;
  publicId?: string | undefined;
  learnerProfileId?: string | undefined;
  badgeTemplateId: string;
  recipientIdentity: string;
  recipientIdentityType: 'email' | 'email_sha256' | 'did' | 'url';
  vcR2Key: string;
  statusListIndex: number;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId?: string | undefined;
}

export interface AssertionStatusListEntryRecord {
  statusListIndex: number;
  revokedAt: string | null;
}

export type JobQueueMessageType =
  | 'issue_badge'
  | 'revoke_badge'
  | 'rebuild_verification_cache'
  | 'import_migration_batch';

export type JobQueueMessageStatus = 'pending' | 'processing' | 'completed' | 'failed';

export interface JobQueueMessageRecord {
  id: string;
  tenantId: string;
  jobType: JobQueueMessageType;
  payloadJson: string;
  idempotencyKey: string;
  attemptCount: number;
  maxAttempts: number;
  availableAt: string;
  leasedUntil: string | null;
  leaseToken: string | null;
  lastError: string | null;
  completedAt: string | null;
  failedAt: string | null;
  status: JobQueueMessageStatus;
  createdAt: string;
  updatedAt: string;
}

export interface EnqueueJobQueueMessageInput {
  tenantId: string;
  jobType: JobQueueMessageType;
  payload: unknown;
  idempotencyKey: string;
  maxAttempts?: number | undefined;
}

export interface LeaseJobQueueMessagesInput {
  limit: number;
  leaseSeconds: number;
  nowIso: string;
}

export interface CompleteJobQueueMessageInput {
  id: string;
  leaseToken: string;
  nowIso: string;
}

export interface FailJobQueueMessageInput {
  id: string;
  leaseToken: string;
  nowIso: string;
  error: string;
  retryDelaySeconds: number;
}

export interface RecordAssertionRevocationInput {
  tenantId: string;
  assertionId: string;
  revocationId: string;
  reason: string;
  idempotencyKey: string;
  revokedByUserId?: string | undefined;
  revokedAt: string;
}

export interface RecordAssertionRevocationResult {
  status: 'revoked' | 'already_revoked';
  revokedAt: string;
}

export interface ListLearnerBadgeSummariesInput {
  tenantId: string;
  userId: string;
}

interface BadgeTemplateRow {
  id: string;
  tenantId: string;
  slug: string;
  title: string;
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
  createdByUserId: string | null;
  isArchived: number;
  createdAt: string;
  updatedAt: string;
}

interface AssertionRow {
  id: string;
  tenantId: string;
  publicId: string | null;
  learnerProfileId: string | null;
  badgeTemplateId: string;
  recipientIdentity: string;
  recipientIdentityType: 'email' | 'email_sha256' | 'did' | 'url';
  vcR2Key: string;
  statusListIndex: number | null;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface LearnerBadgeSummaryRow {
  assertionId: string;
  assertionPublicId: string | null;
  tenantId: string;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  issuedAt: string;
  revokedAt: string | null;
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

interface LearnerIdentityLinkProofRow {
  id: string;
  tenantId: string;
  learnerProfileId: string;
  requestedByUserId: string;
  identityType: 'email';
  identityValue: string;
  tokenHash: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

interface JobQueueMessageRow {
  id: string;
  tenantId: string;
  jobType: JobQueueMessageType;
  payloadJson: string;
  idempotencyKey: string;
  attemptCount: number;
  maxAttempts: number;
  availableAt: string;
  leasedUntil: string | null;
  leaseToken: string | null;
  lastError: string | null;
  completedAt: string | null;
  failedAt: string | null;
  status: JobQueueMessageStatus;
  createdAt: string;
  updatedAt: string;
}

const createPrefixedId = (prefix: string): string => {
  return `${prefix}_${crypto.randomUUID()}`;
};

const defaultLearnerSubjectId = (tenantId: string, learnerProfileId: string): string => {
  return `urn:credtrail:learner:${encodeURIComponent(tenantId)}:${encodeURIComponent(learnerProfileId)}`;
};

const addSecondsToIso = (fromIso: string, seconds: number): string => {
  const fromMs = Date.parse(fromIso);

  if (!Number.isFinite(fromMs)) {
    throw new Error('Invalid ISO timestamp');
  }

  return new Date(fromMs + seconds * 1000).toISOString();
};

export const normalizeEmail = (email: string): string => {
  return email.trim().toLowerCase();
};

export const upsertUserByEmail = async (db: D1Database, email: string): Promise<UserRecord> => {
  const normalizedEmail = normalizeEmail(email);
  const createdUserId = createPrefixedId('usr');

  await db
    .prepare(
      `
      INSERT OR IGNORE INTO users (id, email)
      VALUES (?, ?)
    `,
    )
    .bind(createdUserId, normalizedEmail)
    .run();

  const user = await db
    .prepare(
      `
      SELECT id, email
      FROM users
      WHERE email = ?
      LIMIT 1
    `,
    )
    .bind(normalizedEmail)
    .first<UserRecord>();

  if (user === null) {
    throw new Error(`Unable to upsert user for email "${normalizedEmail}"`);
  }

  return user;
};

export const findUserById = async (db: D1Database, userId: string): Promise<UserRecord | null> => {
  const user = await db
    .prepare(
      `
      SELECT id, email
      FROM users
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(userId)
    .first<UserRecord>();

  return user;
};

export const normalizeLearnerIdentityValue = (
  identityType: LearnerIdentityType,
  identityValue: string,
): string => {
  const trimmed = identityValue.trim();

  switch (identityType) {
    case 'email':
      return normalizeEmail(trimmed);
    case 'email_sha256':
      return trimmed.toLowerCase();
    case 'did':
    case 'url':
    case 'saml_subject':
      return trimmed;
  }
};

export const findLearnerProfileById = async (
  db: D1Database,
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
  db: D1Database,
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
  db: D1Database,
  input: AddLearnerIdentityAliasInput,
): Promise<LearnerIdentityRecord> => {
  const identityId = createPrefixedId('lid');
  const nowIso = new Date().toISOString();
  const normalizedIdentityValue = normalizeLearnerIdentityValue(input.identityType, input.identityValue);
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

export const createLearnerProfile = async (
  db: D1Database,
  input: CreateLearnerProfileInput,
): Promise<LearnerProfileRecord> => {
  const learnerProfileId = createPrefixedId('lpr');
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
  db: D1Database,
  input: FindLearnerProfileByIdentityInput,
): Promise<LearnerProfileRecord | null> => {
  const normalizedIdentityValue = normalizeLearnerIdentityValue(input.identityType, input.identityValue);
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
  db: D1Database,
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
  db: D1Database,
  input: FindLearnerProfileByIdentityInput,
): Promise<LearnerProfileRecord | null> => {
  const normalizedIdentityValue = normalizeLearnerIdentityValue(input.identityType, input.identityValue);
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
  db: D1Database,
  input: ResolveLearnerProfileFromSamlInput,
): Promise<ResolveLearnerProfileFromSamlResult> => {
  const samlSubject =
    input.samlSubject === undefined || input.samlSubject.trim().length === 0
      ? null
      : input.samlSubject.trim();
  const email =
    input.email === undefined || input.email.trim().length === 0 ? null : normalizeEmail(input.email);
  const displayName =
    input.displayName === undefined || input.displayName.trim().length === 0
      ? undefined
      : input.displayName.trim();

  if (samlSubject !== null) {
    const profileBySamlSubject = await findLearnerProfileByIdentity(db, {
      tenantId: input.tenantId,
      identityType: 'saml_subject',
      identityValue: samlSubject,
    });

    if (profileBySamlSubject !== null) {
      return {
        profile: profileBySamlSubject,
        strategy: 'saml_subject',
      };
    }
  }

  if (email !== null) {
    const profileByVerifiedEmail = await findLearnerProfileByVerifiedIdentity(db, {
      tenantId: input.tenantId,
      identityType: 'email',
      identityValue: email,
    });

    if (profileByVerifiedEmail !== null) {
      if (samlSubject !== null) {
        await addLearnerIdentityAlias(db, {
          tenantId: input.tenantId,
          learnerProfileId: profileByVerifiedEmail.id,
          identityType: 'saml_subject',
          identityValue: samlSubject,
          isPrimary: true,
          isVerified: true,
        });
      }

      return {
        profile: profileByVerifiedEmail,
        strategy: 'verified_email',
      };
    }
  }

  if (samlSubject === null && email === null) {
    throw new Error('Cannot resolve learner profile without SAML subject or email');
  }

  const primaryIdentityType: LearnerIdentityType = samlSubject === null ? 'email' : 'saml_subject';
  const primaryIdentityValue = samlSubject ?? email;

  if (primaryIdentityValue === null) {
    throw new Error('Primary learner identity is required');
  }

  const createdProfile = await createLearnerProfile(db, {
    tenantId: input.tenantId,
    displayName,
    primaryIdentityType,
    primaryIdentityValue,
    primaryIdentityVerified: true,
  });

  if (samlSubject !== null && email !== null) {
    await addLearnerIdentityAlias(db, {
      tenantId: input.tenantId,
      learnerProfileId: createdProfile.id,
      identityType: 'email',
      identityValue: email,
      isPrimary: false,
      isVerified: true,
    });
  }

  return {
    profile: createdProfile,
    strategy: 'created',
  };
};

export const ensureTenantMembership = async (
  db: D1Database,
  tenantId: string,
  userId: string,
): Promise<void> => {
  await db
    .prepare(
      `
      INSERT OR IGNORE INTO memberships (tenant_id, user_id, role)
      VALUES (?, ?, 'viewer')
    `,
    )
    .bind(tenantId, userId)
    .run();
};

export const createMagicLinkToken = async (
  db: D1Database,
  input: CreateMagicLinkTokenInput,
): Promise<MagicLinkTokenRecord> => {
  const id = createPrefixedId('mlt');
  const createdAt = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO magic_link_tokens (
        id,
        tenant_id,
        user_id,
        magic_token_hash,
        expires_at,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(id, input.tenantId, input.userId, input.magicTokenHash, input.expiresAt, createdAt)
    .run();

  return {
    id,
    tenantId: input.tenantId,
    userId: input.userId,
    magicTokenHash: input.magicTokenHash,
    expiresAt: input.expiresAt,
    usedAt: null,
    createdAt,
  };
};

export const createLearnerIdentityLinkProof = async (
  db: D1Database,
  input: CreateLearnerIdentityLinkProofInput,
): Promise<LearnerIdentityLinkProofRecord> => {
  const id = createPrefixedId('lip');
  const createdAt = new Date().toISOString();
  const identityValue = normalizeEmail(input.identityValue);

  await db
    .prepare(
      `
      INSERT INTO learner_identity_link_proofs (
        id,
        tenant_id,
        learner_profile_id,
        requested_by_user_id,
        identity_type,
        identity_value,
        token_hash,
        expires_at,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.learnerProfileId,
      input.requestedByUserId,
      input.identityType,
      identityValue,
      input.tokenHash,
      input.expiresAt,
      createdAt,
    )
    .run();

  return {
    id,
    tenantId: input.tenantId,
    learnerProfileId: input.learnerProfileId,
    requestedByUserId: input.requestedByUserId,
    identityType: input.identityType,
    identityValue,
    tokenHash: input.tokenHash,
    expiresAt: input.expiresAt,
    usedAt: null,
    createdAt,
  };
};

export const findMagicLinkTokenByHash = async (
  db: D1Database,
  magicTokenHash: string,
): Promise<MagicLinkTokenRecord | null> => {
  const token = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        user_id AS userId,
        magic_token_hash AS magicTokenHash,
        expires_at AS expiresAt,
        used_at AS usedAt,
        created_at AS createdAt
      FROM magic_link_tokens
      WHERE magic_token_hash = ?
      LIMIT 1
    `,
    )
    .bind(magicTokenHash)
    .first<MagicLinkTokenRecord>();

  return token;
};

export const findLearnerIdentityLinkProofByHash = async (
  db: D1Database,
  tokenHash: string,
): Promise<LearnerIdentityLinkProofRecord | null> => {
  const proof = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        learner_profile_id AS learnerProfileId,
        requested_by_user_id AS requestedByUserId,
        identity_type AS identityType,
        identity_value AS identityValue,
        token_hash AS tokenHash,
        expires_at AS expiresAt,
        used_at AS usedAt,
        created_at AS createdAt
      FROM learner_identity_link_proofs
      WHERE token_hash = ?
      LIMIT 1
    `,
    )
    .bind(tokenHash)
    .first<LearnerIdentityLinkProofRow>();

  return proof;
};

export const markMagicLinkTokenUsed = async (
  db: D1Database,
  tokenId: string,
  usedAt: string,
): Promise<void> => {
  await db
    .prepare(
      `
      UPDATE magic_link_tokens
      SET used_at = ?
      WHERE id = ?
        AND used_at IS NULL
    `,
    )
    .bind(usedAt, tokenId)
    .run();
};

export const markLearnerIdentityLinkProofUsed = async (
  db: D1Database,
  proofId: string,
  usedAt: string,
): Promise<void> => {
  await db
    .prepare(
      `
      UPDATE learner_identity_link_proofs
      SET used_at = ?
      WHERE id = ?
        AND used_at IS NULL
    `,
    )
    .bind(usedAt, proofId)
    .run();
};

export const isMagicLinkTokenValid = (token: MagicLinkTokenRecord, nowIso: string): boolean => {
  if (token.usedAt !== null) {
    return false;
  }

  const expiryMs = Date.parse(token.expiresAt);
  const nowMs = Date.parse(nowIso);

  if (!Number.isFinite(expiryMs) || !Number.isFinite(nowMs)) {
    return false;
  }

  return expiryMs > nowMs;
};

export const isLearnerIdentityLinkProofValid = (
  proof: LearnerIdentityLinkProofRecord,
  nowIso: string,
): boolean => {
  if (proof.usedAt !== null) {
    return false;
  }

  const expiryMs = Date.parse(proof.expiresAt);
  const nowMs = Date.parse(nowIso);

  if (!Number.isFinite(expiryMs) || !Number.isFinite(nowMs)) {
    return false;
  }

  return expiryMs > nowMs;
};

export const createSession = async (
  db: D1Database,
  input: CreateSessionInput,
): Promise<SessionRecord> => {
  const id = createPrefixedId('ses');
  const createdAt = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO sessions (
        id,
        tenant_id,
        user_id,
        session_token_hash,
        expires_at,
        created_at,
        last_seen_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.userId,
      input.sessionTokenHash,
      input.expiresAt,
      createdAt,
      createdAt,
    )
    .run();

  return {
    id,
    tenantId: input.tenantId,
    userId: input.userId,
    sessionTokenHash: input.sessionTokenHash,
    expiresAt: input.expiresAt,
    lastSeenAt: createdAt,
    revokedAt: null,
    createdAt,
  };
};

export const findActiveSessionByHash = async (
  db: D1Database,
  sessionTokenHash: string,
  nowIso: string,
): Promise<SessionRecord | null> => {
  const session = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        user_id AS userId,
        session_token_hash AS sessionTokenHash,
        expires_at AS expiresAt,
        last_seen_at AS lastSeenAt,
        revoked_at AS revokedAt,
        created_at AS createdAt
      FROM sessions
      WHERE session_token_hash = ?
        AND revoked_at IS NULL
        AND expires_at > ?
      LIMIT 1
    `,
    )
    .bind(sessionTokenHash, nowIso)
    .first<SessionRecord>();

  return session;
};

export const touchSession = async (db: D1Database, sessionId: string, seenAt: string): Promise<void> => {
  await db
    .prepare(
      `
      UPDATE sessions
      SET last_seen_at = ?
      WHERE id = ?
    `,
    )
    .bind(seenAt, sessionId)
    .run();
};

export const revokeSessionByHash = async (
  db: D1Database,
  sessionTokenHash: string,
  revokedAt: string,
): Promise<void> => {
  await db
    .prepare(
      `
      UPDATE sessions
      SET revoked_at = COALESCE(revoked_at, ?)
      WHERE session_token_hash = ?
    `,
    )
    .bind(revokedAt, sessionTokenHash)
    .run();
};

const mapBadgeTemplateRow = (row: BadgeTemplateRow): BadgeTemplateRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    slug: row.slug,
    title: row.title,
    description: row.description,
    criteriaUri: row.criteriaUri,
    imageUri: row.imageUri,
    createdByUserId: row.createdByUserId,
    isArchived: row.isArchived === 1,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
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

const mapAssertionRow = (row: AssertionRow): AssertionRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    publicId: row.publicId,
    learnerProfileId: row.learnerProfileId,
    badgeTemplateId: row.badgeTemplateId,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    vcR2Key: row.vcR2Key,
    statusListIndex: row.statusListIndex,
    idempotencyKey: row.idempotencyKey,
    issuedAt: row.issuedAt,
    issuedByUserId: row.issuedByUserId,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLearnerBadgeSummaryRow = (row: LearnerBadgeSummaryRow): LearnerBadgeSummaryRecord => {
  return {
    assertionId: row.assertionId,
    assertionPublicId: row.assertionPublicId,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: row.badgeTitle,
    badgeDescription: row.badgeDescription,
    issuedAt: row.issuedAt,
    revokedAt: row.revokedAt,
  };
};

export const createBadgeTemplate = async (
  db: D1Database,
  input: CreateBadgeTemplateInput,
): Promise<BadgeTemplateRecord> => {
  const id = createPrefixedId('bt');
  const nowIso = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO badge_templates (
        id,
        tenant_id,
        slug,
        title,
        description,
        criteria_uri,
        image_uri,
        created_by_user_id,
        is_archived,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.slug,
      input.title,
      input.description ?? null,
      input.criteriaUri ?? null,
      input.imageUri ?? null,
      input.createdByUserId ?? null,
      nowIso,
      nowIso,
    )
    .run();

  return {
    id,
    tenantId: input.tenantId,
    slug: input.slug,
    title: input.title,
    description: input.description ?? null,
    criteriaUri: input.criteriaUri ?? null,
    imageUri: input.imageUri ?? null,
    createdByUserId: input.createdByUserId ?? null,
    isArchived: false,
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

export const listBadgeTemplates = async (
  db: D1Database,
  input: ListBadgeTemplatesInput,
): Promise<BadgeTemplateRecord[]> => {
  const query = input.includeArchived
    ? `
      SELECT
        id,
        tenant_id AS tenantId,
        slug,
        title,
        description,
        criteria_uri AS criteriaUri,
        image_uri AS imageUri,
        created_by_user_id AS createdByUserId,
        is_archived AS isArchived,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM badge_templates
      WHERE tenant_id = ?
      ORDER BY created_at DESC
    `
    : `
      SELECT
        id,
        tenant_id AS tenantId,
        slug,
        title,
        description,
        criteria_uri AS criteriaUri,
        image_uri AS imageUri,
        created_by_user_id AS createdByUserId,
        is_archived AS isArchived,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM badge_templates
      WHERE tenant_id = ?
        AND is_archived = 0
      ORDER BY created_at DESC
    `;

  const result = await db.prepare(query).bind(input.tenantId).all<BadgeTemplateRow>();
  const rows = result.results;

  return rows.map((row) => mapBadgeTemplateRow(row));
};

export const findBadgeTemplateById = async (
  db: D1Database,
  tenantId: string,
  badgeTemplateId: string,
): Promise<BadgeTemplateRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        slug,
        title,
        description,
        criteria_uri AS criteriaUri,
        image_uri AS imageUri,
        created_by_user_id AS createdByUserId,
        is_archived AS isArchived,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM badge_templates
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, badgeTemplateId)
    .first<BadgeTemplateRow>();

  if (row === null) {
    return null;
  }

  return mapBadgeTemplateRow(row);
};

export const updateBadgeTemplate = async (
  db: D1Database,
  input: UpdateBadgeTemplateInput,
): Promise<BadgeTemplateRecord | null> => {
  const setClauses: string[] = [];
  const params: (string | null)[] = [];

  if (input.slug !== undefined) {
    setClauses.push('slug = ?');
    params.push(input.slug);
  }

  if (input.title !== undefined) {
    setClauses.push('title = ?');
    params.push(input.title);
  }

  if (input.description !== undefined) {
    setClauses.push('description = ?');
    params.push(input.description);
  }

  if (input.criteriaUri !== undefined) {
    setClauses.push('criteria_uri = ?');
    params.push(input.criteriaUri);
  }

  if (input.imageUri !== undefined) {
    setClauses.push('image_uri = ?');
    params.push(input.imageUri);
  }

  if (setClauses.length === 0) {
    throw new Error('No badge template fields were provided for update');
  }

  const updatedAt = new Date().toISOString();
  const sql = `
    UPDATE badge_templates
    SET ${setClauses.join(', ')},
        updated_at = ?
    WHERE tenant_id = ?
      AND id = ?
  `;

  await db
    .prepare(sql)
    .bind(...params, updatedAt, input.tenantId, input.id)
    .run();

  return findBadgeTemplateById(db, input.tenantId, input.id);
};

export const setBadgeTemplateArchivedState = async (
  db: D1Database,
  input: SetBadgeTemplateArchiveStateInput,
): Promise<BadgeTemplateRecord | null> => {
  const updatedAt = new Date().toISOString();

  await db
    .prepare(
      `
      UPDATE badge_templates
      SET is_archived = ?,
          updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(input.isArchived ? 1 : 0, updatedAt, input.tenantId, input.id)
    .run();

  return findBadgeTemplateById(db, input.tenantId, input.id);
};

export const findAssertionById = async (
  db: D1Database,
  tenantId: string,
  assertionId: string,
): Promise<AssertionRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        public_id AS publicId,
        learner_profile_id AS learnerProfileId,
        badge_template_id AS badgeTemplateId,
        recipient_identity AS recipientIdentity,
        recipient_identity_type AS recipientIdentityType,
        vc_r2_key AS vcR2Key,
        status_list_index AS statusListIndex,
        idempotency_key AS idempotencyKey,
        issued_at AS issuedAt,
        issued_by_user_id AS issuedByUserId,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM assertions
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, assertionId)
    .first<AssertionRow>();

  if (row === null) {
    return null;
  }

  return mapAssertionRow(row);
};

export const findAssertionByIdempotencyKey = async (
  db: D1Database,
  tenantId: string,
  idempotencyKey: string,
): Promise<AssertionRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        public_id AS publicId,
        learner_profile_id AS learnerProfileId,
        badge_template_id AS badgeTemplateId,
        recipient_identity AS recipientIdentity,
        recipient_identity_type AS recipientIdentityType,
        vc_r2_key AS vcR2Key,
        status_list_index AS statusListIndex,
        idempotency_key AS idempotencyKey,
        issued_at AS issuedAt,
        issued_by_user_id AS issuedByUserId,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM assertions
      WHERE tenant_id = ?
        AND idempotency_key = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, idempotencyKey)
    .first<AssertionRow>();

  if (row === null) {
    return null;
  }

  return mapAssertionRow(row);
};

export const findAssertionByPublicId = async (
  db: D1Database,
  publicId: string,
): Promise<AssertionRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        public_id AS publicId,
        learner_profile_id AS learnerProfileId,
        badge_template_id AS badgeTemplateId,
        recipient_identity AS recipientIdentity,
        recipient_identity_type AS recipientIdentityType,
        vc_r2_key AS vcR2Key,
        status_list_index AS statusListIndex,
        idempotency_key AS idempotencyKey,
        issued_at AS issuedAt,
        issued_by_user_id AS issuedByUserId,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM assertions
      WHERE public_id = ?
      LIMIT 1
    `,
    )
    .bind(publicId)
    .first<AssertionRow>();

  if (row === null) {
    return null;
  }

  return mapAssertionRow(row);
};

export const listLearnerBadgeSummaries = async (
  db: D1Database,
  input: ListLearnerBadgeSummariesInput,
): Promise<LearnerBadgeSummaryRecord[]> => {
  const user = await findUserById(db, input.userId);

  if (user === null) {
    return [];
  }

  const learnerProfile = await findLearnerProfileByIdentity(db, {
    tenantId: input.tenantId,
    identityType: 'email',
    identityValue: user.email,
  });

  if (learnerProfile === null) {
    const legacyResult = await db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.public_id AS assertionPublicId,
          assertions.tenant_id AS tenantId,
          assertions.badge_template_id AS badgeTemplateId,
          badge_templates.title AS badgeTitle,
          badge_templates.description AS badgeDescription,
          assertions.issued_at AS issuedAt,
          assertions.revoked_at AS revokedAt
        FROM assertions
        INNER JOIN badge_templates
          ON badge_templates.tenant_id = assertions.tenant_id
          AND badge_templates.id = assertions.badge_template_id
        WHERE assertions.tenant_id = ?
          AND assertions.recipient_identity_type = 'email'
          AND LOWER(assertions.recipient_identity) = ?
        ORDER BY assertions.issued_at DESC
      `,
      )
      .bind(input.tenantId, normalizeEmail(user.email))
      .all<LearnerBadgeSummaryRow>();

    return legacyResult.results.map((row) => mapLearnerBadgeSummaryRow(row));
  }

  const identities = await listLearnerIdentitiesByProfile(db, input.tenantId, learnerProfile.id);
  const emailAliases = new Set<string>();
  emailAliases.add(normalizeEmail(user.email));

  for (const identity of identities) {
    if (identity.identityType === 'email') {
      emailAliases.add(normalizeEmail(identity.identityValue));
    }
  }

  const aliasList = Array.from(emailAliases);
  const emailPlaceholders = aliasList.map(() => '?').join(', ');
  const params: unknown[] = [input.tenantId, learnerProfile.id, ...aliasList];
  const result = await db
    .prepare(
      `
      SELECT
        assertions.id AS assertionId,
        assertions.public_id AS assertionPublicId,
        assertions.tenant_id AS tenantId,
        assertions.badge_template_id AS badgeTemplateId,
        badge_templates.title AS badgeTitle,
        badge_templates.description AS badgeDescription,
        assertions.issued_at AS issuedAt,
        assertions.revoked_at AS revokedAt
      FROM assertions
      INNER JOIN badge_templates
        ON badge_templates.tenant_id = assertions.tenant_id
        AND badge_templates.id = assertions.badge_template_id
      WHERE assertions.tenant_id = ?
        AND (
          assertions.learner_profile_id = ?
          OR (
            assertions.recipient_identity_type = 'email'
            AND LOWER(assertions.recipient_identity) IN (${emailPlaceholders})
          )
        )
      ORDER BY assertions.issued_at DESC
    `,
    )
    .bind(...params)
    .all<LearnerBadgeSummaryRow>();

  return result.results.map((row) => mapLearnerBadgeSummaryRow(row));
};

export const createAssertion = async (
  db: D1Database,
  input: CreateAssertionInput,
): Promise<AssertionRecord> => {
  const nowIso = new Date().toISOString();
  const assertionPublicId = input.publicId ?? crypto.randomUUID();

  await db
    .prepare(
      `
      INSERT INTO assertions (
        id,
        tenant_id,
        public_id,
        learner_profile_id,
        badge_template_id,
        recipient_identity,
        recipient_identity_type,
        vc_r2_key,
        status_list_index,
        idempotency_key,
        issued_at,
        issued_by_user_id,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      input.id,
      input.tenantId,
      assertionPublicId,
      input.learnerProfileId ?? null,
      input.badgeTemplateId,
      input.recipientIdentity,
      input.recipientIdentityType,
      input.vcR2Key,
      input.statusListIndex,
      input.idempotencyKey,
      input.issuedAt,
      input.issuedByUserId ?? null,
      nowIso,
      nowIso,
    )
    .run();

  return {
    id: input.id,
    tenantId: input.tenantId,
    publicId: assertionPublicId,
    learnerProfileId: input.learnerProfileId ?? null,
    badgeTemplateId: input.badgeTemplateId,
    recipientIdentity: input.recipientIdentity,
    recipientIdentityType: input.recipientIdentityType,
    vcR2Key: input.vcR2Key,
    statusListIndex: input.statusListIndex,
    idempotencyKey: input.idempotencyKey,
    issuedAt: input.issuedAt,
    issuedByUserId: input.issuedByUserId ?? null,
    revokedAt: null,
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

export const nextAssertionStatusListIndex = async (
  db: D1Database,
  tenantId: string,
): Promise<number> => {
  const row = await db
    .prepare(
      `
      SELECT
        COALESCE(MAX(status_list_index), -1) + 1 AS nextStatusListIndex
      FROM assertions
      WHERE tenant_id = ?
    `,
    )
    .bind(tenantId)
    .first<{ nextStatusListIndex: number }>();

  if (row === null) {
    throw new Error(`Unable to allocate status list index for tenant "${tenantId}"`);
  }

  return row.nextStatusListIndex;
};

export const listAssertionStatusListEntries = async (
  db: D1Database,
  tenantId: string,
): Promise<AssertionStatusListEntryRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        status_list_index AS statusListIndex,
        revoked_at AS revokedAt
      FROM assertions
      WHERE tenant_id = ?
        AND status_list_index IS NOT NULL
      ORDER BY status_list_index ASC
    `,
    )
    .bind(tenantId)
    .all<AssertionStatusListEntryRecord>();

  return result.results;
};

const serializeQueuePayload = (payload: unknown): string => {
  if (payload === undefined) {
    throw new Error('Queue payload is not JSON serializable');
  }

  return JSON.stringify(payload);
};

const mapJobQueueMessageRow = (row: JobQueueMessageRow): JobQueueMessageRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    jobType: row.jobType,
    payloadJson: row.payloadJson,
    idempotencyKey: row.idempotencyKey,
    attemptCount: row.attemptCount,
    maxAttempts: row.maxAttempts,
    availableAt: row.availableAt,
    leasedUntil: row.leasedUntil,
    leaseToken: row.leaseToken,
    lastError: row.lastError,
    completedAt: row.completedAt,
    failedAt: row.failedAt,
    status: row.status,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

export const enqueueJobQueueMessage = async (
  db: D1Database,
  input: EnqueueJobQueueMessageInput,
): Promise<JobQueueMessageRecord> => {
  const messageId = createPrefixedId('job');
  const nowIso = new Date().toISOString();
  const payloadJson = serializeQueuePayload(input.payload);
  const maxAttempts = input.maxAttempts ?? 8;

  await db
    .prepare(
      `
      INSERT INTO job_queue_messages (
        id,
        tenant_id,
        job_type,
        payload_json,
        idempotency_key,
        attempt_count,
        max_attempts,
        available_at,
        leased_until,
        lease_token,
        last_error,
        completed_at,
        failed_at,
        status,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL, NULL, NULL, NULL, 'pending', ?, ?)
    `,
    )
    .bind(
      messageId,
      input.tenantId,
      input.jobType,
      payloadJson,
      input.idempotencyKey,
      maxAttempts,
      nowIso,
      nowIso,
      nowIso,
    )
    .run();

  return {
    id: messageId,
    tenantId: input.tenantId,
    jobType: input.jobType,
    payloadJson,
    idempotencyKey: input.idempotencyKey,
    attemptCount: 0,
    maxAttempts,
    availableAt: nowIso,
    leasedUntil: null,
    leaseToken: null,
    lastError: null,
    completedAt: null,
    failedAt: null,
    status: 'pending',
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

export const leaseJobQueueMessages = async (
  db: D1Database,
  input: LeaseJobQueueMessagesInput,
): Promise<JobQueueMessageRecord[]> => {
  const leaseToken = createPrefixedId('lease');
  const leaseExpiresAt = addSecondsToIso(input.nowIso, input.leaseSeconds);
  const candidateResult = await db
    .prepare(
      `
      SELECT id
      FROM job_queue_messages
      WHERE status IN ('pending', 'processing')
        AND available_at <= ?
        AND (leased_until IS NULL OR leased_until <= ?)
        AND attempt_count < max_attempts
      ORDER BY created_at ASC
      LIMIT ?
    `,
    )
    .bind(input.nowIso, input.nowIso, input.limit)
    .all<{ id: string }>();

  for (const candidate of candidateResult.results) {
    await db
      .prepare(
        `
        UPDATE job_queue_messages
        SET status = 'processing',
            attempt_count = attempt_count + 1,
            leased_until = ?,
            lease_token = ?,
            updated_at = ?
        WHERE id = ?
          AND available_at <= ?
          AND (leased_until IS NULL OR leased_until <= ?)
          AND attempt_count < max_attempts
      `,
      )
      .bind(leaseExpiresAt, leaseToken, input.nowIso, candidate.id, input.nowIso, input.nowIso)
      .run();
  }

  const leasedResult = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        job_type AS jobType,
        payload_json AS payloadJson,
        idempotency_key AS idempotencyKey,
        attempt_count AS attemptCount,
        max_attempts AS maxAttempts,
        available_at AS availableAt,
        leased_until AS leasedUntil,
        lease_token AS leaseToken,
        last_error AS lastError,
        completed_at AS completedAt,
        failed_at AS failedAt,
        status,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM job_queue_messages
      WHERE lease_token = ?
      ORDER BY created_at ASC
    `,
    )
    .bind(leaseToken)
    .all<JobQueueMessageRow>();

  return leasedResult.results.map((row) => mapJobQueueMessageRow(row));
};

export const completeJobQueueMessage = async (
  db: D1Database,
  input: CompleteJobQueueMessageInput,
): Promise<void> => {
  await db
    .prepare(
      `
      UPDATE job_queue_messages
      SET status = 'completed',
          leased_until = NULL,
          lease_token = NULL,
          last_error = NULL,
          completed_at = ?,
          updated_at = ?
      WHERE id = ?
        AND lease_token = ?
    `,
    )
    .bind(input.nowIso, input.nowIso, input.id, input.leaseToken)
    .run();
};

export const failJobQueueMessage = async (
  db: D1Database,
  input: FailJobQueueMessageInput,
): Promise<JobQueueMessageStatus | null> => {
  const retryAt = addSecondsToIso(input.nowIso, input.retryDelaySeconds);

  await db
    .prepare(
      `
      UPDATE job_queue_messages
      SET status = CASE WHEN attempt_count >= max_attempts THEN 'failed' ELSE 'pending' END,
          available_at = CASE WHEN attempt_count >= max_attempts THEN available_at ELSE ? END,
          leased_until = NULL,
          lease_token = NULL,
          last_error = ?,
          failed_at = CASE WHEN attempt_count >= max_attempts THEN ? ELSE NULL END,
          updated_at = ?
      WHERE id = ?
        AND lease_token = ?
    `,
    )
    .bind(retryAt, input.error, input.nowIso, input.nowIso, input.id, input.leaseToken)
    .run();

  const row = await db
    .prepare(
      `
      SELECT
        status,
        lease_token AS leaseToken
      FROM job_queue_messages
      WHERE id = ?
    `,
    )
    .bind(input.id)
    .first<{ status: JobQueueMessageStatus; leaseToken: string | null }>();

  if (row?.leaseToken !== null) {
    return null;
  }

  return row.status;
};

export const recordAssertionRevocation = async (
  db: D1Database,
  input: RecordAssertionRevocationInput,
): Promise<RecordAssertionRevocationResult> => {
  const assertion = await findAssertionById(db, input.tenantId, input.assertionId);

  if (assertion === null) {
    throw new Error(`Assertion "${input.assertionId}" not found for tenant "${input.tenantId}"`);
  }

  const effectiveRevokedAt = assertion.revokedAt ?? input.revokedAt;

  if (assertion.revokedAt === null) {
    await db
      .prepare(
        `
        UPDATE assertions
        SET revoked_at = ?,
            updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
          AND revoked_at IS NULL
      `,
      )
      .bind(effectiveRevokedAt, input.revokedAt, input.tenantId, input.assertionId)
      .run();
  }

  await db
    .prepare(
      `
      INSERT OR IGNORE INTO revocations (
        id,
        tenant_id,
        assertion_id,
        reason,
        idempotency_key,
        revoked_by_user_id,
        revoked_at,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      input.revocationId,
      input.tenantId,
      input.assertionId,
      input.reason,
      input.idempotencyKey,
      input.revokedByUserId ?? null,
      effectiveRevokedAt,
      input.revokedAt,
    )
    .run();

  return {
    status: assertion.revokedAt === null ? 'revoked' : 'already_revoked',
    revokedAt: effectiveRevokedAt,
  };
};
