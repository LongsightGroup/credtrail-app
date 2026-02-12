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

export interface SqlExecutionMeta {
  rowsRead?: number | undefined;
  rowsWritten?: number | undefined;
  durationMs?: number | undefined;
}

export interface SqlRunResult {
  success: boolean;
  meta: SqlExecutionMeta;
}

export interface SqlQueryResult<T> extends SqlRunResult {
  results: T[];
}

export interface SqlPreparedStatement {
  bind(...params: unknown[]): SqlPreparedStatement;
  first<T>(): Promise<T | null>;
  all<T>(): Promise<SqlQueryResult<T>>;
  run(): Promise<SqlRunResult>;
}

export interface SqlDatabase {
  prepare(sql: string): SqlPreparedStatement;
}

export type TenantPlanTier = 'free' | 'team' | 'institution' | 'enterprise';

export interface TenantRecord {
  id: string;
  slug: string;
  displayName: string;
  planTier: TenantPlanTier;
  issuerDomain: string;
  didWeb: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantInput {
  id: string;
  slug: string;
  displayName: string;
  planTier: TenantPlanTier;
  issuerDomain: string;
  didWeb: string;
  isActive?: boolean | undefined;
}

export interface UpsertBadgeTemplateByIdInput {
  id: string;
  tenantId: string;
  slug: string;
  title: string;
  description?: string | undefined;
  criteriaUri?: string | undefined;
  imageUri?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface Ed25519PublicJwkRecord {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid?: string | undefined;
}

export interface Ed25519PrivateJwkRecord extends Ed25519PublicJwkRecord {
  d: string;
}

export interface TenantSigningRegistrationRecord {
  tenantId: string;
  did: string;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantSigningRegistrationInput {
  tenantId: string;
  did: string;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson?: string | undefined;
}

export interface LtiIssuerRegistrationRecord {
  issuer: string;
  tenantId: string;
  authorizationEndpoint: string;
  clientId: string;
  allowUnsignedIdToken: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertLtiIssuerRegistrationInput {
  issuer: string;
  tenantId: string;
  authorizationEndpoint: string;
  clientId: string;
  allowUnsignedIdToken?: boolean | undefined;
}

export interface UserRecord {
  id: string;
  email: string;
}

export type TenantMembershipRole = 'owner' | 'admin' | 'issuer' | 'viewer';

export interface TenantMembershipRecord {
  tenantId: string;
  userId: string;
  role: TenantMembershipRole;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantMembershipRoleInput {
  tenantId: string;
  userId: string;
  role: TenantMembershipRole;
}

export interface UpsertTenantMembershipRoleResult {
  membership: TenantMembershipRecord;
  previousRole: TenantMembershipRole | null;
  changed: boolean;
}

export interface EnsureTenantMembershipResult {
  membership: TenantMembershipRecord;
  created: boolean;
}

export interface AuditLogRecord {
  id: string;
  tenantId: string;
  actorUserId: string | null;
  action: string;
  targetType: string;
  targetId: string;
  metadataJson: string | null;
  occurredAt: string;
  createdAt: string;
}

export interface CreateAuditLogInput {
  tenantId: string;
  actorUserId?: string | undefined;
  action: string;
  targetType: string;
  targetId: string;
  metadata?: unknown;
  occurredAt?: string | undefined;
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

export interface OAuthClientRecord {
  clientId: string;
  clientSecretHash: string;
  clientName: string | null;
  redirectUrisJson: string;
  grantTypesJson: string;
  responseTypesJson: string;
  scope: string;
  tokenEndpointAuthMethod: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateOAuthClientInput {
  clientId: string;
  clientSecretHash: string;
  clientName?: string | undefined;
  redirectUrisJson: string;
  grantTypesJson: string;
  responseTypesJson: string;
  scope: string;
  tokenEndpointAuthMethod: string;
}

export interface OAuthAuthorizationCodeRecord {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  codeHash: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

export interface CreateOAuthAuthorizationCodeInput {
  clientId: string;
  userId: string;
  tenantId: string;
  codeHash: string;
  redirectUri: string;
  scope: string;
  expiresAt: string;
  codeChallenge?: string | undefined;
  codeChallengeMethod?: string | undefined;
}

export interface ConsumeOAuthAuthorizationCodeInput {
  clientId: string;
  codeHash: string;
  redirectUri: string;
  nowIso: string;
}

export interface OAuthAccessTokenRecord {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  accessTokenHash: string;
  scope: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

export interface CreateOAuthAccessTokenInput {
  clientId: string;
  userId: string;
  tenantId: string;
  accessTokenHash: string;
  scope: string;
  expiresAt: string;
}

export interface OAuthRefreshTokenRecord {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  refreshTokenHash: string;
  scope: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

export interface CreateOAuthRefreshTokenInput {
  clientId: string;
  userId: string;
  tenantId: string;
  refreshTokenHash: string;
  scope: string;
  expiresAt: string;
}

export interface ConsumeOAuthRefreshTokenInput {
  clientId: string;
  refreshTokenHash: string;
  nowIso: string;
}

export interface RevokeOAuthAccessTokenByHashInput {
  clientId: string;
  accessTokenHash: string;
  revokedAt: string;
}

export interface RevokeOAuthRefreshTokenByHashInput {
  clientId: string;
  refreshTokenHash: string;
  revokedAt: string;
}

export interface FindActiveOAuthAccessTokenByHashInput {
  accessTokenHash: string;
  nowIso: string;
}

export interface Ob3SubjectCredentialRecord {
  id: string;
  tenantId: string;
  userId: string;
  credentialId: string;
  payloadJson: string | null;
  compactJws: string | null;
  issuedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertOb3SubjectCredentialInput {
  tenantId: string;
  userId: string;
  credentialId: string;
  payloadJson?: string | null | undefined;
  compactJws?: string | null | undefined;
  issuedAt?: string | undefined;
}

export interface UpsertOb3SubjectCredentialResult {
  status: 'created' | 'updated';
  credential: Ob3SubjectCredentialRecord;
}

export interface ListOb3SubjectCredentialsInput {
  tenantId: string;
  userId: string;
  limit: number;
  offset: number;
  since?: string | undefined;
}

export interface ListOb3SubjectCredentialsResult {
  totalCount: number;
  credentials: Ob3SubjectCredentialRecord[];
}

export interface Ob3SubjectProfileRecord {
  tenantId: string;
  userId: string;
  profileJson: string;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertOb3SubjectProfileInput {
  tenantId: string;
  userId: string;
  profileJson: string;
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

export interface PublicBadgeWallEntryRecord {
  assertionId: string;
  assertionPublicId: string;
  tenantId: string;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: 'email' | 'email_sha256' | 'did' | 'url';
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

export interface ListPublicBadgeWallEntriesInput {
  tenantId: string;
  badgeTemplateId?: string | undefined;
  limit?: number | undefined;
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

interface TenantRow {
  id: string;
  slug: string;
  displayName: string;
  planTier: TenantPlanTier;
  issuerDomain: string;
  didWeb: string;
  isActive: number | boolean;
  createdAt: string;
  updatedAt: string;
}

interface TenantSigningRegistrationRow {
  tenantId: string;
  did: string;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson: string | null;
  createdAt: string;
  updatedAt: string;
}

interface LtiIssuerRegistrationRow {
  issuer: string;
  tenantId: string;
  authorizationEndpoint: string;
  clientId: string;
  allowUnsignedIdToken: number | boolean;
  createdAt: string;
  updatedAt: string;
}

interface TenantMembershipRow {
  tenantId: string;
  userId: string;
  role: TenantMembershipRole;
  createdAt: string;
  updatedAt: string;
}

interface AuditLogRow {
  id: string;
  tenantId: string;
  actorUserId: string | null;
  action: string;
  targetType: string;
  targetId: string;
  metadataJson: string | null;
  occurredAt: string;
  createdAt: string;
}

interface OAuthClientRow {
  clientId: string;
  clientSecretHash: string;
  clientName: string | null;
  redirectUrisJson: string;
  grantTypesJson: string;
  responseTypesJson: string;
  scope: string;
  tokenEndpointAuthMethod: string;
  createdAt: string;
  updatedAt: string;
}

interface OAuthAuthorizationCodeRow {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  codeHash: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

interface OAuthAccessTokenRow {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  accessTokenHash: string;
  scope: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

interface OAuthRefreshTokenRow {
  id: string;
  clientId: string;
  userId: string;
  tenantId: string;
  refreshTokenHash: string;
  scope: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

interface Ob3SubjectCredentialRow {
  id: string;
  tenantId: string;
  userId: string;
  credentialId: string;
  payloadJson: string | null;
  compactJws: string | null;
  issuedAt: string;
  createdAt: string;
  updatedAt: string;
}

interface Ob3SubjectCredentialCountRow {
  totalCount: number | string;
}

interface Ob3SubjectProfileRow {
  tenantId: string;
  userId: string;
  profileJson: string;
  createdAt: string;
  updatedAt: string;
}

const isMissingTenantSigningRegistrationsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes('no such table') ||
      error.message.includes('relation') ||
      error.message.includes('does not exist')) &&
    error.message.includes('tenant_signing_registrations')
  );
};

const isMissingLtiIssuerRegistrationsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes('no such table') ||
      error.message.includes('relation') ||
      error.message.includes('does not exist')) &&
    error.message.includes('lti_issuer_registrations')
  );
};

const isMissingAuditLogsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes('no such table') ||
      error.message.includes('relation') ||
      error.message.includes('does not exist')) &&
    error.message.includes('audit_logs')
  );
};

const isMissingOAuthTablesError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const tableMissing =
    error.message.includes('oauth_clients') ||
    error.message.includes('oauth_authorization_codes') ||
    error.message.includes('oauth_access_tokens') ||
    error.message.includes('oauth_refresh_tokens');

  if (!tableMissing) {
    return false;
  }

  return (
    error.message.includes('no such table') ||
    error.message.includes('relation') ||
    error.message.includes('does not exist')
  );
};

const isMissingOb3ResourceTablesError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const tableMissing =
    error.message.includes('ob3_subject_credentials') || error.message.includes('ob3_subject_profiles');

  if (!tableMissing) {
    return false;
  }

  return (
    error.message.includes('no such table') ||
    error.message.includes('relation') ||
    error.message.includes('does not exist')
  );
};

const ensureTenantSigningRegistrationsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_signing_registrations (
        tenant_id TEXT PRIMARY KEY,
        did TEXT NOT NULL UNIQUE,
        key_id TEXT NOT NULL,
        public_jwk_json TEXT NOT NULL,
        private_jwk_json TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_tenant_signing_registrations_did
        ON tenant_signing_registrations (did)
    `,
    )
    .run();
};

const ensureLtiIssuerRegistrationsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS lti_issuer_registrations (
        issuer TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        authorization_endpoint TEXT NOT NULL,
        client_id TEXT NOT NULL,
        allow_unsigned_id_token INTEGER NOT NULL DEFAULT 0 CHECK (allow_unsigned_id_token IN (0, 1)),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_lti_issuer_registrations_tenant
        ON lti_issuer_registrations (tenant_id)
    `,
    )
    .run();
};

const ensureAuditLogsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        actor_user_id TEXT,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        metadata_json TEXT,
        occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_occurred_at
        ON audit_logs (tenant_id, occurred_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_audit_logs_action
        ON audit_logs (action)
    `,
    )
    .run();
};

const ensureOAuthTables = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_secret_hash TEXT NOT NULL,
        client_name TEXT,
        redirect_uris_json TEXT NOT NULL,
        grant_types_json TEXT NOT NULL,
        response_types_json TEXT NOT NULL,
        scope TEXT NOT NULL,
        token_endpoint_auth_method TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
        id TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        code_hash TEXT NOT NULL UNIQUE,
        redirect_uri TEXT NOT NULL,
        scope TEXT NOT NULL,
        code_challenge TEXT,
        code_challenge_method TEXT,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS oauth_access_tokens (
        id TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        access_token_hash TEXT NOT NULL UNIQUE,
        scope TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
        id TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        refresh_token_hash TEXT NOT NULL UNIQUE,
        scope TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_lookup
        ON oauth_authorization_codes (client_id, code_hash)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_expires_at
        ON oauth_authorization_codes (expires_at)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_lookup
        ON oauth_access_tokens (client_id, access_token_hash)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_lookup
        ON oauth_refresh_tokens (client_id, refresh_token_hash)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_expires_at
        ON oauth_refresh_tokens (expires_at)
    `,
    )
    .run();
};

const ensureOb3ResourceTables = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS ob3_subject_credentials (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        credential_id TEXT NOT NULL,
        payload_json TEXT,
        compact_jws TEXT,
        issued_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (tenant_id, user_id, credential_id),
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_ob3_subject_credentials_lookup
        ON ob3_subject_credentials (tenant_id, user_id, issued_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS ob3_subject_profiles (
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        profile_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, user_id),
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `,
    )
    .run();
};

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

interface PublicBadgeWallEntryRow {
  assertionId: string;
  assertionPublicId: string;
  tenantId: string;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: 'email' | 'email_sha256' | 'did' | 'url';
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

export const upsertUserByEmail = async (db: SqlDatabase, email: string): Promise<UserRecord> => {
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

export const findUserById = async (db: SqlDatabase, userId: string): Promise<UserRecord | null> => {
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
  tenantId: string,
  userId: string,
): Promise<EnsureTenantMembershipResult> => {
  const existing = await findTenantMembership(db, tenantId, userId);

  if (existing !== null) {
    return {
      membership: existing,
      created: false,
    };
  }

  const upserted = await upsertTenantMembershipRole(db, {
    tenantId,
    userId,
    role: 'viewer',
  });

  return {
    membership: upserted.membership,
    created: true,
  };
};

export const findTenantMembership = async (
  db: SqlDatabase,
  tenantId: string,
  userId: string,
): Promise<TenantMembershipRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        tenant_id AS tenantId,
        user_id AS userId,
        role,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM memberships
      WHERE tenant_id = ?
        AND user_id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, userId)
    .first<TenantMembershipRow>();

  if (row === null) {
    return null;
  }

  return mapTenantMembershipRow(row);
};

export const upsertTenantMembershipRole = async (
  db: SqlDatabase,
  input: UpsertTenantMembershipRoleInput,
): Promise<UpsertTenantMembershipRoleResult> => {
  const existing = await findTenantMembership(db, input.tenantId, input.userId);
  const nowIso = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO memberships (
        tenant_id,
        user_id,
        role,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (tenant_id, user_id)
      DO UPDATE SET
        role = excluded.role,
        updated_at = excluded.updated_at
    `,
    )
    .bind(input.tenantId, input.userId, input.role, nowIso, nowIso)
    .run();

  const membership = await findTenantMembership(db, input.tenantId, input.userId);

  if (membership === null) {
    throw new Error(
      `Unable to upsert membership role for tenant "${input.tenantId}" and user "${input.userId}"`,
    );
  }

  return {
    membership,
    previousRole: existing?.role ?? null,
    changed: existing?.role !== membership.role,
  };
};

export const createAuditLog = async (
  db: SqlDatabase,
  input: CreateAuditLogInput,
): Promise<AuditLogRecord> => {
  const id = createPrefixedId('aud');
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const metadataJson =
    input.metadata === undefined ? null : JSON.stringify(input.metadata);

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO audit_logs (
          id,
          tenant_id,
          actor_user_id,
          action,
          target_type,
          target_id,
          metadata_json,
          occurred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.actorUserId ?? null,
        input.action,
        input.targetType,
        input.targetId,
        metadataJson,
        occurredAt,
        occurredAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingAuditLogsTableError(error)) {
      throw error;
    }

    await ensureAuditLogsTable(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        actor_user_id AS actorUserId,
        action,
        target_type AS targetType,
        target_id AS targetId,
        metadata_json AS metadataJson,
        occurred_at AS occurredAt,
        created_at AS createdAt
      FROM audit_logs
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(id)
    .first<AuditLogRow>();

  if (row === null) {
    throw new Error(`Unable to create audit log "${id}"`);
  }

  return mapAuditLogRow(row);
};

export const createMagicLinkToken = async (
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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

export const touchSession = async (db: SqlDatabase, sessionId: string, seenAt: string): Promise<void> => {
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
  db: SqlDatabase,
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

const mapOAuthClientRow = (row: OAuthClientRow): OAuthClientRecord => {
  return {
    clientId: row.clientId,
    clientSecretHash: row.clientSecretHash,
    clientName: row.clientName,
    redirectUrisJson: row.redirectUrisJson,
    grantTypesJson: row.grantTypesJson,
    responseTypesJson: row.responseTypesJson,
    scope: row.scope,
    tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapOAuthAuthorizationCodeRow = (
  row: OAuthAuthorizationCodeRow,
): OAuthAuthorizationCodeRecord => {
  return {
    id: row.id,
    clientId: row.clientId,
    userId: row.userId,
    tenantId: row.tenantId,
    codeHash: row.codeHash,
    redirectUri: row.redirectUri,
    scope: row.scope,
    codeChallenge: row.codeChallenge,
    codeChallengeMethod: row.codeChallengeMethod,
    expiresAt: row.expiresAt,
    usedAt: row.usedAt,
    createdAt: row.createdAt,
  };
};

const mapOAuthAccessTokenRow = (row: OAuthAccessTokenRow): OAuthAccessTokenRecord => {
  return {
    id: row.id,
    clientId: row.clientId,
    userId: row.userId,
    tenantId: row.tenantId,
    accessTokenHash: row.accessTokenHash,
    scope: row.scope,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
  };
};

const mapOAuthRefreshTokenRow = (row: OAuthRefreshTokenRow): OAuthRefreshTokenRecord => {
  return {
    id: row.id,
    clientId: row.clientId,
    userId: row.userId,
    tenantId: row.tenantId,
    refreshTokenHash: row.refreshTokenHash,
    scope: row.scope,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
  };
};

const mapOb3SubjectCredentialRow = (row: Ob3SubjectCredentialRow): Ob3SubjectCredentialRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    userId: row.userId,
    credentialId: row.credentialId,
    payloadJson: row.payloadJson,
    compactJws: row.compactJws,
    issuedAt: row.issuedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapOb3SubjectProfileRow = (row: Ob3SubjectProfileRow): Ob3SubjectProfileRecord => {
  return {
    tenantId: row.tenantId,
    userId: row.userId,
    profileJson: row.profileJson,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

export const createOAuthClient = async (
  db: SqlDatabase,
  input: CreateOAuthClientInput,
): Promise<OAuthClientRecord> => {
  const nowIso = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oauth_clients (
          client_id,
          client_secret_hash,
          client_name,
          redirect_uris_json,
          grant_types_json,
          response_types_json,
          scope,
          token_endpoint_auth_method,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        input.clientId,
        input.clientSecretHash,
        input.clientName ?? null,
        input.redirectUrisJson,
        input.grantTypesJson,
        input.responseTypesJson,
        input.scope,
        input.tokenEndpointAuthMethod,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        client_id AS clientId,
        client_secret_hash AS clientSecretHash,
        client_name AS clientName,
        redirect_uris_json AS redirectUrisJson,
        grant_types_json AS grantTypesJson,
        response_types_json AS responseTypesJson,
        scope,
        token_endpoint_auth_method AS tokenEndpointAuthMethod,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM oauth_clients
      WHERE client_id = ?
      LIMIT 1
    `,
    )
    .bind(input.clientId)
    .first<OAuthClientRow>();

  if (row === null) {
    throw new Error(`Unable to create OAuth client "${input.clientId}"`);
  }

  return mapOAuthClientRow(row);
};

export const findOAuthClientById = async (
  db: SqlDatabase,
  clientId: string,
): Promise<OAuthClientRecord | null> => {
  const findStatement = (): Promise<OAuthClientRow | null> =>
    db
      .prepare(
        `
        SELECT
          client_id AS clientId,
          client_secret_hash AS clientSecretHash,
          client_name AS clientName,
          redirect_uris_json AS redirectUrisJson,
          grant_types_json AS grantTypesJson,
          response_types_json AS responseTypesJson,
          scope,
          token_endpoint_auth_method AS tokenEndpointAuthMethod,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM oauth_clients
        WHERE client_id = ?
        LIMIT 1
      `,
      )
      .bind(clientId)
      .first<OAuthClientRow>();

  let row: OAuthClientRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    row = await findStatement();
  }

  if (row === null) {
    return null;
  }

  return mapOAuthClientRow(row);
};

export const createOAuthAuthorizationCode = async (
  db: SqlDatabase,
  input: CreateOAuthAuthorizationCodeInput,
): Promise<OAuthAuthorizationCodeRecord> => {
  const id = createPrefixedId('oac');
  const createdAt = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oauth_authorization_codes (
          id,
          client_id,
          user_id,
          tenant_id,
          code_hash,
          redirect_uri,
          scope,
          code_challenge,
          code_challenge_method,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.clientId,
        input.userId,
        input.tenantId,
        input.codeHash,
        input.redirectUri,
        input.scope,
        input.codeChallenge ?? null,
        input.codeChallengeMethod ?? null,
        input.expiresAt,
        createdAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await insertStatement();
  }

  return {
    id,
    clientId: input.clientId,
    userId: input.userId,
    tenantId: input.tenantId,
    codeHash: input.codeHash,
    redirectUri: input.redirectUri,
    scope: input.scope,
    codeChallenge: input.codeChallenge ?? null,
    codeChallengeMethod: input.codeChallengeMethod ?? null,
    expiresAt: input.expiresAt,
    usedAt: null,
    createdAt,
  };
};

export const consumeOAuthAuthorizationCode = async (
  db: SqlDatabase,
  input: ConsumeOAuthAuthorizationCodeInput,
): Promise<OAuthAuthorizationCodeRecord | null> => {
  const consumeStatement = (): Promise<OAuthAuthorizationCodeRow | null> =>
    db
      .prepare(
        `
        UPDATE oauth_authorization_codes
        SET used_at = ?
        WHERE client_id = ?
          AND code_hash = ?
          AND redirect_uri = ?
          AND used_at IS NULL
          AND expires_at > ?
        RETURNING
          id,
          client_id AS clientId,
          user_id AS userId,
          tenant_id AS tenantId,
          code_hash AS codeHash,
          redirect_uri AS redirectUri,
          scope,
          code_challenge AS codeChallenge,
          code_challenge_method AS codeChallengeMethod,
          expires_at AS expiresAt,
          used_at AS usedAt,
          created_at AS createdAt
      `,
      )
      .bind(input.nowIso, input.clientId, input.codeHash, input.redirectUri, input.nowIso)
      .first<OAuthAuthorizationCodeRow>();

  let row: OAuthAuthorizationCodeRow | null;

  try {
    row = await consumeStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    row = await consumeStatement();
  }

  if (row === null) {
    return null;
  }

  return mapOAuthAuthorizationCodeRow(row);
};

export const createOAuthAccessToken = async (
  db: SqlDatabase,
  input: CreateOAuthAccessTokenInput,
): Promise<OAuthAccessTokenRecord> => {
  const id = createPrefixedId('oat');
  const createdAt = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oauth_access_tokens (
          id,
          client_id,
          user_id,
          tenant_id,
          access_token_hash,
          scope,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.clientId,
        input.userId,
        input.tenantId,
        input.accessTokenHash,
        input.scope,
        input.expiresAt,
        createdAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        client_id AS clientId,
        user_id AS userId,
        tenant_id AS tenantId,
        access_token_hash AS accessTokenHash,
        scope,
        expires_at AS expiresAt,
        revoked_at AS revokedAt,
        created_at AS createdAt
      FROM oauth_access_tokens
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(id)
    .first<OAuthAccessTokenRow>();

  if (row === null) {
    throw new Error(`Unable to create OAuth access token "${id}"`);
  }

  return mapOAuthAccessTokenRow(row);
};

export const createOAuthRefreshToken = async (
  db: SqlDatabase,
  input: CreateOAuthRefreshTokenInput,
): Promise<OAuthRefreshTokenRecord> => {
  const id = createPrefixedId('ort');
  const createdAt = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oauth_refresh_tokens (
          id,
          client_id,
          user_id,
          tenant_id,
          refresh_token_hash,
          scope,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.clientId,
        input.userId,
        input.tenantId,
        input.refreshTokenHash,
        input.scope,
        input.expiresAt,
        createdAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        client_id AS clientId,
        user_id AS userId,
        tenant_id AS tenantId,
        refresh_token_hash AS refreshTokenHash,
        scope,
        expires_at AS expiresAt,
        revoked_at AS revokedAt,
        created_at AS createdAt
      FROM oauth_refresh_tokens
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(id)
    .first<OAuthRefreshTokenRow>();

  if (row === null) {
    throw new Error(`Unable to create OAuth refresh token "${id}"`);
  }

  return mapOAuthRefreshTokenRow(row);
};

export const consumeOAuthRefreshToken = async (
  db: SqlDatabase,
  input: ConsumeOAuthRefreshTokenInput,
): Promise<OAuthRefreshTokenRecord | null> => {
  const consumeStatement = (): Promise<OAuthRefreshTokenRow | null> =>
    db
      .prepare(
        `
        UPDATE oauth_refresh_tokens
        SET revoked_at = ?
        WHERE client_id = ?
          AND refresh_token_hash = ?
          AND revoked_at IS NULL
          AND expires_at > ?
        RETURNING
          id,
          client_id AS clientId,
          user_id AS userId,
          tenant_id AS tenantId,
          refresh_token_hash AS refreshTokenHash,
          scope,
          expires_at AS expiresAt,
          revoked_at AS revokedAt,
          created_at AS createdAt
      `,
      )
      .bind(input.nowIso, input.clientId, input.refreshTokenHash, input.nowIso)
      .first<OAuthRefreshTokenRow>();

  let row: OAuthRefreshTokenRow | null;

  try {
    row = await consumeStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    row = await consumeStatement();
  }

  if (row === null) {
    return null;
  }

  return mapOAuthRefreshTokenRow(row);
};

export const revokeOAuthAccessTokenByHash = async (
  db: SqlDatabase,
  input: RevokeOAuthAccessTokenByHashInput,
): Promise<void> => {
  const revokeStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE oauth_access_tokens
        SET revoked_at = COALESCE(revoked_at, ?)
        WHERE client_id = ?
          AND access_token_hash = ?
      `,
      )
      .bind(input.revokedAt, input.clientId, input.accessTokenHash)
      .run();

  try {
    await revokeStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await revokeStatement();
  }
};

export const revokeOAuthRefreshTokenByHash = async (
  db: SqlDatabase,
  input: RevokeOAuthRefreshTokenByHashInput,
): Promise<void> => {
  const revokeStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE oauth_refresh_tokens
        SET revoked_at = COALESCE(revoked_at, ?)
        WHERE client_id = ?
          AND refresh_token_hash = ?
      `,
      )
      .bind(input.revokedAt, input.clientId, input.refreshTokenHash)
      .run();

  try {
    await revokeStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    await revokeStatement();
  }
};

export const findActiveOAuthAccessTokenByHash = async (
  db: SqlDatabase,
  input: FindActiveOAuthAccessTokenByHashInput,
): Promise<OAuthAccessTokenRecord | null> => {
  const findStatement = (): Promise<OAuthAccessTokenRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          client_id AS clientId,
          user_id AS userId,
          tenant_id AS tenantId,
          access_token_hash AS accessTokenHash,
          scope,
          expires_at AS expiresAt,
          revoked_at AS revokedAt,
          created_at AS createdAt
        FROM oauth_access_tokens
        WHERE access_token_hash = ?
          AND revoked_at IS NULL
          AND expires_at > ?
        LIMIT 1
      `,
      )
      .bind(input.accessTokenHash, input.nowIso)
      .first<OAuthAccessTokenRow>();

  let row: OAuthAccessTokenRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    row = await findStatement();
  }

  return row === null ? null : mapOAuthAccessTokenRow(row);
};

export const listOb3SubjectCredentials = async (
  db: SqlDatabase,
  input: ListOb3SubjectCredentialsInput,
): Promise<ListOb3SubjectCredentialsResult> => {
  const normalizedLimit = Math.max(1, Math.trunc(input.limit));
  const normalizedOffset = Math.max(0, Math.trunc(input.offset));
  const sinceFilter = input.since === undefined ? '' : ' AND issued_at > ?';
  const sharedParams: unknown[] =
    input.since === undefined ? [input.tenantId, input.userId] : [input.tenantId, input.userId, input.since];
  const countStatement = (): Promise<Ob3SubjectCredentialCountRow | null> =>
    db
      .prepare(
        `
        SELECT COUNT(*) AS totalCount
        FROM ob3_subject_credentials
        WHERE tenant_id = ?
          AND user_id = ?${sinceFilter}
      `,
      )
      .bind(...sharedParams)
      .first<Ob3SubjectCredentialCountRow>();
  const listStatement = (): Promise<SqlQueryResult<Ob3SubjectCredentialRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          user_id AS userId,
          credential_id AS credentialId,
          payload_json AS payloadJson,
          compact_jws AS compactJws,
          issued_at AS issuedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM ob3_subject_credentials
        WHERE tenant_id = ?
          AND user_id = ?${sinceFilter}
        ORDER BY issued_at DESC, id DESC
        LIMIT ?
        OFFSET ?
      `,
      )
      .bind(...sharedParams, normalizedLimit, normalizedOffset)
      .all<Ob3SubjectCredentialRow>();

  let totalCountRow: Ob3SubjectCredentialCountRow | null;
  let rowsResult: SqlQueryResult<Ob3SubjectCredentialRow>;

  try {
    totalCountRow = await countStatement();
    rowsResult = await listStatement();
  } catch (error: unknown) {
    if (!isMissingOb3ResourceTablesError(error)) {
      throw error;
    }

    await ensureOb3ResourceTables(db);
    totalCountRow = await countStatement();
    rowsResult = await listStatement();
  }

  const rawTotalCount = totalCountRow?.totalCount ?? 0;
  const totalCount = Number.isFinite(Number(rawTotalCount)) ? Number(rawTotalCount) : 0;

  return {
    totalCount,
    credentials: rowsResult.results.map((row) => mapOb3SubjectCredentialRow(row)),
  };
};

export const upsertOb3SubjectCredential = async (
  db: SqlDatabase,
  input: UpsertOb3SubjectCredentialInput,
): Promise<UpsertOb3SubjectCredentialResult> => {
  const nowIso = new Date().toISOString();
  const issuedAt = input.issuedAt ?? nowIso;
  const safePayloadJson = input.payloadJson ?? null;
  const safeCompactJws = input.compactJws ?? null;
  const selectStatement = (): Promise<Ob3SubjectCredentialRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          user_id AS userId,
          credential_id AS credentialId,
          payload_json AS payloadJson,
          compact_jws AS compactJws,
          issued_at AS issuedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM ob3_subject_credentials
        WHERE tenant_id = ?
          AND user_id = ?
          AND credential_id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.userId, input.credentialId)
      .first<Ob3SubjectCredentialRow>();
  const upsertStatement = (id: string): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO ob3_subject_credentials (
          id,
          tenant_id,
          user_id,
          credential_id,
          payload_json,
          compact_jws,
          issued_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id, user_id, credential_id)
        DO UPDATE SET
          payload_json = excluded.payload_json,
          compact_jws = excluded.compact_jws,
          issued_at = excluded.issued_at,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.userId,
        input.credentialId,
        safePayloadJson,
        safeCompactJws,
        issuedAt,
        nowIso,
        nowIso,
      )
      .run();

  let existingCredential: Ob3SubjectCredentialRow | null;

  try {
    existingCredential = await selectStatement();
  } catch (error: unknown) {
    if (!isMissingOb3ResourceTablesError(error)) {
      throw error;
    }

    await ensureOb3ResourceTables(db);
    existingCredential = await selectStatement();
  }

  const credentialId = existingCredential?.id ?? createPrefixedId('ob3c');
  await upsertStatement(credentialId);
  const persistedCredential = await selectStatement();

  if (persistedCredential === null) {
    throw new Error(
      `Failed to upsert OB3 subject credential "${input.tenantId}:${input.userId}:${input.credentialId}"`,
    );
  }

  return {
    status: existingCredential === null ? 'created' : 'updated',
    credential: mapOb3SubjectCredentialRow(persistedCredential),
  };
};

export const findOb3SubjectProfile = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    userId: string;
  },
): Promise<Ob3SubjectProfileRecord | null> => {
  const findStatement = (): Promise<Ob3SubjectProfileRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          user_id AS userId,
          profile_json AS profileJson,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM ob3_subject_profiles
        WHERE tenant_id = ?
          AND user_id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.userId)
      .first<Ob3SubjectProfileRow>();

  let row: Ob3SubjectProfileRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingOb3ResourceTablesError(error)) {
      throw error;
    }

    await ensureOb3ResourceTables(db);
    row = await findStatement();
  }

  return row === null ? null : mapOb3SubjectProfileRow(row);
};

export const upsertOb3SubjectProfile = async (
  db: SqlDatabase,
  input: UpsertOb3SubjectProfileInput,
): Promise<Ob3SubjectProfileRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO ob3_subject_profiles (
          tenant_id,
          user_id,
          profile_json,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id, user_id)
        DO UPDATE SET
          profile_json = excluded.profile_json,
          updated_at = excluded.updated_at
      `,
      )
      .bind(input.tenantId, input.userId, input.profileJson, nowIso, nowIso)
      .run();
  const findStatement = (): Promise<Ob3SubjectProfileRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          user_id AS userId,
          profile_json AS profileJson,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM ob3_subject_profiles
        WHERE tenant_id = ?
          AND user_id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.userId)
      .first<Ob3SubjectProfileRow>();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingOb3ResourceTablesError(error)) {
      throw error;
    }

    await ensureOb3ResourceTables(db);
    await upsertStatement();
  }

  const row = await findStatement();

  if (row === null) {
    throw new Error(`Failed to upsert OB3 subject profile "${input.tenantId}:${input.userId}"`);
  }

  return mapOb3SubjectProfileRow(row);
};

const mapTenantRow = (row: TenantRow): TenantRecord => {
  return {
    id: row.id,
    slug: row.slug,
    displayName: row.displayName,
    planTier: row.planTier,
    issuerDomain: row.issuerDomain,
    didWeb: row.didWeb,
    isActive: row.isActive === 1 || row.isActive === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapTenantSigningRegistrationRow = (
  row: TenantSigningRegistrationRow,
): TenantSigningRegistrationRecord => {
  return {
    tenantId: row.tenantId,
    did: row.did,
    keyId: row.keyId,
    publicJwkJson: row.publicJwkJson,
    privateJwkJson: row.privateJwkJson,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLtiIssuerRegistrationRow = (
  row: LtiIssuerRegistrationRow,
): LtiIssuerRegistrationRecord => {
  return {
    issuer: row.issuer,
    tenantId: row.tenantId,
    authorizationEndpoint: row.authorizationEndpoint,
    clientId: row.clientId,
    allowUnsignedIdToken: row.allowUnsignedIdToken === 1 || row.allowUnsignedIdToken === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapTenantMembershipRow = (row: TenantMembershipRow): TenantMembershipRecord => {
  return {
    tenantId: row.tenantId,
    userId: row.userId,
    role: row.role,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapAuditLogRow = (row: AuditLogRow): AuditLogRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    actorUserId: row.actorUserId,
    action: row.action,
    targetType: row.targetType,
    targetId: row.targetId,
    metadataJson: row.metadataJson,
    occurredAt: row.occurredAt,
    createdAt: row.createdAt,
  };
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

const mapPublicBadgeWallEntryRow = (row: PublicBadgeWallEntryRow): PublicBadgeWallEntryRecord => {
  return {
    assertionId: row.assertionId,
    assertionPublicId: row.assertionPublicId,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: row.badgeTitle,
    badgeDescription: row.badgeDescription,
    badgeImageUri: row.badgeImageUri,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    issuedAt: row.issuedAt,
    revokedAt: row.revokedAt,
  };
};

export const upsertTenant = async (
  db: SqlDatabase,
  input: UpsertTenantInput,
): Promise<TenantRecord> => {
  const nowIso = new Date().toISOString();
  const isActive = input.isActive ?? true;

  await db
    .prepare(
      `
      INSERT INTO tenants (
        id,
        slug,
        display_name,
        plan_tier,
        issuer_domain,
        did_web,
        is_active,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (id)
      DO UPDATE SET
        slug = excluded.slug,
        display_name = excluded.display_name,
        plan_tier = excluded.plan_tier,
        issuer_domain = excluded.issuer_domain,
        did_web = excluded.did_web,
        is_active = excluded.is_active,
        updated_at = excluded.updated_at
    `,
    )
    .bind(
      input.id,
      input.slug,
      input.displayName,
      input.planTier,
      input.issuerDomain,
      input.didWeb,
      isActive ? 1 : 0,
      nowIso,
      nowIso,
    )
    .run();

  const row = await db
    .prepare(
      `
      SELECT
        id,
        slug,
        display_name AS displayName,
        plan_tier AS planTier,
        issuer_domain AS issuerDomain,
        did_web AS didWeb,
        is_active AS isActive,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenants
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(input.id)
    .first<TenantRow>();

  if (row === null) {
    throw new Error(`Unable to upsert tenant "${input.id}"`);
  }

  return mapTenantRow(row);
};

export const upsertTenantSigningRegistration = async (
  db: SqlDatabase,
  input: UpsertTenantSigningRegistrationInput,
): Promise<TenantSigningRegistrationRecord> => {
  const nowIso = new Date().toISOString();

  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_signing_registrations (
          tenant_id,
          did,
          key_id,
          public_jwk_json,
          private_jwk_json,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id)
        DO UPDATE SET
          did = excluded.did,
          key_id = excluded.key_id,
          public_jwk_json = excluded.public_jwk_json,
          private_jwk_json = excluded.private_jwk_json,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.tenantId,
        input.did,
        input.keyId,
        input.publicJwkJson,
        input.privateJwkJson ?? null,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantSigningRegistrationsTableError(error)) {
      throw error;
    }

    await ensureTenantSigningRegistrationsTable(db);
    await upsertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        tenant_id AS tenantId,
        did,
        key_id AS keyId,
        public_jwk_json AS publicJwkJson,
        private_jwk_json AS privateJwkJson,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_signing_registrations
      WHERE tenant_id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId)
    .first<TenantSigningRegistrationRow>();

  if (row === null) {
    throw new Error(`Unable to upsert signing registration for tenant "${input.tenantId}"`);
  }

  return mapTenantSigningRegistrationRow(row);
};

export const findTenantSigningRegistrationByDid = async (
  db: SqlDatabase,
  did: string,
): Promise<TenantSigningRegistrationRecord | null> => {
  const findStatement = (): Promise<TenantSigningRegistrationRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          did,
          key_id AS keyId,
          public_jwk_json AS publicJwkJson,
          private_jwk_json AS privateJwkJson,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_signing_registrations
        WHERE did = ?
        LIMIT 1
      `,
      )
      .bind(did)
      .first<TenantSigningRegistrationRow>();

  let row: TenantSigningRegistrationRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingTenantSigningRegistrationsTableError(error)) {
      throw error;
    }

    await ensureTenantSigningRegistrationsTable(db);
    row = await findStatement();
  }

  if (row === null) {
    return null;
  }

  return mapTenantSigningRegistrationRow(row);
};

const normalizeLtiIssuer = (issuer: string): string => {
  return issuer.trim().replace(/\/+$/g, '');
};

export const upsertLtiIssuerRegistration = async (
  db: SqlDatabase,
  input: UpsertLtiIssuerRegistrationInput,
): Promise<LtiIssuerRegistrationRecord> => {
  const nowIso = new Date().toISOString();
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);
  const allowUnsignedIdToken = input.allowUnsignedIdToken ?? false;

  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_issuer_registrations (
          issuer,
          tenant_id,
          authorization_endpoint,
          client_id,
          allow_unsigned_id_token,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (issuer)
        DO UPDATE SET
          tenant_id = excluded.tenant_id,
          authorization_endpoint = excluded.authorization_endpoint,
          client_id = excluded.client_id,
          allow_unsigned_id_token = excluded.allow_unsigned_id_token,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        normalizedIssuer,
        input.tenantId,
        input.authorizationEndpoint,
        input.clientId,
        allowUnsignedIdToken ? 1 : 0,
        nowIso,
        nowIso,
      )
      .run();

  const findStatement = (): Promise<LtiIssuerRegistrationRow | null> =>
    db
      .prepare(
        `
        SELECT
          issuer,
          tenant_id AS tenantId,
          authorization_endpoint AS authorizationEndpoint,
          client_id AS clientId,
          allow_unsigned_id_token AS allowUnsignedIdToken,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_issuer_registrations
        WHERE issuer = ?
        LIMIT 1
      `,
      )
      .bind(normalizedIssuer)
      .first<LtiIssuerRegistrationRow>();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingLtiIssuerRegistrationsTableError(error)) {
      throw error;
    }

    await ensureLtiIssuerRegistrationsTable(db);
    await upsertStatement();
  }

  const row = await findStatement();

  if (row === null) {
    throw new Error(`Unable to upsert LTI issuer registration "${normalizedIssuer}"`);
  }

  return mapLtiIssuerRegistrationRow(row);
};

export const listLtiIssuerRegistrations = async (
  db: SqlDatabase,
): Promise<LtiIssuerRegistrationRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<LtiIssuerRegistrationRow>> =>
    db
      .prepare(
        `
        SELECT
          issuer,
          tenant_id AS tenantId,
          authorization_endpoint AS authorizationEndpoint,
          client_id AS clientId,
          allow_unsigned_id_token AS allowUnsignedIdToken,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_issuer_registrations
        ORDER BY issuer ASC
      `,
      )
      .all<LtiIssuerRegistrationRow>();

  let result: SqlQueryResult<LtiIssuerRegistrationRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingLtiIssuerRegistrationsTableError(error)) {
      throw error;
    }

    await ensureLtiIssuerRegistrationsTable(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapLtiIssuerRegistrationRow(row));
};

export const deleteLtiIssuerRegistrationByIssuer = async (
  db: SqlDatabase,
  issuer: string,
): Promise<boolean> => {
  const normalizedIssuer = normalizeLtiIssuer(issuer);

  const deleteStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        DELETE FROM lti_issuer_registrations
        WHERE issuer = ?
      `,
      )
      .bind(normalizedIssuer)
      .run();

  let result: SqlRunResult;

  try {
    result = await deleteStatement();
  } catch (error: unknown) {
    if (!isMissingLtiIssuerRegistrationsTableError(error)) {
      throw error;
    }

    await ensureLtiIssuerRegistrationsTable(db);
    result = await deleteStatement();
  }

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const upsertBadgeTemplateById = async (
  db: SqlDatabase,
  input: UpsertBadgeTemplateByIdInput,
): Promise<BadgeTemplateRecord> => {
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
      ON CONFLICT (id)
      DO UPDATE SET
        tenant_id = excluded.tenant_id,
        slug = excluded.slug,
        title = excluded.title,
        description = excluded.description,
        criteria_uri = excluded.criteria_uri,
        image_uri = excluded.image_uri,
        created_by_user_id = excluded.created_by_user_id,
        is_archived = 0,
        updated_at = excluded.updated_at
    `,
    )
    .bind(
      input.id,
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

  const template = await findBadgeTemplateById(db, input.tenantId, input.id);

  if (template === null) {
    throw new Error(`Unable to upsert badge template "${input.id}"`);
  }

  return template;
};

export const createBadgeTemplate = async (
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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

export const listPublicBadgeWallEntries = async (
  db: SqlDatabase,
  input: ListPublicBadgeWallEntriesInput,
): Promise<PublicBadgeWallEntryRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 300, 1000));
  const result =
    input.badgeTemplateId === undefined
      ? await db
          .prepare(
            `
            SELECT
              assertions.id AS assertionId,
              assertions.public_id AS assertionPublicId,
              assertions.tenant_id AS tenantId,
              assertions.badge_template_id AS badgeTemplateId,
              badge_templates.title AS badgeTitle,
              badge_templates.description AS badgeDescription,
              badge_templates.image_uri AS badgeImageUri,
              assertions.recipient_identity AS recipientIdentity,
              assertions.recipient_identity_type AS recipientIdentityType,
              assertions.issued_at AS issuedAt,
              assertions.revoked_at AS revokedAt
            FROM assertions
            INNER JOIN badge_templates
              ON badge_templates.tenant_id = assertions.tenant_id
              AND badge_templates.id = assertions.badge_template_id
            WHERE assertions.tenant_id = ?
              AND assertions.public_id IS NOT NULL
            ORDER BY assertions.issued_at DESC
            LIMIT ?
          `,
          )
          .bind(input.tenantId, queryLimit)
          .all<PublicBadgeWallEntryRow>()
      : await db
          .prepare(
            `
            SELECT
              assertions.id AS assertionId,
              assertions.public_id AS assertionPublicId,
              assertions.tenant_id AS tenantId,
              assertions.badge_template_id AS badgeTemplateId,
              badge_templates.title AS badgeTitle,
              badge_templates.description AS badgeDescription,
              badge_templates.image_uri AS badgeImageUri,
              assertions.recipient_identity AS recipientIdentity,
              assertions.recipient_identity_type AS recipientIdentityType,
              assertions.issued_at AS issuedAt,
              assertions.revoked_at AS revokedAt
            FROM assertions
            INNER JOIN badge_templates
              ON badge_templates.tenant_id = assertions.tenant_id
              AND badge_templates.id = assertions.badge_template_id
            WHERE assertions.tenant_id = ?
              AND assertions.badge_template_id = ?
              AND assertions.public_id IS NOT NULL
            ORDER BY assertions.issued_at DESC
            LIMIT ?
          `,
          )
          .bind(input.tenantId, input.badgeTemplateId, queryLimit)
          .all<PublicBadgeWallEntryRow>();

  return result.results.map((row) => mapPublicBadgeWallEntryRow(row));
};

export const createAssertion = async (
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
  db: SqlDatabase,
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
