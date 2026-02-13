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
  ownerOrgUnitId?: string | undefined;
  governanceMetadataJson?: string | undefined;
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

export type TenantMembershipOrgUnitScopeRole = 'admin' | 'issuer' | 'viewer';

export interface TenantMembershipOrgUnitScopeRecord {
  tenantId: string;
  userId: string;
  orgUnitId: string;
  role: TenantMembershipOrgUnitScopeRole;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantMembershipOrgUnitScopeInput {
  tenantId: string;
  userId: string;
  orgUnitId: string;
  role: TenantMembershipOrgUnitScopeRole;
  createdByUserId?: string | undefined;
}

export interface UpsertTenantMembershipOrgUnitScopeResult {
  scope: TenantMembershipOrgUnitScopeRecord;
  previousRole: TenantMembershipOrgUnitScopeRole | null;
  changed: boolean;
}

export interface ListTenantMembershipOrgUnitScopesInput {
  tenantId: string;
  userId?: string | undefined;
}

export interface RemoveTenantMembershipOrgUnitScopeInput {
  tenantId: string;
  userId: string;
  orgUnitId: string;
}

export interface CheckTenantMembershipOrgUnitAccessInput {
  tenantId: string;
  userId: string;
  orgUnitId: string;
  requiredRole: TenantMembershipOrgUnitScopeRole;
}

export type DelegatedIssuingAuthorityAction = 'issue_badge' | 'revoke_badge' | 'manage_lifecycle';

export type DelegatedIssuingAuthorityGrantStatus = 'scheduled' | 'active' | 'expired' | 'revoked';

export interface DelegatedIssuingAuthorityGrantRecord {
  id: string;
  tenantId: string;
  delegateUserId: string;
  delegatedByUserId: string | null;
  orgUnitId: string;
  allowedActions: DelegatedIssuingAuthorityAction[];
  badgeTemplateIds: string[];
  startsAt: string;
  endsAt: string;
  revokedAt: string | null;
  revokedByUserId: string | null;
  revokedReason: string | null;
  status: DelegatedIssuingAuthorityGrantStatus;
  createdAt: string;
  updatedAt: string;
}

export type DelegatedIssuingAuthorityGrantEventType = 'granted' | 'revoked' | 'expired';

export interface DelegatedIssuingAuthorityGrantEventRecord {
  id: string;
  tenantId: string;
  grantId: string;
  eventType: DelegatedIssuingAuthorityGrantEventType;
  actorUserId: string | null;
  detailsJson: string | null;
  occurredAt: string;
  createdAt: string;
}

export interface CreateDelegatedIssuingAuthorityGrantInput {
  tenantId: string;
  delegateUserId: string;
  delegatedByUserId?: string | undefined;
  orgUnitId: string;
  allowedActions: readonly DelegatedIssuingAuthorityAction[];
  badgeTemplateIds?: readonly string[] | undefined;
  startsAt: string;
  endsAt: string;
  reason?: string | undefined;
}

export interface ListDelegatedIssuingAuthorityGrantsInput {
  tenantId: string;
  delegateUserId?: string | undefined;
  includeRevoked?: boolean | undefined;
  includeExpired?: boolean | undefined;
  nowIso?: string | undefined;
}

export interface RevokeDelegatedIssuingAuthorityGrantInput {
  tenantId: string;
  grantId: string;
  revokedByUserId?: string | undefined;
  revokedReason?: string | undefined;
  revokedAt: string;
}

export interface RevokeDelegatedIssuingAuthorityGrantResult {
  status: 'revoked' | 'already_revoked';
  grant: DelegatedIssuingAuthorityGrantRecord;
}

export interface ListDelegatedIssuingAuthorityGrantEventsInput {
  tenantId: string;
  grantId: string;
  limit?: number | undefined;
}

export interface ResolveDelegatedIssuingAuthorityInput {
  tenantId: string;
  userId: string;
  orgUnitId: string;
  badgeTemplateId: string;
  requiredAction: DelegatedIssuingAuthorityAction;
  atIso?: string | undefined;
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
  | 'saml_subject'
  | 'sourced_id';

export type RecipientIdentifierType =
  | 'emailAddress'
  | 'sourcedId'
  | 'did'
  | 'nationalIdentityNumber'
  | 'studentId';

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
  ownerOrgUnitId: string;
  governanceMetadataJson: string | null;
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
  ownerOrgUnitId?: string | undefined;
  governanceMetadataJson?: string | undefined;
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

export type OrgUnitType = 'institution' | 'college' | 'department' | 'program';

export interface TenantOrgUnitRecord {
  id: string;
  tenantId: string;
  unitType: OrgUnitType;
  slug: string;
  displayName: string;
  parentOrgUnitId: string | null;
  createdByUserId: string | null;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateTenantOrgUnitInput {
  tenantId: string;
  unitType: OrgUnitType;
  slug: string;
  displayName: string;
  parentOrgUnitId?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface ListTenantOrgUnitsInput {
  tenantId: string;
  includeInactive?: boolean | undefined;
}

export type BadgeTemplateOwnershipReasonCode =
  | 'initial_assignment'
  | 'administrative_transfer'
  | 'reorganization'
  | 'governance_policy_update'
  | 'other';

export interface BadgeTemplateOwnershipEventRecord {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  fromOrgUnitId: string | null;
  toOrgUnitId: string;
  reasonCode: BadgeTemplateOwnershipReasonCode;
  reason: string | null;
  governanceMetadataJson: string | null;
  transferredByUserId: string | null;
  transferredAt: string;
  createdAt: string;
}

export interface ListBadgeTemplateOwnershipEventsInput {
  tenantId: string;
  badgeTemplateId: string;
  limit?: number | undefined;
}

export interface TransferBadgeTemplateOwnershipInput {
  tenantId: string;
  badgeTemplateId: string;
  toOrgUnitId: string;
  reasonCode: Exclude<BadgeTemplateOwnershipReasonCode, 'initial_assignment'>;
  reason?: string | undefined;
  governanceMetadataJson?: string | undefined;
  transferredByUserId?: string | undefined;
  transferredAt: string;
}

export interface TransferBadgeTemplateOwnershipResult {
  status: 'transferred' | 'already_owned';
  template: BadgeTemplateRecord;
  event: BadgeTemplateOwnershipEventRecord | null;
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

export type AssertionLifecycleState = 'active' | 'suspended' | 'revoked' | 'expired';

export type AssertionLifecycleTransitionSource = 'manual' | 'automation';

export type AssertionLifecycleReasonCode =
  | 'administrative_hold'
  | 'policy_violation'
  | 'appeal_pending'
  | 'appeal_resolved'
  | 'credential_expired'
  | 'issuer_requested'
  | 'other';

export interface AssertionLifecycleEventRecord {
  id: string;
  tenantId: string;
  assertionId: string;
  fromState: AssertionLifecycleState;
  toState: AssertionLifecycleState;
  reasonCode: AssertionLifecycleReasonCode;
  reason: string | null;
  transitionSource: AssertionLifecycleTransitionSource;
  actorUserId: string | null;
  transitionedAt: string;
  createdAt: string;
}

export interface ListAssertionLifecycleEventsInput {
  tenantId: string;
  assertionId: string;
  limit?: number | undefined;
}

export interface ResolveAssertionLifecycleStateResult {
  state: AssertionLifecycleState;
  source: 'assertion_revocation' | 'lifecycle_event' | 'default_active';
  reasonCode: AssertionLifecycleReasonCode | null;
  reason: string | null;
  transitionedAt: string | null;
  revokedAt: string | null;
}

export interface RecordAssertionLifecycleTransitionInput {
  tenantId: string;
  assertionId: string;
  toState: AssertionLifecycleState;
  reasonCode: AssertionLifecycleReasonCode;
  reason?: string | undefined;
  transitionSource: AssertionLifecycleTransitionSource;
  actorUserId?: string | undefined;
  transitionedAt: string;
}

export interface RecordAssertionLifecycleTransitionResult {
  status: 'transitioned' | 'already_in_state' | 'invalid_transition';
  fromState: AssertionLifecycleState;
  toState: AssertionLifecycleState;
  currentState: AssertionLifecycleState;
  event: AssertionLifecycleEventRecord | null;
  message: string | null;
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
  recipientIdentifiers?: readonly RecipientIdentifierInput[];
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
  ownerOrgUnitId: string;
  governanceMetadataJson: string | null;
  isArchived: number | boolean;
  createdAt: string;
  updatedAt: string;
}

interface TenantOrgUnitRow {
  id: string;
  tenantId: string;
  unitType: OrgUnitType;
  slug: string;
  displayName: string;
  parentOrgUnitId: string | null;
  createdByUserId: string | null;
  isActive: number | boolean;
  createdAt: string;
  updatedAt: string;
}

interface BadgeTemplateOwnershipEventRow {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  fromOrgUnitId: string | null;
  toOrgUnitId: string;
  reasonCode: BadgeTemplateOwnershipReasonCode;
  reason: string | null;
  governanceMetadataJson: string | null;
  transferredByUserId: string | null;
  transferredAt: string;
  createdAt: string;
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

interface TenantMembershipOrgUnitScopeRow {
  tenantId: string;
  userId: string;
  orgUnitId: string;
  role: TenantMembershipOrgUnitScopeRole;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

interface DelegatedIssuingAuthorityGrantRow {
  id: string;
  tenantId: string;
  delegateUserId: string;
  delegatedByUserId: string | null;
  orgUnitId: string;
  allowedActionsJson: string;
  startsAt: string;
  endsAt: string;
  revokedAt: string | null;
  revokedByUserId: string | null;
  revokedReason: string | null;
  createdAt: string;
  updatedAt: string;
}

interface DelegatedIssuingAuthorityGrantBadgeTemplateRow {
  grantId: string;
  badgeTemplateId: string;
}

interface DelegatedIssuingAuthorityGrantEventRow {
  id: string;
  tenantId: string;
  grantId: string;
  eventType: DelegatedIssuingAuthorityGrantEventType;
  actorUserId: string | null;
  detailsJson: string | null;
  occurredAt: string;
  createdAt: string;
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

const isMissingRecipientIdentifiersTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes('no such table') ||
      error.message.includes('relation') ||
      error.message.includes('does not exist')) &&
    error.message.includes('recipient_identifiers')
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

const isMissingAssertionLifecycleEventsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes('no such table') ||
      error.message.includes('relation') ||
      error.message.includes('does not exist')) &&
    error.message.includes('assertion_lifecycle_events')
  );
};

const isMissingTenantOrgUnitsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes('no such table') ||
      error.message.includes('relation') ||
      error.message.includes('does not exist')) &&
    error.message.includes('tenant_org_units')
  );
};

const isMissingTenantMembershipOrgUnitScopesTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes('no such table') ||
      error.message.includes('relation') ||
      error.message.includes('does not exist')) &&
    error.message.includes('tenant_membership_org_unit_scopes')
  );
};

const isMissingDelegatedIssuingAuthorityTablesError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const tableMissing =
    error.message.includes('delegated_issuing_authority_grants') ||
    error.message.includes('delegated_issuing_authority_grant_badge_templates') ||
    error.message.includes('delegated_issuing_authority_grant_events');

  if (!tableMissing) {
    return false;
  }

  return (
    error.message.includes('no such table') ||
    error.message.includes('relation') ||
    error.message.includes('does not exist')
  );
};

const isMissingBadgeTemplateOwnershipEventsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes('no such table') ||
      error.message.includes('relation') ||
      error.message.includes('does not exist')) &&
    error.message.includes('badge_template_ownership_events')
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
    error.message.includes('ob3_subject_credentials') ||
    error.message.includes('ob3_subject_profiles');

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

const ensureRecipientIdentifiersTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS recipient_identifiers (
        assertion_id TEXT NOT NULL,
        identifier_type TEXT NOT NULL
          CHECK (identifier_type IN ('emailAddress', 'sourcedId', 'did', 'nationalIdentityNumber', 'studentId')),
        identifier_value TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (assertion_id, identifier_type, identifier_value),
        FOREIGN KEY (assertion_id) REFERENCES assertions (id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_recipient_identifiers_assertion
        ON recipient_identifiers (assertion_id)
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

const ensureAssertionLifecycleEventsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS assertion_lifecycle_events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        assertion_id TEXT NOT NULL,
        from_state TEXT NOT NULL CHECK (from_state IN ('active', 'suspended', 'revoked', 'expired')),
        to_state TEXT NOT NULL CHECK (to_state IN ('active', 'suspended', 'revoked', 'expired')),
        reason_code TEXT NOT NULL CHECK (
          reason_code IN (
            'administrative_hold',
            'policy_violation',
            'appeal_pending',
            'appeal_resolved',
            'credential_expired',
            'issuer_requested',
            'other'
          )
        ),
        reason TEXT,
        transition_source TEXT NOT NULL CHECK (transition_source IN ('manual', 'automation')),
        actor_user_id TEXT,
        transitioned_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id, assertion_id) REFERENCES assertions (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_assertion_lifecycle_events_tenant_assertion_transitioned
        ON assertion_lifecycle_events (tenant_id, assertion_id, transitioned_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_assertion_lifecycle_events_tenant_state
        ON assertion_lifecycle_events (tenant_id, to_state)
    `,
    )
    .run();
};

const ensureTenantOrgUnitsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_org_units (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        unit_type TEXT NOT NULL CHECK (unit_type IN ('institution', 'college', 'department', 'program')),
        slug TEXT NOT NULL,
        display_name TEXT NOT NULL,
        parent_org_unit_id TEXT,
        created_by_user_id TEXT,
        is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (tenant_id, id),
        UNIQUE (tenant_id, slug),
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (parent_org_unit_id) REFERENCES tenant_org_units (id) ON DELETE SET NULL,
        FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_tenant_org_units_tenant_type
        ON tenant_org_units (tenant_id, unit_type, is_active)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_tenant_org_units_tenant_parent
        ON tenant_org_units (tenant_id, parent_org_unit_id)
    `,
    )
    .run();
};

const ensureTenantMembershipOrgUnitScopesTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_membership_org_unit_scopes (
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        org_unit_id TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'issuer', 'viewer')),
        created_by_user_id TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, user_id, org_unit_id),
        FOREIGN KEY (tenant_id, user_id) REFERENCES memberships (tenant_id, user_id) ON DELETE CASCADE,
        FOREIGN KEY (tenant_id, org_unit_id) REFERENCES tenant_org_units (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_membership_org_scopes_tenant_user_role
        ON tenant_membership_org_unit_scopes (tenant_id, user_id, role)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_membership_org_scopes_tenant_org_unit
        ON tenant_membership_org_unit_scopes (tenant_id, org_unit_id)
    `,
    )
    .run();
};

const ensureDelegatedIssuingAuthorityTables = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS delegated_issuing_authority_grants (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        delegate_user_id TEXT NOT NULL,
        delegated_by_user_id TEXT,
        org_unit_id TEXT NOT NULL,
        allowed_actions_json TEXT NOT NULL,
        starts_at TEXT NOT NULL,
        ends_at TEXT NOT NULL,
        revoked_at TEXT,
        revoked_by_user_id TEXT,
        revoked_reason TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CHECK (starts_at < ends_at),
        FOREIGN KEY (tenant_id, delegate_user_id) REFERENCES memberships (tenant_id, user_id) ON DELETE CASCADE,
        FOREIGN KEY (delegated_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
        FOREIGN KEY (tenant_id, org_unit_id) REFERENCES tenant_org_units (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (revoked_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS delegated_issuing_authority_grant_badge_templates (
        tenant_id TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        badge_template_id TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, grant_id, badge_template_id),
        FOREIGN KEY (tenant_id, grant_id)
          REFERENCES delegated_issuing_authority_grants (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (tenant_id, badge_template_id)
          REFERENCES badge_templates (tenant_id, id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS delegated_issuing_authority_grant_events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        event_type TEXT NOT NULL CHECK (event_type IN ('granted', 'revoked', 'expired')),
        actor_user_id TEXT,
        details_json TEXT,
        occurred_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id, grant_id)
          REFERENCES delegated_issuing_authority_grants (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (actor_user_id)
          REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_delegated_grants_delegate_active
        ON delegated_issuing_authority_grants (tenant_id, delegate_user_id, revoked_at, starts_at, ends_at)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_delegated_grants_delegate_org
        ON delegated_issuing_authority_grants (tenant_id, delegate_user_id, org_unit_id)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_delegated_grants_org_unit
        ON delegated_issuing_authority_grants (tenant_id, org_unit_id)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_delegated_grant_badge_templates_template
        ON delegated_issuing_authority_grant_badge_templates (tenant_id, badge_template_id)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_delegated_grant_events_grant
        ON delegated_issuing_authority_grant_events (tenant_id, grant_id, occurred_at DESC)
    `,
    )
    .run();
};
const ensureBadgeTemplateOwnershipEventsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS badge_template_ownership_events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        badge_template_id TEXT NOT NULL,
        from_org_unit_id TEXT,
        to_org_unit_id TEXT NOT NULL,
        reason_code TEXT NOT NULL CHECK (
          reason_code IN (
            'initial_assignment',
            'administrative_transfer',
            'reorganization',
            'governance_policy_update',
            'other'
          )
        ),
        reason TEXT,
        governance_metadata_json TEXT,
        transferred_by_user_id TEXT,
        transferred_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id, badge_template_id)
          REFERENCES badge_templates (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (from_org_unit_id) REFERENCES tenant_org_units (id) ON DELETE SET NULL,
        FOREIGN KEY (to_org_unit_id) REFERENCES tenant_org_units (id) ON DELETE RESTRICT,
        FOREIGN KEY (transferred_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_template_ownership_events_template
        ON badge_template_ownership_events (tenant_id, badge_template_id, transferred_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_template_ownership_events_to_org
        ON badge_template_ownership_events (tenant_id, to_org_unit_id, transferred_at DESC)
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

interface AssertionLifecycleEventRow {
  id: string;
  tenantId: string;
  assertionId: string;
  fromState: AssertionLifecycleState;
  toState: AssertionLifecycleState;
  reasonCode: AssertionLifecycleReasonCode;
  reason: string | null;
  transitionSource: AssertionLifecycleTransitionSource;
  actorUserId: string | null;
  transitionedAt: string;
  createdAt: string;
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

interface RecipientIdentifierRow {
  assertionId: string;
  identifierType: RecipientIdentifierType;
  identifierValue: string;
  createdAt: string;
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

const institutionOrgUnitIdForTenant = (tenantId: string): string => {
  return `${tenantId}:org:institution`;
};

const TENANT_MEMBERSHIP_ORG_UNIT_SCOPE_ROLE_PRIORITY: Record<
  TenantMembershipOrgUnitScopeRole,
  number
> = {
  viewer: 1,
  issuer: 2,
  admin: 3,
};

const REQUIRED_PARENT_ORG_UNIT_TYPE: Record<OrgUnitType, OrgUnitType | null> = {
  institution: null,
  college: 'institution',
  department: 'college',
  program: 'department',
};

const BADGE_TEMPLATE_OWNERSHIP_REASON_CODES = new Set<BadgeTemplateOwnershipReasonCode>([
  'initial_assignment',
  'administrative_transfer',
  'reorganization',
  'governance_policy_update',
  'other',
]);

const DELEGATED_ISSUING_AUTHORITY_ACTIONS = new Set<DelegatedIssuingAuthorityAction>([
  'issue_badge',
  'revoke_badge',
  'manage_lifecycle',
]);

const normalizeDelegatedIssuingAuthorityActions = (
  actions: readonly DelegatedIssuingAuthorityAction[],
): DelegatedIssuingAuthorityAction[] => {
  const normalized = Array.from(new Set(actions));

  if (normalized.length === 0) {
    throw new Error('Delegated issuing authority grant must include at least one allowed action');
  }

  for (const action of normalized) {
    if (!DELEGATED_ISSUING_AUTHORITY_ACTIONS.has(action)) {
      throw new Error(`Unsupported delegated issuing authority action: ${action}`);
    }
  }

  return normalized.sort();
};

const parseDelegatedIssuingAuthorityActionsJson = (
  rawJson: string,
): DelegatedIssuingAuthorityAction[] => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(rawJson) as unknown;
  } catch {
    throw new Error('delegated_issuing_authority_grants.allowed_actions_json must be valid JSON');
  }

  if (!Array.isArray(parsed)) {
    throw new Error('delegated_issuing_authority_grants.allowed_actions_json must be a JSON array');
  }

  const parsedArray = parsed as unknown[];
  const parsedActions: DelegatedIssuingAuthorityAction[] = [];

  for (const candidate of parsedArray) {
    if (
      typeof candidate !== 'string' ||
      (candidate !== 'issue_badge' &&
        candidate !== 'revoke_badge' &&
        candidate !== 'manage_lifecycle')
    ) {
      throw new Error(
        `delegated_issuing_authority_grants.allowed_actions_json contains unsupported action: ${String(candidate)}`,
      );
    }

    parsedActions.push(candidate);
  }

  return normalizeDelegatedIssuingAuthorityActions(parsedActions);
};

const normalizeDelegatedIssuingAuthorityBadgeTemplateIds = (
  badgeTemplateIds: readonly string[] | undefined,
): string[] => {
  if (badgeTemplateIds === undefined) {
    return [];
  }

  const normalized = Array.from(new Set(badgeTemplateIds));
  return normalized.sort();
};

const assertValidIsoTimestamp = (timestamp: string, fieldName: string): number => {
  const parsedMs = Date.parse(timestamp);

  if (!Number.isFinite(parsedMs)) {
    throw new Error(`${fieldName} must be a valid ISO timestamp`);
  }

  return parsedMs;
};

const delegatedIssuingAuthorityGrantStatusForRecord = (
  grant: {
    startsAt: string;
    endsAt: string;
    revokedAt: string | null;
  },
  nowIso: string,
): DelegatedIssuingAuthorityGrantStatus => {
  if (grant.revokedAt !== null) {
    return 'revoked';
  }

  const nowMs = assertValidIsoTimestamp(nowIso, 'nowIso');
  const startsAtMs = assertValidIsoTimestamp(grant.startsAt, 'startsAt');
  const endsAtMs = assertValidIsoTimestamp(grant.endsAt, 'endsAt');

  if (nowMs < startsAtMs) {
    return 'scheduled';
  }

  if (nowMs > endsAtMs) {
    return 'expired';
  }

  return 'active';
};

const ASSERTION_LIFECYCLE_REASON_CODES = new Set<AssertionLifecycleReasonCode>([
  'administrative_hold',
  'policy_violation',
  'appeal_pending',
  'appeal_resolved',
  'credential_expired',
  'issuer_requested',
  'other',
]);

const ASSERTION_LIFECYCLE_ALLOWED_TRANSITIONS: Record<
  AssertionLifecycleState,
  ReadonlySet<AssertionLifecycleState>
> = {
  active: new Set<AssertionLifecycleState>(['suspended', 'revoked', 'expired']),
  suspended: new Set<AssertionLifecycleState>(['active', 'revoked', 'expired']),
  expired: new Set<AssertionLifecycleState>(['active', 'revoked']),
  revoked: new Set<AssertionLifecycleState>(),
};

const assertionLifecycleStateFromRecords = (input: {
  assertion: AssertionRecord;
  latestEvent: AssertionLifecycleEventRecord | null;
}): ResolveAssertionLifecycleStateResult => {
  if (input.assertion.revokedAt !== null && input.latestEvent?.toState === 'revoked') {
    return {
      state: 'revoked',
      source: 'lifecycle_event',
      reasonCode: input.latestEvent.reasonCode,
      reason: input.latestEvent.reason ?? 'credential has been revoked by issuer',
      transitionedAt: input.latestEvent.transitionedAt,
      revokedAt: input.assertion.revokedAt,
    };
  }

  if (input.assertion.revokedAt !== null) {
    return {
      state: 'revoked',
      source: 'assertion_revocation',
      reasonCode: null,
      reason: 'credential has been revoked by issuer',
      transitionedAt: input.assertion.revokedAt,
      revokedAt: input.assertion.revokedAt,
    };
  }

  if (input.latestEvent !== null) {
    return {
      state: input.latestEvent.toState,
      source: 'lifecycle_event',
      reasonCode: input.latestEvent.reasonCode,
      reason: input.latestEvent.reason,
      transitionedAt: input.latestEvent.transitionedAt,
      revokedAt: null,
    };
  }

  return {
    state: 'active',
    source: 'default_active',
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    revokedAt: null,
  };
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
    case 'sourced_id':
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
      'DELETE FROM learner_identities WHERE tenant_id = ? AND learner_profile_id = ? AND identity_type = ?',
    )
    .bind(input.tenantId, input.learnerProfileId, input.identityType)
    .run();

  return result.meta.rowsWritten ?? 0;
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
  const metadataJson = input.metadata === undefined ? null : JSON.stringify(input.metadata);

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

export const touchSession = async (
  db: SqlDatabase,
  sessionId: string,
  seenAt: string,
): Promise<void> => {
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
    input.since === undefined
      ? [input.tenantId, input.userId]
      : [input.tenantId, input.userId, input.since];
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

const mapTenantMembershipOrgUnitScopeRow = (
  row: TenantMembershipOrgUnitScopeRow,
): TenantMembershipOrgUnitScopeRecord => {
  return {
    tenantId: row.tenantId,
    userId: row.userId,
    orgUnitId: row.orgUnitId,
    role: row.role,
    createdByUserId: row.createdByUserId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapDelegatedIssuingAuthorityGrantEventRow = (
  row: DelegatedIssuingAuthorityGrantEventRow,
): DelegatedIssuingAuthorityGrantEventRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    grantId: row.grantId,
    eventType: row.eventType,
    actorUserId: row.actorUserId,
    detailsJson: row.detailsJson,
    occurredAt: row.occurredAt,
    createdAt: row.createdAt,
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
    ownerOrgUnitId: row.ownerOrgUnitId,
    governanceMetadataJson: row.governanceMetadataJson,
    isArchived: row.isArchived === 1 || row.isArchived === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapTenantOrgUnitRow = (row: TenantOrgUnitRow): TenantOrgUnitRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    unitType: row.unitType,
    slug: row.slug,
    displayName: row.displayName,
    parentOrgUnitId: row.parentOrgUnitId,
    createdByUserId: row.createdByUserId,
    isActive: row.isActive === 1 || row.isActive === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapBadgeTemplateOwnershipEventRow = (
  row: BadgeTemplateOwnershipEventRow,
): BadgeTemplateOwnershipEventRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    fromOrgUnitId: row.fromOrgUnitId,
    toOrgUnitId: row.toOrgUnitId,
    reasonCode: row.reasonCode,
    reason: row.reason,
    governanceMetadataJson: row.governanceMetadataJson,
    transferredByUserId: row.transferredByUserId,
    transferredAt: row.transferredAt,
    createdAt: row.createdAt,
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

const mapAssertionLifecycleEventRow = (
  row: AssertionLifecycleEventRow,
): AssertionLifecycleEventRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    assertionId: row.assertionId,
    fromState: row.fromState,
    toState: row.toState,
    reasonCode: row.reasonCode,
    reason: row.reason,
    transitionSource: row.transitionSource,
    actorUserId: row.actorUserId,
    transitionedAt: row.transitionedAt,
    createdAt: row.createdAt,
  };
};

const mapRecipientIdentifierRow = (row: RecipientIdentifierRow): RecipientIdentifierRecord => {
  return {
    assertionId: row.assertionId,
    identifierType: row.identifierType,
    identifierValue: row.identifierValue,
    createdAt: row.createdAt,
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

const findTenantOrgUnitById = async (
  db: SqlDatabase,
  tenantId: string,
  orgUnitId: string,
): Promise<TenantOrgUnitRecord | null> => {
  const findStatement = (): Promise<TenantOrgUnitRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          unit_type AS unitType,
          slug,
          display_name AS displayName,
          parent_org_unit_id AS parentOrgUnitId,
          created_by_user_id AS createdByUserId,
          is_active AS isActive,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_org_units
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, orgUnitId)
      .first<TenantOrgUnitRow>();

  let row: TenantOrgUnitRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingTenantOrgUnitsTableError(error)) {
      throw error;
    }

    await ensureTenantOrgUnitsTable(db);
    row = await findStatement();
  }

  return row === null ? null : mapTenantOrgUnitRow(row);
};

const ensureInstitutionOrgUnitForTenant = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<string> => {
  const institutionId = institutionOrgUnitIdForTenant(tenantId);
  const nowIso = new Date().toISOString();
  const seedStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT OR IGNORE INTO tenant_org_units (
          id,
          tenant_id,
          unit_type,
          slug,
          display_name,
          parent_org_unit_id,
          created_by_user_id,
          is_active,
          created_at,
          updated_at
        )
        VALUES (?, ?, 'institution', 'institution', ?, NULL, NULL, 1, ?, ?)
      `,
      )
      .bind(institutionId, tenantId, `${tenantId} Institution`, nowIso, nowIso)
      .run();

  try {
    await seedStatement();
  } catch (error: unknown) {
    if (!isMissingTenantOrgUnitsTableError(error)) {
      throw error;
    }

    await ensureTenantOrgUnitsTable(db);
    await seedStatement();
  }

  return institutionId;
};

const findTenantMembershipOrgUnitScope = async (
  db: SqlDatabase,
  tenantId: string,
  userId: string,
  orgUnitId: string,
): Promise<TenantMembershipOrgUnitScopeRecord | null> => {
  const findStatement = (): Promise<TenantMembershipOrgUnitScopeRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          user_id AS userId,
          org_unit_id AS orgUnitId,
          role,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_membership_org_unit_scopes
        WHERE tenant_id = ?
          AND user_id = ?
          AND org_unit_id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, userId, orgUnitId)
      .first<TenantMembershipOrgUnitScopeRow>();

  let row: TenantMembershipOrgUnitScopeRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingTenantMembershipOrgUnitScopesTableError(error)) {
      throw error;
    }

    await ensureTenantMembershipOrgUnitScopesTable(db);
    row = await findStatement();
  }

  return row === null ? null : mapTenantMembershipOrgUnitScopeRow(row);
};

export const upsertTenantMembershipOrgUnitScope = async (
  db: SqlDatabase,
  input: UpsertTenantMembershipOrgUnitScopeInput,
): Promise<UpsertTenantMembershipOrgUnitScopeResult> => {
  const membership = await findTenantMembership(db, input.tenantId, input.userId);

  if (membership === null) {
    throw new Error(`Membership not found for tenant ${input.tenantId} and user ${input.userId}`);
  }

  const orgUnit = await findTenantOrgUnitById(db, input.tenantId, input.orgUnitId);

  if (orgUnit === null) {
    throw new Error(`Org unit ${input.orgUnitId} not found for tenant ${input.tenantId}`);
  }

  const previous = await findTenantMembershipOrgUnitScope(
    db,
    input.tenantId,
    input.userId,
    input.orgUnitId,
  );
  const nowIso = new Date().toISOString();

  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_membership_org_unit_scopes (
          tenant_id,
          user_id,
          org_unit_id,
          role,
          created_by_user_id,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id, user_id, org_unit_id)
        DO UPDATE SET
          role = excluded.role,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.tenantId,
        input.userId,
        input.orgUnitId,
        input.role,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantMembershipOrgUnitScopesTableError(error)) {
      throw error;
    }

    await ensureTenantMembershipOrgUnitScopesTable(db);
    await upsertStatement();
  }

  const scope = await findTenantMembershipOrgUnitScope(
    db,
    input.tenantId,
    input.userId,
    input.orgUnitId,
  );

  if (scope === null) {
    throw new Error(
      `Unable to upsert org-unit scope for tenant ${input.tenantId}, user ${input.userId}, org unit ${input.orgUnitId}`,
    );
  }

  return {
    scope,
    previousRole: previous?.role ?? null,
    changed: previous?.role !== scope.role,
  };
};

export const listTenantMembershipOrgUnitScopes = async (
  db: SqlDatabase,
  input: ListTenantMembershipOrgUnitScopesInput,
): Promise<TenantMembershipOrgUnitScopeRecord[]> => {
  const query =
    input.userId === undefined
      ? `
        SELECT
          tenant_id AS tenantId,
          user_id AS userId,
          org_unit_id AS orgUnitId,
          role,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_membership_org_unit_scopes
        WHERE tenant_id = ?
        ORDER BY user_id ASC, org_unit_id ASC
      `
      : `
        SELECT
          tenant_id AS tenantId,
          user_id AS userId,
          org_unit_id AS orgUnitId,
          role,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_membership_org_unit_scopes
        WHERE tenant_id = ?
          AND user_id = ?
        ORDER BY org_unit_id ASC
      `;

  const listStatement = (): Promise<SqlQueryResult<TenantMembershipOrgUnitScopeRow>> =>
    input.userId === undefined
      ? db.prepare(query).bind(input.tenantId).all<TenantMembershipOrgUnitScopeRow>()
      : db.prepare(query).bind(input.tenantId, input.userId).all<TenantMembershipOrgUnitScopeRow>();

  let result: SqlQueryResult<TenantMembershipOrgUnitScopeRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingTenantMembershipOrgUnitScopesTableError(error)) {
      throw error;
    }

    await ensureTenantMembershipOrgUnitScopesTable(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapTenantMembershipOrgUnitScopeRow(row));
};

export const removeTenantMembershipOrgUnitScope = async (
  db: SqlDatabase,
  input: RemoveTenantMembershipOrgUnitScopeInput,
): Promise<boolean> => {
  const deleteStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        DELETE FROM tenant_membership_org_unit_scopes
        WHERE tenant_id = ?
          AND user_id = ?
          AND org_unit_id = ?
      `,
      )
      .bind(input.tenantId, input.userId, input.orgUnitId)
      .run();

  let result: SqlRunResult;

  try {
    result = await deleteStatement();
  } catch (error: unknown) {
    if (!isMissingTenantMembershipOrgUnitScopesTableError(error)) {
      throw error;
    }

    await ensureTenantMembershipOrgUnitScopesTable(db);
    result = await deleteStatement();
  }

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const hasTenantMembershipOrgUnitScopeAssignments = async (
  db: SqlDatabase,
  tenantId: string,
  userId: string,
): Promise<boolean> => {
  const countStatement = (): Promise<{ totalCount: number | string } | null> =>
    db
      .prepare(
        `
        SELECT COUNT(*) AS totalCount
        FROM tenant_membership_org_unit_scopes
        WHERE tenant_id = ?
          AND user_id = ?
      `,
      )
      .bind(tenantId, userId)
      .first<{ totalCount: number | string }>();

  let row: { totalCount: number | string } | null;

  try {
    row = await countStatement();
  } catch (error: unknown) {
    if (!isMissingTenantMembershipOrgUnitScopesTableError(error)) {
      throw error;
    }

    await ensureTenantMembershipOrgUnitScopesTable(db);
    row = await countStatement();
  }

  const totalCount = Number.parseInt(String(row?.totalCount ?? 0), 10);
  return Number.isFinite(totalCount) && totalCount > 0;
};

export const hasTenantMembershipOrgUnitAccess = async (
  db: SqlDatabase,
  input: CheckTenantMembershipOrgUnitAccessInput,
): Promise<boolean> => {
  const requiredRolePriority = TENANT_MEMBERSHIP_ORG_UNIT_SCOPE_ROLE_PRIORITY[input.requiredRole];
  const accessStatement = (): Promise<{ orgUnitId: string } | null> =>
    db
      .prepare(
        `
        WITH RECURSIVE org_ancestors AS (
          SELECT id, parent_org_unit_id AS parentOrgUnitId, 0 AS depth
          FROM tenant_org_units
          WHERE tenant_id = ?
            AND id = ?

          UNION ALL

          SELECT parent.id, parent.parent_org_unit_id AS parentOrgUnitId, org_ancestors.depth + 1
          FROM tenant_org_units parent
          INNER JOIN org_ancestors
            ON org_ancestors.parentOrgUnitId = parent.id
          WHERE parent.tenant_id = ?
        )
        SELECT
          scopes.org_unit_id AS orgUnitId
        FROM tenant_membership_org_unit_scopes scopes
        INNER JOIN org_ancestors
          ON org_ancestors.id = scopes.org_unit_id
        WHERE scopes.tenant_id = ?
          AND scopes.user_id = ?
          AND CASE scopes.role
                WHEN 'admin' THEN 3
                WHEN 'issuer' THEN 2
                ELSE 1
              END >= ?
        ORDER BY
          CASE scopes.role
            WHEN 'admin' THEN 3
            WHEN 'issuer' THEN 2
            ELSE 1
          END DESC,
          org_ancestors.depth ASC
        LIMIT 1
      `,
      )
      .bind(
        input.tenantId,
        input.orgUnitId,
        input.tenantId,
        input.tenantId,
        input.userId,
        requiredRolePriority,
      )
      .first<{ orgUnitId: string }>();

  let row: { orgUnitId: string } | null;

  try {
    row = await accessStatement();
  } catch (error: unknown) {
    if (
      !isMissingTenantMembershipOrgUnitScopesTableError(error) &&
      !isMissingTenantOrgUnitsTableError(error)
    ) {
      throw error;
    }

    if (isMissingTenantOrgUnitsTableError(error)) {
      await ensureTenantOrgUnitsTable(db);
    }

    if (isMissingTenantMembershipOrgUnitScopesTableError(error)) {
      await ensureTenantMembershipOrgUnitScopesTable(db);
    }

    row = await accessStatement();
  }

  return row !== null;
};

const isOrgUnitWithinDelegatedAuthorityScope = async (
  db: SqlDatabase,
  tenantId: string,
  targetOrgUnitId: string,
  scopedOrgUnitId: string,
): Promise<boolean> => {
  const statement = (): Promise<{ id: string } | null> =>
    db
      .prepare(
        `
        WITH RECURSIVE org_ancestors AS (
          SELECT id, parent_org_unit_id AS parentOrgUnitId
          FROM tenant_org_units
          WHERE tenant_id = ?
            AND id = ?

          UNION ALL

          SELECT parent.id, parent.parent_org_unit_id AS parentOrgUnitId
          FROM tenant_org_units parent
          INNER JOIN org_ancestors
            ON org_ancestors.parentOrgUnitId = parent.id
          WHERE parent.tenant_id = ?
        )
        SELECT id
        FROM org_ancestors
        WHERE id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, targetOrgUnitId, tenantId, scopedOrgUnitId)
      .first<{ id: string }>();

  let row: { id: string } | null;

  try {
    row = await statement();
  } catch (error: unknown) {
    if (!isMissingTenantOrgUnitsTableError(error)) {
      throw error;
    }

    await ensureTenantOrgUnitsTable(db);
    row = await statement();
  }

  return row !== null;
};

const listDelegatedIssuingAuthorityGrantBadgeTemplateIds = async (
  db: SqlDatabase,
  tenantId: string,
  grantId: string,
): Promise<string[]> => {
  const listStatement = (): Promise<
    SqlQueryResult<DelegatedIssuingAuthorityGrantBadgeTemplateRow>
  > =>
    db
      .prepare(
        `
        SELECT
          grant_id AS grantId,
          badge_template_id AS badgeTemplateId
        FROM delegated_issuing_authority_grant_badge_templates
        WHERE tenant_id = ?
          AND grant_id = ?
        ORDER BY badge_template_id ASC
      `,
      )
      .bind(tenantId, grantId)
      .all<DelegatedIssuingAuthorityGrantBadgeTemplateRow>();

  let result: SqlQueryResult<DelegatedIssuingAuthorityGrantBadgeTemplateRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await listStatement();
  }

  return result.results.map((row) => row.badgeTemplateId);
};

const mapDelegatedIssuingAuthorityGrantRow = async (
  db: SqlDatabase,
  row: DelegatedIssuingAuthorityGrantRow,
  nowIso: string,
): Promise<DelegatedIssuingAuthorityGrantRecord> => {
  const badgeTemplateIds = await listDelegatedIssuingAuthorityGrantBadgeTemplateIds(
    db,
    row.tenantId,
    row.id,
  );

  return {
    id: row.id,
    tenantId: row.tenantId,
    delegateUserId: row.delegateUserId,
    delegatedByUserId: row.delegatedByUserId,
    orgUnitId: row.orgUnitId,
    allowedActions: parseDelegatedIssuingAuthorityActionsJson(row.allowedActionsJson),
    badgeTemplateIds,
    startsAt: row.startsAt,
    endsAt: row.endsAt,
    revokedAt: row.revokedAt,
    revokedByUserId: row.revokedByUserId,
    revokedReason: row.revokedReason,
    status: delegatedIssuingAuthorityGrantStatusForRecord(row, nowIso),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const findDelegatedIssuingAuthorityGrantRowById = async (
  db: SqlDatabase,
  tenantId: string,
  grantId: string,
): Promise<DelegatedIssuingAuthorityGrantRow | null> => {
  const findStatement = (): Promise<DelegatedIssuingAuthorityGrantRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          delegate_user_id AS delegateUserId,
          delegated_by_user_id AS delegatedByUserId,
          org_unit_id AS orgUnitId,
          allowed_actions_json AS allowedActionsJson,
          starts_at AS startsAt,
          ends_at AS endsAt,
          revoked_at AS revokedAt,
          revoked_by_user_id AS revokedByUserId,
          revoked_reason AS revokedReason,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM delegated_issuing_authority_grants
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, grantId)
      .first<DelegatedIssuingAuthorityGrantRow>();

  let row: DelegatedIssuingAuthorityGrantRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    row = await findStatement();
  }

  return row;
};

const createDelegatedIssuingAuthorityGrantEvent = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    grantId: string;
    eventType: DelegatedIssuingAuthorityGrantEventType;
    actorUserId: string | null;
    detailsJson: string | null;
    occurredAt: string;
  },
): Promise<DelegatedIssuingAuthorityGrantEventRecord> => {
  const eventId = createPrefixedId('dage');
  const nowIso = new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO delegated_issuing_authority_grant_events (
          id,
          tenant_id,
          grant_id,
          event_type,
          actor_user_id,
          details_json,
          occurred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        eventId,
        input.tenantId,
        input.grantId,
        input.eventType,
        input.actorUserId,
        input.detailsJson,
        input.occurredAt,
        nowIso,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    await insertStatement();
  }

  return {
    id: eventId,
    tenantId: input.tenantId,
    grantId: input.grantId,
    eventType: input.eventType,
    actorUserId: input.actorUserId,
    detailsJson: input.detailsJson,
    occurredAt: input.occurredAt,
    createdAt: nowIso,
  };
};

const recordExpiredDelegatedIssuingAuthorityGrantEvents = async (
  db: SqlDatabase,
  tenantId: string,
  nowIso: string,
): Promise<void> => {
  const listStatement = (): Promise<SqlQueryResult<{ grantId: string; endsAt: string }>> =>
    db
      .prepare(
        `
        SELECT
          grants.id AS grantId,
          grants.ends_at AS endsAt
        FROM delegated_issuing_authority_grants grants
        WHERE grants.tenant_id = ?
          AND grants.revoked_at IS NULL
          AND grants.ends_at < ?
          AND NOT EXISTS (
            SELECT 1
            FROM delegated_issuing_authority_grant_events events
            WHERE events.tenant_id = grants.tenant_id
              AND events.grant_id = grants.id
              AND events.event_type = 'expired'
          )
      `,
      )
      .bind(tenantId, nowIso)
      .all<{ grantId: string; endsAt: string }>();

  let result: SqlQueryResult<{ grantId: string; endsAt: string }>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await listStatement();
  }

  for (const row of result.results) {
    await createDelegatedIssuingAuthorityGrantEvent(db, {
      tenantId,
      grantId: row.grantId,
      eventType: 'expired',
      actorUserId: null,
      detailsJson: null,
      occurredAt: row.endsAt,
    });
  }
};

const hasDelegatedGrantTemplateScopeOverlap = (
  candidateTemplateIds: readonly string[],
  existingTemplateIds: readonly string[],
): boolean => {
  if (candidateTemplateIds.length === 0 || existingTemplateIds.length === 0) {
    return true;
  }

  const existing = new Set(existingTemplateIds);

  for (const templateId of candidateTemplateIds) {
    if (existing.has(templateId)) {
      return true;
    }
  }

  return false;
};

const hasDelegatedGrantActionOverlap = (
  candidateActions: readonly DelegatedIssuingAuthorityAction[],
  existingActions: readonly DelegatedIssuingAuthorityAction[],
): boolean => {
  const existing = new Set(existingActions);

  for (const action of candidateActions) {
    if (existing.has(action)) {
      return true;
    }
  }

  return false;
};

export const findDelegatedIssuingAuthorityGrantById = async (
  db: SqlDatabase,
  tenantId: string,
  grantId: string,
  nowIso = new Date().toISOString(),
): Promise<DelegatedIssuingAuthorityGrantRecord | null> => {
  await recordExpiredDelegatedIssuingAuthorityGrantEvents(db, tenantId, nowIso);

  const row = await findDelegatedIssuingAuthorityGrantRowById(db, tenantId, grantId);
  return row === null ? null : mapDelegatedIssuingAuthorityGrantRow(db, row, nowIso);
};

export const createDelegatedIssuingAuthorityGrant = async (
  db: SqlDatabase,
  input: CreateDelegatedIssuingAuthorityGrantInput,
): Promise<DelegatedIssuingAuthorityGrantRecord> => {
  const startsAtMs = assertValidIsoTimestamp(input.startsAt, 'startsAt');
  const endsAtMs = assertValidIsoTimestamp(input.endsAt, 'endsAt');

  if (endsAtMs <= startsAtMs) {
    throw new Error('endsAt must be after startsAt');
  }

  const allowedActions = normalizeDelegatedIssuingAuthorityActions(input.allowedActions);
  const badgeTemplateIds = normalizeDelegatedIssuingAuthorityBadgeTemplateIds(
    input.badgeTemplateIds,
  );

  const membership = await findTenantMembership(db, input.tenantId, input.delegateUserId);

  if (membership === null) {
    throw new Error(
      `Membership not found for tenant ${input.tenantId} and user ${input.delegateUserId}`,
    );
  }

  const scopedOrgUnit = await findTenantOrgUnitById(db, input.tenantId, input.orgUnitId);

  if (scopedOrgUnit === null) {
    throw new Error(`Org unit ${input.orgUnitId} not found for tenant ${input.tenantId}`);
  }

  if (!scopedOrgUnit.isActive) {
    throw new Error(`Org unit ${input.orgUnitId} is inactive for tenant ${input.tenantId}`);
  }

  for (const badgeTemplateId of badgeTemplateIds) {
    const template = await findBadgeTemplateById(db, input.tenantId, badgeTemplateId);

    if (template === null) {
      throw new Error(`Badge template ${badgeTemplateId} not found for tenant ${input.tenantId}`);
    }

    const templateInScope = await isOrgUnitWithinDelegatedAuthorityScope(
      db,
      input.tenantId,
      template.ownerOrgUnitId,
      input.orgUnitId,
    );

    if (!templateInScope) {
      throw new Error(
        `Badge template ${badgeTemplateId} is outside delegated org-unit scope ${input.orgUnitId} for tenant ${input.tenantId}`,
      );
    }
  }

  const conflictingStatement = (): Promise<SqlQueryResult<DelegatedIssuingAuthorityGrantRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          delegate_user_id AS delegateUserId,
          delegated_by_user_id AS delegatedByUserId,
          org_unit_id AS orgUnitId,
          allowed_actions_json AS allowedActionsJson,
          starts_at AS startsAt,
          ends_at AS endsAt,
          revoked_at AS revokedAt,
          revoked_by_user_id AS revokedByUserId,
          revoked_reason AS revokedReason,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM delegated_issuing_authority_grants
        WHERE tenant_id = ?
          AND delegate_user_id = ?
          AND org_unit_id = ?
          AND revoked_at IS NULL
          AND starts_at < ?
          AND ends_at > ?
      `,
      )
      .bind(input.tenantId, input.delegateUserId, input.orgUnitId, input.endsAt, input.startsAt)
      .all<DelegatedIssuingAuthorityGrantRow>();

  let conflicts: SqlQueryResult<DelegatedIssuingAuthorityGrantRow>;

  try {
    conflicts = await conflictingStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    conflicts = await conflictingStatement();
  }

  for (const existing of conflicts.results) {
    const existingActions = parseDelegatedIssuingAuthorityActionsJson(existing.allowedActionsJson);

    if (!hasDelegatedGrantActionOverlap(allowedActions, existingActions)) {
      continue;
    }

    const existingTemplateIds = await listDelegatedIssuingAuthorityGrantBadgeTemplateIds(
      db,
      input.tenantId,
      existing.id,
    );

    if (hasDelegatedGrantTemplateScopeOverlap(badgeTemplateIds, existingTemplateIds)) {
      throw new Error(
        `Delegated issuing authority grant conflicts with existing grant ${existing.id}`,
      );
    }
  }

  const grantId = createPrefixedId('dag');
  const nowIso = new Date().toISOString();
  const insertGrantStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO delegated_issuing_authority_grants (
          id,
          tenant_id,
          delegate_user_id,
          delegated_by_user_id,
          org_unit_id,
          allowed_actions_json,
          starts_at,
          ends_at,
          revoked_at,
          revoked_by_user_id,
          revoked_reason,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)
      `,
      )
      .bind(
        grantId,
        input.tenantId,
        input.delegateUserId,
        input.delegatedByUserId ?? null,
        input.orgUnitId,
        JSON.stringify(allowedActions),
        input.startsAt,
        input.endsAt,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await insertGrantStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    await insertGrantStatement();
  }

  if (badgeTemplateIds.length > 0) {
    for (const badgeTemplateId of badgeTemplateIds) {
      const insertTemplateScopeStatement = (): Promise<SqlRunResult> =>
        db
          .prepare(
            `
            INSERT INTO delegated_issuing_authority_grant_badge_templates (
              tenant_id,
              grant_id,
              badge_template_id,
              created_at
            )
            VALUES (?, ?, ?, ?)
          `,
          )
          .bind(input.tenantId, grantId, badgeTemplateId, nowIso)
          .run();

      try {
        await insertTemplateScopeStatement();
      } catch (error: unknown) {
        if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
          throw error;
        }

        await ensureDelegatedIssuingAuthorityTables(db);
        await insertTemplateScopeStatement();
      }
    }
  }

  const detailsJson = input.reason === undefined ? null : JSON.stringify({ reason: input.reason });

  await createDelegatedIssuingAuthorityGrantEvent(db, {
    tenantId: input.tenantId,
    grantId,
    eventType: 'granted',
    actorUserId: input.delegatedByUserId ?? null,
    detailsJson,
    occurredAt: nowIso,
  });

  const created = await findDelegatedIssuingAuthorityGrantById(db, input.tenantId, grantId, nowIso);

  if (created === null) {
    throw new Error(`Unable to load delegated issuing authority grant ${grantId} after insert`);
  }

  return created;
};

export const listDelegatedIssuingAuthorityGrants = async (
  db: SqlDatabase,
  input: ListDelegatedIssuingAuthorityGrantsInput,
): Promise<DelegatedIssuingAuthorityGrantRecord[]> => {
  const nowIso = input.nowIso ?? new Date().toISOString();
  await recordExpiredDelegatedIssuingAuthorityGrantEvents(db, input.tenantId, nowIso);

  const query =
    input.delegateUserId === undefined
      ? `
        SELECT
          id,
          tenant_id AS tenantId,
          delegate_user_id AS delegateUserId,
          delegated_by_user_id AS delegatedByUserId,
          org_unit_id AS orgUnitId,
          allowed_actions_json AS allowedActionsJson,
          starts_at AS startsAt,
          ends_at AS endsAt,
          revoked_at AS revokedAt,
          revoked_by_user_id AS revokedByUserId,
          revoked_reason AS revokedReason,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM delegated_issuing_authority_grants
        WHERE tenant_id = ?
        ORDER BY created_at DESC
      `
      : `
        SELECT
          id,
          tenant_id AS tenantId,
          delegate_user_id AS delegateUserId,
          delegated_by_user_id AS delegatedByUserId,
          org_unit_id AS orgUnitId,
          allowed_actions_json AS allowedActionsJson,
          starts_at AS startsAt,
          ends_at AS endsAt,
          revoked_at AS revokedAt,
          revoked_by_user_id AS revokedByUserId,
          revoked_reason AS revokedReason,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM delegated_issuing_authority_grants
        WHERE tenant_id = ?
          AND delegate_user_id = ?
        ORDER BY created_at DESC
      `;

  const listStatement = (): Promise<SqlQueryResult<DelegatedIssuingAuthorityGrantRow>> =>
    input.delegateUserId === undefined
      ? db.prepare(query).bind(input.tenantId).all<DelegatedIssuingAuthorityGrantRow>()
      : db
          .prepare(query)
          .bind(input.tenantId, input.delegateUserId)
          .all<DelegatedIssuingAuthorityGrantRow>();

  let result: SqlQueryResult<DelegatedIssuingAuthorityGrantRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await listStatement();
  }

  const mapped: DelegatedIssuingAuthorityGrantRecord[] = [];

  for (const row of result.results) {
    const record = await mapDelegatedIssuingAuthorityGrantRow(db, row, nowIso);
    mapped.push(record);
  }

  return mapped.filter((record) => {
    if (input.includeRevoked !== true && record.status === 'revoked') {
      return false;
    }

    if (input.includeExpired !== true && record.status === 'expired') {
      return false;
    }

    return true;
  });
};

export const revokeDelegatedIssuingAuthorityGrant = async (
  db: SqlDatabase,
  input: RevokeDelegatedIssuingAuthorityGrantInput,
): Promise<RevokeDelegatedIssuingAuthorityGrantResult> => {
  assertValidIsoTimestamp(input.revokedAt, 'revokedAt');

  const existing = await findDelegatedIssuingAuthorityGrantById(
    db,
    input.tenantId,
    input.grantId,
    input.revokedAt,
  );

  if (existing === null) {
    throw new Error(
      `Delegated issuing authority grant ${input.grantId} not found for tenant ${input.tenantId}`,
    );
  }

  if (existing.revokedAt !== null) {
    return {
      status: 'already_revoked',
      grant: existing,
    };
  }

  const nowIso = new Date().toISOString();
  const revokeStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE delegated_issuing_authority_grants
        SET revoked_at = ?,
            revoked_by_user_id = ?,
            revoked_reason = ?,
            updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
          AND revoked_at IS NULL
      `,
      )
      .bind(
        input.revokedAt,
        input.revokedByUserId ?? null,
        input.revokedReason ?? null,
        nowIso,
        input.tenantId,
        input.grantId,
      )
      .run();

  let result: SqlRunResult;

  try {
    result = await revokeStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await revokeStatement();
  }

  if ((result.meta.rowsWritten ?? 0) > 0) {
    const detailsJson =
      input.revokedReason === undefined ? null : JSON.stringify({ reason: input.revokedReason });

    await createDelegatedIssuingAuthorityGrantEvent(db, {
      tenantId: input.tenantId,
      grantId: input.grantId,
      eventType: 'revoked',
      actorUserId: input.revokedByUserId ?? null,
      detailsJson,
      occurredAt: input.revokedAt,
    });
  }

  const grant = await findDelegatedIssuingAuthorityGrantById(
    db,
    input.tenantId,
    input.grantId,
    input.revokedAt,
  );

  if (grant === null) {
    throw new Error(
      `Unable to load delegated issuing authority grant ${input.grantId} after revoke`,
    );
  }

  return {
    status: (result.meta.rowsWritten ?? 0) > 0 ? 'revoked' : 'already_revoked',
    grant,
  };
};

export const listDelegatedIssuingAuthorityGrantEvents = async (
  db: SqlDatabase,
  input: ListDelegatedIssuingAuthorityGrantEventsInput,
): Promise<DelegatedIssuingAuthorityGrantEventRecord[]> => {
  await recordExpiredDelegatedIssuingAuthorityGrantEvents(
    db,
    input.tenantId,
    new Date().toISOString(),
  );

  const limit =
    input.limit === undefined ? 100 : Math.max(1, Math.min(500, Math.trunc(input.limit)));
  const listStatement = (): Promise<SqlQueryResult<DelegatedIssuingAuthorityGrantEventRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          grant_id AS grantId,
          event_type AS eventType,
          actor_user_id AS actorUserId,
          details_json AS detailsJson,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM delegated_issuing_authority_grant_events
        WHERE tenant_id = ?
          AND grant_id = ?
        ORDER BY occurred_at DESC, created_at DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.grantId, limit)
      .all<DelegatedIssuingAuthorityGrantEventRow>();

  let result: SqlQueryResult<DelegatedIssuingAuthorityGrantEventRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapDelegatedIssuingAuthorityGrantEventRow(row));
};

export const findActiveDelegatedIssuingAuthorityGrantForAction = async (
  db: SqlDatabase,
  input: ResolveDelegatedIssuingAuthorityInput,
): Promise<DelegatedIssuingAuthorityGrantRecord | null> => {
  const atIso = input.atIso ?? new Date().toISOString();
  assertValidIsoTimestamp(atIso, 'atIso');
  await recordExpiredDelegatedIssuingAuthorityGrantEvents(db, input.tenantId, atIso);

  const listStatement = (): Promise<SqlQueryResult<DelegatedIssuingAuthorityGrantRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          delegate_user_id AS delegateUserId,
          delegated_by_user_id AS delegatedByUserId,
          org_unit_id AS orgUnitId,
          allowed_actions_json AS allowedActionsJson,
          starts_at AS startsAt,
          ends_at AS endsAt,
          revoked_at AS revokedAt,
          revoked_by_user_id AS revokedByUserId,
          revoked_reason AS revokedReason,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM delegated_issuing_authority_grants
        WHERE tenant_id = ?
          AND delegate_user_id = ?
          AND revoked_at IS NULL
          AND starts_at <= ?
          AND ends_at >= ?
        ORDER BY starts_at ASC, created_at ASC
      `,
      )
      .bind(input.tenantId, input.userId, atIso, atIso)
      .all<DelegatedIssuingAuthorityGrantRow>();

  let result: SqlQueryResult<DelegatedIssuingAuthorityGrantRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDelegatedIssuingAuthorityTablesError(error)) {
      throw error;
    }

    await ensureDelegatedIssuingAuthorityTables(db);
    result = await listStatement();
  }

  for (const row of result.results) {
    const grant = await mapDelegatedIssuingAuthorityGrantRow(db, row, atIso);

    if (!grant.allowedActions.includes(input.requiredAction)) {
      continue;
    }

    const orgUnitAllowed = await isOrgUnitWithinDelegatedAuthorityScope(
      db,
      input.tenantId,
      input.orgUnitId,
      grant.orgUnitId,
    );

    if (!orgUnitAllowed) {
      continue;
    }

    if (
      grant.badgeTemplateIds.length > 0 &&
      !grant.badgeTemplateIds.includes(input.badgeTemplateId)
    ) {
      continue;
    }

    return grant;
  }

  return null;
};

export const hasDelegatedIssuingAuthorityAccess = async (
  db: SqlDatabase,
  input: ResolveDelegatedIssuingAuthorityInput,
): Promise<boolean> => {
  const grant = await findActiveDelegatedIssuingAuthorityGrantForAction(db, input);
  return grant !== null;
};

interface CreateBadgeTemplateOwnershipEventInput {
  tenantId: string;
  badgeTemplateId: string;
  fromOrgUnitId: string | null;
  toOrgUnitId: string;
  reasonCode: BadgeTemplateOwnershipReasonCode;
  reason: string | null;
  governanceMetadataJson: string | null;
  transferredByUserId: string | null;
  transferredAt: string;
}

const createBadgeTemplateOwnershipEvent = async (
  db: SqlDatabase,
  input: CreateBadgeTemplateOwnershipEventInput,
): Promise<BadgeTemplateOwnershipEventRecord> => {
  const eventId = createPrefixedId('btoe');
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_template_ownership_events (
          id,
          tenant_id,
          badge_template_id,
          from_org_unit_id,
          to_org_unit_id,
          reason_code,
          reason,
          governance_metadata_json,
          transferred_by_user_id,
          transferred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        eventId,
        input.tenantId,
        input.badgeTemplateId,
        input.fromOrgUnitId,
        input.toOrgUnitId,
        input.reasonCode,
        input.reason,
        input.governanceMetadataJson,
        input.transferredByUserId,
        input.transferredAt,
        input.transferredAt,
      )
      .run();

  const findStatement = (): Promise<BadgeTemplateOwnershipEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          from_org_unit_id AS fromOrgUnitId,
          to_org_unit_id AS toOrgUnitId,
          reason_code AS reasonCode,
          reason,
          governance_metadata_json AS governanceMetadataJson,
          transferred_by_user_id AS transferredByUserId,
          transferred_at AS transferredAt,
          created_at AS createdAt
        FROM badge_template_ownership_events
        WHERE id = ?
        LIMIT 1
      `,
      )
      .bind(eventId)
      .first<BadgeTemplateOwnershipEventRow>();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeTemplateOwnershipEventsTableError(error)) {
      throw error;
    }

    await ensureBadgeTemplateOwnershipEventsTable(db);
    await insertStatement();
  }

  const eventRow = await findStatement();

  if (eventRow === null) {
    throw new Error(`Unable to load badge template ownership event ${eventId} after insert`);
  }

  return mapBadgeTemplateOwnershipEventRow(eventRow);
};

export const createTenantOrgUnit = async (
  db: SqlDatabase,
  input: CreateTenantOrgUnitInput,
): Promise<TenantOrgUnitRecord> => {
  const requiredParentType = REQUIRED_PARENT_ORG_UNIT_TYPE[input.unitType];

  if (requiredParentType === null && input.parentOrgUnitId !== undefined) {
    throw new Error(`Org unit type ${input.unitType} cannot have a parent org unit`);
  }

  if (requiredParentType !== null && input.parentOrgUnitId === undefined) {
    throw new Error(
      `Org unit type ${input.unitType} requires parent org unit type ${requiredParentType}`,
    );
  }

  if (input.parentOrgUnitId !== undefined) {
    const parent = await findTenantOrgUnitById(db, input.tenantId, input.parentOrgUnitId);

    if (parent === null) {
      throw new Error(
        `Parent org unit ${input.parentOrgUnitId} not found for tenant ${input.tenantId}`,
      );
    }

    const expectedParentType = requiredParentType ?? 'institution';

    if (parent.unitType !== expectedParentType) {
      throw new Error(
        `Org unit type ${input.unitType} requires parent org unit type ${expectedParentType}`,
      );
    }

    if (!parent.isActive) {
      throw new Error(
        `Parent org unit ${input.parentOrgUnitId} is inactive for tenant ${input.tenantId}`,
      );
    }
  }

  const id = createPrefixedId('ou');
  const nowIso = new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_org_units (
          id,
          tenant_id,
          unit_type,
          slug,
          display_name,
          parent_org_unit_id,
          created_by_user_id,
          is_active,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.unitType,
        input.slug,
        input.displayName,
        input.parentOrgUnitId ?? null,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantOrgUnitsTableError(error)) {
      throw error;
    }

    await ensureTenantOrgUnitsTable(db);
    await insertStatement();
  }

  const orgUnit = await findTenantOrgUnitById(db, input.tenantId, id);

  if (orgUnit === null) {
    throw new Error(`Unable to create org unit ${id} for tenant ${input.tenantId}`);
  }

  return orgUnit;
};

export const listTenantOrgUnits = async (
  db: SqlDatabase,
  input: ListTenantOrgUnitsInput,
): Promise<TenantOrgUnitRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<TenantOrgUnitRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          unit_type AS unitType,
          slug,
          display_name AS displayName,
          parent_org_unit_id AS parentOrgUnitId,
          created_by_user_id AS createdByUserId,
          is_active AS isActive,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_org_units
        WHERE tenant_id = ?
          AND (? = 1 OR is_active = 1)
        ORDER BY
          CASE unit_type
            WHEN 'institution' THEN 1
            WHEN 'college' THEN 2
            WHEN 'department' THEN 3
            WHEN 'program' THEN 4
            ELSE 5
          END,
          display_name ASC,
          created_at ASC
      `,
      )
      .bind(input.tenantId, input.includeInactive === true ? 1 : 0)
      .all<TenantOrgUnitRow>();

  let result: SqlQueryResult<TenantOrgUnitRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingTenantOrgUnitsTableError(error)) {
      throw error;
    }

    await ensureTenantOrgUnitsTable(db);
    await ensureInstitutionOrgUnitForTenant(db, input.tenantId);
    result = await listStatement();
  }

  if (result.results.length === 0) {
    await ensureInstitutionOrgUnitForTenant(db, input.tenantId);
    result = await listStatement();
  }

  return result.results.map((row) => mapTenantOrgUnitRow(row));
};

export const upsertBadgeTemplateById = async (
  db: SqlDatabase,
  input: UpsertBadgeTemplateByIdInput,
): Promise<BadgeTemplateRecord> => {
  const nowIso = new Date().toISOString();
  const previous = await findBadgeTemplateById(db, input.tenantId, input.id);

  if (
    previous !== null &&
    input.ownerOrgUnitId !== undefined &&
    input.ownerOrgUnitId !== previous.ownerOrgUnitId
  ) {
    throw new Error('Badge template ownership changes must use transferBadgeTemplateOwnership');
  }

  const fallbackOwnerOrgUnitId = await ensureInstitutionOrgUnitForTenant(db, input.tenantId);
  const ownerOrgUnitId = previous?.ownerOrgUnitId ?? input.ownerOrgUnitId ?? fallbackOwnerOrgUnitId;
  const ownerOrgUnit = await findTenantOrgUnitById(db, input.tenantId, ownerOrgUnitId);

  if (ownerOrgUnit === null) {
    throw new Error(`Org unit ${ownerOrgUnitId} not found for tenant ${input.tenantId}`);
  }

  const governanceMetadataJson =
    previous?.governanceMetadataJson ??
    input.governanceMetadataJson ??
    '{"stability":"institution_registry"}';

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
        owner_org_unit_id,
        governance_metadata_json,
        is_archived,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
      ON CONFLICT (id)
      DO UPDATE SET
        tenant_id = excluded.tenant_id,
        slug = excluded.slug,
        title = excluded.title,
        description = excluded.description,
        criteria_uri = excluded.criteria_uri,
        image_uri = excluded.image_uri,
        created_by_user_id = excluded.created_by_user_id,
        owner_org_unit_id = badge_templates.owner_org_unit_id,
        governance_metadata_json = badge_templates.governance_metadata_json,
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
      ownerOrgUnitId,
      governanceMetadataJson,
      nowIso,
      nowIso,
    )
    .run();

  const template = await findBadgeTemplateById(db, input.tenantId, input.id);

  if (template === null) {
    throw new Error(`Unable to upsert badge template "${input.id}"`);
  }

  if (previous === null) {
    await createBadgeTemplateOwnershipEvent(db, {
      tenantId: input.tenantId,
      badgeTemplateId: template.id,
      fromOrgUnitId: null,
      toOrgUnitId: template.ownerOrgUnitId,
      reasonCode: 'initial_assignment',
      reason: 'Badge template ownership assigned at creation',
      governanceMetadataJson: template.governanceMetadataJson,
      transferredByUserId: template.createdByUserId,
      transferredAt: template.createdAt,
    });
  }

  return template;
};

export const createBadgeTemplate = async (
  db: SqlDatabase,
  input: CreateBadgeTemplateInput,
): Promise<BadgeTemplateRecord> => {
  const id = createPrefixedId('bt');
  const nowIso = new Date().toISOString();
  const fallbackOwnerOrgUnitId = await ensureInstitutionOrgUnitForTenant(db, input.tenantId);
  const ownerOrgUnitId = input.ownerOrgUnitId ?? fallbackOwnerOrgUnitId;
  const ownerOrgUnit = await findTenantOrgUnitById(db, input.tenantId, ownerOrgUnitId);

  if (ownerOrgUnit === null) {
    throw new Error(`Org unit ${ownerOrgUnitId} not found for tenant ${input.tenantId}`);
  }

  const governanceMetadataJson =
    input.governanceMetadataJson ?? '{"stability":"institution_registry"}';

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
        owner_org_unit_id,
        governance_metadata_json,
        is_archived,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
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
      ownerOrgUnitId,
      governanceMetadataJson,
      nowIso,
      nowIso,
    )
    .run();

  const template: BadgeTemplateRecord = {
    id,
    tenantId: input.tenantId,
    slug: input.slug,
    title: input.title,
    description: input.description ?? null,
    criteriaUri: input.criteriaUri ?? null,
    imageUri: input.imageUri ?? null,
    createdByUserId: input.createdByUserId ?? null,
    ownerOrgUnitId,
    governanceMetadataJson,
    isArchived: false,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  await createBadgeTemplateOwnershipEvent(db, {
    tenantId: input.tenantId,
    badgeTemplateId: template.id,
    fromOrgUnitId: null,
    toOrgUnitId: template.ownerOrgUnitId,
    reasonCode: 'initial_assignment',
    reason: 'Badge template ownership assigned at creation',
    governanceMetadataJson: template.governanceMetadataJson,
    transferredByUserId: template.createdByUserId,
    transferredAt: template.createdAt,
  });

  return template;
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
        owner_org_unit_id AS ownerOrgUnitId,
        governance_metadata_json AS governanceMetadataJson,
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
        owner_org_unit_id AS ownerOrgUnitId,
        governance_metadata_json AS governanceMetadataJson,
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
        owner_org_unit_id AS ownerOrgUnitId,
        governance_metadata_json AS governanceMetadataJson,
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

export const listBadgeTemplateOwnershipEvents = async (
  db: SqlDatabase,
  input: ListBadgeTemplateOwnershipEventsInput,
): Promise<BadgeTemplateOwnershipEventRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 100, 500));
  const listStatement = (): Promise<SqlQueryResult<BadgeTemplateOwnershipEventRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          from_org_unit_id AS fromOrgUnitId,
          to_org_unit_id AS toOrgUnitId,
          reason_code AS reasonCode,
          reason,
          governance_metadata_json AS governanceMetadataJson,
          transferred_by_user_id AS transferredByUserId,
          transferred_at AS transferredAt,
          created_at AS createdAt
        FROM badge_template_ownership_events
        WHERE tenant_id = ?
          AND badge_template_id = ?
        ORDER BY transferred_at DESC, created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.badgeTemplateId, queryLimit)
      .all<BadgeTemplateOwnershipEventRow>();

  let result: SqlQueryResult<BadgeTemplateOwnershipEventRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeTemplateOwnershipEventsTableError(error)) {
      throw error;
    }

    await ensureBadgeTemplateOwnershipEventsTable(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapBadgeTemplateOwnershipEventRow(row));
};

export const transferBadgeTemplateOwnership = async (
  db: SqlDatabase,
  input: TransferBadgeTemplateOwnershipInput,
): Promise<TransferBadgeTemplateOwnershipResult> => {
  const transferredAtMs = Date.parse(input.transferredAt);

  if (!Number.isFinite(transferredAtMs)) {
    throw new Error('transferredAt must be a valid ISO timestamp');
  }

  if (!BADGE_TEMPLATE_OWNERSHIP_REASON_CODES.has(input.reasonCode)) {
    throw new Error(`Unsupported badge template ownership reason code: ${input.reasonCode}`);
  }

  const template = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (template === null) {
    throw new Error(
      `Badge template ${input.badgeTemplateId} not found for tenant ${input.tenantId}`,
    );
  }

  const toOrgUnit = await findTenantOrgUnitById(db, input.tenantId, input.toOrgUnitId);

  if (toOrgUnit === null) {
    throw new Error(`Org unit ${input.toOrgUnitId} not found for tenant ${input.tenantId}`);
  }

  if (template.ownerOrgUnitId === input.toOrgUnitId) {
    return {
      status: 'already_owned',
      template,
      event: null,
    };
  }

  const normalizedReason = input.reason?.trim();
  const reason =
    normalizedReason === undefined || normalizedReason.length === 0 ? null : normalizedReason;
  const governanceMetadataJson = input.governanceMetadataJson ?? template.governanceMetadataJson;

  await db
    .prepare(
      `
      UPDATE badge_templates
      SET owner_org_unit_id = ?,
          governance_metadata_json = ?,
          updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(
      input.toOrgUnitId,
      governanceMetadataJson,
      input.transferredAt,
      input.tenantId,
      input.badgeTemplateId,
    )
    .run();

  const updatedTemplate = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (updatedTemplate === null) {
    throw new Error(
      `Unable to load badge template ${input.badgeTemplateId} after ownership transfer`,
    );
  }

  const event = await createBadgeTemplateOwnershipEvent(db, {
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    fromOrgUnitId: template.ownerOrgUnitId,
    toOrgUnitId: input.toOrgUnitId,
    reasonCode: input.reasonCode,
    reason,
    governanceMetadataJson,
    transferredByUserId: input.transferredByUserId ?? null,
    transferredAt: input.transferredAt,
  });

  return {
    status: 'transferred',
    template: updatedTemplate,
    event,
  };
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

const findLatestAssertionLifecycleEvent = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<AssertionLifecycleEventRecord | null> => {
  const latestStatement = (): Promise<AssertionLifecycleEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          from_state AS fromState,
          to_state AS toState,
          reason_code AS reasonCode,
          reason,
          transition_source AS transitionSource,
          actor_user_id AS actorUserId,
          transitioned_at AS transitionedAt,
          created_at AS createdAt
        FROM assertion_lifecycle_events
        WHERE tenant_id = ?
          AND assertion_id = ?
        ORDER BY transitioned_at DESC, created_at DESC, id DESC
        LIMIT 1
      `,
      )
      .bind(tenantId, assertionId)
      .first<AssertionLifecycleEventRow>();

  let row: AssertionLifecycleEventRow | null;

  try {
    row = await latestStatement();
  } catch (error: unknown) {
    if (!isMissingAssertionLifecycleEventsTableError(error)) {
      throw error;
    }

    await ensureAssertionLifecycleEventsTable(db);
    row = await latestStatement();
  }

  return row === null ? null : mapAssertionLifecycleEventRow(row);
};

const findAssertionLifecycleEventById = async (
  db: SqlDatabase,
  id: string,
): Promise<AssertionLifecycleEventRecord | null> => {
  const lookupStatement = (): Promise<AssertionLifecycleEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          from_state AS fromState,
          to_state AS toState,
          reason_code AS reasonCode,
          reason,
          transition_source AS transitionSource,
          actor_user_id AS actorUserId,
          transitioned_at AS transitionedAt,
          created_at AS createdAt
        FROM assertion_lifecycle_events
        WHERE id = ?
        LIMIT 1
      `,
      )
      .bind(id)
      .first<AssertionLifecycleEventRow>();

  let row: AssertionLifecycleEventRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingAssertionLifecycleEventsTableError(error)) {
      throw error;
    }

    await ensureAssertionLifecycleEventsTable(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapAssertionLifecycleEventRow(row);
};

export const listAssertionLifecycleEvents = async (
  db: SqlDatabase,
  input: ListAssertionLifecycleEventsInput,
): Promise<AssertionLifecycleEventRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 50, 200));
  const listStatement = (): Promise<SqlQueryResult<AssertionLifecycleEventRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          from_state AS fromState,
          to_state AS toState,
          reason_code AS reasonCode,
          reason,
          transition_source AS transitionSource,
          actor_user_id AS actorUserId,
          transitioned_at AS transitionedAt,
          created_at AS createdAt
        FROM assertion_lifecycle_events
        WHERE tenant_id = ?
          AND assertion_id = ?
        ORDER BY transitioned_at DESC, created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.assertionId, queryLimit)
      .all<AssertionLifecycleEventRow>();

  let result: SqlQueryResult<AssertionLifecycleEventRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingAssertionLifecycleEventsTableError(error)) {
      throw error;
    }

    await ensureAssertionLifecycleEventsTable(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapAssertionLifecycleEventRow(row));
};

export const resolveAssertionLifecycleState = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<ResolveAssertionLifecycleStateResult | null> => {
  const assertion = await findAssertionById(db, tenantId, assertionId);

  if (assertion === null) {
    return null;
  }

  const latestEvent = await findLatestAssertionLifecycleEvent(db, tenantId, assertionId);
  return assertionLifecycleStateFromRecords({
    assertion,
    latestEvent,
  });
};

export const recordAssertionLifecycleTransition = async (
  db: SqlDatabase,
  input: RecordAssertionLifecycleTransitionInput,
): Promise<RecordAssertionLifecycleTransitionResult> => {
  const transitionedAtMs = Date.parse(input.transitionedAt);

  if (!Number.isFinite(transitionedAtMs)) {
    throw new Error('transitionedAt must be a valid ISO timestamp');
  }

  if (!ASSERTION_LIFECYCLE_REASON_CODES.has(input.reasonCode)) {
    throw new Error(`Unsupported assertion lifecycle reason code: ${input.reasonCode}`);
  }

  if (input.transitionSource === 'manual' && input.actorUserId === undefined) {
    throw new Error('Manual lifecycle transitions require actorUserId');
  }

  if (input.transitionSource === 'automation' && input.actorUserId !== undefined) {
    throw new Error('Automated lifecycle transitions must not set actorUserId');
  }

  const assertion = await findAssertionById(db, input.tenantId, input.assertionId);

  if (assertion === null) {
    throw new Error(`Assertion ${input.assertionId} not found for tenant ${input.tenantId}`);
  }

  const latestEvent = await findLatestAssertionLifecycleEvent(
    db,
    input.tenantId,
    input.assertionId,
  );
  const current = assertionLifecycleStateFromRecords({
    assertion,
    latestEvent,
  });

  if (current.state === input.toState) {
    return {
      status: 'already_in_state',
      fromState: current.state,
      toState: input.toState,
      currentState: current.state,
      event: null,
      message: `assertion is already in ${current.state} state`,
    };
  }

  const allowedTransitions = ASSERTION_LIFECYCLE_ALLOWED_TRANSITIONS[current.state];

  if (!allowedTransitions.has(input.toState)) {
    return {
      status: 'invalid_transition',
      fromState: current.state,
      toState: input.toState,
      currentState: current.state,
      event: null,
      message: `transition from ${current.state} to ${input.toState} is not allowed`,
    };
  }

  const normalizedReason = input.reason?.trim();
  const reason =
    normalizedReason === undefined || normalizedReason.length === 0 ? null : normalizedReason;
  let effectiveTransitionedAt = input.transitionedAt;

  if (input.toState === 'revoked') {
    const revocationResult = await recordAssertionRevocation(db, {
      tenantId: input.tenantId,
      assertionId: input.assertionId,
      revocationId: createPrefixedId('rev'),
      reason: reason ?? input.reasonCode,
      idempotencyKey: createPrefixedId('idem'),
      ...(input.actorUserId === undefined ? {} : { revokedByUserId: input.actorUserId }),
      revokedAt: input.transitionedAt,
    });

    if (revocationResult.status === 'already_revoked') {
      return {
        status: 'already_in_state',
        fromState: current.state,
        toState: input.toState,
        currentState: 'revoked',
        event: null,
        message: 'assertion is already in revoked state',
      };
    }

    effectiveTransitionedAt = revocationResult.revokedAt;
  }

  const eventId = createPrefixedId('ale');
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO assertion_lifecycle_events (
          id,
          tenant_id,
          assertion_id,
          from_state,
          to_state,
          reason_code,
          reason,
          transition_source,
          actor_user_id,
          transitioned_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        eventId,
        input.tenantId,
        input.assertionId,
        current.state,
        input.toState,
        input.reasonCode,
        reason,
        input.transitionSource,
        input.actorUserId ?? null,
        effectiveTransitionedAt,
        effectiveTransitionedAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingAssertionLifecycleEventsTableError(error)) {
      throw error;
    }

    await ensureAssertionLifecycleEventsTable(db);
    await insertStatement();
  }

  await db
    .prepare(
      `
      UPDATE assertions
      SET updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(effectiveTransitionedAt, input.tenantId, input.assertionId)
    .run();

  const event = await findAssertionLifecycleEventById(db, eventId);

  if (event === null) {
    throw new Error(`Unable to load assertion lifecycle event ${eventId} after insert`);
  }

  return {
    status: 'transitioned',
    fromState: current.state,
    toState: input.toState,
    currentState: input.toState,
    event,
    message: null,
  };
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

const normalizeRecipientIdentifierValue = (
  identifierType: RecipientIdentifierType,
  identifierValue: string,
): string => {
  const trimmedValue = identifierValue.trim();

  if (identifierType === 'emailAddress') {
    return normalizeEmail(trimmedValue);
  }

  return trimmedValue;
};

const uniqueRecipientIdentifiers = (
  input: readonly RecipientIdentifierInput[],
): RecipientIdentifierInput[] => {
  const seen = new Set<string>();
  const unique: RecipientIdentifierInput[] = [];

  for (const entry of input) {
    const normalizedValue = normalizeRecipientIdentifierValue(
      entry.identifierType,
      entry.identifierValue,
    );

    if (normalizedValue.length === 0) {
      continue;
    }

    const dedupeKey = `${entry.identifierType}::${normalizedValue}`;

    if (seen.has(dedupeKey)) {
      continue;
    }

    seen.add(dedupeKey);
    unique.push({
      identifierType: entry.identifierType,
      identifierValue: normalizedValue,
    });
  }

  return unique;
};

const insertAssertionRecipientIdentifiers = async (
  db: SqlDatabase,
  assertionId: string,
  recipientIdentifiers: readonly RecipientIdentifierInput[],
): Promise<void> => {
  if (recipientIdentifiers.length === 0) {
    return;
  }

  const insertStatement = async (): Promise<void> => {
    for (const entry of recipientIdentifiers) {
      await db
        .prepare(
          `
          INSERT OR IGNORE INTO recipient_identifiers (
            assertion_id,
            identifier_type,
            identifier_value,
            created_at
          )
          VALUES (?, ?, ?, ?)
        `,
        )
        .bind(assertionId, entry.identifierType, entry.identifierValue, new Date().toISOString())
        .run();
    }
  };

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingRecipientIdentifiersTableError(error)) {
      throw error;
    }

    await ensureRecipientIdentifiersTable(db);
    await insertStatement();
  }
};

export const listRecipientIdentifiersForAssertion = async (
  db: SqlDatabase,
  assertionId: string,
): Promise<RecipientIdentifierRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<RecipientIdentifierRow>> =>
    db
      .prepare(
        `
        SELECT
          assertion_id AS assertionId,
          identifier_type AS identifierType,
          identifier_value AS identifierValue,
          created_at AS createdAt
        FROM recipient_identifiers
        WHERE assertion_id = ?
        ORDER BY created_at ASC
      `,
      )
      .bind(assertionId)
      .all<RecipientIdentifierRow>();

  let result: SqlQueryResult<RecipientIdentifierRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingRecipientIdentifiersTableError(error)) {
      throw error;
    }

    await ensureRecipientIdentifiersTable(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapRecipientIdentifierRow(row));
};

export const createAssertion = async (
  db: SqlDatabase,
  input: CreateAssertionInput,
): Promise<AssertionRecord> => {
  const nowIso = new Date().toISOString();
  const assertionPublicId = input.publicId ?? crypto.randomUUID();
  const recipientIdentifiers = uniqueRecipientIdentifiers(input.recipientIdentifiers ?? []);

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

  await insertAssertionRecipientIdentifiers(db, input.id, recipientIdentifiers);

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
