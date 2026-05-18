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

export type TenantPlanTier = "free" | "team" | "institution" | "enterprise";

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
  kty: "OKP";
  crv: "Ed25519";
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
  platformJwksEndpoint: string | null;
  tokenEndpoint: string | null;
  clientSecret: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertLtiIssuerRegistrationInput {
  issuer: string;
  tenantId: string;
  authorizationEndpoint: string;
  clientId: string;
  platformJwksEndpoint?: string | undefined;
  tokenEndpoint?: string | undefined;
  clientSecret?: string | undefined;
}

export interface LtiDeploymentRecord {
  id: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  name: string | null;
  description: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertLtiDeploymentInput {
  id?: string | undefined;
  issuer: string;
  clientId: string;
  deploymentId: string;
  name?: string | undefined;
  description?: string | undefined;
}

export interface LtiToolKeyRecord {
  id: string;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateLtiToolKeyInput {
  id?: string | undefined;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson: string;
  isActive?: boolean | undefined;
}

export interface LtiLaunchSessionRecord {
  id: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  tenantId: string | null;
  userId: string | null;
  dataJson: string;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertLtiLaunchSessionInput {
  id: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  tenantId?: string | null | undefined;
  userId?: string | null | undefined;
  dataJson: string;
  expiresAt: string;
}

export interface LtiDynamicRegistrationSessionRecord {
  id: string;
  dataJson: string;
  expiresAt: string;
  createdAt: string;
}

export interface LtiResourceLinkPlacementRecord {
  id: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  contextId: string | null;
  resourceLinkId: string;
  badgeTemplateId: string;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertLtiResourceLinkPlacementInput {
  id?: string | undefined;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  contextId?: string | null | undefined;
  resourceLinkId: string;
  badgeTemplateId: string;
  createdByUserId?: string | null | undefined;
}

export interface UserRecord {
  id: string;
  email: string;
}

export interface AuthIdentityLinkRecord {
  id: string;
  authSystem: string;
  authUserId: string;
  authAccountId: string | null;
  credtrailUserId: string;
  emailSnapshot: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateAuthIdentityLinkInput {
  authSystem: string;
  authUserId: string;
  authAccountId?: string | null | undefined;
  credtrailUserId: string;
  emailSnapshot?: string | null | undefined;
}

export type TenantMembershipRole = "owner" | "admin" | "issuer" | "viewer";

export interface TenantMembershipRecord {
  tenantId: string;
  userId: string;
  role: TenantMembershipRole;
  createdAt: string;
  updatedAt: string;
}

export interface TenantMemberRecord extends TenantMembershipRecord {
  email: string;
}

export interface TenantMembershipRoleCounts {
  owner: number;
  admin: number;
  issuer: number;
  viewer: number;
}

export interface AccessibleTenantContextRecord {
  tenantId: string;
  tenantSlug: string;
  tenantDisplayName: string;
  tenantPlanTier: TenantPlanTier;
  membershipRole: TenantMembershipRole;
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

export type TenantMembershipOrgUnitScopeRole = "admin" | "issuer" | "viewer";

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

export type DelegatedIssuingAuthorityAction = "issue_badge" | "revoke_badge" | "manage_lifecycle";

export type DelegatedIssuingAuthorityGrantStatus = "scheduled" | "active" | "expired" | "revoked";

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

export type DelegatedIssuingAuthorityGrantEventType = "granted" | "revoked" | "expired";

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
  status: "revoked" | "already_revoked";
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

export interface ListAuditLogsInput {
  tenantId: string;
  action?: string | undefined;
  limit?: number | undefined;
}

export interface TenantApiKeyRecord {
  id: string;
  tenantId: string;
  label: string;
  keyPrefix: string;
  keyHash: string;
  scopesJson: string;
  createdByUserId: string | null;
  expiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateTenantApiKeyInput {
  tenantId: string;
  label: string;
  keyPrefix: string;
  keyHash: string;
  scopesJson: string;
  createdByUserId?: string | undefined;
  expiresAt?: string | undefined;
}

export interface ListTenantApiKeysInput {
  tenantId: string;
  includeRevoked?: boolean | undefined;
}

export interface RevokeTenantApiKeyInput {
  tenantId: string;
  apiKeyId: string;
  revokedAt: string;
}

export interface FindActiveTenantApiKeyByHashInput {
  keyHash: string;
  nowIso: string;
}

export type TenantLoginMode = "local" | "hybrid" | "sso_required";

export type TenantAuthPolicyEnforceForRoles = "all_users" | "admins_only";

export const HOSTED_ENTERPRISE_OIDC_ONLY_ERROR =
  "Hosted enterprise sign-in currently supports OIDC providers only. Legacy SAML compatibility remains available for visibility and cleanup.";

export interface TenantAuthPolicyRecord {
  tenantId: string;
  loginMode: TenantLoginMode;
  breakGlassEnabled: boolean;
  localMfaRequired: boolean;
  defaultProviderId: string | null;
  enforceForRoles: TenantAuthPolicyEnforceForRoles;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantAuthPolicyInput {
  tenantId: string;
  loginMode: TenantLoginMode;
  breakGlassEnabled?: boolean | undefined;
  localMfaRequired?: boolean | undefined;
  defaultProviderId?: string | null | undefined;
  enforceForRoles?: TenantAuthPolicyEnforceForRoles | undefined;
}

export type TenantAuthProviderProtocol = "oidc" | "saml";

export interface TenantAuthProviderRecord {
  id: string;
  tenantId: string;
  protocol: TenantAuthProviderProtocol;
  label: string;
  enabled: boolean;
  isDefault: boolean;
  configJson: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateTenantAuthProviderInput {
  id?: string | undefined;
  tenantId: string;
  protocol: TenantAuthProviderProtocol;
  label: string;
  enabled?: boolean | undefined;
  isDefault?: boolean | undefined;
  configJson: string;
}

export interface UpdateTenantAuthProviderInput {
  tenantId: string;
  providerId: string;
  protocol: TenantAuthProviderProtocol;
  label: string;
  enabled?: boolean | undefined;
  isDefault?: boolean | undefined;
  configJson: string;
}

export interface TenantBreakGlassAccountRecord {
  tenantId: string;
  userId: string;
  email: string;
  createdByUserId: string | null;
  lastUsedAt: string | null;
  lastEnrollmentEmailSentAt: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
  betterAuthUserId: string | null;
  localCredentialEnabled: boolean;
  twoFactorEnabled: boolean;
}

export interface UpsertTenantBreakGlassAccountInput {
  tenantId: string;
  userId: string;
  createdByUserId?: string | null | undefined;
  lastEnrollmentEmailSentAt?: string | null | undefined;
}

export interface RevokeTenantBreakGlassAccountInput {
  tenantId: string;
  userId: string;
  revokedAt: string;
}

export interface MarkTenantBreakGlassAccountUsedInput {
  tenantId: string;
  userId: string;
  usedAt: string;
}

export interface MarkTenantBreakGlassEnrollmentEmailSentInput {
  tenantId: string;
  userId: string;
  sentAt: string;
}

export interface TenantSsoSamlConfigurationRecord {
  tenantId: string;
  idpEntityId: string;
  ssoLoginUrl: string;
  idpCertificatePem: string;
  idpMetadataUrl: string | null;
  spEntityId: string;
  assertionConsumerServiceUrl: string;
  nameIdFormat: string | null;
  enforced: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantSsoSamlConfigurationInput {
  tenantId: string;
  idpEntityId: string;
  ssoLoginUrl: string;
  idpCertificatePem: string;
  idpMetadataUrl?: string | undefined;
  spEntityId: string;
  assertionConsumerServiceUrl: string;
  nameIdFormat?: string | undefined;
  enforced?: boolean | undefined;
}

export interface TenantCanvasGradebookIntegrationRecord {
  tenantId: string;
  apiBaseUrl: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  accessToken: string | null;
  refreshToken: string | null;
  accessTokenExpiresAt: string | null;
  refreshTokenExpiresAt: string | null;
  connectedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpsertTenantCanvasGradebookIntegrationInput {
  tenantId: string;
  apiBaseUrl: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  scope: string;
}

export interface UpdateTenantCanvasGradebookIntegrationTokensInput {
  tenantId: string;
  accessToken: string;
  refreshToken?: string | undefined;
  accessTokenExpiresAt?: string | undefined;
  refreshTokenExpiresAt?: string | undefined;
  connectedAt?: string | undefined;
}

export type BadgeIssuanceRuleLmsProviderKind =
  | "canvas"
  | "moodle"
  | "blackboard_ultra"
  | "d2l_brightspace"
  | "sakai";

export type BadgeIssuanceRuleVersionStatus =
  | "draft"
  | "pending_approval"
  | "approved"
  | "active"
  | "rejected"
  | "deprecated";

export type BadgeIssuanceRuleApprovalStepStatus = "queued" | "pending" | "approved" | "rejected";

export type BadgeIssuanceRuleApprovalEventAction = "submitted" | "approved" | "rejected";

export interface BadgeIssuanceRuleRecord {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  badgeTemplateId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  activeVersionId: string | null;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BadgeIssuanceRuleVersionRecord {
  id: string;
  tenantId: string;
  ruleId: string;
  versionNumber: number;
  status: BadgeIssuanceRuleVersionStatus;
  ruleJson: string;
  changeSummary: string | null;
  createdByUserId: string | null;
  approvedByUserId: string | null;
  approvedAt: string | null;
  activatedByUserId: string | null;
  activatedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BadgeIssuanceRuleApprovalChainStepInput {
  requiredRole: TenantMembershipRole;
  label?: string | undefined;
}

export interface BadgeIssuanceRuleApprovalStepRecord {
  id: string;
  tenantId: string;
  versionId: string;
  stepNumber: number;
  requiredRole: TenantMembershipRole;
  label: string | null;
  status: BadgeIssuanceRuleApprovalStepStatus;
  decidedByUserId: string | null;
  decidedAt: string | null;
  decisionComment: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BadgeIssuanceRuleApprovalEventRecord {
  id: string;
  tenantId: string;
  versionId: string;
  stepNumber: number | null;
  action: BadgeIssuanceRuleApprovalEventAction;
  actorUserId: string | null;
  actorRole: TenantMembershipRole | null;
  comment: string | null;
  occurredAt: string;
  createdAt: string;
}

export interface BadgeIssuanceRuleValueListRecord {
  id: string;
  tenantId: string;
  label: string;
  kind: "course_ids" | "badge_template_ids";
  values: string[];
  createdByUserId: string | null;
  archivedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

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

export interface CreateBadgeIssuanceRuleInput {
  tenantId: string;
  name: string;
  description?: string | undefined;
  badgeTemplateId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  ruleJson: string;
  approvalChain?: BadgeIssuanceRuleApprovalChainStepInput[] | undefined;
  changeSummary?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface CreateBadgeIssuanceRuleVersionInput {
  tenantId: string;
  ruleId: string;
  ruleJson: string;
  approvalChain?: BadgeIssuanceRuleApprovalChainStepInput[] | undefined;
  changeSummary?: string | undefined;
  createdByUserId?: string | undefined;
}

export interface ListBadgeIssuanceRulesInput {
  tenantId: string;
}

export interface ListBadgeIssuanceRuleVersionsInput {
  tenantId: string;
  ruleId: string;
}

export interface CreateBadgeIssuanceRuleValueListInput {
  tenantId: string;
  label: string;
  kind: "course_ids" | "badge_template_ids";
  values: readonly string[];
  createdByUserId?: string | undefined;
}

export interface ListBadgeIssuanceRuleValueListsInput {
  tenantId: string;
  kind?: "course_ids" | "badge_template_ids" | undefined;
  includeArchived?: boolean | undefined;
}

export interface SubmitBadgeIssuanceRuleVersionForApprovalInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  actorUserId?: string | undefined;
  actorRole?: TenantMembershipRole | undefined;
  comment?: string | undefined;
  occurredAt?: string | undefined;
}

export interface DecideBadgeIssuanceRuleVersionInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  decision: "approved" | "rejected";
  actorUserId: string;
  actorRole: TenantMembershipRole;
  comment?: string | undefined;
  occurredAt?: string | undefined;
}

export interface ListBadgeIssuanceRuleVersionApprovalStepsInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
}

export interface ListBadgeIssuanceRuleVersionApprovalEventsInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
}

export interface ActivateBadgeIssuanceRuleVersionInput {
  tenantId: string;
  ruleId: string;
  versionId: string;
  actorUserId: string;
  activatedAt?: string | undefined;
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

export interface DedicatedDbProvisioningRequestStatusInput {
  status: "pending" | "provisioned" | "failed" | "canceled";
}

export type DedicatedDbProvisioningRequestStatus =
  DedicatedDbProvisioningRequestStatusInput["status"];

export interface DedicatedDbProvisioningRequestRecord {
  id: string;
  tenantId: string;
  requestedByUserId: string | null;
  targetRegion: string;
  status: DedicatedDbProvisioningRequestStatus;
  dedicatedDatabaseUrl: string | null;
  notes: string | null;
  requestedAt: string;
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateDedicatedDbProvisioningRequestInput {
  tenantId: string;
  requestedByUserId?: string | undefined;
  targetRegion: string;
  notes?: string | undefined;
  requestedAt?: string | undefined;
}

export interface ListDedicatedDbProvisioningRequestsInput {
  tenantId: string;
  status?: DedicatedDbProvisioningRequestStatus | undefined;
}

export interface ResolveDedicatedDbProvisioningRequestInput {
  tenantId: string;
  requestId: string;
  status: Exclude<DedicatedDbProvisioningRequestStatus, "pending">;
  dedicatedDatabaseUrl?: string | undefined;
  notes?: string | undefined;
  resolvedAt?: string | undefined;
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

export interface Oid4vciPreAuthorizedCodeRecord {
  id: string;
  codeHash: string;
  tenantId: string;
  assertionId: string;
  publicBadgeId: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

export interface CreateOid4vciPreAuthorizedCodeInput {
  codeHash: string;
  tenantId: string;
  assertionId: string;
  publicBadgeId: string;
  expiresAt: string;
}

export interface ConsumeOid4vciPreAuthorizedCodeInput {
  codeHash: string;
  nowIso: string;
}

export interface Oid4vciAccessTokenRecord {
  id: string;
  accessTokenHash: string;
  tenantId: string;
  assertionId: string;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

export interface CreateOid4vciAccessTokenInput {
  accessTokenHash: string;
  tenantId: string;
  assertionId: string;
  expiresAt: string;
}

export interface FindActiveOid4vciAccessTokenByHashInput {
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
  status: "created" | "updated";
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
  identityType: "email";
  identityValue: string;
  tokenHash: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

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

export type LearnerRecordTrustLevel = "issuer_verified" | "learner_supplemental";

export type LearnerRecordStatus = "active" | "revoked" | "expired";

export type LearnerRecordEntryType =
  | "course"
  | "certificate"
  | "license"
  | "competency"
  | "work_based_learning"
  | "experience"
  | "membership"
  | "supplemental_artifact"
  | "custom";

export type LearnerRecordSourceSystem =
  | "credtrail_admin"
  | "csv_import"
  | "api"
  | "migration"
  | "badge_assertion"
  | "learner_self_reported";

export interface LearnerRecordEntryRecord {
  id: string;
  tenantId: string;
  learnerProfileId: string;
  trustLevel: LearnerRecordTrustLevel;
  recordType: LearnerRecordEntryType;
  status: LearnerRecordStatus;
  title: string;
  description: string | null;
  issuerName: string;
  issuerUserId: string | null;
  sourceSystem: LearnerRecordSourceSystem;
  sourceRecordId: string | null;
  issuedAt: string;
  revisedAt: string | null;
  revokedAt: string | null;
  evidenceLinksJson: string;
  detailsJson: string | null;
  createdAt: string;
  updatedAt: string;
}

export type LearnerRecordImportContextInferenceSource =
  | "row"
  | "badge_template"
  | "org_unit"
  | "none";

export interface LearnerRecordImportContextRecord {
  entryId: string;
  tenantId: string;
  orgUnitId: string | null;
  badgeTemplateId: string | null;
  pathwayLabel: string | null;
  inferredFromJson: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateLearnerRecordEntryInput {
  tenantId: string;
  learnerProfileId: string;
  trustLevel: LearnerRecordTrustLevel;
  recordType: LearnerRecordEntryType;
  status?: LearnerRecordStatus | undefined;
  title: string;
  description?: string | undefined;
  issuerName: string;
  issuerUserId?: string | null | undefined;
  sourceSystem: LearnerRecordSourceSystem;
  sourceRecordId?: string | null | undefined;
  issuedAt: string;
  revisedAt?: string | null | undefined;
  revokedAt?: string | null | undefined;
  evidenceLinks: readonly string[];
  detailsJson?: string | null | undefined;
}

export interface CreateLearnerRecordImportContextInput {
  tenantId: string;
  entryId: string;
  orgUnitId?: string | null | undefined;
  badgeTemplateId?: string | null | undefined;
  pathwayLabel?: string | null | undefined;
  inferredFrom: readonly LearnerRecordImportContextInferenceSource[];
}

export interface ListLearnerRecordEntriesInput {
  tenantId: string;
  learnerProfileId: string;
  trustLevel?: LearnerRecordTrustLevel | undefined;
  status?: LearnerRecordStatus | undefined;
}

export interface PatchLearnerRecordEntryInput {
  tenantId: string;
  entryId: string;
  trustLevel?: LearnerRecordTrustLevel | undefined;
  recordType?: LearnerRecordEntryType | undefined;
  status?: LearnerRecordStatus | undefined;
  title?: string | undefined;
  description?: string | null | undefined;
  issuerName?: string | undefined;
  issuerUserId?: string | null | undefined;
  sourceSystem?: LearnerRecordSourceSystem | undefined;
  sourceRecordId?: string | null | undefined;
  issuedAt?: string | undefined;
  revisedAt?: string | null | undefined;
  revokedAt?: string | null | undefined;
  evidenceLinks?: readonly string[] | undefined;
  detailsJson?: string | null | undefined;
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

export type LearnerProfileResolutionStrategy = "saml_subject" | "verified_email" | "created";

export interface ResolveLearnerProfileFromSamlResult {
  profile: LearnerProfileRecord;
  strategy: LearnerProfileResolutionStrategy;
}

export interface CreateLearnerIdentityLinkProofInput {
  tenantId: string;
  learnerProfileId: string;
  requestedByUserId: string;
  identityType: "email";
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

export type BadgeTemplateImageRevisionSource =
  | "manual_update"
  | "upload"
  | "ai_generated"
  | "restore";

export interface BadgeTemplateImageRevisionRecord {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  previousImageUri: string | null;
  newImageUri: string | null;
  sourceType: BadgeTemplateImageRevisionSource;
  promptText: string | null;
  provider: string | null;
  model: string | null;
  metadataJson: string | null;
  createdByUserId: string | null;
  createdAt: string;
}

export interface CreateBadgeTemplateImageRevisionInput {
  tenantId: string;
  badgeTemplateId: string;
  previousImageUri: string | null;
  newImageUri: string | null;
  sourceType: BadgeTemplateImageRevisionSource;
  promptText?: string | null | undefined;
  provider?: string | null | undefined;
  model?: string | null | undefined;
  metadataJson?: string | null | undefined;
  createdByUserId?: string | null | undefined;
}

export interface ListBadgeTemplateImageRevisionsInput {
  tenantId: string;
  badgeTemplateId: string;
  limit?: number | undefined;
}

export type BadgeTemplateImageGenerationStatus = "queued" | "processing" | "succeeded" | "failed";

export interface BadgeTemplateImageGenerationRecord {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  status: BadgeTemplateImageGenerationStatus;
  promptText: string;
  stylePreset: string;
  promptNotes: string | null;
  accentColor: string | null;
  resultImageUri: string | null;
  errorMessage: string | null;
  requestedByUserId: string | null;
  queuedJobId: string | null;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
}

export interface CreateBadgeTemplateImageGenerationInput {
  tenantId: string;
  badgeTemplateId: string;
  promptText: string;
  stylePreset: string;
  promptNotes?: string | null | undefined;
  accentColor?: string | null | undefined;
  requestedByUserId?: string | null | undefined;
}

export interface UpdateBadgeTemplateImageGenerationInput {
  tenantId: string;
  id: string;
  status?: BadgeTemplateImageGenerationStatus | undefined;
  resultImageUri?: string | null | undefined;
  errorMessage?: string | null | undefined;
  queuedJobId?: string | null | undefined;
  completedAt?: string | null | undefined;
}

export interface SetBadgeTemplateArchiveStateInput {
  tenantId: string;
  id: string;
  isArchived: boolean;
}

export type OrgUnitType = "institution" | "college" | "department" | "program";

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
  | "initial_assignment"
  | "administrative_transfer"
  | "reorganization"
  | "governance_policy_update"
  | "other";

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
  reasonCode: Exclude<BadgeTemplateOwnershipReasonCode, "initial_assignment">;
  reason?: string | undefined;
  governanceMetadataJson?: string | undefined;
  transferredByUserId?: string | undefined;
  transferredAt: string;
}

export interface TransferBadgeTemplateOwnershipResult {
  status: "transferred" | "already_owned";
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
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  vcR2Key: string;
  statusListIndex: number | null;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface LearnerRecordAssertionExportRecord {
  assertionId: string;
  assertionPublicId: string | null;
  tenantId: string;
  learnerProfileId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  badgeCriteriaUri: string | null;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  vcR2Key: string;
  statusListIndex: number | null;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  issuerName: string;
  createdAt: string;
  updatedAt: string;
}

export interface ListLearnerRecordAssertionExportsInput {
  tenantId: string;
  learnerProfileId: string;
}

export type AssertionLifecycleState = "active" | "suspended" | "revoked" | "expired";

export type AssertionLifecycleTransitionSource = "manual" | "automation";

export type AssertionLifecycleReasonCode =
  | "administrative_hold"
  | "policy_violation"
  | "appeal_pending"
  | "appeal_resolved"
  | "credential_expired"
  | "issuer_requested"
  | "other";

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
  source: "assertion_revocation" | "lifecycle_event" | "default_active";
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
  status: "transitioned" | "already_in_state" | "invalid_transition";
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
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
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
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
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
  | "issue_badge"
  | "revoke_badge"
  | "rebuild_verification_cache"
  | "import_migration_batch"
  | "import_learner_record_batch"
  | "generate_badge_template_image";

export type JobQueueMessageStatus = "pending" | "processing" | "completed" | "failed";

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

export type AuthMagicLinkRateLimitDimension = "ip" | "tenant" | "email" | "tenant_email";

export interface RecordAuthMagicLinkRateLimitAttemptInput {
  dimensionType: AuthMagicLinkRateLimitDimension;
  dimensionHash: string;
  occurredAt: string;
}

export interface CountAuthMagicLinkRateLimitAttemptsInput {
  dimensionType: AuthMagicLinkRateLimitDimension;
  dimensionHash: string;
  sinceIso: string;
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

export type MigrationBatchSource = "file_upload" | "credly_export" | "parchment_export" | "unknown";

export interface ImportMigrationBatchQueueMessageRecord extends JobQueueMessageRecord {
  source: MigrationBatchSource;
  batchId: string;
  rowNumber: number | null;
  fileName: string | null;
  format: string | null;
}

export interface ImportLearnerRecordBatchQueueMessageRecord extends JobQueueMessageRecord {
  batchId: string;
  rowNumber: number | null;
  fileName: string | null;
  format: string | null;
  defaultTrustLevel: LearnerRecordTrustLevel | null;
}

export interface ListImportMigrationBatchQueueMessagesInput {
  tenantId: string;
  source?: Exclude<MigrationBatchSource, "unknown"> | undefined;
  limit?: number | undefined;
}

export interface RetryFailedImportMigrationBatchQueueMessagesInput {
  tenantId: string;
  batchId: string;
  source?: Exclude<MigrationBatchSource, "unknown"> | undefined;
  rowNumbers?: readonly number[] | undefined;
  nowIso?: string | undefined;
}

export interface RetryFailedImportMigrationBatchQueueMessagesResult {
  matched: number;
  retried: number;
  skippedNotFailed: number;
}

export interface ListImportLearnerRecordBatchQueueMessagesInput {
  tenantId: string;
  limit?: number | undefined;
}

export interface RetryFailedImportLearnerRecordBatchQueueMessagesInput {
  tenantId: string;
  batchId: string;
  rowNumbers?: readonly number[] | undefined;
  nowIso?: string | undefined;
}

export interface RetryFailedImportLearnerRecordBatchQueueMessagesResult {
  matched: number;
  retried: number;
  skippedNotFailed: number;
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
  status: "revoked" | "already_revoked";
  revokedAt: string;
}

export interface ListLearnerBadgeSummariesInput {
  tenantId: string;
  userId: string;
}

export interface ListTenantAssertionsInput {
  tenantId: string;
  badgeTemplateId?: string | undefined;
  recipientQuery?: string | undefined;
  state?: AssertionLifecycleState | undefined;
  limit?: number | undefined;
}

export type AssertionReportingAttributionSource =
  | "issuance_snapshot"
  | "historical_backfill"
  | "current_owner_fallback";

export interface AssertionReportingAttributionRecord {
  assertionId: string;
  tenantId: string;
  badgeTemplateId: string;
  orgUnitId: string;
  attributionSource: AssertionReportingAttributionSource;
  attributedAt: string;
  createdAt: string;
  updatedAt: string;
}

export const ASSERTION_ENGAGEMENT_EVENT_TYPES = [
  "public_badge_view",
  "verification_view",
  "share_click",
  "learner_claim",
  "wallet_accept",
] as const;

export type AssertionEngagementEventType = (typeof ASSERTION_ENGAGEMENT_EVENT_TYPES)[number];

export type AssertionEngagementActorType = "anonymous" | "learner" | "wallet" | "system";

export interface AssertionEngagementEventRecord {
  id: string;
  tenantId: string;
  assertionId: string;
  eventType: AssertionEngagementEventType;
  actorType: AssertionEngagementActorType;
  channel: string | null;
  occurredAt: string;
  createdAt: string;
}

export interface RecordAssertionEngagementEventInput {
  tenantId: string;
  assertionId: string;
  eventType: AssertionEngagementEventType;
  actorType: AssertionEngagementActorType;
  channel?: string | undefined;
  occurredAt: string;
}

export interface RecordAssertionEngagementEventResult {
  status: "recorded" | "already_recorded";
  event: AssertionEngagementEventRecord;
}

export interface ListAssertionEngagementEventsInput {
  tenantId: string;
  assertionId: string;
  limit?: number | undefined;
}

export type TenantReportingLifecycleFilter = AssertionLifecycleState | "pending_review";

export interface TenantReportingOverviewFilters {
  issuedFrom?: string | undefined;
  issuedTo?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: TenantReportingLifecycleFilter | undefined;
}

export interface GetTenantReportingOverviewInput extends TenantReportingOverviewFilters {
  tenantId: string;
}

export interface TenantReportingOverviewCounts {
  issued: number;
  active: number;
  suspended: number;
  revoked: number;
  pendingReview: number;
  claimRate?: number | undefined;
  shareRate?: number | undefined;
}

export interface TenantReportingOverviewRecord {
  tenantId: string;
  filters: {
    issuedFrom: string | null;
    issuedTo: string | null;
    badgeTemplateId: string | null;
    orgUnitId: string | null;
    state: TenantReportingLifecycleFilter | null;
  };
  counts: TenantReportingOverviewCounts;
  generatedAt: string;
}

export interface TenantReportingEngagementFilters {
  from?: string | undefined;
  to?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: TenantReportingLifecycleFilter | undefined;
}

export interface TenantReportingHierarchyQuery {
  from?: string | undefined;
  to?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: TenantReportingLifecycleFilter | undefined;
  focusOrgUnitId?: string | undefined;
  level: OrgUnitType;
}

export interface TenantReportingHierarchySourceRow {
  assertionId: string;
  badgeTemplateId: string;
  orgUnitId: string;
  issuedAt: string;
  eventType: AssertionEngagementEventType | null;
  occurredAt: string | null;
}

export interface TenantReportingHierarchyOrgUnitRecord {
  id: string;
  unitType: OrgUnitType;
  displayName: string;
  parentOrgUnitId: string | null;
}

export interface TenantReportingHierarchyGroupRecord {
  level: OrgUnitType;
  orgUnitId: string;
  displayName: string;
  parentOrgUnitId: string | null;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
}

export interface TenantExecutiveRollupQuery {
  from?: string | undefined;
  to?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: TenantReportingLifecycleFilter | undefined;
  focusOrgUnitId: string;
  comparisonLevel: OrgUnitType;
}

export interface TenantExecutiveRollupRecord {
  focusOrgUnitId: string;
  focusDisplayName: string;
  focusParentOrgUnitId: string | null;
  focusUnitType: OrgUnitType;
  comparisonLevel: OrgUnitType;
  focusLineageOrgUnitIds: string[];
  filters: {
    from: string | null;
    to: string | null;
    badgeTemplateId: string | null;
    orgUnitId: string | null;
    state: TenantReportingLifecycleFilter | null;
  };
  rows: TenantReportingHierarchyGroupRecord[];
}

export interface GetTenantExecutiveRollupInput extends TenantReportingEngagementFilters {
  tenantId: string;
  focusOrgUnitId: string;
  comparisonLevel: OrgUnitType;
  scopedRootOrgUnitIds?: readonly string[] | undefined;
}

export interface GetTenantExecutiveRollupResult extends TenantExecutiveRollupRecord {
  tenantId: string;
  generatedAt: string;
}

export interface GetTenantReportingEngagementCountsInput extends TenantReportingEngagementFilters {
  tenantId: string;
}

export interface TenantReportingEngagementCounts {
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
}

export type TenantReportingTrendBucket = "day";

export interface GetTenantReportingTrendsInput extends TenantReportingEngagementFilters {
  tenantId: string;
  bucket: TenantReportingTrendBucket;
}

export interface TenantReportingTrendBucketRecord {
  bucketStart: string;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
}

export interface TenantReportingTrendRecord {
  tenantId: string;
  filters: {
    from: string | null;
    to: string | null;
    badgeTemplateId: string | null;
    orgUnitId: string | null;
    state: TenantReportingLifecycleFilter | null;
  };
  bucket: TenantReportingTrendBucket;
  series: TenantReportingTrendBucketRecord[];
  generatedAt: string;
}

export type TenantReportingComparisonGroupBy = "badgeTemplate" | "orgUnit";

export interface ListTenantReportingComparisonsInput extends TenantReportingEngagementFilters {
  tenantId: string;
  groupBy: TenantReportingComparisonGroupBy;
}

export interface TenantReportingComparisonRowRecord {
  groupBy: TenantReportingComparisonGroupBy;
  groupId: string;
  issuedCount: number;
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
  claimRate: number;
  shareRate: number;
}

export interface TenantAssertionSummaryRecord {
  assertionId: string;
  tenantId: string;
  publicId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  state: AssertionLifecycleState;
  source: ResolveAssertionLifecycleStateResult["source"];
  reasonCode: AssertionLifecycleReasonCode | null;
  reason: string | null;
  transitionedAt: string | null;
}

export const SYNCHRONOUS_EXPORT_ROW_LIMIT = 5000;

export interface ListTenantAssertionLedgerExportRowsInput {
  tenantId: string;
  issuedFrom?: string | undefined;
  issuedTo?: string | undefined;
  badgeTemplateId?: string | undefined;
  orgUnitId?: string | undefined;
  state?: AssertionLifecycleState | undefined;
  recipientQuery?: string | undefined;
}

export interface TenantAssertionLedgerExportRowRecord {
  assertionId: string;
  tenantId: string;
  publicId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  state: AssertionLifecycleState;
  source: ResolveAssertionLifecycleStateResult["source"];
  reasonCode: AssertionLifecycleReasonCode | null;
  reason: string | null;
  transitionedAt: string | null;
  orgUnitId: string;
  orgUnitDisplayName: string;
  attributionSource: AssertionReportingAttributionSource;
  currentInstitutionName: string | null;
  currentCollegeName: string | null;
  currentDepartmentName: string | null;
  currentProgramName: string | null;
}

export type TenantAssertionLedgerExportResult =
  | {
      status: "ok";
      rowLimit: number;
      rows: TenantAssertionLedgerExportRowRecord[];
    }
  | {
      status: "too_large";
      rowLimit: number;
    };

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

interface BadgeTemplateImageRevisionRow {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  previousImageUri: string | null;
  newImageUri: string | null;
  sourceType: BadgeTemplateImageRevisionSource;
  promptText: string | null;
  provider: string | null;
  model: string | null;
  metadataJson: string | null;
  createdByUserId: string | null;
  createdAt: string;
}

interface BadgeTemplateImageGenerationRow {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  status: BadgeTemplateImageGenerationStatus;
  promptText: string;
  stylePreset: string;
  promptNotes: string | null;
  accentColor: string | null;
  resultImageUri: string | null;
  errorMessage: string | null;
  requestedByUserId: string | null;
  queuedJobId: string | null;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
}

interface BadgeIssuanceRuleRow {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  badgeTemplateId: string;
  lmsProviderKind: BadgeIssuanceRuleLmsProviderKind;
  activeVersionId: string | null;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
}

interface BadgeIssuanceRuleValueListRow {
  id: string;
  tenantId: string;
  label: string;
  kind: "course_ids" | "badge_template_ids";
  valuesJson: string;
  createdByUserId: string | null;
  archivedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface BadgeIssuanceRuleVersionRow {
  id: string;
  tenantId: string;
  ruleId: string;
  versionNumber: number;
  status: BadgeIssuanceRuleVersionStatus;
  ruleJson: string;
  changeSummary: string | null;
  createdByUserId: string | null;
  approvedByUserId: string | null;
  approvedAt: string | null;
  activatedByUserId: string | null;
  activatedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface BadgeIssuanceRuleApprovalStepRow {
  id: string;
  tenantId: string;
  versionId: string;
  stepNumber: number;
  requiredRole: TenantMembershipRole;
  label: string | null;
  status: BadgeIssuanceRuleApprovalStepStatus;
  decidedByUserId: string | null;
  decidedAt: string | null;
  decisionComment: string | null;
  createdAt: string;
  updatedAt: string;
}

interface BadgeIssuanceRuleApprovalEventRow {
  id: string;
  tenantId: string;
  versionId: string;
  stepNumber: number | null;
  action: BadgeIssuanceRuleApprovalEventAction;
  actorUserId: string | null;
  actorRole: TenantMembershipRole | null;
  comment: string | null;
  occurredAt: string;
  createdAt: string;
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

interface BadgeIssuanceRuleVersionNumberRow {
  maxVersionNumber: number | string | null;
}

interface BadgeTemplateIdRow {
  badgeTemplateId: string;
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
  platformJwksEndpoint: string | null;
  tokenEndpoint: string | null;
  clientSecret: string | null;
  createdAt: string;
  updatedAt: string;
}

interface LtiDeploymentRow {
  id: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  name: string | null;
  description: string | null;
  createdAt: string;
  updatedAt: string;
}

interface LtiToolKeyRow {
  id: string;
  keyId: string;
  publicJwkJson: string;
  privateJwkJson: string;
  isActive: number | boolean;
  createdAt: string;
  updatedAt: string;
}

interface LtiLaunchSessionRow {
  id: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  tenantId: string | null;
  userId: string | null;
  dataJson: string;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
}

interface LtiDynamicRegistrationSessionRow {
  id: string;
  dataJson: string;
  expiresAt: string;
  createdAt: string;
}

interface LtiResourceLinkPlacementRow {
  id: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  deploymentId: string;
  contextId: string | null;
  resourceLinkId: string;
  badgeTemplateId: string;
  createdByUserId: string | null;
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

interface TenantMemberRow extends TenantMembershipRow {
  email: string;
}

interface TenantMembershipRoleCountRow {
  role: TenantMembershipRole;
  totalCount: number | string;
}

interface AccessibleTenantContextRow {
  tenantId: string;
  tenantSlug: string;
  tenantDisplayName: string;
  tenantPlanTier: TenantPlanTier;
  membershipRole: TenantMembershipRole;
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

interface TenantApiKeyRow {
  id: string;
  tenantId: string;
  label: string;
  keyPrefix: string;
  keyHash: string;
  scopesJson: string;
  createdByUserId: string | null;
  expiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface TenantAuthPolicyRow {
  tenantId: string;
  loginMode: TenantLoginMode;
  breakGlassEnabled: number | boolean;
  localMfaRequired: number | boolean;
  defaultProviderId: string | null;
  enforceForRoles: TenantAuthPolicyEnforceForRoles;
  createdAt: string;
  updatedAt: string;
}

interface TenantAuthProviderRow {
  id: string;
  tenantId: string;
  protocol: TenantAuthProviderProtocol;
  label: string;
  enabled: number | boolean;
  isDefault: number | boolean;
  configJson: string;
  createdAt: string;
  updatedAt: string;
}

interface TenantBreakGlassAccountRow {
  tenantId: string;
  userId: string;
  email: string;
  createdByUserId: string | null;
  lastUsedAt: string | null;
  lastEnrollmentEmailSentAt: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
  betterAuthUserId: string | null;
  localCredentialEnabled: number | boolean;
  twoFactorEnabled: number | boolean;
}

interface TenantSsoSamlConfigurationRow {
  tenantId: string;
  idpEntityId: string;
  ssoLoginUrl: string;
  idpCertificatePem: string;
  idpMetadataUrl: string | null;
  spEntityId: string;
  assertionConsumerServiceUrl: string;
  nameIdFormat: string | null;
  enforced: number | boolean;
  createdAt: string;
  updatedAt: string;
}

interface TenantCanvasGradebookIntegrationRow {
  tenantId: string;
  apiBaseUrl: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  accessToken: string | null;
  refreshToken: string | null;
  accessTokenExpiresAt: string | null;
  refreshTokenExpiresAt: string | null;
  connectedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface DedicatedDbProvisioningRequestRow {
  id: string;
  tenantId: string;
  requestedByUserId: string | null;
  targetRegion: string;
  status: DedicatedDbProvisioningRequestStatus;
  dedicatedDatabaseUrl: string | null;
  notes: string | null;
  requestedAt: string;
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;
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

interface Oid4vciPreAuthorizedCodeRow {
  id: string;
  codeHash: string;
  tenantId: string;
  assertionId: string;
  publicBadgeId: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

interface Oid4vciAccessTokenRow {
  id: string;
  accessTokenHash: string;
  tenantId: string;
  assertionId: string;
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
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_signing_registrations")
  );
};

const isMissingLtiIssuerRegistrationsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const missingTable =
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("lti_issuer_registrations");
  const missingNrpsColumns =
    error.message.includes("column") &&
    error.message.includes("does not exist") &&
    (error.message.includes("token_endpoint") ||
      error.message.includes("client_secret") ||
      error.message.includes("platform_jwks_endpoint"));

  return missingTable || missingNrpsColumns;
};

const isMissingLtiAdvantageTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    (error.message.includes("lti_deployments") ||
      error.message.includes("lti_tool_keys") ||
      error.message.includes("lti_launch_nonces") ||
      error.message.includes("lti_launch_sessions") ||
      error.message.includes("lti_dynamic_registration_sessions") ||
      error.message.includes("lti_resource_link_placements"))
  );
};

const isMissingRecipientIdentifiersTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("recipient_identifiers")
  );
};

const isMissingAuditLogsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("audit_logs")
  );
};

const isMissingTenantApiKeysTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_api_keys")
  );
};

const isMissingTenantAuthPoliciesTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_auth_policies")
  );
};

const isMissingTenantAuthProvidersTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_auth_providers")
  );
};

const isMissingTenantBreakGlassAccountsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_break_glass_accounts")
  );
};

const isMissingTenantSsoSamlConfigurationsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_sso_saml_configurations")
  );
};

const isMissingTenantCanvasGradebookIntegrationsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_canvas_gradebook_integrations")
  );
};

const isMissingBadgeIssuanceRulesTablesError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const tableMissing =
    error.message.includes("badge_issuance_rules") ||
    error.message.includes("badge_issuance_rule_value_lists") ||
    error.message.includes("badge_issuance_rule_versions") ||
    error.message.includes("badge_issuance_rule_evaluations") ||
    error.message.includes("badge_issuance_rule_approval_steps") ||
    error.message.includes("badge_issuance_rule_approval_events");

  if (!tableMissing) {
    return false;
  }

  return (
    error.message.includes("no such table") ||
    error.message.includes("relation") ||
    error.message.includes("does not exist")
  );
};

const isMissingBadgeIssuanceRuleEvaluationReviewColumnsError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const message = error.message.toLowerCase();
  const missingColumn =
    message.includes("does not exist") ||
    message.includes("no such column") ||
    message.includes("unknown column");

  if (!missingColumn) {
    return false;
  }

  return [
    "review_status",
    "review_decision",
    "review_comment",
    "reviewed_by_user_id",
    "reviewed_at",
  ].some((columnName) => message.includes(columnName));
};

const isMissingBadgeIssuanceRulesSchemaError = (error: unknown): boolean => {
  return (
    isMissingBadgeIssuanceRulesTablesError(error) ||
    isMissingBadgeIssuanceRuleEvaluationReviewColumnsError(error)
  );
};

const isMissingDedicatedDbProvisioningRequestsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_dedicated_db_provisioning_requests")
  );
};

const isMissingAssertionLifecycleEventsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("assertion_lifecycle_events")
  );
};

const isMissingAssertionReportingAttributionsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("assertion_reporting_attributions")
  );
};

const isMissingAssertionEngagementEventsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("assertion_engagement_events")
  );
};

const isMissingTenantOrgUnitsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_org_units")
  );
};

const isMissingTenantMembershipOrgUnitScopesTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("tenant_membership_org_unit_scopes")
  );
};

const isMissingDelegatedIssuingAuthorityTablesError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const tableMissing =
    error.message.includes("delegated_issuing_authority_grants") ||
    error.message.includes("delegated_issuing_authority_grant_badge_templates") ||
    error.message.includes("delegated_issuing_authority_grant_events");

  if (!tableMissing) {
    return false;
  }

  return (
    error.message.includes("no such table") ||
    error.message.includes("relation") ||
    error.message.includes("does not exist")
  );
};

const isMissingBadgeTemplateOwnershipEventsTableError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    (error.message.includes("no such table") ||
      error.message.includes("relation") ||
      error.message.includes("does not exist")) &&
    error.message.includes("badge_template_ownership_events")
  );
};

const isMissingBadgeTemplateImageTablesError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const tableMissing =
    error.message.includes("badge_template_image_revisions") ||
    error.message.includes("badge_template_image_generations");

  if (!tableMissing) {
    return false;
  }

  return (
    error.message.includes("no such table") ||
    error.message.includes("relation") ||
    error.message.includes("does not exist")
  );
};

const isMissingOAuthTablesError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const tableMissing =
    error.message.includes("oauth_clients") ||
    error.message.includes("oauth_authorization_codes") ||
    error.message.includes("oauth_access_tokens") ||
    error.message.includes("oauth_refresh_tokens") ||
    error.message.includes("oid4vci_pre_authorized_codes") ||
    error.message.includes("oid4vci_access_tokens");

  if (!tableMissing) {
    return false;
  }

  return (
    error.message.includes("no such table") ||
    error.message.includes("relation") ||
    error.message.includes("does not exist")
  );
};

const isMissingOb3ResourceTablesError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false;
  }

  const tableMissing =
    error.message.includes("ob3_subject_credentials") ||
    error.message.includes("ob3_subject_profiles");

  if (!tableMissing) {
    return false;
  }

  return (
    error.message.includes("no such table") ||
    error.message.includes("relation") ||
    error.message.includes("does not exist")
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
        platform_jwks_endpoint TEXT,
        token_endpoint TEXT,
        client_secret TEXT,
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

  await db
    .prepare(
      `
      ALTER TABLE lti_issuer_registrations
      ADD COLUMN IF NOT EXISTS token_endpoint TEXT
    `,
    )
    .run();

  await db
    .prepare(
      `
      ALTER TABLE lti_issuer_registrations
      ADD COLUMN IF NOT EXISTS client_secret TEXT
    `,
    )
    .run();

  await db
    .prepare(
      `
      ALTER TABLE lti_issuer_registrations
      ADD COLUMN IF NOT EXISTS platform_jwks_endpoint TEXT
    `,
    )
    .run();
};

const ensureLtiAdvantageTables = async (db: SqlDatabase): Promise<void> => {
  await ensureLtiIssuerRegistrationsTable(db);

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS lti_deployments (
        id TEXT PRIMARY KEY,
        issuer TEXT NOT NULL,
        client_id TEXT NOT NULL,
        deployment_id TEXT NOT NULL,
        name TEXT,
        description TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (issuer) REFERENCES lti_issuer_registrations (issuer) ON DELETE CASCADE,
        UNIQUE (issuer, client_id, deployment_id)
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_lti_deployments_issuer
        ON lti_deployments (issuer)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS lti_tool_keys (
        id TEXT PRIMARY KEY,
        key_id TEXT NOT NULL UNIQUE,
        public_jwk_json TEXT NOT NULL,
        private_jwk_json TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_lti_tool_keys_active
        ON lti_tool_keys (is_active, created_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS lti_launch_nonces (
        nonce TEXT PRIMARY KEY,
        expires_at TEXT NOT NULL,
        consumed_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_lti_launch_nonces_expires
        ON lti_launch_nonces (expires_at)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS lti_launch_sessions (
        id TEXT PRIMARY KEY,
        issuer TEXT NOT NULL,
        client_id TEXT NOT NULL,
        deployment_id TEXT NOT NULL,
        user_id TEXT,
        tenant_id TEXT,
        data_json TEXT NOT NULL,
        expires_at TEXT NOT NULL,
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
      CREATE INDEX IF NOT EXISTS idx_lti_launch_sessions_expires
        ON lti_launch_sessions (expires_at)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS lti_dynamic_registration_sessions (
        id TEXT PRIMARY KEY,
        data_json TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_lti_dynamic_registration_sessions_expires
        ON lti_dynamic_registration_sessions (expires_at)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS lti_resource_link_placements (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        issuer TEXT NOT NULL,
        client_id TEXT NOT NULL,
        deployment_id TEXT NOT NULL,
        context_id TEXT,
        resource_link_id TEXT NOT NULL,
        badge_template_id TEXT NOT NULL,
        created_by_user_id TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (badge_template_id) REFERENCES badge_templates (id) ON DELETE CASCADE,
        UNIQUE (issuer, client_id, deployment_id, resource_link_id)
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_lti_resource_link_placements_tenant
        ON lti_resource_link_placements (tenant_id)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_lti_resource_link_placements_lookup
        ON lti_resource_link_placements (issuer, client_id, deployment_id, resource_link_id)
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

const ensureTenantApiKeysTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_api_keys (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        label TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE,
        scopes_json TEXT NOT NULL,
        created_by_user_id TEXT,
        expires_at TEXT,
        last_used_at TEXT,
        revoked_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_tenant_api_keys_tenant_active
        ON tenant_api_keys (tenant_id, revoked_at, expires_at, created_at DESC)
    `,
    )
    .run();
};

const ensureTenantSsoSamlConfigurationsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_sso_saml_configurations (
        tenant_id TEXT PRIMARY KEY,
        idp_entity_id TEXT NOT NULL,
        sso_login_url TEXT NOT NULL,
        idp_certificate_pem TEXT NOT NULL,
        idp_metadata_url TEXT,
        sp_entity_id TEXT NOT NULL,
        assertion_consumer_service_url TEXT NOT NULL,
        name_id_format TEXT,
        enforced INTEGER NOT NULL DEFAULT 0 CHECK (enforced IN (0, 1)),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
      )
    `,
    )
    .run();
};

const ensureTenantAuthPoliciesTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_auth_policies (
        tenant_id TEXT PRIMARY KEY,
        login_mode TEXT NOT NULL DEFAULT 'local'
          CHECK (login_mode IN ('local', 'hybrid', 'sso_required')),
        break_glass_enabled INTEGER NOT NULL DEFAULT 0
          CHECK (break_glass_enabled IN (0, 1)),
        local_mfa_required INTEGER NOT NULL DEFAULT 0
          CHECK (local_mfa_required IN (0, 1)),
        default_provider_id TEXT,
        enforce_for_roles TEXT NOT NULL DEFAULT 'all_users'
          CHECK (enforce_for_roles IN ('all_users', 'admins_only')),
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
      CREATE INDEX IF NOT EXISTS idx_tenant_auth_policies_default_provider
        ON tenant_auth_policies (default_provider_id)
    `,
    )
    .run();
};

const ensureTenantAuthProvidersTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_auth_providers (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        protocol TEXT NOT NULL CHECK (protocol IN ('oidc', 'saml')),
        label TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
        config_json TEXT NOT NULL,
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
      CREATE INDEX IF NOT EXISTS idx_tenant_auth_providers_tenant
        ON tenant_auth_providers (tenant_id, created_at DESC, id DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_auth_providers_default_per_tenant
        ON tenant_auth_providers (tenant_id)
        WHERE is_default = 1
    `,
    )
    .run();
};

const ensureTenantBreakGlassAccountsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_break_glass_accounts (
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        created_by_user_id TEXT,
        last_used_at TEXT,
        last_enrollment_email_sent_at TEXT,
        revoked_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tenant_id, user_id),
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_tenant_break_glass_accounts_tenant_active
        ON tenant_break_glass_accounts (tenant_id, revoked_at, updated_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_tenant_break_glass_accounts_user
        ON tenant_break_glass_accounts (user_id, revoked_at)
    `,
    )
    .run();
};

const ensureTenantCanvasGradebookIntegrationsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_canvas_gradebook_integrations (
        tenant_id TEXT PRIMARY KEY,
        api_base_url TEXT NOT NULL,
        authorization_endpoint TEXT NOT NULL,
        token_endpoint TEXT NOT NULL,
        client_id TEXT NOT NULL,
        client_secret TEXT NOT NULL,
        scope TEXT NOT NULL,
        access_token TEXT,
        refresh_token TEXT,
        access_token_expires_at TEXT,
        refresh_token_expires_at TEXT,
        connected_at TEXT,
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
      CREATE INDEX IF NOT EXISTS idx_canvas_gradebook_connected_at
        ON tenant_canvas_gradebook_integrations (connected_at DESC)
    `,
    )
    .run();
};

const ensureBadgeIssuanceRulesTables = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS badge_issuance_rules (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        badge_template_id TEXT NOT NULL,
        lms_provider_kind TEXT NOT NULL,
        active_version_id TEXT,
        created_by_user_id TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (tenant_id, badge_template_id) REFERENCES badge_templates (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_issuance_rules_tenant
        ON badge_issuance_rules (tenant_id, created_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS badge_issuance_rule_value_lists (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        label TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('course_ids', 'badge_template_ids')),
        values_json TEXT NOT NULL,
        created_by_user_id TEXT,
        archived_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_rule_value_lists_tenant_kind
        ON badge_issuance_rule_value_lists (tenant_id, kind, archived_at, created_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS badge_issuance_rule_versions (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        version_number INTEGER NOT NULL CHECK (version_number > 0),
        status TEXT NOT NULL CHECK (status IN ('draft', 'pending_approval', 'approved', 'active', 'rejected', 'deprecated')),
        rule_json TEXT NOT NULL,
        change_summary TEXT,
        created_by_user_id TEXT,
        approved_by_user_id TEXT,
        approved_at TEXT,
        activated_by_user_id TEXT,
        activated_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (rule_id, version_number),
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (rule_id) REFERENCES badge_issuance_rules (id) ON DELETE CASCADE,
        FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
        FOREIGN KEY (approved_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
        FOREIGN KEY (activated_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_issuance_rule_versions_rule
        ON badge_issuance_rule_versions (rule_id, version_number DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_issuance_rule_versions_status
        ON badge_issuance_rule_versions (tenant_id, status, created_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS badge_issuance_rule_approval_steps (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        version_id TEXT NOT NULL,
        step_number INTEGER NOT NULL CHECK (step_number > 0),
        required_role TEXT NOT NULL CHECK (required_role IN ('owner', 'admin', 'issuer', 'viewer')),
        label TEXT,
        status TEXT NOT NULL CHECK (status IN ('queued', 'pending', 'approved', 'rejected')),
        decided_by_user_id TEXT,
        decided_at TEXT,
        decision_comment TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (version_id, step_number),
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (version_id) REFERENCES badge_issuance_rule_versions (id) ON DELETE CASCADE,
        FOREIGN KEY (decided_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_rule_approval_steps_version
        ON badge_issuance_rule_approval_steps (version_id, step_number ASC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS badge_issuance_rule_approval_events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        version_id TEXT NOT NULL,
        step_number INTEGER,
        action TEXT NOT NULL CHECK (action IN ('submitted', 'approved', 'rejected')),
        actor_user_id TEXT,
        actor_role TEXT CHECK (actor_role IN ('owner', 'admin', 'issuer', 'viewer')),
        comment TEXT,
        occurred_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (version_id) REFERENCES badge_issuance_rule_versions (id) ON DELETE CASCADE,
        FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_rule_approval_events_version
        ON badge_issuance_rule_approval_events (version_id, occurred_at ASC, created_at ASC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS badge_issuance_rule_evaluations (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        version_id TEXT NOT NULL,
        learner_id TEXT NOT NULL,
        recipient_identity TEXT NOT NULL,
        recipient_identity_type TEXT NOT NULL CHECK (recipient_identity_type IN ('email', 'email_sha256', 'did', 'url')),
        matched INTEGER NOT NULL CHECK (matched IN (0, 1)),
        issuance_status TEXT,
        assertion_id TEXT,
        evaluation_json TEXT NOT NULL,
        evaluated_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (rule_id) REFERENCES badge_issuance_rules (id) ON DELETE CASCADE,
        FOREIGN KEY (version_id) REFERENCES badge_issuance_rule_versions (id) ON DELETE CASCADE,
        FOREIGN KEY (assertion_id) REFERENCES assertions (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_issuance_rule_evaluations_rule
        ON badge_issuance_rule_evaluations (tenant_id, rule_id, learner_id, evaluated_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      ALTER TABLE badge_issuance_rule_evaluations
      ADD COLUMN IF NOT EXISTS review_status TEXT
        CHECK (review_status IS NULL OR review_status IN ('pending', 'resolved'))
    `,
    )
    .run();

  await db
    .prepare(
      `
      ALTER TABLE badge_issuance_rule_evaluations
      ADD COLUMN IF NOT EXISTS review_decision TEXT
        CHECK (review_decision IS NULL OR review_decision IN ('issue', 'dismiss'))
    `,
    )
    .run();

  await db
    .prepare(
      `
      ALTER TABLE badge_issuance_rule_evaluations
      ADD COLUMN IF NOT EXISTS review_comment TEXT
    `,
    )
    .run();

  await db
    .prepare(
      `
      ALTER TABLE badge_issuance_rule_evaluations
      ADD COLUMN IF NOT EXISTS reviewed_by_user_id TEXT
    `,
    )
    .run();

  await db
    .prepare(
      `
      ALTER TABLE badge_issuance_rule_evaluations
      ADD COLUMN IF NOT EXISTS reviewed_at TEXT
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_issuance_rule_evaluations_review_queue
        ON badge_issuance_rule_evaluations (tenant_id, review_status, evaluated_at DESC)
    `,
    )
    .run();
};

const ensureDedicatedDbProvisioningRequestsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS tenant_dedicated_db_provisioning_requests (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        requested_by_user_id TEXT,
        target_region TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'provisioned', 'failed', 'canceled')),
        dedicated_database_url TEXT,
        notes TEXT,
        requested_at TEXT NOT NULL,
        resolved_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (requested_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_dedicated_db_provisioning_tenant_status
        ON tenant_dedicated_db_provisioning_requests (tenant_id, status, requested_at DESC)
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

const ensureAssertionReportingAttributionsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS assertion_reporting_attributions (
        assertion_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        badge_template_id TEXT NOT NULL,
        org_unit_id TEXT NOT NULL,
        attribution_source TEXT NOT NULL CHECK (
          attribution_source IN ('issuance_snapshot', 'historical_backfill', 'current_owner_fallback')
        ),
        attributed_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (tenant_id, assertion_id),
        FOREIGN KEY (assertion_id) REFERENCES assertions (id) ON DELETE CASCADE,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
        FOREIGN KEY (tenant_id, badge_template_id) REFERENCES badge_templates (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (tenant_id, org_unit_id) REFERENCES tenant_org_units (tenant_id, id) ON DELETE RESTRICT
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_assertion_reporting_attributions_tenant_org
        ON assertion_reporting_attributions (tenant_id, org_unit_id, attributed_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_assertion_reporting_attributions_tenant_template
        ON assertion_reporting_attributions (tenant_id, badge_template_id, attributed_at DESC)
    `,
    )
    .run();
};

const ensureAssertionEngagementEventsTable = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS assertion_engagement_events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        assertion_id TEXT NOT NULL,
        event_type TEXT NOT NULL
          CHECK (event_type IN (
            'public_badge_view',
            'verification_view',
            'share_click',
            'learner_claim',
            'wallet_accept'
          )),
        actor_type TEXT NOT NULL
          CHECK (actor_type IN ('anonymous', 'learner', 'wallet', 'system')),
        channel TEXT,
        occurred_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (tenant_id, id),
        FOREIGN KEY (assertion_id) REFERENCES assertions (id) ON DELETE CASCADE,
        FOREIGN KEY (tenant_id, assertion_id) REFERENCES assertions (tenant_id, id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_assertion_engagement_events_tenant_occurred_at
        ON assertion_engagement_events (tenant_id, occurred_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_assertion_engagement_events_assertion_type
        ON assertion_engagement_events (tenant_id, assertion_id, event_type, occurred_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_assertion_engagement_events_type_occurred_at
        ON assertion_engagement_events (tenant_id, event_type, occurred_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE UNIQUE INDEX IF NOT EXISTS idx_assertion_engagement_events_one_shot
        ON assertion_engagement_events (tenant_id, assertion_id, event_type)
        WHERE event_type IN ('learner_claim', 'wallet_accept')
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
        UNIQUE (tenant_id, id),
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

const ensureBadgeTemplateImageTables = async (db: SqlDatabase): Promise<void> => {
  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS badge_template_image_revisions (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        badge_template_id TEXT NOT NULL,
        previous_image_uri TEXT,
        new_image_uri TEXT,
        source_type TEXT NOT NULL CHECK (
          source_type IN ('manual_update', 'upload', 'ai_generated', 'restore')
        ),
        prompt_text TEXT,
        provider TEXT,
        model TEXT,
        metadata_json TEXT,
        created_by_user_id TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id, badge_template_id)
          REFERENCES badge_templates (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_template_image_revisions_template
        ON badge_template_image_revisions (tenant_id, badge_template_id, created_at DESC)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS badge_template_image_generations (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        badge_template_id TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('queued', 'processing', 'succeeded', 'failed')),
        prompt_text TEXT NOT NULL,
        style_preset TEXT NOT NULL,
        prompt_notes TEXT,
        accent_color TEXT,
        result_image_uri TEXT,
        error_message TEXT,
        requested_by_user_id TEXT,
        queued_job_id TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        completed_at TEXT,
        FOREIGN KEY (tenant_id, badge_template_id)
          REFERENCES badge_templates (tenant_id, id) ON DELETE CASCADE,
        FOREIGN KEY (requested_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
        FOREIGN KEY (queued_job_id) REFERENCES job_queue_messages (id) ON DELETE SET NULL
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_badge_template_image_generations_template
        ON badge_template_image_generations (tenant_id, badge_template_id, created_at DESC)
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
      CREATE TABLE IF NOT EXISTS oid4vci_pre_authorized_codes (
        id TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL UNIQUE,
        tenant_id TEXT NOT NULL,
        assertion_id TEXT NOT NULL,
        public_badge_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
      )
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS oid4vci_access_tokens (
        id TEXT PRIMARY KEY,
        access_token_hash TEXT NOT NULL UNIQUE,
        tenant_id TEXT NOT NULL,
        assertion_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
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

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_oid4vci_pre_authorized_codes_lookup
        ON oid4vci_pre_authorized_codes (code_hash, expires_at)
    `,
    )
    .run();

  await db
    .prepare(
      `
      CREATE INDEX IF NOT EXISTS idx_oid4vci_access_tokens_lookup
        ON oid4vci_access_tokens (access_token_hash, expires_at)
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
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  vcR2Key: string;
  statusListIndex: number | null;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface AssertionReportingAttributionRow {
  assertionId: string;
  tenantId: string;
  badgeTemplateId: string;
  orgUnitId: string;
  attributionSource: AssertionReportingAttributionSource;
  attributedAt: string;
  createdAt: string;
  updatedAt: string;
}

interface AssertionEngagementEventRow {
  id: string;
  tenantId: string;
  assertionId: string;
  eventType: AssertionEngagementEventType;
  actorType: AssertionEngagementActorType;
  channel: string | null;
  occurredAt: string;
  createdAt: string;
}

interface TenantReportingOverviewRow {
  assertionId: string;
  issuedAt: string;
  badgeTemplateId: string;
  orgUnitId: string;
  revokedAt: string | null;
  latestToState: AssertionLifecycleState | null;
  latestReasonCode: AssertionLifecycleReasonCode | null;
}

interface TenantReportingEngagementRow {
  assertionId: string;
  badgeTemplateId: string;
  orgUnitId: string;
  issuedAt: string;
  revokedAt: string | null;
  latestToState: AssertionLifecycleState | null;
  latestReasonCode: AssertionLifecycleReasonCode | null;
  eventType: AssertionEngagementEventType | null;
  occurredAt: string | null;
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

interface LearnerRecordAssertionExportRow {
  assertionId: string;
  assertionPublicId: string | null;
  tenantId: string;
  learnerProfileId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDescription: string | null;
  badgeCriteriaUri: string | null;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  vcR2Key: string;
  statusListIndex: number | null;
  idempotencyKey: string;
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  issuerName: string;
  createdAt: string;
  updatedAt: string;
}

interface TenantAssertionSummaryRow {
  assertionId: string;
  tenantId: string;
  publicId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeImageUri: string | null;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  latestToState: AssertionLifecycleState | null;
  latestReasonCode: AssertionLifecycleReasonCode | null;
  latestReason: string | null;
  latestTransitionedAt: string | null;
}

interface TenantAssertionLedgerExportRow {
  assertionId: string;
  tenantId: string;
  publicId: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  issuedAt: string;
  issuedByUserId: string | null;
  revokedAt: string | null;
  latestToState: AssertionLifecycleState | null;
  latestReasonCode: AssertionLifecycleReasonCode | null;
  latestReason: string | null;
  latestTransitionedAt: string | null;
  orgUnitId: string;
  orgUnitDisplayName: string;
  attributionSource: AssertionReportingAttributionSource;
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
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
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

interface LearnerRecordEntryRow {
  id: string;
  tenantId: string;
  learnerProfileId: string;
  trustLevel: LearnerRecordTrustLevel;
  recordType: LearnerRecordEntryType;
  status: LearnerRecordStatus;
  title: string;
  description: string | null;
  issuerName: string;
  issuerUserId: string | null;
  sourceSystem: LearnerRecordSourceSystem;
  sourceRecordId: string | null;
  issuedAt: string;
  revisedAt: string | null;
  revokedAt: string | null;
  evidenceLinksJson: string;
  detailsJson: string | null;
  createdAt: string;
  updatedAt: string;
}

interface LearnerRecordImportContextRow {
  entryId: string;
  tenantId: string;
  orgUnitId: string | null;
  badgeTemplateId: string | null;
  pathwayLabel: string | null;
  inferredFromJson: string;
  createdAt: string;
  updatedAt: string;
}

interface LearnerIdentityLinkProofRow {
  id: string;
  tenantId: string;
  learnerProfileId: string;
  requestedByUserId: string;
  identityType: "email";
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
    throw new Error("Invalid ISO timestamp");
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
  college: "institution",
  department: "college",
  program: "department",
};

const BADGE_TEMPLATE_OWNERSHIP_REASON_CODES = new Set<BadgeTemplateOwnershipReasonCode>([
  "initial_assignment",
  "administrative_transfer",
  "reorganization",
  "governance_policy_update",
  "other",
]);

const DELEGATED_ISSUING_AUTHORITY_ACTIONS = new Set<DelegatedIssuingAuthorityAction>([
  "issue_badge",
  "revoke_badge",
  "manage_lifecycle",
]);

const normalizeDelegatedIssuingAuthorityActions = (
  actions: readonly DelegatedIssuingAuthorityAction[],
): DelegatedIssuingAuthorityAction[] => {
  const normalized = Array.from(new Set(actions));

  if (normalized.length === 0) {
    throw new Error("Delegated issuing authority grant must include at least one allowed action");
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
    throw new Error("delegated_issuing_authority_grants.allowed_actions_json must be valid JSON");
  }

  if (!Array.isArray(parsed)) {
    throw new Error("delegated_issuing_authority_grants.allowed_actions_json must be a JSON array");
  }

  const parsedArray = parsed as unknown[];
  const parsedActions: DelegatedIssuingAuthorityAction[] = [];

  for (const candidate of parsedArray) {
    if (
      typeof candidate !== "string" ||
      (candidate !== "issue_badge" &&
        candidate !== "revoke_badge" &&
        candidate !== "manage_lifecycle")
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

const normalizeRequiredLearnerRecordText = (value: string, fieldName: string): string => {
  const normalized = value.trim();

  if (normalized.length === 0) {
    throw new Error(`${fieldName} is required`);
  }

  return normalized;
};

const normalizeOptionalLearnerRecordText = (value: string | null | undefined): string | null => {
  if (value === undefined || value === null) {
    return null;
  }

  const normalized = value.trim();
  return normalized.length === 0 ? null : normalized;
};

const normalizeLearnerRecordEvidenceLinksJson = (evidenceLinks: readonly string[]): string => {
  return JSON.stringify(Array.from(new Set(evidenceLinks)));
};

const normalizeLearnerRecordDetailsJson = (
  detailsJson: string | null | undefined,
): string | null => {
  if (detailsJson === undefined || detailsJson === null) {
    return null;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(detailsJson) as unknown;
  } catch {
    throw new Error("detailsJson must be valid JSON");
  }

  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("detailsJson must encode a JSON object");
  }

  return JSON.stringify(parsed);
};

const normalizeLearnerRecordImportInferredFromJson = (
  inferredFrom: readonly LearnerRecordImportContextInferenceSource[],
): string => {
  const normalized = Array.from(new Set(inferredFrom));

  if (normalized.length === 0) {
    throw new Error("Learner-record import context must include at least one inference source");
  }

  for (const entry of normalized) {
    if (entry !== "row" && entry !== "badge_template" && entry !== "org_unit" && entry !== "none") {
      throw new Error("Unsupported learner-record import inference source");
    }
  }

  return JSON.stringify(normalized);
};

const assertValidIsoTimestamp = (timestamp: string, fieldName: string): number => {
  const parsedMs = Date.parse(timestamp);

  if (!Number.isFinite(parsedMs)) {
    throw new Error(`${fieldName} must be a valid ISO timestamp`);
  }

  return parsedMs;
};

const assertLearnerRecordEntrySemantics = (input: {
  trustLevel: LearnerRecordTrustLevel;
  recordType: LearnerRecordEntryType;
  status: LearnerRecordStatus;
  sourceSystem: LearnerRecordSourceSystem;
  revokedAt: string | null;
}): void => {
  if (input.trustLevel === "issuer_verified" && input.sourceSystem === "learner_self_reported") {
    throw new Error("issuer-verified learner-record entries cannot be learner_self_reported");
  }

  if (input.recordType === "supplemental_artifact" && input.trustLevel !== "learner_supplemental") {
    throw new Error(
      "supplemental_artifact learner-record entries must use learner_supplemental trust",
    );
  }

  if (input.status === "revoked" && input.revokedAt === null) {
    throw new Error("revoked learner-record entries must include revokedAt");
  }
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
    return "revoked";
  }

  const nowMs = assertValidIsoTimestamp(nowIso, "nowIso");
  const startsAtMs = assertValidIsoTimestamp(grant.startsAt, "startsAt");
  const endsAtMs = assertValidIsoTimestamp(grant.endsAt, "endsAt");

  if (nowMs < startsAtMs) {
    return "scheduled";
  }

  if (nowMs > endsAtMs) {
    return "expired";
  }

  return "active";
};

const ASSERTION_LIFECYCLE_REASON_CODES = new Set<AssertionLifecycleReasonCode>([
  "administrative_hold",
  "policy_violation",
  "appeal_pending",
  "appeal_resolved",
  "credential_expired",
  "issuer_requested",
  "other",
]);

const ASSERTION_LIFECYCLE_ALLOWED_TRANSITIONS: Record<
  AssertionLifecycleState,
  ReadonlySet<AssertionLifecycleState>
> = {
  active: new Set<AssertionLifecycleState>(["suspended", "revoked", "expired"]),
  suspended: new Set<AssertionLifecycleState>(["active", "revoked", "expired"]),
  expired: new Set<AssertionLifecycleState>(["active", "revoked"]),
  revoked: new Set<AssertionLifecycleState>(),
};

const BADGE_ISSUANCE_RULE_VERSION_STATUSES = new Set<BadgeIssuanceRuleVersionStatus>([
  "draft",
  "pending_approval",
  "approved",
  "active",
  "rejected",
  "deprecated",
]);

const BADGE_ISSUANCE_RULE_APPROVAL_STEP_STATUSES = new Set<BadgeIssuanceRuleApprovalStepStatus>([
  "queued",
  "pending",
  "approved",
  "rejected",
]);

const BADGE_ISSUANCE_RULE_APPROVAL_EVENT_ACTIONS = new Set<BadgeIssuanceRuleApprovalEventAction>([
  "submitted",
  "approved",
  "rejected",
]);

const TENANT_ROLE_RANK: Record<TenantMembershipRole, number> = {
  viewer: 0,
  issuer: 1,
  admin: 2,
  owner: 3,
};

const roleSatisfiesMinimumRole = (
  actorRole: TenantMembershipRole,
  requiredRole: TenantMembershipRole,
): boolean => {
  return TENANT_ROLE_RANK[actorRole] >= TENANT_ROLE_RANK[requiredRole];
};

const assertionLifecycleStateFromRecords = (input: {
  assertion: AssertionRecord;
  latestEvent: AssertionLifecycleEventRecord | null;
}): ResolveAssertionLifecycleStateResult => {
  if (input.assertion.revokedAt !== null && input.latestEvent?.toState === "revoked") {
    return {
      state: "revoked",
      source: "lifecycle_event",
      reasonCode: input.latestEvent.reasonCode,
      reason: input.latestEvent.reason ?? "credential has been revoked by issuer",
      transitionedAt: input.latestEvent.transitionedAt,
      revokedAt: input.assertion.revokedAt,
    };
  }

  if (input.assertion.revokedAt !== null) {
    return {
      state: "revoked",
      source: "assertion_revocation",
      reasonCode: null,
      reason: "credential has been revoked by issuer",
      transitionedAt: input.assertion.revokedAt,
      revokedAt: input.assertion.revokedAt,
    };
  }

  if (input.latestEvent !== null) {
    return {
      state: input.latestEvent.toState,
      source: "lifecycle_event",
      reasonCode: input.latestEvent.reasonCode,
      reason: input.latestEvent.reason,
      transitionedAt: input.latestEvent.transitionedAt,
      revokedAt: null,
    };
  }

  return {
    state: "active",
    source: "default_active",
    reasonCode: null,
    reason: null,
    transitionedAt: null,
    revokedAt: null,
  };
};

const tenantReportingCountsZero = (): TenantReportingOverviewCounts => {
  return {
    issued: 0,
    active: 0,
    suspended: 0,
    revoked: 0,
    pendingReview: 0,
  };
};

const tenantReportingLifecycleFromRow = (
  row: Pick<TenantReportingOverviewRow, "revokedAt" | "latestToState">,
): AssertionLifecycleState => {
  if (row.revokedAt !== null) {
    return "revoked";
  }

  return row.latestToState ?? "active";
};

export const resolveAssertionReportingAttribution = (input: {
  issuedAt: string;
  currentOwnerOrgUnitId: string;
  ownershipEvents: readonly Pick<
    BadgeTemplateOwnershipEventRecord,
    "toOrgUnitId" | "transferredAt"
  >[];
}): {
  orgUnitId: string;
  attributionSource: AssertionReportingAttributionSource;
  attributedAt: string;
} => {
  const issuedAtMs = Date.parse(input.issuedAt);

  if (!Number.isFinite(issuedAtMs)) {
    throw new Error("issuedAt must be a valid ISO timestamp");
  }

  const matchedEvent = [...input.ownershipEvents]
    .filter((event) => {
      const transferredAtMs = Date.parse(event.transferredAt);
      return Number.isFinite(transferredAtMs) && transferredAtMs <= issuedAtMs;
    })
    .sort((left, right) => right.transferredAt.localeCompare(left.transferredAt))[0];

  if (matchedEvent !== undefined) {
    return {
      orgUnitId: matchedEvent.toOrgUnitId,
      attributionSource: "historical_backfill",
      attributedAt: input.issuedAt,
    };
  }

  return {
    orgUnitId: input.currentOwnerOrgUnitId,
    attributionSource: "current_owner_fallback",
    attributedAt: input.issuedAt,
  };
};

export const summarizeTenantReportingOverviewRows = (
  rows: readonly TenantReportingOverviewRow[],
  stateFilter?: TenantReportingLifecycleFilter,
): TenantReportingOverviewCounts => {
  const filteredRows =
    stateFilter === undefined
      ? rows
      : rows.filter((row) => {
          const lifecycleState = tenantReportingLifecycleFromRow(row);

          if (stateFilter === "pending_review") {
            return lifecycleState === "suspended" && row.latestReasonCode === "appeal_pending";
          }

          return lifecycleState === stateFilter;
        });

  const counts = tenantReportingCountsZero();
  counts.issued = filteredRows.length;

  for (const row of filteredRows) {
    const lifecycleState = tenantReportingLifecycleFromRow(row);

    if (lifecycleState === "active") {
      counts.active += 1;
    } else if (lifecycleState === "suspended") {
      counts.suspended += 1;
    } else if (lifecycleState === "revoked") {
      counts.revoked += 1;
    }

    if (lifecycleState === "suspended" && row.latestReasonCode === "appeal_pending") {
      counts.pendingReview += 1;
    }
  }

  return counts;
};

interface TenantReportingEngagementCountTarget {
  publicBadgeViewCount: number;
  verificationViewCount: number;
  shareClickCount: number;
  learnerClaimCount: number;
  walletAcceptCount: number;
}

interface TenantReportingEngagementAggregate {
  issuedAssertionIds: Set<string>;
  shareEngagedAssertionIds: Set<string>;
  claimEngagedAssertionIds: Set<string>;
  counts: TenantReportingEngagementCountTarget;
}

const ONE_SHOT_ASSERTION_ENGAGEMENT_EVENT_TYPES = new Set<AssertionEngagementEventType>([
  "learner_claim",
  "wallet_accept",
]);

const tenantReportingEngagementCountsZero = (): TenantReportingEngagementCounts => {
  return {
    issuedCount: 0,
    publicBadgeViewCount: 0,
    verificationViewCount: 0,
    shareClickCount: 0,
    learnerClaimCount: 0,
    walletAcceptCount: 0,
    claimRate: 0,
    shareRate: 0,
  };
};

const tenantReportingTrendBucketZero = (bucketStart: string): TenantReportingTrendBucketRecord => {
  return {
    bucketStart,
    issuedCount: 0,
    publicBadgeViewCount: 0,
    verificationViewCount: 0,
    shareClickCount: 0,
    learnerClaimCount: 0,
    walletAcceptCount: 0,
  };
};

const tenantReportingComparisonRowZero = (
  groupBy: TenantReportingComparisonGroupBy,
  groupId: string,
): TenantReportingComparisonRowRecord => {
  return {
    groupBy,
    groupId,
    issuedCount: 0,
    publicBadgeViewCount: 0,
    verificationViewCount: 0,
    shareClickCount: 0,
    learnerClaimCount: 0,
    walletAcceptCount: 0,
    claimRate: 0,
    shareRate: 0,
  };
};

const ORG_UNIT_HIERARCHY_DEPTH: Record<OrgUnitType, number> = {
  institution: 0,
  college: 1,
  department: 2,
  program: 3,
};

const createTenantReportingEngagementAggregate = (): TenantReportingEngagementAggregate => {
  return {
    issuedAssertionIds: new Set<string>(),
    shareEngagedAssertionIds: new Set<string>(),
    claimEngagedAssertionIds: new Set<string>(),
    counts: {
      publicBadgeViewCount: 0,
      verificationViewCount: 0,
      shareClickCount: 0,
      learnerClaimCount: 0,
      walletAcceptCount: 0,
    },
  };
};

const incrementTenantReportingEngagementCount = (
  target: TenantReportingEngagementCountTarget,
  eventType: AssertionEngagementEventType,
): void => {
  if (eventType === "public_badge_view") {
    target.publicBadgeViewCount += 1;
  } else if (eventType === "verification_view") {
    target.verificationViewCount += 1;
  } else if (eventType === "share_click") {
    target.shareClickCount += 1;
  } else if (eventType === "learner_claim") {
    target.learnerClaimCount += 1;
  } else if (eventType === "wallet_accept") {
    target.walletAcceptCount += 1;
  }
};

const dateKeyFromTimestamp = (value: string): string => {
  const parsed = new Date(value);

  if (!Number.isFinite(parsed.getTime())) {
    throw new Error(`Invalid reporting timestamp: ${value}`);
  }

  return parsed.toISOString().slice(0, 10);
};

const normalizeReportingDateKey = (value: string, boundary: "start" | "end"): string => {
  return normalizeReportingDateBoundary(value, boundary).slice(0, 10);
};

const isTimestampWithinReportingRange = (
  timestamp: string,
  from: string | undefined,
  to: string | undefined,
): boolean => {
  const dateKey = dateKeyFromTimestamp(timestamp);

  if (from !== undefined && dateKey < from) {
    return false;
  }

  if (to !== undefined && dateKey > to) {
    return false;
  }

  return true;
};

const matchesTenantReportingEngagementFilters = (
  row: Pick<
    TenantReportingEngagementRow,
    "badgeTemplateId" | "orgUnitId" | "revokedAt" | "latestToState" | "latestReasonCode"
  >,
  input: Pick<TenantReportingEngagementFilters, "badgeTemplateId" | "orgUnitId" | "state">,
): boolean => {
  if (input.badgeTemplateId !== undefined && row.badgeTemplateId !== input.badgeTemplateId) {
    return false;
  }

  if (input.orgUnitId !== undefined && row.orgUnitId !== input.orgUnitId) {
    return false;
  }

  if (input.state !== undefined) {
    const lifecycleState = tenantReportingLifecycleFromRow(row);

    if (input.state === "pending_review") {
      return lifecycleState === "suspended" && row.latestReasonCode === "appeal_pending";
    }

    if (lifecycleState !== input.state) {
      return false;
    }
  }

  return true;
};

const buildReportingDateSeries = (from: string, to: string): string[] => {
  if (from > to) {
    throw new Error("Reporting trend range must start on or before the end date");
  }

  const bucketKeys: string[] = [];
  const current = new Date(`${from}T00:00:00.000Z`);
  const end = new Date(`${to}T00:00:00.000Z`);

  while (current.getTime() <= end.getTime()) {
    bucketKeys.push(current.toISOString().slice(0, 10));
    current.setUTCDate(current.getUTCDate() + 1);
  }

  return bucketKeys;
};

const resolveTenantReportingTrendRange = (
  rows: readonly TenantReportingEngagementRow[],
  input: Pick<TenantReportingEngagementFilters, "from" | "to">,
): { from: string; to: string } | null => {
  const explicitFrom = input.from?.trim();
  const explicitTo = input.to?.trim();
  const derivedKeys = rows.flatMap((row) => {
    const keys = [dateKeyFromTimestamp(row.issuedAt)];

    if (row.occurredAt !== null) {
      keys.push(dateKeyFromTimestamp(row.occurredAt));
    }

    return keys;
  });

  if (derivedKeys.length === 0 && explicitFrom === undefined && explicitTo === undefined) {
    return null;
  }

  const sortedKeys = [...derivedKeys].sort((left, right) => left.localeCompare(right));

  return {
    from:
      explicitFrom === undefined
        ? (sortedKeys[0] ?? normalizeReportingDateKey(explicitTo!, "start"))
        : normalizeReportingDateKey(explicitFrom, "start"),
    to:
      explicitTo === undefined
        ? (sortedKeys.at(-1) ?? normalizeReportingDateKey(explicitFrom!, "end"))
        : normalizeReportingDateKey(explicitTo, "end"),
  };
};

const applyTenantReportingEngagementEvent = (
  aggregate: TenantReportingEngagementAggregate,
  assertionId: string,
  eventType: AssertionEngagementEventType,
): void => {
  incrementTenantReportingEngagementCount(aggregate.counts, eventType);

  if (eventType === "share_click") {
    aggregate.shareEngagedAssertionIds.add(assertionId);
  }

  if (eventType === "learner_claim" || eventType === "wallet_accept") {
    aggregate.claimEngagedAssertionIds.add(assertionId);
  }
};

const finalizeTenantReportingEngagementCounts = (
  aggregate: TenantReportingEngagementAggregate,
): TenantReportingEngagementCounts => {
  const issuedCount = aggregate.issuedAssertionIds.size;
  const counts = tenantReportingEngagementCountsZero();

  counts.issuedCount = issuedCount;
  counts.publicBadgeViewCount = aggregate.counts.publicBadgeViewCount;
  counts.verificationViewCount = aggregate.counts.verificationViewCount;
  counts.shareClickCount = aggregate.counts.shareClickCount;
  counts.learnerClaimCount = aggregate.counts.learnerClaimCount;
  counts.walletAcceptCount = aggregate.counts.walletAcceptCount;
  counts.shareRate = issuedCount === 0 ? 0 : aggregate.shareEngagedAssertionIds.size / issuedCount;
  counts.claimRate = issuedCount === 0 ? 0 : aggregate.claimEngagedAssertionIds.size / issuedCount;

  return counts;
};

const summarizeTenantReportingEngagementCounts = (
  rows: readonly TenantReportingEngagementRow[],
  input: TenantReportingEngagementFilters,
): TenantReportingEngagementCounts => {
  const aggregate = createTenantReportingEngagementAggregate();

  for (const row of rows) {
    if (!matchesTenantReportingEngagementFilters(row, input)) {
      continue;
    }

    if (!isTimestampWithinReportingRange(row.issuedAt, input.from, input.to)) {
      continue;
    }

    aggregate.issuedAssertionIds.add(row.assertionId);

    if (
      row.eventType !== null &&
      row.occurredAt !== null &&
      isTimestampWithinReportingRange(row.occurredAt, input.from, input.to)
    ) {
      applyTenantReportingEngagementEvent(aggregate, row.assertionId, row.eventType);
    }
  }

  return finalizeTenantReportingEngagementCounts(aggregate);
};

export const summarizeTenantReportingTrendRows = (
  rows: readonly TenantReportingEngagementRow[],
  input: TenantReportingEngagementFilters & { bucket: TenantReportingTrendBucket },
): TenantReportingTrendBucketRecord[] => {
  if (input.bucket !== "day") {
    throw new Error("Unsupported reporting trend bucket");
  }

  const filteredRows = rows.filter((row) => matchesTenantReportingEngagementFilters(row, input));
  const range = resolveTenantReportingTrendRange(filteredRows, input);

  if (range === null) {
    return [];
  }

  const bucketMap = new Map<
    string,
    TenantReportingTrendBucketRecord & { issuedAssertionIds: Set<string> }
  >();

  for (const bucketStart of buildReportingDateSeries(range.from, range.to)) {
    bucketMap.set(bucketStart, {
      ...tenantReportingTrendBucketZero(bucketStart),
      issuedAssertionIds: new Set<string>(),
    });
  }

  for (const row of filteredRows) {
    if (isTimestampWithinReportingRange(row.issuedAt, range.from, range.to)) {
      const issueBucket = bucketMap.get(dateKeyFromTimestamp(row.issuedAt));
      issueBucket?.issuedAssertionIds.add(row.assertionId);
    }

    if (
      row.eventType !== null &&
      row.occurredAt !== null &&
      isTimestampWithinReportingRange(row.occurredAt, range.from, range.to)
    ) {
      const eventBucket = bucketMap.get(dateKeyFromTimestamp(row.occurredAt));

      if (eventBucket !== undefined) {
        incrementTenantReportingEngagementCount(eventBucket, row.eventType);
      }
    }
  }

  return Array.from(bucketMap.values()).map((bucket) => {
    return {
      bucketStart: bucket.bucketStart,
      issuedCount: bucket.issuedAssertionIds.size,
      publicBadgeViewCount: bucket.publicBadgeViewCount,
      verificationViewCount: bucket.verificationViewCount,
      shareClickCount: bucket.shareClickCount,
      learnerClaimCount: bucket.learnerClaimCount,
      walletAcceptCount: bucket.walletAcceptCount,
    };
  });
};

export const summarizeTenantReportingComparisonRows = (
  rows: readonly TenantReportingEngagementRow[],
  input: TenantReportingEngagementFilters & {
    groupBy: TenantReportingComparisonGroupBy;
  },
): TenantReportingComparisonRowRecord[] => {
  const groups = new Map<
    string,
    {
      row: TenantReportingComparisonRowRecord;
      aggregate: TenantReportingEngagementAggregate;
    }
  >();

  for (const row of rows) {
    if (!matchesTenantReportingEngagementFilters(row, input)) {
      continue;
    }

    if (!isTimestampWithinReportingRange(row.issuedAt, input.from, input.to)) {
      continue;
    }

    const groupId = input.groupBy === "badgeTemplate" ? row.badgeTemplateId : row.orgUnitId;
    const group =
      groups.get(groupId) ??
      (() => {
        const created = {
          row: tenantReportingComparisonRowZero(input.groupBy, groupId),
          aggregate: createTenantReportingEngagementAggregate(),
        };
        groups.set(groupId, created);
        return created;
      })();

    group.aggregate.issuedAssertionIds.add(row.assertionId);

    if (
      row.eventType !== null &&
      row.occurredAt !== null &&
      isTimestampWithinReportingRange(row.occurredAt, input.from, input.to)
    ) {
      applyTenantReportingEngagementEvent(group.aggregate, row.assertionId, row.eventType);
    }
  }

  return Array.from(groups.values())
    .map((group) => {
      const counts = finalizeTenantReportingEngagementCounts(group.aggregate);
      return {
        ...group.row,
        issuedCount: counts.issuedCount,
        publicBadgeViewCount: counts.publicBadgeViewCount,
        verificationViewCount: counts.verificationViewCount,
        shareClickCount: counts.shareClickCount,
        learnerClaimCount: counts.learnerClaimCount,
        walletAcceptCount: counts.walletAcceptCount,
        claimRate: counts.claimRate,
        shareRate: counts.shareRate,
      };
    })
    .sort((left, right) => {
      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.groupId.localeCompare(right.groupId);
    });
};

const getReportingHierarchyOrgUnitOrThrow = (
  orgUnitsById: ReadonlyMap<string, TenantReportingHierarchyOrgUnitRecord>,
  orgUnitId: string,
): TenantReportingHierarchyOrgUnitRecord => {
  const orgUnit = orgUnitsById.get(orgUnitId);

  if (orgUnit === undefined) {
    throw new Error(`Org unit ${orgUnitId} is missing from the reporting hierarchy`);
  }

  return orgUnit;
};

const listReportingHierarchyLineage = (
  orgUnitsById: ReadonlyMap<string, TenantReportingHierarchyOrgUnitRecord>,
  orgUnitId: string,
): TenantReportingHierarchyOrgUnitRecord[] => {
  const lineage: TenantReportingHierarchyOrgUnitRecord[] = [];
  const visited = new Set<string>();
  let currentOrgUnitId: string | null = orgUnitId;

  while (currentOrgUnitId !== null) {
    if (visited.has(currentOrgUnitId)) {
      throw new Error(`Detected an org-unit cycle while resolving hierarchy for ${orgUnitId}`);
    }

    visited.add(currentOrgUnitId);

    const orgUnit = getReportingHierarchyOrgUnitOrThrow(orgUnitsById, currentOrgUnitId);
    lineage.push(orgUnit);
    currentOrgUnitId = orgUnit.parentOrgUnitId;
  }

  return lineage;
};

const isReportingHierarchyLineageWithinRoot = (
  lineage: readonly TenantReportingHierarchyOrgUnitRecord[],
  rootOrgUnitId: string,
): boolean => {
  return lineage.some((orgUnit) => orgUnit.id === rootOrgUnitId);
};

export const summarizeTenantReportingHierarchyRows = (input: {
  rows: readonly TenantReportingHierarchySourceRow[];
  orgUnits: readonly TenantReportingHierarchyOrgUnitRecord[];
  query: TenantReportingHierarchyQuery;
  scopedRootOrgUnitIds?: readonly string[] | undefined;
}): TenantReportingHierarchyGroupRecord[] => {
  const orgUnitsById = new Map(
    input.orgUnits.map((orgUnit) => {
      return [orgUnit.id, orgUnit] as const;
    }),
  );
  const focusOrgUnit =
    input.query.focusOrgUnitId === undefined
      ? null
      : getReportingHierarchyOrgUnitOrThrow(orgUnitsById, input.query.focusOrgUnitId);

  if (
    focusOrgUnit !== null &&
    ORG_UNIT_HIERARCHY_DEPTH[focusOrgUnit.unitType] > ORG_UNIT_HIERARCHY_DEPTH[input.query.level]
  ) {
    throw new Error("focusOrgUnitId must be at or above the requested hierarchy level");
  }

  const scopedRootOrgUnitIds = Array.from(new Set(input.scopedRootOrgUnitIds ?? []));
  for (const scopedRootOrgUnitId of scopedRootOrgUnitIds) {
    getReportingHierarchyOrgUnitOrThrow(orgUnitsById, scopedRootOrgUnitId);
  }

  const groups = new Map<
    string,
    {
      orgUnit: TenantReportingHierarchyOrgUnitRecord;
      aggregate: TenantReportingEngagementAggregate;
    }
  >();

  for (const row of input.rows) {
    if (
      input.query.badgeTemplateId !== undefined &&
      row.badgeTemplateId !== input.query.badgeTemplateId
    ) {
      continue;
    }

    if (input.query.orgUnitId !== undefined && row.orgUnitId !== input.query.orgUnitId) {
      continue;
    }

    if (!isTimestampWithinReportingRange(row.issuedAt, input.query.from, input.query.to)) {
      continue;
    }

    const lineage = listReportingHierarchyLineage(orgUnitsById, row.orgUnitId);

    if (focusOrgUnit !== null && !isReportingHierarchyLineageWithinRoot(lineage, focusOrgUnit.id)) {
      continue;
    }

    if (
      scopedRootOrgUnitIds.length > 0 &&
      !scopedRootOrgUnitIds.some((scopedRootOrgUnitId) => {
        return isReportingHierarchyLineageWithinRoot(lineage, scopedRootOrgUnitId);
      })
    ) {
      continue;
    }

    const targetOrgUnit = lineage.find((orgUnit) => orgUnit.unitType === input.query.level);

    if (targetOrgUnit === undefined) {
      continue;
    }

    const group =
      groups.get(targetOrgUnit.id) ??
      (() => {
        const created = {
          orgUnit: targetOrgUnit,
          aggregate: createTenantReportingEngagementAggregate(),
        };
        groups.set(targetOrgUnit.id, created);
        return created;
      })();

    group.aggregate.issuedAssertionIds.add(row.assertionId);

    if (
      row.eventType !== null &&
      row.occurredAt !== null &&
      isTimestampWithinReportingRange(row.occurredAt, input.query.from, input.query.to)
    ) {
      applyTenantReportingEngagementEvent(group.aggregate, row.assertionId, row.eventType);
    }
  }

  return Array.from(groups.values())
    .map((group) => {
      const counts = finalizeTenantReportingEngagementCounts(group.aggregate);
      return {
        level: input.query.level,
        orgUnitId: group.orgUnit.id,
        displayName: group.orgUnit.displayName,
        parentOrgUnitId: group.orgUnit.parentOrgUnitId,
        issuedCount: counts.issuedCount,
        publicBadgeViewCount: counts.publicBadgeViewCount,
        verificationViewCount: counts.verificationViewCount,
        shareClickCount: counts.shareClickCount,
        learnerClaimCount: counts.learnerClaimCount,
        walletAcceptCount: counts.walletAcceptCount,
        claimRate: counts.claimRate,
        shareRate: counts.shareRate,
      };
    })
    .sort((left, right) => {
      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.orgUnitId.localeCompare(right.orgUnitId);
    });
};

export const summarizeTenantExecutiveRollup = (input: {
  rows: readonly TenantReportingHierarchySourceRow[];
  orgUnits: readonly TenantReportingHierarchyOrgUnitRecord[];
  query: TenantExecutiveRollupQuery;
  scopedRootOrgUnitIds?: readonly string[] | undefined;
}): TenantExecutiveRollupRecord => {
  const orgUnitsById = new Map(
    input.orgUnits.map((orgUnit) => {
      return [orgUnit.id, orgUnit] as const;
    }),
  );
  const focusOrgUnit = getReportingHierarchyOrgUnitOrThrow(
    orgUnitsById,
    input.query.focusOrgUnitId,
  );
  const focusLineageOrgUnitIds = listReportingHierarchyLineage(
    orgUnitsById,
    input.query.focusOrgUnitId,
  )
    .map((orgUnit) => orgUnit.id)
    .reverse();

  return {
    focusOrgUnitId: focusOrgUnit.id,
    focusDisplayName: focusOrgUnit.displayName,
    focusParentOrgUnitId: focusOrgUnit.parentOrgUnitId,
    focusUnitType: focusOrgUnit.unitType,
    comparisonLevel: input.query.comparisonLevel,
    focusLineageOrgUnitIds,
    filters: {
      from: input.query.from ?? null,
      to: input.query.to ?? null,
      badgeTemplateId: input.query.badgeTemplateId ?? null,
      orgUnitId: input.query.orgUnitId ?? null,
      state: input.query.state ?? null,
    },
    rows: summarizeTenantReportingHierarchyRows({
      rows: input.rows,
      orgUnits: input.orgUnits,
      query: {
        from: input.query.from,
        to: input.query.to,
        badgeTemplateId: input.query.badgeTemplateId,
        orgUnitId: input.query.orgUnitId,
        state: input.query.state,
        focusOrgUnitId: input.query.focusOrgUnitId,
        level: input.query.comparisonLevel,
      },
      scopedRootOrgUnitIds: input.scopedRootOrgUnitIds,
    }),
  };
};

export const normalizeEmail = (email: string): string => {
  return email.trim().toLowerCase();
};

export const upsertUserByEmail = async (db: SqlDatabase, email: string): Promise<UserRecord> => {
  const normalizedEmail = normalizeEmail(email);
  const createdUserId = createPrefixedId("usr");

  await db
    .prepare(
      `
      INSERT INTO users (id, email)
      VALUES (?, ?)
      ON CONFLICT DO NOTHING
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

export const findUserByEmail = async (
  db: SqlDatabase,
  email: string,
): Promise<UserRecord | null> => {
  const normalizedEmail = normalizeEmail(email);
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

export const createAuthIdentityLink = async (
  db: SqlDatabase,
  input: CreateAuthIdentityLinkInput,
): Promise<AuthIdentityLinkRecord> => {
  const id = createPrefixedId("ail");
  const createdAt = new Date().toISOString();
  const emailSnapshot =
    input.emailSnapshot === undefined || input.emailSnapshot === null
      ? null
      : normalizeEmail(input.emailSnapshot);

  await db
    .prepare(
      `
      INSERT INTO auth_identity_links (
        id,
        auth_system,
        auth_user_id,
        auth_account_id,
        credtrail_user_id,
        email_snapshot,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      input.authSystem,
      input.authUserId,
      input.authAccountId ?? null,
      input.credtrailUserId,
      emailSnapshot,
      createdAt,
      createdAt,
    )
    .run();

  return {
    id,
    authSystem: input.authSystem,
    authUserId: input.authUserId,
    authAccountId: input.authAccountId ?? null,
    credtrailUserId: input.credtrailUserId,
    emailSnapshot,
    createdAt,
    updatedAt: createdAt,
  };
};

export const findAuthIdentityLinkByAuthUserId = async (
  db: SqlDatabase,
  authSystem: string,
  authUserId: string,
): Promise<AuthIdentityLinkRecord | null> => {
  const link = await db
    .prepare(
      `
      SELECT
        id,
        auth_system AS authSystem,
        auth_user_id AS authUserId,
        auth_account_id AS authAccountId,
        credtrail_user_id AS credtrailUserId,
        email_snapshot AS emailSnapshot,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM auth_identity_links
      WHERE auth_system = ?
        AND auth_user_id = ?
      LIMIT 1
    `,
    )
    .bind(authSystem, authUserId)
    .first<AuthIdentityLinkRecord>();

  return link;
};

export const findAuthIdentityLinkByCredtrailUserId = async (
  db: SqlDatabase,
  authSystem: string,
  credtrailUserId: string,
): Promise<AuthIdentityLinkRecord | null> => {
  const link = await db
    .prepare(
      `
      SELECT
        id,
        auth_system AS authSystem,
        auth_user_id AS authUserId,
        auth_account_id AS authAccountId,
        credtrail_user_id AS credtrailUserId,
        email_snapshot AS emailSnapshot,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM auth_identity_links
      WHERE auth_system = ?
        AND credtrail_user_id = ?
      LIMIT 1
    `,
    )
    .bind(authSystem, credtrailUserId)
    .first<AuthIdentityLinkRecord>();

  return link;
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
        await addLearnerIdentityAlias(db, {
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
    await addLearnerIdentityAlias(db, {
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

const findLearnerRecordEntryById = async (
  db: SqlDatabase,
  tenantId: string,
  entryId: string,
): Promise<LearnerRecordEntryRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        learner_profile_id AS learnerProfileId,
        trust_level AS trustLevel,
        record_type AS recordType,
        status,
        title,
        description,
        issuer_name AS issuerName,
        issuer_user_id AS issuerUserId,
        source_system AS sourceSystem,
        source_record_id AS sourceRecordId,
        issued_at AS issuedAt,
        revised_at AS revisedAt,
        revoked_at AS revokedAt,
        evidence_links_json AS evidenceLinksJson,
        details_json AS detailsJson,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM learner_record_entries
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, entryId)
    .first<LearnerRecordEntryRow>();

  return row === null ? null : mapLearnerRecordEntryRow(row);
};

export const createLearnerRecordEntry = async (
  db: SqlDatabase,
  input: CreateLearnerRecordEntryInput,
): Promise<LearnerRecordEntryRecord> => {
  const id = createPrefixedId("lre");
  const nowIso = new Date().toISOString();
  const status = input.status ?? "active";
  const title = normalizeRequiredLearnerRecordText(input.title, "title");
  const description = normalizeOptionalLearnerRecordText(input.description);
  const issuerName = normalizeRequiredLearnerRecordText(input.issuerName, "issuerName");
  const sourceRecordId = normalizeOptionalLearnerRecordText(input.sourceRecordId);
  const revisedAt = input.revisedAt ?? null;
  const revokedAt = input.revokedAt ?? null;
  const evidenceLinksJson = normalizeLearnerRecordEvidenceLinksJson(input.evidenceLinks);
  const detailsJson = normalizeLearnerRecordDetailsJson(input.detailsJson);

  assertValidIsoTimestamp(input.issuedAt, "issuedAt");

  if (revisedAt !== null) {
    assertValidIsoTimestamp(revisedAt, "revisedAt");
  }

  if (revokedAt !== null) {
    assertValidIsoTimestamp(revokedAt, "revokedAt");
  }

  assertLearnerRecordEntrySemantics({
    trustLevel: input.trustLevel,
    recordType: input.recordType,
    status,
    sourceSystem: input.sourceSystem,
    revokedAt,
  });

  await db
    .prepare(
      `
      INSERT INTO learner_record_entries (
        id,
        tenant_id,
        learner_profile_id,
        trust_level,
        record_type,
        status,
        title,
        description,
        issuer_name,
        issuer_user_id,
        source_system,
        source_record_id,
        issued_at,
        revised_at,
        revoked_at,
        evidence_links_json,
        details_json,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.learnerProfileId,
      input.trustLevel,
      input.recordType,
      status,
      title,
      description,
      issuerName,
      input.issuerUserId ?? null,
      input.sourceSystem,
      sourceRecordId,
      input.issuedAt,
      revisedAt,
      revokedAt,
      evidenceLinksJson,
      detailsJson,
      nowIso,
      nowIso,
    )
    .run();

  const entry = await findLearnerRecordEntryById(db, input.tenantId, id);

  if (entry === null) {
    throw new Error(`Failed to create learner-record entry "${id}"`);
  }

  return entry;
};

export const listLearnerRecordEntries = async (
  db: SqlDatabase,
  input: ListLearnerRecordEntriesInput,
): Promise<LearnerRecordEntryRecord[]> => {
  const params: unknown[] = [input.tenantId, input.learnerProfileId];
  const conditions = ["tenant_id = ?", "learner_profile_id = ?"];

  if (input.trustLevel !== undefined) {
    conditions.push("trust_level = ?");
    params.push(input.trustLevel);
  }

  if (input.status !== undefined) {
    conditions.push("status = ?");
    params.push(input.status);
  }

  const result = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        learner_profile_id AS learnerProfileId,
        trust_level AS trustLevel,
        record_type AS recordType,
        status,
        title,
        description,
        issuer_name AS issuerName,
        issuer_user_id AS issuerUserId,
        source_system AS sourceSystem,
        source_record_id AS sourceRecordId,
        issued_at AS issuedAt,
        revised_at AS revisedAt,
        revoked_at AS revokedAt,
        evidence_links_json AS evidenceLinksJson,
        details_json AS detailsJson,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM learner_record_entries
      WHERE ${conditions.join(" AND ")}
      ORDER BY issued_at DESC, created_at DESC
    `,
    )
    .bind(...params)
    .all<LearnerRecordEntryRow>();

  return result.results.map((row) => mapLearnerRecordEntryRow(row));
};

export const patchLearnerRecordEntry = async (
  db: SqlDatabase,
  input: PatchLearnerRecordEntryInput,
): Promise<LearnerRecordEntryRecord | null> => {
  const existing = await findLearnerRecordEntryById(db, input.tenantId, input.entryId);

  if (existing === null) {
    return null;
  }

  const nowIso = new Date().toISOString();
  const trustLevel = input.trustLevel ?? existing.trustLevel;
  const recordType = input.recordType ?? existing.recordType;
  const status = input.status ?? existing.status;
  const title =
    input.title === undefined
      ? existing.title
      : normalizeRequiredLearnerRecordText(input.title, "title");
  const description =
    input.description === undefined
      ? existing.description
      : normalizeOptionalLearnerRecordText(input.description);
  const issuerName =
    input.issuerName === undefined
      ? existing.issuerName
      : normalizeRequiredLearnerRecordText(input.issuerName, "issuerName");
  const issuerUserId =
    input.issuerUserId === undefined ? existing.issuerUserId : (input.issuerUserId ?? null);
  const sourceSystem =
    input.sourceSystem === undefined ? existing.sourceSystem : input.sourceSystem;
  const sourceRecordId =
    input.sourceRecordId === undefined
      ? existing.sourceRecordId
      : normalizeOptionalLearnerRecordText(input.sourceRecordId);
  const issuedAt = input.issuedAt === undefined ? existing.issuedAt : input.issuedAt;
  const revisedAt = input.revisedAt === undefined ? existing.revisedAt : input.revisedAt;
  const revokedAt = input.revokedAt === undefined ? existing.revokedAt : input.revokedAt;
  const evidenceLinksJson =
    input.evidenceLinks === undefined
      ? existing.evidenceLinksJson
      : normalizeLearnerRecordEvidenceLinksJson(input.evidenceLinks);
  const detailsJson =
    input.detailsJson === undefined
      ? existing.detailsJson
      : normalizeLearnerRecordDetailsJson(input.detailsJson);

  assertValidIsoTimestamp(issuedAt, "issuedAt");

  if (revisedAt !== null) {
    assertValidIsoTimestamp(revisedAt, "revisedAt");
  }

  if (revokedAt !== null) {
    assertValidIsoTimestamp(revokedAt, "revokedAt");
  }

  assertLearnerRecordEntrySemantics({
    trustLevel,
    recordType,
    status,
    sourceSystem,
    revokedAt,
  });

  await db
    .prepare(
      `
      UPDATE learner_record_entries
      SET
        trust_level = ?,
        record_type = ?,
        status = ?,
        title = ?,
        description = ?,
        issuer_name = ?,
        issuer_user_id = ?,
        source_system = ?,
        source_record_id = ?,
        issued_at = ?,
        revised_at = ?,
        revoked_at = ?,
        evidence_links_json = ?,
        details_json = ?,
        updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(
      trustLevel,
      recordType,
      status,
      title,
      description,
      issuerName,
      issuerUserId,
      sourceSystem,
      sourceRecordId,
      issuedAt,
      revisedAt,
      revokedAt,
      evidenceLinksJson,
      detailsJson,
      nowIso,
      input.tenantId,
      input.entryId,
    )
    .run();

  return findLearnerRecordEntryById(db, input.tenantId, input.entryId);
};

export const findLearnerRecordImportContextByEntryId = async (
  db: SqlDatabase,
  tenantId: string,
  entryId: string,
): Promise<LearnerRecordImportContextRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        entry_id AS entryId,
        tenant_id AS tenantId,
        org_unit_id AS orgUnitId,
        badge_template_id AS badgeTemplateId,
        pathway_label AS pathwayLabel,
        inferred_from_json AS inferredFromJson,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM learner_record_import_context
      WHERE tenant_id = ?
        AND entry_id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, entryId)
    .first<LearnerRecordImportContextRow>();

  return row === null ? null : mapLearnerRecordImportContextRow(row);
};

export const createLearnerRecordImportContext = async (
  db: SqlDatabase,
  input: CreateLearnerRecordImportContextInput,
): Promise<LearnerRecordImportContextRecord> => {
  const nowIso = new Date().toISOString();
  const orgUnitId = input.orgUnitId ?? null;
  const badgeTemplateId = input.badgeTemplateId ?? null;
  const pathwayLabel = normalizeOptionalLearnerRecordText(input.pathwayLabel);
  const inferredFromJson = normalizeLearnerRecordImportInferredFromJson(input.inferredFrom);

  await db
    .prepare(
      `
      INSERT INTO learner_record_import_context (
        entry_id,
        tenant_id,
        org_unit_id,
        badge_template_id,
        pathway_label,
        inferred_from_json,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(entry_id) DO UPDATE SET
        tenant_id = excluded.tenant_id,
        org_unit_id = excluded.org_unit_id,
        badge_template_id = excluded.badge_template_id,
        pathway_label = excluded.pathway_label,
        inferred_from_json = excluded.inferred_from_json,
        updated_at = excluded.updated_at
    `,
    )
    .bind(
      input.entryId,
      input.tenantId,
      orgUnitId,
      badgeTemplateId,
      pathwayLabel,
      inferredFromJson,
      nowIso,
      nowIso,
    )
    .run();

  const context = await findLearnerRecordImportContextByEntryId(db, input.tenantId, input.entryId);

  if (context === null) {
    throw new Error(`Failed to create learner-record import context for entry "${input.entryId}"`);
  }

  return context;
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
    role: "viewer",
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

export const listTenantMembers = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantMemberRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        memberships.tenant_id AS tenantId,
        memberships.user_id AS userId,
        users.email AS email,
        memberships.role AS role,
        memberships.created_at AS createdAt,
        memberships.updated_at AS updatedAt
      FROM memberships
      INNER JOIN users
        ON users.id = memberships.user_id
      WHERE memberships.tenant_id = ?
      ORDER BY
        CASE memberships.role
          WHEN 'owner' THEN 0
          WHEN 'admin' THEN 1
          WHEN 'issuer' THEN 2
          ELSE 3
        END,
        lower(users.email),
        memberships.user_id
    `,
    )
    .bind(tenantId)
    .all<TenantMemberRow>();

  return result.results.map(mapTenantMemberRow);
};

export const countTenantMembershipsByRole = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantMembershipRoleCounts> => {
  const result = await db
    .prepare(
      `
      SELECT
        role,
        COUNT(*) AS totalCount
      FROM memberships
      WHERE tenant_id = ?
      GROUP BY role
    `,
    )
    .bind(tenantId)
    .all<TenantMembershipRoleCountRow>();

  const counts: TenantMembershipRoleCounts = {
    owner: 0,
    admin: 0,
    issuer: 0,
    viewer: 0,
  };

  for (const row of result.results) {
    const totalCount = Number.parseInt(String(row.totalCount), 10);
    counts[row.role] = Number.isFinite(totalCount) ? totalCount : 0;
  }

  return counts;
};

export const removeTenantMembership = async (
  db: SqlDatabase,
  tenantId: string,
  userId: string,
): Promise<boolean> => {
  const result = await db
    .prepare(
      `
      DELETE FROM memberships
      WHERE tenant_id = ?
        AND user_id = ?
    `,
    )
    .bind(tenantId, userId)
    .run();

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const listAccessibleTenantContextsForUser = async (
  db: SqlDatabase,
  userId: string,
): Promise<AccessibleTenantContextRecord[]> => {
  const result = await db
    .prepare(
      `
      SELECT
        memberships.tenant_id AS tenantId,
        tenants.slug AS tenantSlug,
        tenants.display_name AS tenantDisplayName,
        tenants.plan_tier AS tenantPlanTier,
        memberships.role AS membershipRole
      FROM memberships
      INNER JOIN tenants
        ON tenants.id = memberships.tenant_id
      WHERE memberships.user_id = ?
        AND tenants.is_active = 1
      ORDER BY lower(tenants.display_name), tenants.slug, memberships.tenant_id
    `,
    )
    .bind(userId)
    .all<AccessibleTenantContextRow>();

  return result.results.map(mapAccessibleTenantContextRow);
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
  const id = createPrefixedId("aud");
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

export const listAuditLogs = async (
  db: SqlDatabase,
  input: ListAuditLogsInput,
): Promise<AuditLogRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 100, 200));
  const whereClauses = ["tenant_id = ?"];
  const queryParams: unknown[] = [input.tenantId];

  if (input.action !== undefined) {
    whereClauses.push("action = ?");
    queryParams.push(input.action);
  }

  const listStatement = (): Promise<SqlQueryResult<AuditLogRow>> =>
    db
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
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY occurred_at DESC, created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(...queryParams, queryLimit)
      .all<AuditLogRow>();

  let result: SqlQueryResult<AuditLogRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingAuditLogsTableError(error)) {
      throw error;
    }

    await ensureAuditLogsTable(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapAuditLogRow(row));
};

export const createTenantApiKey = async (
  db: SqlDatabase,
  input: CreateTenantApiKeyInput,
): Promise<TenantApiKeyRecord> => {
  const id = createPrefixedId("tak");
  const nowIso = new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_api_keys (
          id,
          tenant_id,
          label,
          key_prefix,
          key_hash,
          scopes_json,
          created_by_user_id,
          expires_at,
          last_used_at,
          revoked_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.label,
        input.keyPrefix,
        input.keyHash,
        input.scopesJson,
        input.createdByUserId ?? null,
        input.expiresAt ?? null,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantApiKeysTableError(error)) {
      throw error;
    }

    await ensureTenantApiKeysTable(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        label,
        key_prefix AS keyPrefix,
        key_hash AS keyHash,
        scopes_json AS scopesJson,
        created_by_user_id AS createdByUserId,
        expires_at AS expiresAt,
        last_used_at AS lastUsedAt,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_api_keys
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(id)
    .first<TenantApiKeyRow>();

  if (row === null) {
    throw new Error(`Unable to create tenant API key "${id}"`);
  }

  return mapTenantApiKeyRow(row);
};

export const listTenantApiKeys = async (
  db: SqlDatabase,
  input: ListTenantApiKeysInput,
): Promise<TenantApiKeyRecord[]> => {
  const query = input.includeRevoked
    ? `
      SELECT
        id,
        tenant_id AS tenantId,
        label,
        key_prefix AS keyPrefix,
        key_hash AS keyHash,
        scopes_json AS scopesJson,
        created_by_user_id AS createdByUserId,
        expires_at AS expiresAt,
        last_used_at AS lastUsedAt,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_api_keys
      WHERE tenant_id = ?
      ORDER BY created_at DESC
    `
    : `
      SELECT
        id,
        tenant_id AS tenantId,
        label,
        key_prefix AS keyPrefix,
        key_hash AS keyHash,
        scopes_json AS scopesJson,
        created_by_user_id AS createdByUserId,
        expires_at AS expiresAt,
        last_used_at AS lastUsedAt,
        revoked_at AS revokedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_api_keys
      WHERE tenant_id = ?
        AND revoked_at IS NULL
      ORDER BY created_at DESC
    `;

  let result: SqlQueryResult<TenantApiKeyRow>;

  try {
    result = await db.prepare(query).bind(input.tenantId).all<TenantApiKeyRow>();
  } catch (error: unknown) {
    if (!isMissingTenantApiKeysTableError(error)) {
      throw error;
    }

    await ensureTenantApiKeysTable(db);
    result = await db.prepare(query).bind(input.tenantId).all<TenantApiKeyRow>();
  }

  return result.results.map((row) => mapTenantApiKeyRow(row));
};

export const findActiveTenantApiKeyByHash = async (
  db: SqlDatabase,
  input: FindActiveTenantApiKeyByHashInput,
): Promise<TenantApiKeyRecord | null> => {
  const lookupStatement = (): Promise<TenantApiKeyRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          label,
          key_prefix AS keyPrefix,
          key_hash AS keyHash,
          scopes_json AS scopesJson,
          created_by_user_id AS createdByUserId,
          expires_at AS expiresAt,
          last_used_at AS lastUsedAt,
          revoked_at AS revokedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_api_keys
        WHERE key_hash = ?
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > ?)
        LIMIT 1
      `,
      )
      .bind(input.keyHash, input.nowIso)
      .first<TenantApiKeyRow>();

  let row: TenantApiKeyRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingTenantApiKeysTableError(error)) {
      throw error;
    }

    await ensureTenantApiKeysTable(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapTenantApiKeyRow(row);
};

export const touchTenantApiKeyLastUsedAt = async (
  db: SqlDatabase,
  id: string,
  lastUsedAt: string,
): Promise<void> => {
  const touchStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_api_keys
        SET
          last_used_at = ?,
          updated_at = ?
        WHERE id = ?
      `,
      )
      .bind(lastUsedAt, lastUsedAt, id)
      .run();

  try {
    await touchStatement();
  } catch (error: unknown) {
    if (!isMissingTenantApiKeysTableError(error)) {
      throw error;
    }

    await ensureTenantApiKeysTable(db);
    await touchStatement();
  }
};

export const revokeTenantApiKey = async (
  db: SqlDatabase,
  input: RevokeTenantApiKeyInput,
): Promise<boolean> => {
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_api_keys
        SET
          revoked_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
          AND revoked_at IS NULL
      `,
      )
      .bind(input.revokedAt, input.revokedAt, input.tenantId, input.apiKeyId)
      .run();

  let result: SqlRunResult;

  try {
    result = await updateStatement();
  } catch (error: unknown) {
    if (!isMissingTenantApiKeysTableError(error)) {
      throw error;
    }

    await ensureTenantApiKeysTable(db);
    result = await updateStatement();
  }

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const createLearnerIdentityLinkProof = async (
  db: SqlDatabase,
  input: CreateLearnerIdentityLinkProofInput,
): Promise<LearnerIdentityLinkProofRecord> => {
  const id = createPrefixedId("lip");
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

const mapOid4vciPreAuthorizedCodeRow = (
  row: Oid4vciPreAuthorizedCodeRow,
): Oid4vciPreAuthorizedCodeRecord => {
  return {
    id: row.id,
    codeHash: row.codeHash,
    tenantId: row.tenantId,
    assertionId: row.assertionId,
    publicBadgeId: row.publicBadgeId,
    expiresAt: row.expiresAt,
    usedAt: row.usedAt,
    createdAt: row.createdAt,
  };
};

const mapOid4vciAccessTokenRow = (row: Oid4vciAccessTokenRow): Oid4vciAccessTokenRecord => {
  return {
    id: row.id,
    accessTokenHash: row.accessTokenHash,
    tenantId: row.tenantId,
    assertionId: row.assertionId,
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
  const id = createPrefixedId("oac");
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
  const id = createPrefixedId("oat");
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
  const id = createPrefixedId("ort");
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

export const createOid4vciPreAuthorizedCode = async (
  db: SqlDatabase,
  input: CreateOid4vciPreAuthorizedCodeInput,
): Promise<Oid4vciPreAuthorizedCodeRecord> => {
  const id = createPrefixedId("ovp");
  const createdAt = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oid4vci_pre_authorized_codes (
          id,
          code_hash,
          tenant_id,
          assertion_id,
          public_badge_id,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.codeHash,
        input.tenantId,
        input.assertionId,
        input.publicBadgeId,
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
    codeHash: input.codeHash,
    tenantId: input.tenantId,
    assertionId: input.assertionId,
    publicBadgeId: input.publicBadgeId,
    expiresAt: input.expiresAt,
    usedAt: null,
    createdAt,
  };
};

export const consumeOid4vciPreAuthorizedCode = async (
  db: SqlDatabase,
  input: ConsumeOid4vciPreAuthorizedCodeInput,
): Promise<Oid4vciPreAuthorizedCodeRecord | null> => {
  const consumeStatement = (): Promise<Oid4vciPreAuthorizedCodeRow | null> =>
    db
      .prepare(
        `
        UPDATE oid4vci_pre_authorized_codes
        SET used_at = ?
        WHERE code_hash = ?
          AND used_at IS NULL
          AND expires_at > ?
        RETURNING
          id,
          code_hash AS codeHash,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          public_badge_id AS publicBadgeId,
          expires_at AS expiresAt,
          used_at AS usedAt,
          created_at AS createdAt
      `,
      )
      .bind(input.nowIso, input.codeHash, input.nowIso)
      .first<Oid4vciPreAuthorizedCodeRow>();

  let row: Oid4vciPreAuthorizedCodeRow | null;

  try {
    row = await consumeStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    row = await consumeStatement();
  }

  return row === null ? null : mapOid4vciPreAuthorizedCodeRow(row);
};

export const createOid4vciAccessToken = async (
  db: SqlDatabase,
  input: CreateOid4vciAccessTokenInput,
): Promise<Oid4vciAccessTokenRecord> => {
  const id = createPrefixedId("ova");
  const createdAt = new Date().toISOString();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO oid4vci_access_tokens (
          id,
          access_token_hash,
          tenant_id,
          assertion_id,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.accessTokenHash,
        input.tenantId,
        input.assertionId,
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
    accessTokenHash: input.accessTokenHash,
    tenantId: input.tenantId,
    assertionId: input.assertionId,
    expiresAt: input.expiresAt,
    revokedAt: null,
    createdAt,
  };
};

export const findActiveOid4vciAccessTokenByHash = async (
  db: SqlDatabase,
  input: FindActiveOid4vciAccessTokenByHashInput,
): Promise<Oid4vciAccessTokenRecord | null> => {
  const findStatement = (): Promise<Oid4vciAccessTokenRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          access_token_hash AS accessTokenHash,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          expires_at AS expiresAt,
          revoked_at AS revokedAt,
          created_at AS createdAt
        FROM oid4vci_access_tokens
        WHERE access_token_hash = ?
          AND revoked_at IS NULL
          AND expires_at > ?
        LIMIT 1
      `,
      )
      .bind(input.accessTokenHash, input.nowIso)
      .first<Oid4vciAccessTokenRow>();

  let row: Oid4vciAccessTokenRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingOAuthTablesError(error)) {
      throw error;
    }

    await ensureOAuthTables(db);
    row = await findStatement();
  }

  return row === null ? null : mapOid4vciAccessTokenRow(row);
};

export const listOb3SubjectCredentials = async (
  db: SqlDatabase,
  input: ListOb3SubjectCredentialsInput,
): Promise<ListOb3SubjectCredentialsResult> => {
  const normalizedLimit = Math.max(1, Math.trunc(input.limit));
  const normalizedOffset = Math.max(0, Math.trunc(input.offset));
  const sinceFilter = input.since === undefined ? "" : " AND issued_at > ?";
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

  const credentialId = existingCredential?.id ?? createPrefixedId("ob3c");
  await upsertStatement(credentialId);
  const persistedCredential = await selectStatement();

  if (persistedCredential === null) {
    throw new Error(
      `Failed to upsert OB3 subject credential "${input.tenantId}:${input.userId}:${input.credentialId}"`,
    );
  }

  return {
    status: existingCredential === null ? "created" : "updated",
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
    platformJwksEndpoint: row.platformJwksEndpoint,
    tokenEndpoint: row.tokenEndpoint,
    clientSecret: row.clientSecret,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLtiDeploymentRow = (row: LtiDeploymentRow): LtiDeploymentRecord => {
  return {
    id: row.id,
    issuer: row.issuer,
    clientId: row.clientId,
    deploymentId: row.deploymentId,
    name: row.name,
    description: row.description,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLtiToolKeyRow = (row: LtiToolKeyRow): LtiToolKeyRecord => {
  return {
    id: row.id,
    keyId: row.keyId,
    publicJwkJson: row.publicJwkJson,
    privateJwkJson: row.privateJwkJson,
    isActive: row.isActive === 1 || row.isActive === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLtiLaunchSessionRow = (row: LtiLaunchSessionRow): LtiLaunchSessionRecord => {
  return {
    id: row.id,
    issuer: row.issuer,
    clientId: row.clientId,
    deploymentId: row.deploymentId,
    tenantId: row.tenantId,
    userId: row.userId,
    dataJson: row.dataJson,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLtiDynamicRegistrationSessionRow = (
  row: LtiDynamicRegistrationSessionRow,
): LtiDynamicRegistrationSessionRecord => {
  return {
    id: row.id,
    dataJson: row.dataJson,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
  };
};

const mapLtiResourceLinkPlacementRow = (
  row: LtiResourceLinkPlacementRow,
): LtiResourceLinkPlacementRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    issuer: row.issuer,
    clientId: row.clientId,
    deploymentId: row.deploymentId,
    contextId: row.contextId,
    resourceLinkId: row.resourceLinkId,
    badgeTemplateId: row.badgeTemplateId,
    createdByUserId: row.createdByUserId,
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

const mapTenantMemberRow = (row: TenantMemberRow): TenantMemberRecord => {
  return {
    ...mapTenantMembershipRow(row),
    email: row.email,
  };
};

const mapAccessibleTenantContextRow = (
  row: AccessibleTenantContextRow,
): AccessibleTenantContextRecord => {
  return {
    tenantId: row.tenantId,
    tenantSlug: row.tenantSlug,
    tenantDisplayName: row.tenantDisplayName,
    tenantPlanTier: row.tenantPlanTier,
    membershipRole: row.membershipRole,
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

const mapTenantApiKeyRow = (row: TenantApiKeyRow): TenantApiKeyRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    label: row.label,
    keyPrefix: row.keyPrefix,
    keyHash: row.keyHash,
    scopesJson: row.scopesJson,
    createdByUserId: row.createdByUserId,
    expiresAt: row.expiresAt,
    lastUsedAt: row.lastUsedAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapTenantAuthPolicyRow = (row: TenantAuthPolicyRow): TenantAuthPolicyRecord => {
  return {
    tenantId: row.tenantId,
    loginMode: row.loginMode,
    breakGlassEnabled: row.breakGlassEnabled === 1 || row.breakGlassEnabled === true,
    localMfaRequired: row.localMfaRequired === 1 || row.localMfaRequired === true,
    defaultProviderId: row.defaultProviderId,
    enforceForRoles: "all_users",
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapTenantAuthProviderRow = (row: TenantAuthProviderRow): TenantAuthProviderRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    protocol: row.protocol,
    label: row.label,
    enabled: row.enabled === 1 || row.enabled === true,
    isDefault: row.isDefault === 1 || row.isDefault === true,
    configJson: row.configJson,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapTenantBreakGlassAccountRow = (
  row: TenantBreakGlassAccountRow,
): TenantBreakGlassAccountRecord => {
  return {
    tenantId: row.tenantId,
    userId: row.userId,
    email: row.email,
    createdByUserId: row.createdByUserId,
    lastUsedAt: row.lastUsedAt,
    lastEnrollmentEmailSentAt: row.lastEnrollmentEmailSentAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    betterAuthUserId: row.betterAuthUserId,
    localCredentialEnabled: row.localCredentialEnabled === 1 || row.localCredentialEnabled === true,
    twoFactorEnabled: row.twoFactorEnabled === 1 || row.twoFactorEnabled === true,
  };
};

const mapTenantSsoSamlConfigurationRow = (
  row: TenantSsoSamlConfigurationRow,
): TenantSsoSamlConfigurationRecord => {
  return {
    tenantId: row.tenantId,
    idpEntityId: row.idpEntityId,
    ssoLoginUrl: row.ssoLoginUrl,
    idpCertificatePem: row.idpCertificatePem,
    idpMetadataUrl: row.idpMetadataUrl,
    spEntityId: row.spEntityId,
    assertionConsumerServiceUrl: row.assertionConsumerServiceUrl,
    nameIdFormat: row.nameIdFormat,
    enforced: row.enforced === 1 || row.enforced === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const buildLegacyTenantAuthProviderId = (tenantId: string): string => {
  return `${tenantId}:provider:saml-default`;
};

const buildDefaultTenantAuthPolicy = (
  tenantId: string,
  nowIso: string = new Date().toISOString(),
): TenantAuthPolicyRecord => {
  return {
    tenantId,
    loginMode: "local",
    breakGlassEnabled: false,
    localMfaRequired: false,
    defaultProviderId: null,
    enforceForRoles: "all_users",
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

const buildLegacyTenantAuthPolicy = (
  configuration: TenantSsoSamlConfigurationRecord,
): TenantAuthPolicyRecord => {
  return {
    tenantId: configuration.tenantId,
    loginMode: configuration.enforced ? "sso_required" : "hybrid",
    breakGlassEnabled: false,
    localMfaRequired: false,
    defaultProviderId: buildLegacyTenantAuthProviderId(configuration.tenantId),
    enforceForRoles: "all_users",
    createdAt: configuration.createdAt,
    updatedAt: configuration.updatedAt,
  };
};

const buildLegacyTenantAuthProvider = (
  configuration: TenantSsoSamlConfigurationRecord,
): TenantAuthProviderRecord => {
  return {
    id: buildLegacyTenantAuthProviderId(configuration.tenantId),
    tenantId: configuration.tenantId,
    protocol: "saml",
    label: "Legacy SAML (compatibility only)",
    enabled: true,
    isDefault: true,
    configJson: JSON.stringify({
      idpEntityId: configuration.idpEntityId,
      ssoLoginUrl: configuration.ssoLoginUrl,
      idpCertificatePem: configuration.idpCertificatePem,
      idpMetadataUrl: configuration.idpMetadataUrl,
      spEntityId: configuration.spEntityId,
      assertionConsumerServiceUrl: configuration.assertionConsumerServiceUrl,
      nameIdFormat: configuration.nameIdFormat,
      enforced: configuration.enforced,
    }),
    createdAt: configuration.createdAt,
    updatedAt: configuration.updatedAt,
  };
};

export const isHostedEnterpriseAuthProviderSupported = (
  provider: Pick<TenantAuthProviderRecord, "protocol">,
): boolean => {
  return provider.protocol === "oidc";
};

const assertHostedEnterpriseAuthProviderWritable = (protocol: TenantAuthProviderProtocol): void => {
  if (protocol !== "oidc") {
    throw new Error(HOSTED_ENTERPRISE_OIDC_ONLY_ERROR);
  }
};

const mapTenantCanvasGradebookIntegrationRow = (
  row: TenantCanvasGradebookIntegrationRow,
): TenantCanvasGradebookIntegrationRecord => {
  return {
    tenantId: row.tenantId,
    apiBaseUrl: row.apiBaseUrl,
    authorizationEndpoint: row.authorizationEndpoint,
    tokenEndpoint: row.tokenEndpoint,
    clientId: row.clientId,
    clientSecret: row.clientSecret,
    scope: row.scope,
    accessToken: row.accessToken,
    refreshToken: row.refreshToken,
    accessTokenExpiresAt: row.accessTokenExpiresAt,
    refreshTokenExpiresAt: row.refreshTokenExpiresAt,
    connectedAt: row.connectedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapBadgeIssuanceRuleRow = (row: BadgeIssuanceRuleRow): BadgeIssuanceRuleRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    name: row.name,
    description: row.description,
    badgeTemplateId: row.badgeTemplateId,
    lmsProviderKind: row.lmsProviderKind,
    activeVersionId: row.activeVersionId,
    createdByUserId: row.createdByUserId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapBadgeIssuanceRuleVersionRow = (
  row: BadgeIssuanceRuleVersionRow,
): BadgeIssuanceRuleVersionRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    ruleId: row.ruleId,
    versionNumber: row.versionNumber,
    status: row.status,
    ruleJson: row.ruleJson,
    changeSummary: row.changeSummary,
    createdByUserId: row.createdByUserId,
    approvedByUserId: row.approvedByUserId,
    approvedAt: row.approvedAt,
    activatedByUserId: row.activatedByUserId,
    activatedAt: row.activatedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapBadgeIssuanceRuleApprovalStepRow = (
  row: BadgeIssuanceRuleApprovalStepRow,
): BadgeIssuanceRuleApprovalStepRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    versionId: row.versionId,
    stepNumber: row.stepNumber,
    requiredRole: row.requiredRole,
    label: row.label,
    status: row.status,
    decidedByUserId: row.decidedByUserId,
    decidedAt: row.decidedAt,
    decisionComment: row.decisionComment,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapBadgeIssuanceRuleApprovalEventRow = (
  row: BadgeIssuanceRuleApprovalEventRow,
): BadgeIssuanceRuleApprovalEventRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    versionId: row.versionId,
    stepNumber: row.stepNumber,
    action: row.action,
    actorUserId: row.actorUserId,
    actorRole: row.actorRole,
    comment: row.comment,
    occurredAt: row.occurredAt,
    createdAt: row.createdAt,
  };
};

const mapBadgeIssuanceRuleValueListRow = (
  row: BadgeIssuanceRuleValueListRow,
): BadgeIssuanceRuleValueListRecord => {
  let values: string[] = [];

  try {
    const parsed = JSON.parse(row.valuesJson) as unknown;

    if (Array.isArray(parsed)) {
      values = parsed.filter((entry): entry is string => typeof entry === "string");
    }
  } catch {
    values = [];
  }

  return {
    id: row.id,
    tenantId: row.tenantId,
    label: row.label,
    kind: row.kind,
    values,
    createdByUserId: row.createdByUserId,
    archivedAt: row.archivedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

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

const mapDedicatedDbProvisioningRequestRow = (
  row: DedicatedDbProvisioningRequestRow,
): DedicatedDbProvisioningRequestRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    requestedByUserId: row.requestedByUserId,
    targetRegion: row.targetRegion,
    status: row.status,
    dedicatedDatabaseUrl: row.dedicatedDatabaseUrl,
    notes: row.notes,
    requestedAt: row.requestedAt,
    resolvedAt: row.resolvedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
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

const resolveAssertionLifecycleProjection = (input: {
  revokedAt: string | null;
  latestToState: AssertionLifecycleState | null;
  latestReasonCode: AssertionLifecycleReasonCode | null;
  latestReason: string | null;
  latestTransitionedAt: string | null;
}): Pick<
  TenantAssertionSummaryRecord,
  "state" | "source" | "reasonCode" | "reason" | "transitionedAt"
> => {
  let state: AssertionLifecycleState = "active";
  let source: ResolveAssertionLifecycleStateResult["source"] = "default_active";
  let reasonCode: AssertionLifecycleReasonCode | null = null;
  let reason: string | null = null;
  let transitionedAt: string | null = null;

  if (input.revokedAt !== null && input.latestToState === "revoked") {
    state = "revoked";
    source = "lifecycle_event";
    reasonCode = input.latestReasonCode;
    reason = input.latestReason ?? "credential has been revoked by issuer";
    transitionedAt = input.latestTransitionedAt ?? input.revokedAt;
  } else if (input.revokedAt !== null) {
    state = "revoked";
    source = "assertion_revocation";
    reason = "credential has been revoked by issuer";
    transitionedAt = input.revokedAt;
  } else if (input.latestToState !== null) {
    state = input.latestToState;
    source = "lifecycle_event";
    reasonCode = input.latestReasonCode;
    reason = input.latestReason;
    transitionedAt = input.latestTransitionedAt;
  }

  return {
    state,
    source,
    reasonCode,
    reason,
    transitionedAt,
  };
};

const buildCurrentOrgUnitLineageNames = (
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
  orgUnitId: string,
): Pick<
  TenantAssertionLedgerExportRowRecord,
  "currentInstitutionName" | "currentCollegeName" | "currentDepartmentName" | "currentProgramName"
> => {
  const lineageNames: Pick<
    TenantAssertionLedgerExportRowRecord,
    "currentInstitutionName" | "currentCollegeName" | "currentDepartmentName" | "currentProgramName"
  > = {
    currentInstitutionName: null,
    currentCollegeName: null,
    currentDepartmentName: null,
    currentProgramName: null,
  };

  const visited = new Set<string>();
  let currentOrgUnitId: string | null = orgUnitId;

  while (currentOrgUnitId !== null) {
    if (visited.has(currentOrgUnitId)) {
      throw new Error(`Detected an org-unit cycle while resolving export lineage for ${orgUnitId}`);
    }

    visited.add(currentOrgUnitId);
    const orgUnit = orgUnitsById.get(currentOrgUnitId);

    if (orgUnit === undefined) {
      return lineageNames;
    }

    if (orgUnit.unitType === "institution") {
      lineageNames.currentInstitutionName = orgUnit.displayName;
    } else if (orgUnit.unitType === "college") {
      lineageNames.currentCollegeName = orgUnit.displayName;
    } else if (orgUnit.unitType === "department") {
      lineageNames.currentDepartmentName = orgUnit.displayName;
    } else if (orgUnit.unitType === "program") {
      lineageNames.currentProgramName = orgUnit.displayName;
    }

    currentOrgUnitId = orgUnit.parentOrgUnitId;
  }

  return lineageNames;
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

const mapBadgeTemplateImageRevisionRow = (
  row: BadgeTemplateImageRevisionRow,
): BadgeTemplateImageRevisionRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    previousImageUri: row.previousImageUri,
    newImageUri: row.newImageUri,
    sourceType: row.sourceType,
    promptText: row.promptText,
    provider: row.provider,
    model: row.model,
    metadataJson: row.metadataJson,
    createdByUserId: row.createdByUserId,
    createdAt: row.createdAt,
  };
};

const mapBadgeTemplateImageGenerationRow = (
  row: BadgeTemplateImageGenerationRow,
): BadgeTemplateImageGenerationRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    status: row.status,
    promptText: row.promptText,
    stylePreset: row.stylePreset,
    promptNotes: row.promptNotes,
    accentColor: row.accentColor,
    resultImageUri: row.resultImageUri,
    errorMessage: row.errorMessage,
    requestedByUserId: row.requestedByUserId,
    queuedJobId: row.queuedJobId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    completedAt: row.completedAt,
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

const mapLearnerRecordEntryRow = (row: LearnerRecordEntryRow): LearnerRecordEntryRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    learnerProfileId: row.learnerProfileId,
    trustLevel: row.trustLevel,
    recordType: row.recordType,
    status: row.status,
    title: row.title,
    description: row.description,
    issuerName: row.issuerName,
    issuerUserId: row.issuerUserId,
    sourceSystem: row.sourceSystem,
    sourceRecordId: row.sourceRecordId,
    issuedAt: row.issuedAt,
    revisedAt: row.revisedAt,
    revokedAt: row.revokedAt,
    evidenceLinksJson: row.evidenceLinksJson,
    detailsJson: row.detailsJson,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapLearnerRecordImportContextRow = (
  row: LearnerRecordImportContextRow,
): LearnerRecordImportContextRecord => {
  return {
    entryId: row.entryId,
    tenantId: row.tenantId,
    orgUnitId: row.orgUnitId,
    badgeTemplateId: row.badgeTemplateId,
    pathwayLabel: row.pathwayLabel,
    inferredFromJson: row.inferredFromJson,
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

const mapAssertionReportingAttributionRow = (
  row: AssertionReportingAttributionRow,
): AssertionReportingAttributionRecord => {
  return {
    assertionId: row.assertionId,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    orgUnitId: row.orgUnitId,
    attributionSource: row.attributionSource,
    attributedAt: row.attributedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapAssertionEngagementEventRow = (
  row: AssertionEngagementEventRow,
): AssertionEngagementEventRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    assertionId: row.assertionId,
    eventType: row.eventType,
    actorType: row.actorType,
    channel: row.channel,
    occurredAt: row.occurredAt,
    createdAt: row.createdAt,
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

const mapLearnerRecordAssertionExportRow = (
  row: LearnerRecordAssertionExportRow,
): LearnerRecordAssertionExportRecord => {
  return {
    assertionId: row.assertionId,
    assertionPublicId: row.assertionPublicId,
    tenantId: row.tenantId,
    learnerProfileId: row.learnerProfileId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: row.badgeTitle,
    badgeDescription: row.badgeDescription,
    badgeCriteriaUri: row.badgeCriteriaUri,
    badgeImageUri: row.badgeImageUri,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    vcR2Key: row.vcR2Key,
    statusListIndex: row.statusListIndex,
    idempotencyKey: row.idempotencyKey,
    issuedAt: row.issuedAt,
    issuedByUserId: row.issuedByUserId,
    revokedAt: row.revokedAt,
    issuerName: row.issuerName,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapTenantAssertionSummaryRow = (
  row: TenantAssertionSummaryRow,
): TenantAssertionSummaryRecord => {
  const lifecycle = resolveAssertionLifecycleProjection({
    revokedAt: row.revokedAt,
    latestToState: row.latestToState,
    latestReasonCode: row.latestReasonCode,
    latestReason: row.latestReason,
    latestTransitionedAt: row.latestTransitionedAt,
  });

  return {
    assertionId: row.assertionId,
    tenantId: row.tenantId,
    publicId: row.publicId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: row.badgeTitle,
    badgeImageUri: row.badgeImageUri,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    issuedAt: row.issuedAt,
    issuedByUserId: row.issuedByUserId,
    revokedAt: row.revokedAt,
    ...lifecycle,
  };
};

const mapTenantAssertionLedgerExportRow = (
  row: TenantAssertionLedgerExportRow,
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
): TenantAssertionLedgerExportRowRecord => {
  const lifecycle = resolveAssertionLifecycleProjection({
    revokedAt: row.revokedAt,
    latestToState: row.latestToState,
    latestReasonCode: row.latestReasonCode,
    latestReason: row.latestReason,
    latestTransitionedAt: row.latestTransitionedAt,
  });

  return {
    assertionId: row.assertionId,
    tenantId: row.tenantId,
    publicId: row.publicId,
    badgeTemplateId: row.badgeTemplateId,
    badgeTitle: row.badgeTitle,
    recipientIdentity: row.recipientIdentity,
    recipientIdentityType: row.recipientIdentityType,
    issuedAt: row.issuedAt,
    issuedByUserId: row.issuedByUserId,
    revokedAt: row.revokedAt,
    orgUnitId: row.orgUnitId,
    orgUnitDisplayName: row.orgUnitDisplayName,
    attributionSource: row.attributionSource,
    ...lifecycle,
    ...buildCurrentOrgUnitLineageNames(orgUnitsById, row.orgUnitId),
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

export const findTenantById = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantRecord | null> => {
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
    .bind(tenantId)
    .first<TenantRow>();

  return row === null ? null : mapTenantRow(row);
};

export const findTenantAuthPolicy = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantAuthPolicyRecord | null> => {
  const lookupStatement = (): Promise<TenantAuthPolicyRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          login_mode AS loginMode,
          break_glass_enabled AS breakGlassEnabled,
          local_mfa_required AS localMfaRequired,
          default_provider_id AS defaultProviderId,
          enforce_for_roles AS enforceForRoles,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_auth_policies
        WHERE tenant_id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId)
      .first<TenantAuthPolicyRow>();

  let row: TenantAuthPolicyRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingTenantAuthPoliciesTableError(error)) {
      throw error;
    }

    await ensureTenantAuthPoliciesTable(db);
    row = await lookupStatement();
  }

  if (row !== null) {
    return mapTenantAuthPolicyRow(row);
  }

  const legacyConfiguration = await findTenantSsoSamlConfiguration(db, tenantId);
  return legacyConfiguration === null ? null : buildLegacyTenantAuthPolicy(legacyConfiguration);
};

export const resolveTenantAuthPolicy = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantAuthPolicyRecord> => {
  const policy = await findTenantAuthPolicy(db, tenantId);
  return policy ?? buildDefaultTenantAuthPolicy(tenantId);
};

export const upsertTenantAuthPolicy = async (
  db: SqlDatabase,
  input: UpsertTenantAuthPolicyInput,
): Promise<TenantAuthPolicyRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_auth_policies (
          tenant_id,
          login_mode,
          break_glass_enabled,
          local_mfa_required,
          default_provider_id,
          enforce_for_roles,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id)
        DO UPDATE SET
          login_mode = excluded.login_mode,
          break_glass_enabled = excluded.break_glass_enabled,
          local_mfa_required = excluded.local_mfa_required,
          default_provider_id = excluded.default_provider_id,
          enforce_for_roles = excluded.enforce_for_roles,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.tenantId,
        input.loginMode,
        input.breakGlassEnabled === true ? 1 : 0,
        input.localMfaRequired === true ? 1 : 0,
        input.defaultProviderId ?? null,
        "all_users",
        nowIso,
        nowIso,
      )
      .run();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantAuthPoliciesTableError(error)) {
      throw error;
    }

    await ensureTenantAuthPoliciesTable(db);
    await upsertStatement();
  }

  const policy = await findTenantAuthPolicy(db, input.tenantId);

  if (policy === null) {
    throw new Error(`Unable to upsert auth policy for tenant "${input.tenantId}"`);
  }

  return policy;
};

const hydrateLegacyTenantAuthProvider = async (
  db: SqlDatabase,
  provider: TenantAuthProviderRecord,
): Promise<TenantAuthProviderRecord> => {
  if (provider.protocol !== "saml") {
    return provider;
  }

  if (provider.id !== buildLegacyTenantAuthProviderId(provider.tenantId)) {
    return provider;
  }

  const legacyConfiguration = await findTenantSsoSamlConfiguration(db, provider.tenantId);

  if (legacyConfiguration === null) {
    return provider;
  }

  const hydratedProvider = buildLegacyTenantAuthProvider(legacyConfiguration);
  return {
    ...hydratedProvider,
    label: provider.label,
    enabled: provider.enabled,
    isDefault: provider.isDefault,
  };
};

export const listTenantAuthProviders = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantAuthProviderRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<TenantAuthProviderRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          protocol,
          label,
          enabled,
          is_default AS isDefault,
          config_json AS configJson,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_auth_providers
        WHERE tenant_id = ?
        ORDER BY is_default DESC, created_at ASC, id ASC
      `,
      )
      .bind(tenantId)
      .all<TenantAuthProviderRow>();

  let result: SqlQueryResult<TenantAuthProviderRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingTenantAuthProvidersTableError(error)) {
      throw error;
    }

    await ensureTenantAuthProvidersTable(db);
    result = await listStatement();
  }

  if (result.results.length === 0) {
    const legacyConfiguration = await findTenantSsoSamlConfiguration(db, tenantId);
    return legacyConfiguration === null ? [] : [buildLegacyTenantAuthProvider(legacyConfiguration)];
  }

  return Promise.all(
    result.results.map(async (row) =>
      hydrateLegacyTenantAuthProvider(db, mapTenantAuthProviderRow(row)),
    ),
  );
};

export const findTenantAuthProviderById = async (
  db: SqlDatabase,
  tenantId: string,
  providerId: string,
): Promise<TenantAuthProviderRecord | null> => {
  const lookupStatement = (): Promise<TenantAuthProviderRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          protocol,
          label,
          enabled,
          is_default AS isDefault,
          config_json AS configJson,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_auth_providers
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, providerId)
      .first<TenantAuthProviderRow>();

  let row: TenantAuthProviderRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingTenantAuthProvidersTableError(error)) {
      throw error;
    }

    await ensureTenantAuthProvidersTable(db);
    row = await lookupStatement();
  }

  if (row !== null) {
    return hydrateLegacyTenantAuthProvider(db, mapTenantAuthProviderRow(row));
  }

  if (providerId !== buildLegacyTenantAuthProviderId(tenantId)) {
    return null;
  }

  const legacyConfiguration = await findTenantSsoSamlConfiguration(db, tenantId);
  return legacyConfiguration === null ? null : buildLegacyTenantAuthProvider(legacyConfiguration);
};

export const createTenantAuthProvider = async (
  db: SqlDatabase,
  input: CreateTenantAuthProviderInput,
): Promise<TenantAuthProviderRecord> => {
  assertHostedEnterpriseAuthProviderWritable(input.protocol);
  const id = input.id ?? createPrefixedId("tap");
  const nowIso = new Date().toISOString();
  const enabled = input.enabled ?? true;
  const isDefault = input.isDefault ?? false;

  const clearDefaultStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_auth_providers
        SET
          is_default = 0,
          updated_at = ?
        WHERE tenant_id = ?
          AND is_default = 1
      `,
      )
      .bind(nowIso, input.tenantId)
      .run();

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_auth_providers (
          id,
          tenant_id,
          protocol,
          label,
          enabled,
          is_default,
          config_json,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.protocol,
        input.label,
        enabled ? 1 : 0,
        isDefault ? 1 : 0,
        input.configJson,
        nowIso,
        nowIso,
      )
      .run();

  try {
    if (isDefault) {
      await clearDefaultStatement();
    }

    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantAuthProvidersTableError(error)) {
      throw error;
    }

    await ensureTenantAuthProvidersTable(db);

    if (isDefault) {
      await clearDefaultStatement();
    }

    await insertStatement();
  }

  const provider = await findTenantAuthProviderById(db, input.tenantId, id);

  if (provider === null) {
    throw new Error(`Unable to create auth provider "${id}"`);
  }

  return provider;
};

export const updateTenantAuthProvider = async (
  db: SqlDatabase,
  input: UpdateTenantAuthProviderInput,
): Promise<TenantAuthProviderRecord | null> => {
  assertHostedEnterpriseAuthProviderWritable(input.protocol);
  const nowIso = new Date().toISOString();
  const enabled = input.enabled ?? true;
  const isDefault = input.isDefault ?? false;

  const clearDefaultStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_auth_providers
        SET
          is_default = 0,
          updated_at = ?
        WHERE tenant_id = ?
          AND id <> ?
          AND is_default = 1
      `,
      )
      .bind(nowIso, input.tenantId, input.providerId)
      .run();

  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_auth_providers
        SET
          protocol = ?,
          label = ?,
          enabled = ?,
          is_default = ?,
          config_json = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
      `,
      )
      .bind(
        input.protocol,
        input.label,
        enabled ? 1 : 0,
        isDefault ? 1 : 0,
        input.configJson,
        nowIso,
        input.tenantId,
        input.providerId,
      )
      .run();

  let result: SqlRunResult;

  try {
    if (isDefault) {
      await clearDefaultStatement();
    }

    result = await updateStatement();
  } catch (error: unknown) {
    if (!isMissingTenantAuthProvidersTableError(error)) {
      throw error;
    }

    await ensureTenantAuthProvidersTable(db);

    if (isDefault) {
      await clearDefaultStatement();
    }

    result = await updateStatement();
  }

  if ((result.meta.rowsWritten ?? 0) === 0) {
    return null;
  }

  return findTenantAuthProviderById(db, input.tenantId, input.providerId);
};

export const deleteTenantAuthProvider = async (
  db: SqlDatabase,
  tenantId: string,
  providerId: string,
): Promise<boolean> => {
  const deleteStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        DELETE FROM tenant_auth_providers
        WHERE tenant_id = ?
          AND id = ?
      `,
      )
      .bind(tenantId, providerId)
      .run();

  let result: SqlRunResult;

  try {
    result = await deleteStatement();
  } catch (error: unknown) {
    if (!isMissingTenantAuthProvidersTableError(error)) {
      throw error;
    }

    await ensureTenantAuthProvidersTable(db);
    result = await deleteStatement();
  }

  if ((result.meta.rowsWritten ?? 0) === 0) {
    return false;
  }

  const clearPolicyDefaultStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_auth_policies
        SET
          default_provider_id = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND default_provider_id = ?
      `,
      )
      .bind(new Date().toISOString(), tenantId, providerId)
      .run();

  try {
    await clearPolicyDefaultStatement();
  } catch (error: unknown) {
    if (!isMissingTenantAuthPoliciesTableError(error)) {
      throw error;
    }

    await ensureTenantAuthPoliciesTable(db);
    await clearPolicyDefaultStatement();
  }

  return true;
};

const tenantBreakGlassSelectSql = `
  SELECT
    account.tenant_id AS tenantId,
    account.user_id AS userId,
    users.email AS email,
    account.created_by_user_id AS createdByUserId,
    account.last_used_at AS lastUsedAt,
    account.last_enrollment_email_sent_at AS lastEnrollmentEmailSentAt,
    account.revoked_at AS revokedAt,
    account.created_at AS createdAt,
    account.updated_at AS updatedAt,
    auth_user.id AS betterAuthUserId,
    CASE
      WHEN auth_account.id IS NULL OR auth_account.password IS NULL THEN 0
      ELSE 1
    END AS localCredentialEnabled,
    COALESCE(auth_user.two_factor_enabled, 0) AS twoFactorEnabled
  FROM tenant_break_glass_accounts AS account
  INNER JOIN users
    ON users.id = account.user_id
  LEFT JOIN auth.user AS auth_user
    ON auth_user.email = users.email
  LEFT JOIN auth.account AS auth_account
    ON auth_account.user_id = auth_user.id
   AND auth_account.provider_id = 'credential'
`;

export const listTenantBreakGlassAccounts = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantBreakGlassAccountRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<TenantBreakGlassAccountRow>> =>
    db
      .prepare(
        `
        ${tenantBreakGlassSelectSql}
        WHERE account.tenant_id = ?
        ORDER BY
          account.revoked_at IS NULL DESC,
          account.last_used_at DESC,
          account.created_at ASC,
          users.email ASC
      `,
      )
      .bind(tenantId)
      .all<TenantBreakGlassAccountRow>();

  let result: SqlQueryResult<TenantBreakGlassAccountRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingTenantBreakGlassAccountsTableError(error)) {
      throw error;
    }

    await ensureTenantBreakGlassAccountsTable(db);
    result = await listStatement();
  }

  return result.results.map(mapTenantBreakGlassAccountRow);
};

export const findActiveTenantBreakGlassAccountByUserId = async (
  db: SqlDatabase,
  tenantId: string,
  userId: string,
): Promise<TenantBreakGlassAccountRecord | null> => {
  const lookupStatement = (): Promise<TenantBreakGlassAccountRow | null> =>
    db
      .prepare(
        `
        ${tenantBreakGlassSelectSql}
        WHERE account.tenant_id = ?
          AND account.user_id = ?
          AND account.revoked_at IS NULL
        LIMIT 1
      `,
      )
      .bind(tenantId, userId)
      .first<TenantBreakGlassAccountRow>();

  let row: TenantBreakGlassAccountRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingTenantBreakGlassAccountsTableError(error)) {
      throw error;
    }

    await ensureTenantBreakGlassAccountsTable(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapTenantBreakGlassAccountRow(row);
};

export const findActiveTenantBreakGlassAccountByEmail = async (
  db: SqlDatabase,
  tenantId: string,
  email: string,
): Promise<TenantBreakGlassAccountRecord | null> => {
  const normalizedEmail = normalizeEmail(email);
  const lookupStatement = (): Promise<TenantBreakGlassAccountRow | null> =>
    db
      .prepare(
        `
        ${tenantBreakGlassSelectSql}
        WHERE account.tenant_id = ?
          AND users.email = ?
          AND account.revoked_at IS NULL
        LIMIT 1
      `,
      )
      .bind(tenantId, normalizedEmail)
      .first<TenantBreakGlassAccountRow>();

  let row: TenantBreakGlassAccountRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingTenantBreakGlassAccountsTableError(error)) {
      throw error;
    }

    await ensureTenantBreakGlassAccountsTable(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapTenantBreakGlassAccountRow(row);
};

export const upsertTenantBreakGlassAccount = async (
  db: SqlDatabase,
  input: UpsertTenantBreakGlassAccountInput,
): Promise<TenantBreakGlassAccountRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_break_glass_accounts (
          tenant_id,
          user_id,
          created_by_user_id,
          last_used_at,
          last_enrollment_email_sent_at,
          revoked_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, NULL, ?, NULL, ?, ?)
        ON CONFLICT (tenant_id, user_id)
        DO UPDATE SET
          created_by_user_id = excluded.created_by_user_id,
          last_enrollment_email_sent_at = COALESCE(
            excluded.last_enrollment_email_sent_at,
            tenant_break_glass_accounts.last_enrollment_email_sent_at
          ),
          revoked_at = NULL,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.tenantId,
        input.userId,
        input.createdByUserId ?? null,
        input.lastEnrollmentEmailSentAt ?? null,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantBreakGlassAccountsTableError(error)) {
      throw error;
    }

    await ensureTenantBreakGlassAccountsTable(db);
    await upsertStatement();
  }

  const account = await findActiveTenantBreakGlassAccountByUserId(db, input.tenantId, input.userId);

  if (account === null) {
    throw new Error(
      `Unable to upsert break-glass account for tenant "${input.tenantId}" and user "${input.userId}"`,
    );
  }

  return account;
};

export const revokeTenantBreakGlassAccount = async (
  db: SqlDatabase,
  input: RevokeTenantBreakGlassAccountInput,
): Promise<boolean> => {
  const revokeStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_break_glass_accounts
        SET
          revoked_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND user_id = ?
          AND revoked_at IS NULL
      `,
      )
      .bind(input.revokedAt, input.revokedAt, input.tenantId, input.userId)
      .run();

  let result: SqlRunResult;

  try {
    result = await revokeStatement();
  } catch (error: unknown) {
    if (!isMissingTenantBreakGlassAccountsTableError(error)) {
      throw error;
    }

    await ensureTenantBreakGlassAccountsTable(db);
    result = await revokeStatement();
  }

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const markTenantBreakGlassAccountUsed = async (
  db: SqlDatabase,
  input: MarkTenantBreakGlassAccountUsedInput,
): Promise<void> => {
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_break_glass_accounts
        SET
          last_used_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND user_id = ?
      `,
      )
      .bind(input.usedAt, input.usedAt, input.tenantId, input.userId)
      .run();

  try {
    await updateStatement();
  } catch (error: unknown) {
    if (!isMissingTenantBreakGlassAccountsTableError(error)) {
      throw error;
    }

    await ensureTenantBreakGlassAccountsTable(db);
    await updateStatement();
  }
};

export const markTenantBreakGlassEnrollmentEmailSent = async (
  db: SqlDatabase,
  input: MarkTenantBreakGlassEnrollmentEmailSentInput,
): Promise<void> => {
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_break_glass_accounts
        SET
          last_enrollment_email_sent_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND user_id = ?
      `,
      )
      .bind(input.sentAt, input.sentAt, input.tenantId, input.userId)
      .run();

  try {
    await updateStatement();
  } catch (error: unknown) {
    if (!isMissingTenantBreakGlassAccountsTableError(error)) {
      throw error;
    }

    await ensureTenantBreakGlassAccountsTable(db);
    await updateStatement();
  }
};

export const findTenantSsoSamlConfiguration = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantSsoSamlConfigurationRecord | null> => {
  const lookupStatement = (): Promise<TenantSsoSamlConfigurationRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          idp_entity_id AS idpEntityId,
          sso_login_url AS ssoLoginUrl,
          idp_certificate_pem AS idpCertificatePem,
          idp_metadata_url AS idpMetadataUrl,
          sp_entity_id AS spEntityId,
          assertion_consumer_service_url AS assertionConsumerServiceUrl,
          name_id_format AS nameIdFormat,
          enforced,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_sso_saml_configurations
        WHERE tenant_id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId)
      .first<TenantSsoSamlConfigurationRow>();

  let row: TenantSsoSamlConfigurationRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingTenantSsoSamlConfigurationsTableError(error)) {
      throw error;
    }

    await ensureTenantSsoSamlConfigurationsTable(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapTenantSsoSamlConfigurationRow(row);
};

export const upsertTenantSsoSamlConfiguration = async (
  db: SqlDatabase,
  input: UpsertTenantSsoSamlConfigurationInput,
): Promise<TenantSsoSamlConfigurationRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_sso_saml_configurations (
          tenant_id,
          idp_entity_id,
          sso_login_url,
          idp_certificate_pem,
          idp_metadata_url,
          sp_entity_id,
          assertion_consumer_service_url,
          name_id_format,
          enforced,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id)
        DO UPDATE SET
          idp_entity_id = excluded.idp_entity_id,
          sso_login_url = excluded.sso_login_url,
          idp_certificate_pem = excluded.idp_certificate_pem,
          idp_metadata_url = excluded.idp_metadata_url,
          sp_entity_id = excluded.sp_entity_id,
          assertion_consumer_service_url = excluded.assertion_consumer_service_url,
          name_id_format = excluded.name_id_format,
          enforced = excluded.enforced,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.tenantId,
        input.idpEntityId,
        input.ssoLoginUrl,
        input.idpCertificatePem,
        input.idpMetadataUrl ?? null,
        input.spEntityId,
        input.assertionConsumerServiceUrl,
        input.nameIdFormat ?? null,
        input.enforced === true ? 1 : 0,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantSsoSamlConfigurationsTableError(error)) {
      throw error;
    }

    await ensureTenantSsoSamlConfigurationsTable(db);
    await upsertStatement();
  }

  const configuration = await findTenantSsoSamlConfiguration(db, input.tenantId);

  if (configuration === null) {
    throw new Error(`Unable to upsert SAML SSO configuration for tenant "${input.tenantId}"`);
  }

  return configuration;
};

export const deleteTenantSsoSamlConfiguration = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<boolean> => {
  const deleteStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        DELETE FROM tenant_sso_saml_configurations
        WHERE tenant_id = ?
      `,
      )
      .bind(tenantId)
      .run();

  let result: SqlRunResult;

  try {
    result = await deleteStatement();
  } catch (error: unknown) {
    if (!isMissingTenantSsoSamlConfigurationsTableError(error)) {
      throw error;
    }

    await ensureTenantSsoSamlConfigurationsTable(db);
    result = await deleteStatement();
  }

  return (result.meta.rowsWritten ?? 0) > 0;
};

export const findTenantCanvasGradebookIntegration = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<TenantCanvasGradebookIntegrationRecord | null> => {
  const lookupStatement = (): Promise<TenantCanvasGradebookIntegrationRow | null> =>
    db
      .prepare(
        `
        SELECT
          tenant_id AS tenantId,
          api_base_url AS apiBaseUrl,
          authorization_endpoint AS authorizationEndpoint,
          token_endpoint AS tokenEndpoint,
          client_id AS clientId,
          client_secret AS clientSecret,
          scope,
          access_token AS accessToken,
          refresh_token AS refreshToken,
          access_token_expires_at AS accessTokenExpiresAt,
          refresh_token_expires_at AS refreshTokenExpiresAt,
          connected_at AS connectedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_canvas_gradebook_integrations
        WHERE tenant_id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId)
      .first<TenantCanvasGradebookIntegrationRow>();

  let row: TenantCanvasGradebookIntegrationRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingTenantCanvasGradebookIntegrationsTableError(error)) {
      throw error;
    }

    await ensureTenantCanvasGradebookIntegrationsTable(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapTenantCanvasGradebookIntegrationRow(row);
};

export const upsertTenantCanvasGradebookIntegration = async (
  db: SqlDatabase,
  input: UpsertTenantCanvasGradebookIntegrationInput,
): Promise<TenantCanvasGradebookIntegrationRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_canvas_gradebook_integrations (
          tenant_id,
          api_base_url,
          authorization_endpoint,
          token_endpoint,
          client_id,
          client_secret,
          scope,
          access_token,
          refresh_token,
          access_token_expires_at,
          refresh_token_expires_at,
          connected_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?)
        ON CONFLICT (tenant_id)
        DO UPDATE SET
          api_base_url = excluded.api_base_url,
          authorization_endpoint = excluded.authorization_endpoint,
          token_endpoint = excluded.token_endpoint,
          client_id = excluded.client_id,
          client_secret = excluded.client_secret,
          scope = excluded.scope,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.tenantId,
        input.apiBaseUrl,
        input.authorizationEndpoint,
        input.tokenEndpoint,
        input.clientId,
        input.clientSecret,
        input.scope,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingTenantCanvasGradebookIntegrationsTableError(error)) {
      throw error;
    }

    await ensureTenantCanvasGradebookIntegrationsTable(db);
    await upsertStatement();
  }

  const integration = await findTenantCanvasGradebookIntegration(db, input.tenantId);

  if (integration === null) {
    throw new Error(`Unable to upsert Canvas integration for tenant "${input.tenantId}"`);
  }

  return integration;
};

export const updateTenantCanvasGradebookIntegrationTokens = async (
  db: SqlDatabase,
  input: UpdateTenantCanvasGradebookIntegrationTokensInput,
): Promise<TenantCanvasGradebookIntegrationRecord | null> => {
  const nowIso = new Date().toISOString();
  const connectedAt = input.connectedAt ?? nowIso;
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_canvas_gradebook_integrations
        SET
          access_token = ?,
          refresh_token = COALESCE(?, refresh_token),
          access_token_expires_at = ?,
          refresh_token_expires_at = ?,
          connected_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
      `,
      )
      .bind(
        input.accessToken,
        input.refreshToken ?? null,
        input.accessTokenExpiresAt ?? null,
        input.refreshTokenExpiresAt ?? null,
        connectedAt,
        nowIso,
        input.tenantId,
      )
      .run();

  let updated: SqlRunResult;

  try {
    updated = await updateStatement();
  } catch (error: unknown) {
    if (!isMissingTenantCanvasGradebookIntegrationsTableError(error)) {
      throw error;
    }

    await ensureTenantCanvasGradebookIntegrationsTable(db);
    updated = await updateStatement();
  }

  if ((updated.meta.rowsWritten ?? 0) === 0) {
    return null;
  }

  return findTenantCanvasGradebookIntegration(db, input.tenantId);
};

export interface CreateBadgeIssuanceRuleResult {
  rule: BadgeIssuanceRuleRecord;
  version: BadgeIssuanceRuleVersionRecord;
}

export const findBadgeIssuanceRuleById = async (
  db: SqlDatabase,
  tenantId: string,
  ruleId: string,
): Promise<BadgeIssuanceRuleRecord | null> => {
  const lookupStatement = (): Promise<BadgeIssuanceRuleRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          name,
          description,
          badge_template_id AS badgeTemplateId,
          lms_provider_kind AS lmsProviderKind,
          active_version_id AS activeVersionId,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM badge_issuance_rules
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, ruleId)
      .first<BadgeIssuanceRuleRow>();

  let row: BadgeIssuanceRuleRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapBadgeIssuanceRuleRow(row);
};

export const listBadgeIssuanceRules = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRulesInput,
): Promise<BadgeIssuanceRuleRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          name,
          description,
          badge_template_id AS badgeTemplateId,
          lms_provider_kind AS lmsProviderKind,
          active_version_id AS activeVersionId,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM badge_issuance_rules
        WHERE tenant_id = ?
        ORDER BY created_at DESC, id DESC
      `,
      )
      .bind(input.tenantId)
      .all<BadgeIssuanceRuleRow>();

  let result: SqlQueryResult<BadgeIssuanceRuleRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapBadgeIssuanceRuleRow(row));
};

export const createBadgeIssuanceRuleValueList = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleValueListInput,
): Promise<BadgeIssuanceRuleValueListRecord> => {
  const valueListId = createPrefixedId("brvl");
  const nowIso = new Date().toISOString();
  const normalizedValues = Array.from(
    new Set(input.values.map((entry) => entry.trim()).filter((entry) => entry.length > 0)),
  );
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_value_lists (
          id,
          tenant_id,
          label,
          kind,
          values_json,
          created_by_user_id,
          archived_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)
      `,
      )
      .bind(
        valueListId,
        input.tenantId,
        input.label,
        input.kind,
        JSON.stringify(normalizedValues),
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();
  const lookupStatement = (): Promise<BadgeIssuanceRuleValueListRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          label,
          kind,
          values_json AS valuesJson,
          created_by_user_id AS createdByUserId,
          archived_at AS archivedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM badge_issuance_rule_value_lists
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, valueListId)
      .first<BadgeIssuanceRuleValueListRow>();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    await insertStatement();
  }

  const row = await lookupStatement();

  if (row === null) {
    throw new Error(`Unable to create badge issuance rule value list "${valueListId}"`);
  }

  return mapBadgeIssuanceRuleValueListRow(row);
};

export const listBadgeIssuanceRuleValueLists = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleValueListsInput,
): Promise<BadgeIssuanceRuleValueListRecord[]> => {
  const includeArchived = input.includeArchived ?? false;
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleValueListRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          label,
          kind,
          values_json AS valuesJson,
          created_by_user_id AS createdByUserId,
          archived_at AS archivedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM badge_issuance_rule_value_lists
        WHERE tenant_id = ?
          AND (CAST(? AS TEXT) IS NULL OR kind = ?)
          AND (? = 1 OR archived_at IS NULL)
        ORDER BY created_at DESC, id DESC
      `,
      )
      .bind(input.tenantId, input.kind ?? null, input.kind ?? null, includeArchived ? 1 : 0)
      .all<BadgeIssuanceRuleValueListRow>();

  let result: SqlQueryResult<BadgeIssuanceRuleValueListRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapBadgeIssuanceRuleValueListRow(row));
};

export const listBadgeIssuanceRuleVersions = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleVersionsInput,
): Promise<BadgeIssuanceRuleVersionRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleVersionRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          rule_id AS ruleId,
          version_number AS versionNumber,
          status,
          rule_json AS ruleJson,
          change_summary AS changeSummary,
          created_by_user_id AS createdByUserId,
          approved_by_user_id AS approvedByUserId,
          approved_at AS approvedAt,
          activated_by_user_id AS activatedByUserId,
          activated_at AS activatedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND rule_id = ?
        ORDER BY version_number DESC
      `,
      )
      .bind(input.tenantId, input.ruleId)
      .all<BadgeIssuanceRuleVersionRow>();

  let result: SqlQueryResult<BadgeIssuanceRuleVersionRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    result = await listStatement();
  }

  return result.results
    .map((row) => mapBadgeIssuanceRuleVersionRow(row))
    .filter((version) => BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status));
};

export const listBadgeIssuanceRuleVersionApprovalSteps = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleVersionApprovalStepsInput,
): Promise<BadgeIssuanceRuleApprovalStepRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleApprovalStepRow>> =>
    db
      .prepare(
        `
        SELECT
          steps.id,
          steps.tenant_id AS tenantId,
          steps.version_id AS versionId,
          steps.step_number AS stepNumber,
          steps.required_role AS requiredRole,
          steps.label,
          steps.status,
          steps.decided_by_user_id AS decidedByUserId,
          steps.decided_at AS decidedAt,
          steps.decision_comment AS decisionComment,
          steps.created_at AS createdAt,
          steps.updated_at AS updatedAt
        FROM badge_issuance_rule_approval_steps AS steps
        INNER JOIN badge_issuance_rule_versions AS versions
          ON versions.id = steps.version_id
          AND versions.tenant_id = steps.tenant_id
        WHERE steps.tenant_id = ?
          AND versions.rule_id = ?
          AND steps.version_id = ?
        ORDER BY steps.step_number ASC
      `,
      )
      .bind(input.tenantId, input.ruleId, input.versionId)
      .all<BadgeIssuanceRuleApprovalStepRow>();

  let result: SqlQueryResult<BadgeIssuanceRuleApprovalStepRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    result = await listStatement();
  }

  return result.results
    .map((row) => mapBadgeIssuanceRuleApprovalStepRow(row))
    .filter((step) => BADGE_ISSUANCE_RULE_APPROVAL_STEP_STATUSES.has(step.status));
};

export const listBadgeIssuanceRuleVersionApprovalEvents = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleVersionApprovalEventsInput,
): Promise<BadgeIssuanceRuleApprovalEventRecord[]> => {
  const listStatement = (): Promise<SqlQueryResult<BadgeIssuanceRuleApprovalEventRow>> =>
    db
      .prepare(
        `
        SELECT
          events.id,
          events.tenant_id AS tenantId,
          events.version_id AS versionId,
          events.step_number AS stepNumber,
          events.action,
          events.actor_user_id AS actorUserId,
          events.actor_role AS actorRole,
          events.comment,
          events.occurred_at AS occurredAt,
          events.created_at AS createdAt
        FROM badge_issuance_rule_approval_events AS events
        INNER JOIN badge_issuance_rule_versions AS versions
          ON versions.id = events.version_id
          AND versions.tenant_id = events.tenant_id
        WHERE events.tenant_id = ?
          AND versions.rule_id = ?
          AND events.version_id = ?
        ORDER BY events.occurred_at ASC, events.created_at ASC
      `,
      )
      .bind(input.tenantId, input.ruleId, input.versionId)
      .all<BadgeIssuanceRuleApprovalEventRow>();

  let result: SqlQueryResult<BadgeIssuanceRuleApprovalEventRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    result = await listStatement();
  }

  return result.results
    .map((row) => mapBadgeIssuanceRuleApprovalEventRow(row))
    .filter((event) => BADGE_ISSUANCE_RULE_APPROVAL_EVENT_ACTIONS.has(event.action));
};

export const findBadgeIssuanceRuleVersionById = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    versionId: string;
  },
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const lookupStatement = (): Promise<BadgeIssuanceRuleVersionRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          rule_id AS ruleId,
          version_number AS versionNumber,
          status,
          rule_json AS ruleJson,
          change_summary AS changeSummary,
          created_by_user_id AS createdByUserId,
          approved_by_user_id AS approvedByUserId,
          approved_at AS approvedAt,
          activated_by_user_id AS activatedByUserId,
          activated_at AS activatedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.ruleId, input.versionId)
      .first<BadgeIssuanceRuleVersionRow>();

  let row: BadgeIssuanceRuleVersionRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    row = await lookupStatement();
  }

  if (row === null) {
    return null;
  }

  const version = mapBadgeIssuanceRuleVersionRow(row);
  return BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status) ? version : null;
};

export const findActiveBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
  },
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const lookupStatement = (): Promise<BadgeIssuanceRuleVersionRow | null> =>
    db
      .prepare(
        `
        SELECT
          versions.id,
          versions.tenant_id AS tenantId,
          versions.rule_id AS ruleId,
          versions.version_number AS versionNumber,
          versions.status,
          versions.rule_json AS ruleJson,
          versions.change_summary AS changeSummary,
          versions.created_by_user_id AS createdByUserId,
          versions.approved_by_user_id AS approvedByUserId,
          versions.approved_at AS approvedAt,
          versions.activated_by_user_id AS activatedByUserId,
          versions.activated_at AS activatedAt,
          versions.created_at AS createdAt,
          versions.updated_at AS updatedAt
        FROM badge_issuance_rules AS rules
        INNER JOIN badge_issuance_rule_versions AS versions
          ON versions.id = rules.active_version_id
          AND versions.rule_id = rules.id
          AND versions.tenant_id = rules.tenant_id
        WHERE rules.tenant_id = ?
          AND rules.id = ?
        LIMIT 1
      `,
      )
      .bind(input.tenantId, input.ruleId)
      .first<BadgeIssuanceRuleVersionRow>();

  let row: BadgeIssuanceRuleVersionRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    row = await lookupStatement();
  }

  if (row === null) {
    return null;
  }

  const version = mapBadgeIssuanceRuleVersionRow(row);
  return BADGE_ISSUANCE_RULE_VERSION_STATUSES.has(version.status) ? version : null;
};

const DEFAULT_BADGE_ISSUANCE_RULE_APPROVAL_CHAIN: readonly BadgeIssuanceRuleApprovalChainStepInput[] =
  [
    {
      requiredRole: "admin",
      label: "Administrative approval",
    },
  ] as const;

const normalizeBadgeIssuanceRuleApprovalChain = (
  chain: readonly BadgeIssuanceRuleApprovalChainStepInput[] | undefined,
): BadgeIssuanceRuleApprovalChainStepInput[] => {
  const normalizedChain =
    chain === undefined ? [...DEFAULT_BADGE_ISSUANCE_RULE_APPROVAL_CHAIN] : [...chain];

  if (normalizedChain.length === 0) {
    throw new Error("Badge issuance rule approval chain must include at least one step");
  }

  for (const step of normalizedChain) {
    if (!(step.requiredRole in TENANT_ROLE_RANK)) {
      throw new Error(`Unsupported tenant role in approval chain: ${step.requiredRole}`);
    }
  }

  return normalizedChain;
};

const insertBadgeIssuanceRuleApprovalSteps = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    versionId: string;
    approvalChain: readonly BadgeIssuanceRuleApprovalChainStepInput[];
    createdAt: string;
  },
): Promise<void> => {
  const insertSteps = async (): Promise<void> => {
    for (const [index, step] of input.approvalChain.entries()) {
      await db
        .prepare(
          `
          INSERT INTO badge_issuance_rule_approval_steps (
            id,
            tenant_id,
            version_id,
            step_number,
            required_role,
            label,
            status,
            decided_by_user_id,
            decided_at,
            decision_comment,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, 'queued', NULL, NULL, NULL, ?, ?)
        `,
        )
        .bind(
          createPrefixedId("bras"),
          input.tenantId,
          input.versionId,
          index + 1,
          step.requiredRole,
          step.label ?? null,
          input.createdAt,
          input.createdAt,
        )
        .run();
    }
  };

  try {
    await insertSteps();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    await insertSteps();
  }
};

const insertBadgeIssuanceRuleApprovalEvent = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    versionId: string;
    stepNumber: number | null;
    action: BadgeIssuanceRuleApprovalEventAction;
    actorUserId: string | null;
    actorRole: TenantMembershipRole | null;
    comment: string | null;
    occurredAt: string;
  },
): Promise<void> => {
  const insertEventStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_approval_events (
          id,
          tenant_id,
          version_id,
          step_number,
          action,
          actor_user_id,
          actor_role,
          comment,
          occurred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        createPrefixedId("brae"),
        input.tenantId,
        input.versionId,
        input.stepNumber,
        input.action,
        input.actorUserId,
        input.actorRole,
        input.comment,
        input.occurredAt,
        input.occurredAt,
      )
      .run();

  try {
    await insertEventStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    await insertEventStatement();
  }
};

const ensureBadgeIssuanceRuleApprovalStepsInitialized = async (
  db: SqlDatabase,
  input: {
    tenantId: string;
    ruleId: string;
    versionId: string;
  },
): Promise<BadgeIssuanceRuleApprovalStepRecord[]> => {
  const existingSteps = await listBadgeIssuanceRuleVersionApprovalSteps(db, input);

  if (existingSteps.length > 0) {
    return existingSteps;
  }

  const nowIso = new Date().toISOString();
  await insertBadgeIssuanceRuleApprovalSteps(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    approvalChain: DEFAULT_BADGE_ISSUANCE_RULE_APPROVAL_CHAIN,
    createdAt: nowIso,
  });

  return listBadgeIssuanceRuleVersionApprovalSteps(db, input);
};

export const createBadgeIssuanceRule = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleInput,
): Promise<CreateBadgeIssuanceRuleResult> => {
  const nowIso = new Date().toISOString();
  const ruleId = createPrefixedId("brl");
  const versionId = createPrefixedId("brv");
  const approvalChain = normalizeBadgeIssuanceRuleApprovalChain(input.approvalChain);
  const insertRuleStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rules (
          id,
          tenant_id,
          name,
          description,
          badge_template_id,
          lms_provider_kind,
          active_version_id,
          created_by_user_id,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
      `,
      )
      .bind(
        ruleId,
        input.tenantId,
        input.name,
        input.description ?? null,
        input.badgeTemplateId,
        input.lmsProviderKind,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();
  const insertVersionStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_versions (
          id,
          tenant_id,
          rule_id,
          version_number,
          status,
          rule_json,
          change_summary,
          created_by_user_id,
          approved_by_user_id,
          approved_at,
          activated_by_user_id,
          activated_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, 1, 'draft', ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
      `,
      )
      .bind(
        versionId,
        input.tenantId,
        ruleId,
        input.ruleJson,
        input.changeSummary ?? null,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await insertRuleStatement();
    await insertVersionStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    await insertRuleStatement();
    await insertVersionStatement();
  }

  await insertBadgeIssuanceRuleApprovalSteps(db, {
    tenantId: input.tenantId,
    versionId,
    approvalChain,
    createdAt: nowIso,
  });

  const rule = await findBadgeIssuanceRuleById(db, input.tenantId, ruleId);
  const version = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId,
    versionId,
  });

  if (rule === null || version === null) {
    throw new Error(`Unable to create badge issuance rule "${ruleId}"`);
  }

  return {
    rule,
    version,
  };
};

export const createBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: CreateBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord> => {
  const nowIso = new Date().toISOString();
  const versionId = createPrefixedId("brv");
  const approvalChain = normalizeBadgeIssuanceRuleApprovalChain(input.approvalChain);
  const nextVersionStatement = (): Promise<BadgeIssuanceRuleVersionNumberRow | null> =>
    db
      .prepare(
        `
        SELECT MAX(version_number) AS maxVersionNumber
        FROM badge_issuance_rule_versions
        WHERE tenant_id = ?
          AND rule_id = ?
      `,
      )
      .bind(input.tenantId, input.ruleId)
      .first<BadgeIssuanceRuleVersionNumberRow>();
  const insertStatement = (versionNumber: number): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_issuance_rule_versions (
          id,
          tenant_id,
          rule_id,
          version_number,
          status,
          rule_json,
          change_summary,
          created_by_user_id,
          approved_by_user_id,
          approved_at,
          activated_by_user_id,
          activated_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
      `,
      )
      .bind(
        versionId,
        input.tenantId,
        input.ruleId,
        versionNumber,
        input.ruleJson,
        input.changeSummary ?? null,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  let maxRow: BadgeIssuanceRuleVersionNumberRow | null;

  try {
    maxRow = await nextVersionStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    maxRow = await nextVersionStatement();
  }

  const currentMax =
    maxRow?.maxVersionNumber === null || maxRow?.maxVersionNumber === undefined
      ? 0
      : Number(maxRow.maxVersionNumber);
  const nextVersionNumber = Number.isFinite(currentMax) ? Math.floor(currentMax) + 1 : 1;
  await insertStatement(nextVersionNumber);
  await insertBadgeIssuanceRuleApprovalSteps(db, {
    tenantId: input.tenantId,
    versionId,
    approvalChain,
    createdAt: nowIso,
  });

  const version = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId,
  });

  if (version === null) {
    throw new Error(
      `Unable to create badge issuance rule version for rule "${input.ruleId}" in tenant "${input.tenantId}"`,
    );
  }

  return version;
};

export const submitBadgeIssuanceRuleVersionForApproval = async (
  db: SqlDatabase,
  input: SubmitBadgeIssuanceRuleVersionForApprovalInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const version = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });

  if (version === null) {
    return null;
  }

  if (version.status !== "draft" && version.status !== "rejected") {
    return null;
  }

  const approvalSteps = await ensureBadgeIssuanceRuleApprovalStepsInitialized(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
  const firstStep = approvalSteps[0];

  if (firstStep === undefined) {
    return null;
  }

  const resetApprovalStepsStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_approval_steps
        SET
          status = 'queued',
          decided_by_user_id = NULL,
          decided_at = NULL,
          decision_comment = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND version_id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.versionId)
      .run();
  const activateFirstApprovalStepStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_approval_steps
        SET
          status = 'pending',
          updated_at = ?
        WHERE tenant_id = ?
          AND version_id = ?
          AND step_number = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.versionId, firstStep.stepNumber)
      .run();
  const submitVersionStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'pending_approval',
          approved_by_user_id = NULL,
          approved_at = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();

  try {
    await resetApprovalStepsStatement();
    await activateFirstApprovalStepStatement();
    await submitVersionStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    await resetApprovalStepsStatement();
    await activateFirstApprovalStepStatement();
    await submitVersionStatement();
  }

  await insertBadgeIssuanceRuleApprovalEvent(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    stepNumber: firstStep.stepNumber,
    action: "submitted",
    actorUserId: input.actorUserId ?? null,
    actorRole: input.actorRole ?? null,
    comment: input.comment ?? null,
    occurredAt,
  });

  return findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
};

export const decideBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: DecideBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const currentVersion = await findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });

  if (currentVersion?.status !== "pending_approval") {
    return null;
  }

  const steps = await ensureBadgeIssuanceRuleApprovalStepsInitialized(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
  const currentStep = steps.find((step) => step.status === "pending");

  if (currentStep === undefined) {
    return null;
  }

  if (!roleSatisfiesMinimumRole(input.actorRole, currentStep.requiredRole)) {
    throw new Error(
      `Role ${input.actorRole} does not satisfy required approval role ${currentStep.requiredRole}`,
    );
  }

  const nextStep = steps.find((step) => step.stepNumber > currentStep.stepNumber);
  const markCurrentStepStatement = (status: "approved" | "rejected"): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_approval_steps
        SET
          status = ?,
          decided_by_user_id = ?,
          decided_at = ?,
          decision_comment = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND version_id = ?
          AND step_number = ?
      `,
      )
      .bind(
        status,
        input.actorUserId,
        occurredAt,
        input.comment ?? null,
        occurredAt,
        input.tenantId,
        input.versionId,
        currentStep.stepNumber,
      )
      .run();
  const markNextStepPendingStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_approval_steps
        SET
          status = 'pending',
          updated_at = ?
        WHERE tenant_id = ?
          AND version_id = ?
          AND step_number = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.versionId, nextStep?.stepNumber ?? null)
      .run();
  const updateVersionPendingStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'pending_approval',
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();
  const updateVersionApprovedStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'approved',
          approved_by_user_id = ?,
          approved_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(
        input.actorUserId,
        occurredAt,
        occurredAt,
        input.tenantId,
        input.ruleId,
        input.versionId,
      )
      .run();
  const updateVersionRejectedStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'rejected',
          approved_by_user_id = NULL,
          approved_at = NULL,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(occurredAt, input.tenantId, input.ruleId, input.versionId)
      .run();

  try {
    if (input.decision === "rejected") {
      await markCurrentStepStatement("rejected");
      await updateVersionRejectedStatement();
    } else {
      await markCurrentStepStatement("approved");

      if (nextStep === undefined) {
        await updateVersionApprovedStatement();
      } else {
        await markNextStepPendingStatement();
        await updateVersionPendingStatement();
      }
    }
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    if (input.decision === "rejected") {
      await markCurrentStepStatement("rejected");
      await updateVersionRejectedStatement();
    } else {
      await markCurrentStepStatement("approved");

      if (nextStep === undefined) {
        await updateVersionApprovedStatement();
      } else {
        await markNextStepPendingStatement();
        await updateVersionPendingStatement();
      }
    }
  }

  await insertBadgeIssuanceRuleApprovalEvent(db, {
    tenantId: input.tenantId,
    versionId: input.versionId,
    stepNumber: currentStep.stepNumber,
    action: input.decision,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
    comment: input.comment ?? null,
    occurredAt,
  });

  return findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
};

export const activateBadgeIssuanceRuleVersion = async (
  db: SqlDatabase,
  input: ActivateBadgeIssuanceRuleVersionInput,
): Promise<BadgeIssuanceRuleVersionRecord | null> => {
  const activatedAt = input.activatedAt ?? new Date().toISOString();
  const deprecateExistingStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'deprecated',
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND status = 'active'
          AND id <> ?
      `,
      )
      .bind(activatedAt, input.tenantId, input.ruleId, input.versionId)
      .run();
  const activateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rule_versions
        SET
          status = 'active',
          activated_by_user_id = ?,
          activated_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND rule_id = ?
          AND id = ?
      `,
      )
      .bind(
        input.actorUserId,
        activatedAt,
        activatedAt,
        input.tenantId,
        input.ruleId,
        input.versionId,
      )
      .run();
  const updateRuleActiveVersionStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_issuance_rules
        SET
          active_version_id = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
      `,
      )
      .bind(input.versionId, activatedAt, input.tenantId, input.ruleId)
      .run();

  let activated: SqlRunResult;

  try {
    await deprecateExistingStatement();
    activated = await activateStatement();
    await updateRuleActiveVersionStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    await deprecateExistingStatement();
    activated = await activateStatement();
    await updateRuleActiveVersionStatement();
  }

  if ((activated.meta.rowsWritten ?? 0) === 0) {
    return null;
  }

  return findBadgeIssuanceRuleVersionById(db, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    versionId: input.versionId,
  });
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

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    await insertStatement();
  }

  const row = await lookupStatement();

  if (row === null) {
    throw new Error(`Unable to load badge issuance rule evaluation "${evaluationId}" after insert`);
  }

  return mapBadgeIssuanceRuleEvaluationRow(row);
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

  let row: BadgeIssuanceRuleEvaluationRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapBadgeIssuanceRuleEvaluationRow(row);
};

export const listBadgeIssuanceRuleEvaluations = async (
  db: SqlDatabase,
  input: ListBadgeIssuanceRuleEvaluationsInput,
): Promise<BadgeIssuanceRuleEvaluationRecord[]> => {
  const limit = input.limit ?? 50;
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
        WHERE evaluations.tenant_id = ?
          AND (CAST(? AS TEXT) IS NULL OR evaluations.rule_id = ?)
          AND (CAST(? AS TEXT) IS NULL OR evaluations.version_id = ?)
          AND (CAST(? AS TEXT) IS NULL OR rules.badge_template_id = ?)
          AND (CAST(? AS TEXT) IS NULL OR evaluations.issuance_status = ?)
          AND (CAST(? AS TEXT) IS NULL OR evaluations.review_status = ?)
        ORDER BY evaluations.evaluated_at DESC, evaluations.id DESC
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
        limit,
      )
      .all<BadgeIssuanceRuleEvaluationRow>();

  let result: SqlQueryResult<BadgeIssuanceRuleEvaluationRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    result = await listStatement();
  }

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

  let updated: SqlRunResult;

  try {
    updated = await updateStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeIssuanceRulesSchemaError(error)) {
      throw error;
    }

    await ensureBadgeIssuanceRulesTables(db);
    updated = await updateStatement();
  }

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

export const createDedicatedDbProvisioningRequest = async (
  db: SqlDatabase,
  input: CreateDedicatedDbProvisioningRequestInput,
): Promise<DedicatedDbProvisioningRequestRecord> => {
  const id = createPrefixedId("dpr");
  const requestedAt = input.requestedAt ?? new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO tenant_dedicated_db_provisioning_requests (
          id,
          tenant_id,
          requested_by_user_id,
          target_region,
          status,
          dedicated_database_url,
          notes,
          requested_at,
          resolved_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, 'pending', NULL, ?, ?, NULL, ?, ?)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.requestedByUserId ?? null,
        input.targetRegion,
        input.notes ?? null,
        requestedAt,
        requestedAt,
        requestedAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingDedicatedDbProvisioningRequestsTableError(error)) {
      throw error;
    }

    await ensureDedicatedDbProvisioningRequestsTable(db);
    await insertStatement();
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        requested_by_user_id AS requestedByUserId,
        target_region AS targetRegion,
        status,
        dedicated_database_url AS dedicatedDatabaseUrl,
        notes,
        requested_at AS requestedAt,
        resolved_at AS resolvedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_dedicated_db_provisioning_requests
      WHERE id = ?
      LIMIT 1
    `,
    )
    .bind(id)
    .first<DedicatedDbProvisioningRequestRow>();

  if (row === null) {
    throw new Error(`Unable to create dedicated DB provisioning request "${id}"`);
  }

  return mapDedicatedDbProvisioningRequestRow(row);
};

export const listDedicatedDbProvisioningRequests = async (
  db: SqlDatabase,
  input: ListDedicatedDbProvisioningRequestsInput,
): Promise<DedicatedDbProvisioningRequestRecord[]> => {
  const whereClauses = ["tenant_id = ?"];
  const queryParams: unknown[] = [input.tenantId];

  if (input.status !== undefined) {
    whereClauses.push("status = ?");
    queryParams.push(input.status);
  }

  const listStatement = (): Promise<SqlQueryResult<DedicatedDbProvisioningRequestRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          requested_by_user_id AS requestedByUserId,
          target_region AS targetRegion,
          status,
          dedicated_database_url AS dedicatedDatabaseUrl,
          notes,
          requested_at AS requestedAt,
          resolved_at AS resolvedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM tenant_dedicated_db_provisioning_requests
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY requested_at DESC, created_at DESC
      `,
      )
      .bind(...queryParams)
      .all<DedicatedDbProvisioningRequestRow>();

  let result: SqlQueryResult<DedicatedDbProvisioningRequestRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingDedicatedDbProvisioningRequestsTableError(error)) {
      throw error;
    }

    await ensureDedicatedDbProvisioningRequestsTable(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapDedicatedDbProvisioningRequestRow(row));
};

export const resolveDedicatedDbProvisioningRequest = async (
  db: SqlDatabase,
  input: ResolveDedicatedDbProvisioningRequestInput,
): Promise<DedicatedDbProvisioningRequestRecord | null> => {
  const resolvedAt = input.resolvedAt ?? new Date().toISOString();
  let result: SqlRunResult;
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE tenant_dedicated_db_provisioning_requests
        SET
          status = ?,
          dedicated_database_url = ?,
          notes = ?,
          resolved_at = ?,
          updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
          AND status = 'pending'
      `,
      )
      .bind(
        input.status,
        input.dedicatedDatabaseUrl ?? null,
        input.notes ?? null,
        resolvedAt,
        resolvedAt,
        input.tenantId,
        input.requestId,
      )
      .run();

  try {
    result = await updateStatement();
  } catch (error: unknown) {
    if (!isMissingDedicatedDbProvisioningRequestsTableError(error)) {
      throw error;
    }

    await ensureDedicatedDbProvisioningRequestsTable(db);
    result = await updateStatement();
  }

  if ((result.meta.rowsWritten ?? 0) === 0) {
    return null;
  }

  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        requested_by_user_id AS requestedByUserId,
        target_region AS targetRegion,
        status,
        dedicated_database_url AS dedicatedDatabaseUrl,
        notes,
        requested_at AS requestedAt,
        resolved_at AS resolvedAt,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM tenant_dedicated_db_provisioning_requests
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(input.tenantId, input.requestId)
    .first<DedicatedDbProvisioningRequestRow>();

  return row === null ? null : mapDedicatedDbProvisioningRequestRow(row);
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
  return issuer.trim().replace(/\/+$/g, "");
};

export const upsertLtiIssuerRegistration = async (
  db: SqlDatabase,
  input: UpsertLtiIssuerRegistrationInput,
): Promise<LtiIssuerRegistrationRecord> => {
  const nowIso = new Date().toISOString();
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);

  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_issuer_registrations (
          issuer,
          tenant_id,
          authorization_endpoint,
          client_id,
          platform_jwks_endpoint,
          token_endpoint,
          client_secret,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (issuer)
        DO UPDATE SET
          tenant_id = excluded.tenant_id,
          authorization_endpoint = excluded.authorization_endpoint,
          client_id = excluded.client_id,
          platform_jwks_endpoint = COALESCE(excluded.platform_jwks_endpoint, lti_issuer_registrations.platform_jwks_endpoint),
          token_endpoint = COALESCE(excluded.token_endpoint, lti_issuer_registrations.token_endpoint),
          client_secret = COALESCE(excluded.client_secret, lti_issuer_registrations.client_secret),
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        normalizedIssuer,
        input.tenantId,
        input.authorizationEndpoint,
        input.clientId,
        input.platformJwksEndpoint ?? null,
        input.tokenEndpoint ?? null,
        input.clientSecret ?? null,
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
          platform_jwks_endpoint AS platformJwksEndpoint,
          token_endpoint AS tokenEndpoint,
          client_secret AS clientSecret,
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
          platform_jwks_endpoint AS platformJwksEndpoint,
          token_endpoint AS tokenEndpoint,
          client_secret AS clientSecret,
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

export const upsertLtiDeployment = async (
  db: SqlDatabase,
  input: UpsertLtiDeploymentInput,
): Promise<LtiDeploymentRecord> => {
  const nowIso = new Date().toISOString();
  const id = input.id ?? `lti_dep_${crypto.randomUUID().replace(/-/g, "")}`;
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);

  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_deployments (
          id,
          issuer,
          client_id,
          deployment_id,
          name,
          description,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (issuer, client_id, deployment_id)
        DO UPDATE SET
          name = COALESCE(excluded.name, lti_deployments.name),
          description = COALESCE(excluded.description, lti_deployments.description),
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        id,
        normalizedIssuer,
        input.clientId,
        input.deploymentId,
        input.name ?? null,
        input.description ?? null,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    await upsertStatement();
  }

  const deployment = await findLtiDeploymentByIssuerClientDeployment(db, {
    issuer: normalizedIssuer,
    clientId: input.clientId,
    deploymentId: input.deploymentId,
  });

  if (deployment === null) {
    throw new Error(`Unable to upsert LTI deployment "${input.deploymentId}"`);
  }

  return deployment;
};

export const findLtiDeploymentByIssuerClientDeployment = async (
  db: SqlDatabase,
  input: {
    issuer: string;
    clientId: string;
    deploymentId: string;
  },
): Promise<LtiDeploymentRecord | null> => {
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);
  const lookupStatement = (): Promise<LtiDeploymentRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          issuer,
          client_id AS clientId,
          deployment_id AS deploymentId,
          name,
          description,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_deployments
        WHERE issuer = ?
          AND client_id = ?
          AND deployment_id = ?
        LIMIT 1
      `,
      )
      .bind(normalizedIssuer, input.clientId, input.deploymentId)
      .first<LtiDeploymentRow>();

  let row: LtiDeploymentRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapLtiDeploymentRow(row);
};

export const listLtiDeploymentsForIssuer = async (
  db: SqlDatabase,
  issuer: string,
): Promise<LtiDeploymentRecord[]> => {
  const normalizedIssuer = normalizeLtiIssuer(issuer);
  const listStatement = (): Promise<SqlQueryResult<LtiDeploymentRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          issuer,
          client_id AS clientId,
          deployment_id AS deploymentId,
          name,
          description,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_deployments
        WHERE issuer = ?
        ORDER BY created_at ASC
      `,
      )
      .bind(normalizedIssuer)
      .all<LtiDeploymentRow>();

  let result: SqlQueryResult<LtiDeploymentRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapLtiDeploymentRow(row));
};

export const createLtiToolKey = async (
  db: SqlDatabase,
  input: CreateLtiToolKeyInput,
): Promise<LtiToolKeyRecord> => {
  const nowIso = new Date().toISOString();
  const id = input.id ?? `lti_key_${crypto.randomUUID().replace(/-/g, "")}`;
  const isActive = input.isActive ?? true;

  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_tool_keys (
          id,
          key_id,
          public_jwk_json,
          private_jwk_json,
          is_active,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (key_id)
        DO UPDATE SET
          public_jwk_json = excluded.public_jwk_json,
          private_jwk_json = excluded.private_jwk_json,
          is_active = excluded.is_active,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        id,
        input.keyId,
        input.publicJwkJson,
        input.privateJwkJson,
        isActive ? 1 : 0,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    await insertStatement();
  }

  const key = await findActiveLtiToolKey(db);

  if (key === null) {
    throw new Error(`Unable to create LTI tool key "${input.keyId}"`);
  }

  return key;
};

export const findActiveLtiToolKey = async (db: SqlDatabase): Promise<LtiToolKeyRecord | null> => {
  const findStatement = (): Promise<LtiToolKeyRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          key_id AS keyId,
          public_jwk_json AS publicJwkJson,
          private_jwk_json AS privateJwkJson,
          is_active AS isActive,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_tool_keys
        WHERE is_active = 1
        ORDER BY created_at DESC
        LIMIT 1
      `,
      )
      .first<LtiToolKeyRow>();

  let row: LtiToolKeyRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    row = await findStatement();
  }

  return row === null ? null : mapLtiToolKeyRow(row);
};

export const storeLtiLaunchNonce = async (
  db: SqlDatabase,
  nonce: string,
  expiresAt: string,
): Promise<void> => {
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_launch_nonces (
          nonce,
          expires_at
        )
        VALUES (?, ?)
        ON CONFLICT (nonce)
        DO NOTHING
      `,
      )
      .bind(nonce, expiresAt)
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    await insertStatement();
  }
};

export const consumeLtiLaunchNonce = async (
  db: SqlDatabase,
  nonce: string,
  nowIso: string,
): Promise<boolean> => {
  const updateStatement = (): Promise<SqlQueryResult<{ nonce: string }>> =>
    db
      .prepare(
        `
        UPDATE lti_launch_nonces
        SET consumed_at = ?
        WHERE nonce = ?
          AND consumed_at IS NULL
          AND expires_at > ?
        RETURNING nonce
      `,
      )
      .bind(nowIso, nonce, nowIso)
      .all<{ nonce: string }>();

  let result: SqlQueryResult<{ nonce: string }>;

  try {
    result = await updateStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    result = await updateStatement();
  }

  return result.results.length > 0;
};

export const upsertLtiLaunchSession = async (
  db: SqlDatabase,
  input: UpsertLtiLaunchSessionInput,
): Promise<LtiLaunchSessionRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_launch_sessions (
          id,
          issuer,
          client_id,
          deployment_id,
          tenant_id,
          user_id,
          data_json,
          expires_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (id)
        DO UPDATE SET
          tenant_id = excluded.tenant_id,
          user_id = excluded.user_id,
          data_json = excluded.data_json,
          expires_at = excluded.expires_at,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.id,
        normalizeLtiIssuer(input.issuer),
        input.clientId,
        input.deploymentId,
        input.tenantId ?? null,
        input.userId ?? null,
        input.dataJson,
        input.expiresAt,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    await upsertStatement();
  }

  const session = await findLtiLaunchSessionById(db, input.id);

  if (session === null) {
    throw new Error(`Unable to upsert LTI launch session "${input.id}"`);
  }

  return session;
};

export const findLtiLaunchSessionById = async (
  db: SqlDatabase,
  sessionId: string,
): Promise<LtiLaunchSessionRecord | null> => {
  const nowIso = new Date().toISOString();
  const findStatement = (): Promise<LtiLaunchSessionRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          issuer,
          client_id AS clientId,
          deployment_id AS deploymentId,
          tenant_id AS tenantId,
          user_id AS userId,
          data_json AS dataJson,
          expires_at AS expiresAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_launch_sessions
        WHERE id = ?
          AND expires_at > ?
        LIMIT 1
      `,
      )
      .bind(sessionId, nowIso)
      .first<LtiLaunchSessionRow>();

  let row: LtiLaunchSessionRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    row = await findStatement();
  }

  return row === null ? null : mapLtiLaunchSessionRow(row);
};

export const upsertLtiDynamicRegistrationSession = async (
  db: SqlDatabase,
  input: {
    id: string;
    dataJson: string;
    expiresAt: string;
  },
): Promise<void> => {
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_dynamic_registration_sessions (
          id,
          data_json,
          expires_at
        )
        VALUES (?, ?, ?)
        ON CONFLICT (id)
        DO UPDATE SET
          data_json = excluded.data_json,
          expires_at = excluded.expires_at
      `,
      )
      .bind(input.id, input.dataJson, input.expiresAt)
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    await insertStatement();
  }
};

export const findLtiDynamicRegistrationSessionById = async (
  db: SqlDatabase,
  sessionId: string,
): Promise<LtiDynamicRegistrationSessionRecord | null> => {
  const nowIso = new Date().toISOString();
  const findStatement = (): Promise<LtiDynamicRegistrationSessionRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          data_json AS dataJson,
          expires_at AS expiresAt,
          created_at AS createdAt
        FROM lti_dynamic_registration_sessions
        WHERE id = ?
          AND expires_at > ?
        LIMIT 1
      `,
      )
      .bind(sessionId, nowIso)
      .first<LtiDynamicRegistrationSessionRow>();

  let row: LtiDynamicRegistrationSessionRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    row = await findStatement();
  }

  return row === null ? null : mapLtiDynamicRegistrationSessionRow(row);
};

export const deleteLtiDynamicRegistrationSessionById = async (
  db: SqlDatabase,
  sessionId: string,
): Promise<void> => {
  const deleteStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        DELETE FROM lti_dynamic_registration_sessions
        WHERE id = ?
      `,
      )
      .bind(sessionId)
      .run();

  try {
    await deleteStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    await deleteStatement();
  }
};

export const upsertLtiResourceLinkPlacement = async (
  db: SqlDatabase,
  input: UpsertLtiResourceLinkPlacementInput,
): Promise<LtiResourceLinkPlacementRecord> => {
  const nowIso = new Date().toISOString();
  const id = input.id ?? `lti_place_${crypto.randomUUID().replace(/-/g, "")}`;
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);

  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO lti_resource_link_placements (
          id,
          tenant_id,
          issuer,
          client_id,
          deployment_id,
          context_id,
          resource_link_id,
          badge_template_id,
          created_by_user_id,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (issuer, client_id, deployment_id, resource_link_id)
        DO UPDATE SET
          tenant_id = excluded.tenant_id,
          context_id = excluded.context_id,
          badge_template_id = excluded.badge_template_id,
          created_by_user_id = COALESCE(excluded.created_by_user_id, lti_resource_link_placements.created_by_user_id),
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        id,
        input.tenantId,
        normalizedIssuer,
        input.clientId,
        input.deploymentId,
        input.contextId ?? null,
        input.resourceLinkId,
        input.badgeTemplateId,
        input.createdByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    await upsertStatement();
  }

  const placement = await findLtiResourceLinkPlacement(db, {
    issuer: normalizedIssuer,
    clientId: input.clientId,
    deploymentId: input.deploymentId,
    resourceLinkId: input.resourceLinkId,
  });

  if (placement === null) {
    throw new Error(`Unable to upsert LTI resource-link placement "${input.resourceLinkId}"`);
  }

  return placement;
};

export const findLtiResourceLinkPlacement = async (
  db: SqlDatabase,
  input: {
    issuer: string;
    clientId: string;
    deploymentId: string;
    resourceLinkId: string;
  },
): Promise<LtiResourceLinkPlacementRecord | null> => {
  const normalizedIssuer = normalizeLtiIssuer(input.issuer);
  const findStatement = (): Promise<LtiResourceLinkPlacementRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          issuer,
          client_id AS clientId,
          deployment_id AS deploymentId,
          context_id AS contextId,
          resource_link_id AS resourceLinkId,
          badge_template_id AS badgeTemplateId,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM lti_resource_link_placements
        WHERE issuer = ?
          AND client_id = ?
          AND deployment_id = ?
          AND resource_link_id = ?
        LIMIT 1
      `,
      )
      .bind(normalizedIssuer, input.clientId, input.deploymentId, input.resourceLinkId)
      .first<LtiResourceLinkPlacementRow>();

  let row: LtiResourceLinkPlacementRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingLtiAdvantageTableError(error)) {
      throw error;
    }

    await ensureLtiAdvantageTables(db);
    row = await findStatement();
  }

  return row === null ? null : mapLtiResourceLinkPlacementRow(row);
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
        VALUES (?, ?, 'institution', 'institution', ?, NULL, NULL, 1, ?, ?)
        ON CONFLICT DO NOTHING
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
  const eventId = createPrefixedId("dage");
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
      eventType: "expired",
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
  const startsAtMs = assertValidIsoTimestamp(input.startsAt, "startsAt");
  const endsAtMs = assertValidIsoTimestamp(input.endsAt, "endsAt");

  if (endsAtMs <= startsAtMs) {
    throw new Error("endsAt must be after startsAt");
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

  const grantId = createPrefixedId("dag");
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
    eventType: "granted",
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
    if (input.includeRevoked !== true && record.status === "revoked") {
      return false;
    }

    if (input.includeExpired !== true && record.status === "expired") {
      return false;
    }

    return true;
  });
};

export const revokeDelegatedIssuingAuthorityGrant = async (
  db: SqlDatabase,
  input: RevokeDelegatedIssuingAuthorityGrantInput,
): Promise<RevokeDelegatedIssuingAuthorityGrantResult> => {
  assertValidIsoTimestamp(input.revokedAt, "revokedAt");

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
      status: "already_revoked",
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
      eventType: "revoked",
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
    status: (result.meta.rowsWritten ?? 0) > 0 ? "revoked" : "already_revoked",
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
  assertValidIsoTimestamp(atIso, "atIso");
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
  const eventId = createPrefixedId("btoe");
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

    const expectedParentType = requiredParentType ?? "institution";

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

  const id = createPrefixedId("ou");
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
    throw new Error("Badge template ownership changes must use transferBadgeTemplateOwnership");
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
      reasonCode: "initial_assignment",
      reason: "Badge template ownership assigned at creation",
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
  const id = createPrefixedId("bt");
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
    reasonCode: "initial_assignment",
    reason: "Badge template ownership assigned at creation",
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
    setClauses.push("slug = ?");
    params.push(input.slug);
  }

  if (input.title !== undefined) {
    setClauses.push("title = ?");
    params.push(input.title);
  }

  if (input.description !== undefined) {
    setClauses.push("description = ?");
    params.push(input.description);
  }

  if (input.criteriaUri !== undefined) {
    setClauses.push("criteria_uri = ?");
    params.push(input.criteriaUri);
  }

  if (input.imageUri !== undefined) {
    setClauses.push("image_uri = ?");
    params.push(input.imageUri);
  }

  if (setClauses.length === 0) {
    throw new Error("No badge template fields were provided for update");
  }

  const updatedAt = new Date().toISOString();
  const sql = `
    UPDATE badge_templates
    SET ${setClauses.join(", ")},
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

export const createBadgeTemplateImageRevision = async (
  db: SqlDatabase,
  input: CreateBadgeTemplateImageRevisionInput,
): Promise<BadgeTemplateImageRevisionRecord> => {
  const id = createPrefixedId("btir");
  const nowIso = new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_template_image_revisions (
          id,
          tenant_id,
          badge_template_id,
          previous_image_uri,
          new_image_uri,
          source_type,
          prompt_text,
          provider,
          model,
          metadata_json,
          created_by_user_id,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.badgeTemplateId,
        input.previousImageUri,
        input.newImageUri,
        input.sourceType,
        input.promptText ?? null,
        input.provider ?? null,
        input.model ?? null,
        input.metadataJson ?? null,
        input.createdByUserId ?? null,
        nowIso,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeTemplateImageTablesError(error)) {
      throw error;
    }

    await ensureBadgeTemplateImageTables(db);
    await insertStatement();
  }

  const revision = await findBadgeTemplateImageRevisionById(
    db,
    input.tenantId,
    input.badgeTemplateId,
    id,
  );

  if (revision === null) {
    throw new Error(`Unable to load badge template image revision ${id} after insert`);
  }

  return revision;
};

export const listBadgeTemplateImageRevisions = async (
  db: SqlDatabase,
  input: ListBadgeTemplateImageRevisionsInput,
): Promise<BadgeTemplateImageRevisionRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 25, 100));
  const listStatement = (): Promise<SqlQueryResult<BadgeTemplateImageRevisionRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          previous_image_uri AS previousImageUri,
          new_image_uri AS newImageUri,
          source_type AS sourceType,
          prompt_text AS promptText,
          provider,
          model,
          metadata_json AS metadataJson,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt
        FROM badge_template_image_revisions
        WHERE tenant_id = ?
          AND badge_template_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.badgeTemplateId, queryLimit)
      .all<BadgeTemplateImageRevisionRow>();

  let result: SqlQueryResult<BadgeTemplateImageRevisionRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeTemplateImageTablesError(error)) {
      throw error;
    }

    await ensureBadgeTemplateImageTables(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapBadgeTemplateImageRevisionRow(row));
};

export const findBadgeTemplateImageRevisionById = async (
  db: SqlDatabase,
  tenantId: string,
  badgeTemplateId: string,
  revisionId: string,
): Promise<BadgeTemplateImageRevisionRecord | null> => {
  const findStatement = (): Promise<BadgeTemplateImageRevisionRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          previous_image_uri AS previousImageUri,
          new_image_uri AS newImageUri,
          source_type AS sourceType,
          prompt_text AS promptText,
          provider,
          model,
          metadata_json AS metadataJson,
          created_by_user_id AS createdByUserId,
          created_at AS createdAt
        FROM badge_template_image_revisions
        WHERE tenant_id = ?
          AND badge_template_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, badgeTemplateId, revisionId)
      .first<BadgeTemplateImageRevisionRow>();

  let row: BadgeTemplateImageRevisionRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeTemplateImageTablesError(error)) {
      throw error;
    }

    await ensureBadgeTemplateImageTables(db);
    row = await findStatement();
  }

  return row === null ? null : mapBadgeTemplateImageRevisionRow(row);
};

export const createBadgeTemplateImageGeneration = async (
  db: SqlDatabase,
  input: CreateBadgeTemplateImageGenerationInput,
): Promise<BadgeTemplateImageGenerationRecord> => {
  const id = createPrefixedId("btig");
  const nowIso = new Date().toISOString();
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_template_image_generations (
          id,
          tenant_id,
          badge_template_id,
          status,
          prompt_text,
          style_preset,
          prompt_notes,
          accent_color,
          result_image_uri,
          error_message,
          requested_by_user_id,
          queued_job_id,
          created_at,
          updated_at,
          completed_at
        )
        VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, NULL, NULL, ?, NULL, ?, ?, NULL)
      `,
      )
      .bind(
        id,
        input.tenantId,
        input.badgeTemplateId,
        input.promptText,
        input.stylePreset,
        input.promptNotes ?? null,
        input.accentColor ?? null,
        input.requestedByUserId ?? null,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeTemplateImageTablesError(error)) {
      throw error;
    }

    await ensureBadgeTemplateImageTables(db);
    await insertStatement();
  }

  const generation = await findBadgeTemplateImageGenerationById(db, input.tenantId, id);

  if (generation === null) {
    throw new Error(`Unable to load badge template image generation ${id} after insert`);
  }

  return generation;
};

export const updateBadgeTemplateImageGeneration = async (
  db: SqlDatabase,
  input: UpdateBadgeTemplateImageGenerationInput,
): Promise<BadgeTemplateImageGenerationRecord | null> => {
  const setClauses: string[] = [];
  const params: (string | null)[] = [];

  if (input.status !== undefined) {
    setClauses.push("status = ?");
    params.push(input.status);
  }

  if (input.resultImageUri !== undefined) {
    setClauses.push("result_image_uri = ?");
    params.push(input.resultImageUri);
  }

  if (input.errorMessage !== undefined) {
    setClauses.push("error_message = ?");
    params.push(input.errorMessage);
  }

  if (input.queuedJobId !== undefined) {
    setClauses.push("queued_job_id = ?");
    params.push(input.queuedJobId);
  }

  if (input.completedAt !== undefined) {
    setClauses.push("completed_at = ?");
    params.push(input.completedAt);
  }

  if (setClauses.length === 0) {
    throw new Error("No badge template image generation fields were provided for update");
  }

  const updatedAt = new Date().toISOString();
  const updateStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        UPDATE badge_template_image_generations
        SET ${setClauses.join(", ")},
            updated_at = ?
        WHERE tenant_id = ?
          AND id = ?
      `,
      )
      .bind(...params, updatedAt, input.tenantId, input.id)
      .run();

  try {
    await updateStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeTemplateImageTablesError(error)) {
      throw error;
    }

    await ensureBadgeTemplateImageTables(db);
    await updateStatement();
  }

  return findBadgeTemplateImageGenerationById(db, input.tenantId, input.id);
};

export const findBadgeTemplateImageGenerationById = async (
  db: SqlDatabase,
  tenantId: string,
  generationId: string,
): Promise<BadgeTemplateImageGenerationRecord | null> => {
  const findStatement = (): Promise<BadgeTemplateImageGenerationRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          status,
          prompt_text AS promptText,
          style_preset AS stylePreset,
          prompt_notes AS promptNotes,
          accent_color AS accentColor,
          result_image_uri AS resultImageUri,
          error_message AS errorMessage,
          requested_by_user_id AS requestedByUserId,
          queued_job_id AS queuedJobId,
          created_at AS createdAt,
          updated_at AS updatedAt,
          completed_at AS completedAt
        FROM badge_template_image_generations
        WHERE tenant_id = ?
          AND id = ?
        LIMIT 1
      `,
      )
      .bind(tenantId, generationId)
      .first<BadgeTemplateImageGenerationRow>();

  let row: BadgeTemplateImageGenerationRow | null;

  try {
    row = await findStatement();
  } catch (error: unknown) {
    if (!isMissingBadgeTemplateImageTablesError(error)) {
      throw error;
    }

    await ensureBadgeTemplateImageTables(db);
    row = await findStatement();
  }

  return row === null ? null : mapBadgeTemplateImageGenerationRow(row);
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
    throw new Error("transferredAt must be a valid ISO timestamp");
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
      status: "already_owned",
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
    status: "transferred",
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
    throw new Error("transitionedAt must be a valid ISO timestamp");
  }

  if (!ASSERTION_LIFECYCLE_REASON_CODES.has(input.reasonCode)) {
    throw new Error(`Unsupported assertion lifecycle reason code: ${input.reasonCode}`);
  }

  if (input.transitionSource === "manual" && input.actorUserId === undefined) {
    throw new Error("Manual lifecycle transitions require actorUserId");
  }

  if (input.transitionSource === "automation" && input.actorUserId !== undefined) {
    throw new Error("Automated lifecycle transitions must not set actorUserId");
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
      status: "already_in_state",
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
      status: "invalid_transition",
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

  if (input.toState === "revoked") {
    const revocationResult = await recordAssertionRevocation(db, {
      tenantId: input.tenantId,
      assertionId: input.assertionId,
      revocationId: createPrefixedId("rev"),
      reason: reason ?? input.reasonCode,
      idempotencyKey: createPrefixedId("idem"),
      ...(input.actorUserId === undefined ? {} : { revokedByUserId: input.actorUserId }),
      revokedAt: input.transitionedAt,
    });

    if (revocationResult.status === "already_revoked") {
      return {
        status: "already_in_state",
        fromState: current.state,
        toState: input.toState,
        currentState: "revoked",
        event: null,
        message: "assertion is already in revoked state",
      };
    }

    effectiveTransitionedAt = revocationResult.revokedAt;
  }

  const eventId = createPrefixedId("ale");
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
    status: "transitioned",
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
    identityType: "email",
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
    if (identity.identityType === "email") {
      emailAliases.add(normalizeEmail(identity.identityValue));
    }
  }

  const aliasList = Array.from(emailAliases);
  const emailPlaceholders = aliasList.map(() => "?").join(", ");
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

export const listLearnerRecordAssertionExports = async (
  db: SqlDatabase,
  input: ListLearnerRecordAssertionExportsInput,
): Promise<LearnerRecordAssertionExportRecord[]> => {
  const identities = await listLearnerIdentitiesByProfile(
    db,
    input.tenantId,
    input.learnerProfileId,
  );
  const emailAliases = Array.from(
    new Set(
      identities
        .filter((identity) => identity.identityType === "email")
        .map((identity) => normalizeEmail(identity.identityValue)),
    ),
  );
  const emailAliasClause =
    emailAliases.length === 0
      ? ""
      : `
          OR (
            assertions.recipient_identity_type = 'email'
            AND LOWER(assertions.recipient_identity) IN (${emailAliases.map(() => "?").join(", ")})
          )
        `;
  const params: unknown[] = [input.tenantId, input.learnerProfileId, ...emailAliases];
  const result = await db
    .prepare(
      `
      SELECT
        assertions.id AS assertionId,
        assertions.public_id AS assertionPublicId,
        assertions.tenant_id AS tenantId,
        assertions.learner_profile_id AS learnerProfileId,
        assertions.badge_template_id AS badgeTemplateId,
        badge_templates.title AS badgeTitle,
        badge_templates.description AS badgeDescription,
        badge_templates.criteria_uri AS badgeCriteriaUri,
        badge_templates.image_uri AS badgeImageUri,
        assertions.recipient_identity AS recipientIdentity,
        assertions.recipient_identity_type AS recipientIdentityType,
        assertions.vc_r2_key AS vcR2Key,
        assertions.status_list_index AS statusListIndex,
        assertions.idempotency_key AS idempotencyKey,
        assertions.issued_at AS issuedAt,
        assertions.issued_by_user_id AS issuedByUserId,
        assertions.revoked_at AS revokedAt,
        tenants.display_name AS issuerName,
        assertions.created_at AS createdAt,
        assertions.updated_at AS updatedAt
      FROM assertions
      INNER JOIN badge_templates
        ON badge_templates.tenant_id = assertions.tenant_id
        AND badge_templates.id = assertions.badge_template_id
      INNER JOIN tenants
        ON tenants.id = assertions.tenant_id
      WHERE assertions.tenant_id = ?
        AND (
          assertions.learner_profile_id = ?
          ${emailAliasClause}
        )
      ORDER BY assertions.issued_at DESC, assertions.id DESC
    `,
    )
    .bind(...params)
    .all<LearnerRecordAssertionExportRow>();

  return result.results.map((row) => mapLearnerRecordAssertionExportRow(row));
};

export const listTenantAssertions = async (
  db: SqlDatabase,
  input: ListTenantAssertionsInput,
): Promise<TenantAssertionSummaryRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 100, 500));
  const whereClauses = ["assertions.tenant_id = ?"];
  const params: unknown[] = [input.tenantId];

  if (input.badgeTemplateId !== undefined) {
    whereClauses.push("assertions.badge_template_id = ?");
    params.push(input.badgeTemplateId);
  }

  if (input.recipientQuery !== undefined) {
    const normalizedQuery = `%${input.recipientQuery.trim().toLowerCase()}%`;
    whereClauses.push(
      `(
        LOWER(assertions.recipient_identity) LIKE ?
        OR LOWER(assertions.id) LIKE ?
        OR LOWER(COALESCE(assertions.public_id, '')) LIKE ?
      )`,
    );
    params.push(normalizedQuery, normalizedQuery, normalizedQuery);
  }

  if (input.state !== undefined) {
    whereClauses.push(
      `(
        CASE
          WHEN assertions.revoked_at IS NOT NULL THEN 'revoked'
          WHEN lifecycle.to_state IS NOT NULL THEN lifecycle.to_state
          ELSE 'active'
        END
      ) = ?`,
    );
    params.push(input.state);
  }

  const listStatement = (): Promise<SqlQueryResult<TenantAssertionSummaryRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.tenant_id AS tenantId,
          assertions.public_id AS publicId,
          assertions.badge_template_id AS badgeTemplateId,
          badge_templates.title AS badgeTitle,
          badge_templates.image_uri AS badgeImageUri,
          assertions.recipient_identity AS recipientIdentity,
          assertions.recipient_identity_type AS recipientIdentityType,
          assertions.issued_at AS issuedAt,
          assertions.issued_by_user_id AS issuedByUserId,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode,
          lifecycle.reason AS latestReason,
          lifecycle.transitioned_at AS latestTransitionedAt
        FROM assertions
        INNER JOIN badge_templates
          ON badge_templates.tenant_id = assertions.tenant_id
          AND badge_templates.id = assertions.badge_template_id
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at DESC, assertions.id DESC
        LIMIT ?
      `,
      )
      .bind(...params, queryLimit)
      .all<TenantAssertionSummaryRow>();

  let result: SqlQueryResult<TenantAssertionSummaryRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingAssertionLifecycleEventsTableError(error)) {
      throw error;
    }

    await ensureAssertionLifecycleEventsTable(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapTenantAssertionSummaryRow(row));
};

export const listTenantAssertionLedgerExportRows = async (
  db: SqlDatabase,
  input: ListTenantAssertionLedgerExportRowsInput,
): Promise<TenantAssertionLedgerExportResult> => {
  await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);

  const whereClauses = ["assertions.tenant_id = ?"];
  const params: unknown[] = [input.tenantId];

  if (input.issuedFrom !== undefined) {
    whereClauses.push("assertions.issued_at >= ?");
    params.push(normalizeReportingDateBoundary(input.issuedFrom, "start"));
  }

  if (input.issuedTo !== undefined) {
    whereClauses.push("assertions.issued_at <= ?");
    params.push(normalizeReportingDateBoundary(input.issuedTo, "end"));
  }

  if (input.badgeTemplateId !== undefined) {
    whereClauses.push("assertions.badge_template_id = ?");
    params.push(input.badgeTemplateId);
  }

  if (input.orgUnitId !== undefined) {
    whereClauses.push("attribution.org_unit_id = ?");
    params.push(input.orgUnitId);
  }

  if (input.recipientQuery !== undefined) {
    const normalizedQuery = `%${input.recipientQuery.trim().toLowerCase()}%`;
    whereClauses.push(
      `(
        LOWER(assertions.recipient_identity) LIKE ?
        OR LOWER(assertions.id) LIKE ?
        OR LOWER(COALESCE(assertions.public_id, '')) LIKE ?
      )`,
    );
    params.push(normalizedQuery, normalizedQuery, normalizedQuery);
  }

  if (input.state !== undefined) {
    whereClauses.push(
      `(
        CASE
          WHEN assertions.revoked_at IS NOT NULL THEN 'revoked'
          WHEN lifecycle.to_state IS NOT NULL THEN lifecycle.to_state
          ELSE 'active'
        END
      ) = ?`,
    );
    params.push(input.state);
  }

  const rowLimit = SYNCHRONOUS_EXPORT_ROW_LIMIT;
  const listStatement = (): Promise<SqlQueryResult<TenantAssertionLedgerExportRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.tenant_id AS tenantId,
          assertions.public_id AS publicId,
          assertions.badge_template_id AS badgeTemplateId,
          badge_templates.title AS badgeTitle,
          assertions.recipient_identity AS recipientIdentity,
          assertions.recipient_identity_type AS recipientIdentityType,
          assertions.issued_at AS issuedAt,
          assertions.issued_by_user_id AS issuedByUserId,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode,
          lifecycle.reason AS latestReason,
          lifecycle.transitioned_at AS latestTransitionedAt,
          attribution.org_unit_id AS orgUnitId,
          COALESCE(org_units.display_name, attribution.org_unit_id) AS orgUnitDisplayName,
          attribution.attribution_source AS attributionSource
        FROM assertions
        INNER JOIN badge_templates
          ON badge_templates.tenant_id = assertions.tenant_id
          AND badge_templates.id = assertions.badge_template_id
        INNER JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        LEFT JOIN tenant_org_units org_units
          ON org_units.tenant_id = assertions.tenant_id
          AND org_units.id = attribution.org_unit_id
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at DESC, assertions.id DESC
        LIMIT ?
      `,
      )
      .bind(...params, rowLimit + 1)
      .all<TenantAssertionLedgerExportRow>();

  let rows: TenantAssertionLedgerExportRow[];

  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      rows = (await listStatement()).results;
      const orgUnits = await listTenantOrgUnits(db, {
        tenantId: input.tenantId,
      });
      const orgUnitsById = new Map(orgUnits.map((orgUnit) => [orgUnit.id, orgUnit] as const));

      if (rows.length > rowLimit) {
        return {
          status: "too_large",
          rowLimit,
        };
      }

      return {
        status: "ok",
        rowLimit,
        rows: rows.map((row) => mapTenantAssertionLedgerExportRow(row, orgUnitsById)),
      };
    } catch (error: unknown) {
      if (isMissingAssertionReportingAttributionsTableError(error)) {
        await ensureAssertionReportingAttributionsTable(db);
        await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);
        continue;
      }

      if (isMissingAssertionLifecycleEventsTableError(error)) {
        await ensureAssertionLifecycleEventsTable(db);
        continue;
      }

      if (isMissingTenantOrgUnitsTableError(error)) {
        await ensureTenantOrgUnitsTable(db);
        continue;
      }

      throw error;
    }
  }

  throw new Error("Unable to load tenant assertion ledger export rows after retrying setup");
};

const normalizeReportingDateBoundary = (value: string, boundary: "start" | "end"): string => {
  const trimmed = value.trim();
  const date = trimmed.includes("T")
    ? new Date(trimmed)
    : new Date(`${trimmed}${boundary === "start" ? "T00:00:00.000Z" : "T23:59:59.999Z"}`);

  if (!Number.isFinite(date.getTime())) {
    throw new Error(`Invalid reporting date boundary: ${value}`);
  }

  return date.toISOString();
};

export const findAssertionReportingAttributionByAssertionId = async (
  db: SqlDatabase,
  assertionId: string,
): Promise<AssertionReportingAttributionRecord | null> => {
  const lookupStatement = (): Promise<AssertionReportingAttributionRow | null> =>
    db
      .prepare(
        `
        SELECT
          assertion_id AS assertionId,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          org_unit_id AS orgUnitId,
          attribution_source AS attributionSource,
          attributed_at AS attributedAt,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM assertion_reporting_attributions
        WHERE assertion_id = ?
        LIMIT 1
      `,
      )
      .bind(assertionId)
      .first<AssertionReportingAttributionRow>();

  let row: AssertionReportingAttributionRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingAssertionReportingAttributionsTableError(error)) {
      throw error;
    }

    await ensureAssertionReportingAttributionsTable(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapAssertionReportingAttributionRow(row);
};

const upsertAssertionReportingAttribution = async (
  db: SqlDatabase,
  input: {
    assertionId: string;
    tenantId: string;
    badgeTemplateId: string;
    orgUnitId: string;
    attributionSource: AssertionReportingAttributionSource;
    attributedAt: string;
  },
): Promise<AssertionReportingAttributionRecord> => {
  const nowIso = new Date().toISOString();
  const upsertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO assertion_reporting_attributions (
          assertion_id,
          tenant_id,
          badge_template_id,
          org_unit_id,
          attribution_source,
          attributed_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (assertion_id)
        DO UPDATE SET
          tenant_id = excluded.tenant_id,
          badge_template_id = excluded.badge_template_id,
          org_unit_id = excluded.org_unit_id,
          attribution_source = excluded.attribution_source,
          attributed_at = excluded.attributed_at,
          updated_at = excluded.updated_at
      `,
      )
      .bind(
        input.assertionId,
        input.tenantId,
        input.badgeTemplateId,
        input.orgUnitId,
        input.attributionSource,
        input.attributedAt,
        nowIso,
        nowIso,
      )
      .run();

  try {
    await upsertStatement();
  } catch (error: unknown) {
    if (!isMissingAssertionReportingAttributionsTableError(error)) {
      throw error;
    }

    await ensureAssertionReportingAttributionsTable(db);
    await upsertStatement();
  }

  const attribution = await findAssertionReportingAttributionByAssertionId(db, input.assertionId);

  if (attribution === null) {
    throw new Error(`Unable to load reporting attribution for assertion "${input.assertionId}"`);
  }

  return attribution;
};

const backfillAssertionReportingAttributionsForTenant = async (
  db: SqlDatabase,
  tenantId: string,
): Promise<number> => {
  type MissingAttributionRow = {
    assertionId: string;
    badgeTemplateId: string;
    currentOwnerOrgUnitId: string;
    issuedAt: string;
  };

  const missingStatement = (): Promise<SqlQueryResult<MissingAttributionRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.badge_template_id AS badgeTemplateId,
          badge_templates.owner_org_unit_id AS currentOwnerOrgUnitId,
          assertions.issued_at AS issuedAt
        FROM assertions
        INNER JOIN badge_templates
          ON badge_templates.tenant_id = assertions.tenant_id
          AND badge_templates.id = assertions.badge_template_id
        LEFT JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        WHERE assertions.tenant_id = ?
          AND attribution.assertion_id IS NULL
        ORDER BY assertions.issued_at ASC, assertions.id ASC
      `,
      )
      .bind(tenantId)
      .all<MissingAttributionRow>();

  let missingRows: MissingAttributionRow[];

  try {
    missingRows = (await missingStatement()).results;
  } catch (error: unknown) {
    if (isMissingAssertionReportingAttributionsTableError(error)) {
      await ensureAssertionReportingAttributionsTable(db);
      missingRows = (await missingStatement()).results;
    } else if (isMissingTenantOrgUnitsTableError(error)) {
      await ensureTenantOrgUnitsTable(db);
      missingRows = (await missingStatement()).results;
    } else {
      throw error;
    }
  }

  if (missingRows.length === 0) {
    return 0;
  }

  const ownershipEventsByTemplateId = new Map<string, BadgeTemplateOwnershipEventRecord[]>();

  for (const badgeTemplateId of new Set(missingRows.map((row) => row.badgeTemplateId))) {
    ownershipEventsByTemplateId.set(
      badgeTemplateId,
      await listBadgeTemplateOwnershipEvents(db, {
        tenantId,
        badgeTemplateId,
        limit: 5000,
      }),
    );
  }

  for (const row of missingRows) {
    const attribution = resolveAssertionReportingAttribution({
      issuedAt: row.issuedAt,
      currentOwnerOrgUnitId: row.currentOwnerOrgUnitId,
      ownershipEvents: ownershipEventsByTemplateId.get(row.badgeTemplateId) ?? [],
    });

    await upsertAssertionReportingAttribution(db, {
      assertionId: row.assertionId,
      tenantId,
      badgeTemplateId: row.badgeTemplateId,
      orgUnitId: attribution.orgUnitId,
      attributionSource: attribution.attributionSource,
      attributedAt: attribution.attributedAt,
    });
  }

  return missingRows.length;
};

const findAssertionEngagementEventById = async (
  db: SqlDatabase,
  id: string,
): Promise<AssertionEngagementEventRecord | null> => {
  const lookupStatement = (): Promise<AssertionEngagementEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          event_type AS eventType,
          actor_type AS actorType,
          channel,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM assertion_engagement_events
        WHERE id = ?
        LIMIT 1
      `,
      )
      .bind(id)
      .first<AssertionEngagementEventRow>();

  let row: AssertionEngagementEventRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingAssertionEngagementEventsTableError(error)) {
      throw error;
    }

    await ensureAssertionEngagementEventsTable(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapAssertionEngagementEventRow(row);
};

const findAssertionEngagementEventByType = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
  eventType: AssertionEngagementEventType,
): Promise<AssertionEngagementEventRecord | null> => {
  const lookupStatement = (): Promise<AssertionEngagementEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          event_type AS eventType,
          actor_type AS actorType,
          channel,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM assertion_engagement_events
        WHERE tenant_id = ?
          AND assertion_id = ?
          AND event_type = ?
        ORDER BY occurred_at ASC, created_at ASC, id ASC
        LIMIT 1
      `,
      )
      .bind(tenantId, assertionId, eventType)
      .first<AssertionEngagementEventRow>();

  let row: AssertionEngagementEventRow | null;

  try {
    row = await lookupStatement();
  } catch (error: unknown) {
    if (!isMissingAssertionEngagementEventsTableError(error)) {
      throw error;
    }

    await ensureAssertionEngagementEventsTable(db);
    row = await lookupStatement();
  }

  return row === null ? null : mapAssertionEngagementEventRow(row);
};

export const listAssertionEngagementEvents = async (
  db: SqlDatabase,
  input: ListAssertionEngagementEventsInput,
): Promise<AssertionEngagementEventRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 50, 200));
  const listStatement = (): Promise<SqlQueryResult<AssertionEngagementEventRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          event_type AS eventType,
          actor_type AS actorType,
          channel,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM assertion_engagement_events
        WHERE tenant_id = ?
          AND assertion_id = ?
        ORDER BY occurred_at DESC, created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.assertionId, queryLimit)
      .all<AssertionEngagementEventRow>();

  let result: SqlQueryResult<AssertionEngagementEventRow>;

  try {
    result = await listStatement();
  } catch (error: unknown) {
    if (!isMissingAssertionEngagementEventsTableError(error)) {
      throw error;
    }

    await ensureAssertionEngagementEventsTable(db);
    result = await listStatement();
  }

  return result.results.map((row) => mapAssertionEngagementEventRow(row));
};

export const recordAssertionEngagementEvent = async (
  db: SqlDatabase,
  input: RecordAssertionEngagementEventInput,
): Promise<RecordAssertionEngagementEventResult> => {
  const assertion = await findAssertionById(db, input.tenantId, input.assertionId);

  if (assertion === null) {
    throw new Error(`Assertion ${input.assertionId} not found for tenant ${input.tenantId}`);
  }

  const existingAttribution = await findAssertionReportingAttributionByAssertionId(
    db,
    input.assertionId,
  );

  if (existingAttribution === null) {
    await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);
  }

  if (ONE_SHOT_ASSERTION_ENGAGEMENT_EVENT_TYPES.has(input.eventType)) {
    const existingEvent = await findAssertionEngagementEventByType(
      db,
      input.tenantId,
      input.assertionId,
      input.eventType,
    );

    if (existingEvent !== null) {
      return {
        status: "already_recorded",
        event: existingEvent,
      };
    }
  }

  assertValidIsoTimestamp(input.occurredAt, "occurredAt");

  const normalizedChannel = input.channel?.trim();
  const channel =
    normalizedChannel === undefined || normalizedChannel.length === 0 ? null : normalizedChannel;
  const eventId = createPrefixedId("aee");
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO assertion_engagement_events (
          id,
          tenant_id,
          assertion_id,
          event_type,
          actor_type,
          channel,
          occurred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        eventId,
        input.tenantId,
        input.assertionId,
        input.eventType,
        input.actorType,
        channel,
        input.occurredAt,
        input.occurredAt,
      )
      .run();

  try {
    await insertStatement();
  } catch (error: unknown) {
    if (!isMissingAssertionEngagementEventsTableError(error)) {
      throw error;
    }

    await ensureAssertionEngagementEventsTable(db);
    await insertStatement();
  }

  const event = await findAssertionEngagementEventById(db, eventId);

  if (event === null) {
    throw new Error(`Unable to load assertion engagement event ${eventId} after insert`);
  }

  return {
    status: "recorded",
    event,
  };
};

const listTenantReportingEngagementRows = async (
  db: SqlDatabase,
  input: GetTenantReportingEngagementCountsInput,
): Promise<TenantReportingEngagementRow[]> => {
  await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);

  const whereClauses = ["assertions.tenant_id = ?"];
  const params: unknown[] = [input.tenantId];

  if (input.from !== undefined) {
    whereClauses.push("assertions.issued_at >= ?");
    params.push(normalizeReportingDateBoundary(input.from, "start"));
  }

  if (input.to !== undefined) {
    whereClauses.push("assertions.issued_at <= ?");
    params.push(normalizeReportingDateBoundary(input.to, "end"));
  }

  if (input.badgeTemplateId !== undefined) {
    whereClauses.push("attribution.badge_template_id = ?");
    params.push(input.badgeTemplateId);
  }

  if (input.orgUnitId !== undefined) {
    whereClauses.push("attribution.org_unit_id = ?");
    params.push(input.orgUnitId);
  }

  const listStatement = (): Promise<SqlQueryResult<TenantReportingEngagementRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          attribution.badge_template_id AS badgeTemplateId,
          attribution.org_unit_id AS orgUnitId,
          assertions.issued_at AS issuedAt,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode,
          events.event_type AS eventType,
          events.occurred_at AS occurredAt
        FROM assertions
        INNER JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        LEFT JOIN assertion_engagement_events events
          ON events.tenant_id = assertions.tenant_id
          AND events.assertion_id = assertions.id
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at ASC, assertions.id ASC, events.occurred_at ASC, events.id ASC
      `,
      )
      .bind(...params)
      .all<TenantReportingEngagementRow>();

  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return (await listStatement()).results;
    } catch (error: unknown) {
      if (isMissingAssertionReportingAttributionsTableError(error)) {
        await ensureAssertionReportingAttributionsTable(db);
        await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);
        continue;
      }

      if (isMissingAssertionEngagementEventsTableError(error)) {
        await ensureAssertionEngagementEventsTable(db);
        continue;
      }

      if (isMissingAssertionLifecycleEventsTableError(error)) {
        await ensureAssertionLifecycleEventsTable(db);
        continue;
      }

      throw error;
    }
  }

  throw new Error("Unable to load tenant reporting engagement rows after retrying table setup");
};

export const getTenantReportingEngagementCounts = async (
  db: SqlDatabase,
  input: GetTenantReportingEngagementCountsInput,
): Promise<TenantReportingEngagementCounts> => {
  const rows = await listTenantReportingEngagementRows(db, input);
  return summarizeTenantReportingEngagementCounts(rows, input);
};

export const getTenantReportingTrends = async (
  db: SqlDatabase,
  input: GetTenantReportingTrendsInput,
): Promise<TenantReportingTrendRecord> => {
  const rows = await listTenantReportingEngagementRows(db, input);

  return {
    tenantId: input.tenantId,
    filters: {
      from: input.from ?? null,
      to: input.to ?? null,
      badgeTemplateId: input.badgeTemplateId ?? null,
      orgUnitId: input.orgUnitId ?? null,
      state: input.state ?? null,
    },
    bucket: input.bucket,
    series: summarizeTenantReportingTrendRows(rows, input),
    generatedAt: new Date().toISOString(),
  };
};

export const listTenantReportingComparisons = async (
  db: SqlDatabase,
  input: ListTenantReportingComparisonsInput,
): Promise<TenantReportingComparisonRowRecord[]> => {
  const rows = await listTenantReportingEngagementRows(db, input);
  return summarizeTenantReportingComparisonRows(rows, input);
};

export const getTenantExecutiveRollup = async (
  db: SqlDatabase,
  input: GetTenantExecutiveRollupInput,
): Promise<GetTenantExecutiveRollupResult> => {
  const [rows, orgUnits] = await Promise.all([
    listTenantReportingEngagementRows(db, {
      tenantId: input.tenantId,
      from: input.from,
      to: input.to,
      badgeTemplateId: input.badgeTemplateId,
      orgUnitId: input.orgUnitId,
      state: input.state,
    }),
    listTenantOrgUnits(db, {
      tenantId: input.tenantId,
      includeInactive: true,
    }),
  ]);

  return {
    tenantId: input.tenantId,
    ...summarizeTenantExecutiveRollup({
      rows,
      orgUnits: orgUnits.map((orgUnit) => {
        return {
          id: orgUnit.id,
          unitType: orgUnit.unitType,
          displayName: orgUnit.displayName,
          parentOrgUnitId: orgUnit.parentOrgUnitId,
        };
      }),
      query: {
        from: input.from,
        to: input.to,
        badgeTemplateId: input.badgeTemplateId,
        orgUnitId: input.orgUnitId,
        state: input.state,
        focusOrgUnitId: input.focusOrgUnitId,
        comparisonLevel: input.comparisonLevel,
      },
      scopedRootOrgUnitIds: input.scopedRootOrgUnitIds,
    }),
    generatedAt: new Date().toISOString(),
  };
};

export const getTenantReportingOverview = async (
  db: SqlDatabase,
  input: GetTenantReportingOverviewInput,
): Promise<TenantReportingOverviewRecord> => {
  await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);

  const whereClauses = ["assertions.tenant_id = ?"];
  const params: unknown[] = [input.tenantId];

  if (input.issuedFrom !== undefined) {
    whereClauses.push("assertions.issued_at >= ?");
    params.push(normalizeReportingDateBoundary(input.issuedFrom, "start"));
  }

  if (input.issuedTo !== undefined) {
    whereClauses.push("assertions.issued_at <= ?");
    params.push(normalizeReportingDateBoundary(input.issuedTo, "end"));
  }

  if (input.badgeTemplateId !== undefined) {
    whereClauses.push("assertions.badge_template_id = ?");
    params.push(input.badgeTemplateId);
  }

  if (input.orgUnitId !== undefined) {
    whereClauses.push("attribution.org_unit_id = ?");
    params.push(input.orgUnitId);
  }

  const overviewStatement = (): Promise<SqlQueryResult<TenantReportingOverviewRow>> =>
    db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.issued_at AS issuedAt,
          assertions.badge_template_id AS badgeTemplateId,
          attribution.org_unit_id AS orgUnitId,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode
        FROM assertions
        INNER JOIN assertion_reporting_attributions attribution
          ON attribution.assertion_id = assertions.id
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        WHERE ${whereClauses.join("\n          AND ")}
        ORDER BY assertions.issued_at DESC, assertions.id DESC
      `,
      )
      .bind(...params)
      .all<TenantReportingOverviewRow>();

  let rows: TenantReportingOverviewRow[];

  try {
    rows = (await overviewStatement()).results;
  } catch (error: unknown) {
    if (isMissingAssertionReportingAttributionsTableError(error)) {
      await ensureAssertionReportingAttributionsTable(db);
      await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);
      rows = (await overviewStatement()).results;
    } else if (isMissingAssertionLifecycleEventsTableError(error)) {
      await ensureAssertionLifecycleEventsTable(db);
      rows = (await overviewStatement()).results;
    } else {
      throw error;
    }
  }

  const engagementCounts = await getTenantReportingEngagementCounts(db, {
    tenantId: input.tenantId,
    from: input.issuedFrom,
    to: input.issuedTo,
    badgeTemplateId: input.badgeTemplateId,
    orgUnitId: input.orgUnitId,
    state: input.state,
  });

  return {
    tenantId: input.tenantId,
    filters: {
      issuedFrom: input.issuedFrom ?? null,
      issuedTo: input.issuedTo ?? null,
      badgeTemplateId: input.badgeTemplateId ?? null,
      orgUnitId: input.orgUnitId ?? null,
      state: input.state ?? null,
    },
    counts: {
      ...summarizeTenantReportingOverviewRows(rows, input.state),
      claimRate: engagementCounts.claimRate,
      shareRate: engagementCounts.shareRate,
    },
    generatedAt: new Date().toISOString(),
  };
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

  if (identifierType === "emailAddress") {
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
          INSERT INTO recipient_identifiers (
            assertion_id,
            identifier_type,
            identifier_value,
            created_at
          )
          VALUES (?, ?, ?, ?)
          ON CONFLICT DO NOTHING
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
  const badgeTemplate = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (badgeTemplate === null) {
    throw new Error(
      `Badge template ${input.badgeTemplateId} not found for tenant ${input.tenantId}`,
    );
  }

  await upsertAssertionReportingAttribution(db, {
    assertionId: input.id,
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    orgUnitId: badgeTemplate.ownerOrgUnitId,
    attributionSource: "issuance_snapshot",
    attributedAt: input.issuedAt,
  });

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
    throw new Error("Queue payload is not JSON serializable");
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

const migrationBatchPayloadFromJson = (
  payloadJson: string,
): {
  source: MigrationBatchSource;
  batchId: string;
  rowNumber: number | null;
  fileName: string | null;
  format: string | null;
} | null => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(payloadJson) as unknown;
  } catch {
    return null;
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }

  const payload = parsed as Record<string, unknown>;
  const rawBatchId = payload.batchId;

  if (typeof rawBatchId !== "string") {
    return null;
  }

  const batchId = rawBatchId.trim();

  if (batchId.length === 0) {
    return null;
  }

  const source =
    payload.source === "file_upload" ||
    payload.source === "credly_export" ||
    payload.source === "parchment_export"
      ? payload.source
      : "unknown";
  const rowNumberRaw = payload.rowNumber;
  const rowNumber =
    typeof rowNumberRaw === "number" && Number.isInteger(rowNumberRaw) && rowNumberRaw > 0
      ? rowNumberRaw
      : null;
  const fileName =
    typeof payload.fileName === "string" && payload.fileName.trim().length > 0
      ? payload.fileName.trim()
      : null;
  const format =
    typeof payload.format === "string" && payload.format.trim().length > 0
      ? payload.format.trim()
      : null;

  return {
    source,
    batchId,
    rowNumber,
    fileName,
    format,
  };
};

const learnerRecordImportBatchPayloadFromJson = (
  payloadJson: string,
): {
  batchId: string;
  rowNumber: number | null;
  fileName: string | null;
  format: string | null;
  defaultTrustLevel: LearnerRecordTrustLevel | null;
} | null => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(payloadJson) as unknown;
  } catch {
    return null;
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }

  const payload = parsed as Record<string, unknown>;
  const rawBatchId = payload.batchId;

  if (typeof rawBatchId !== "string") {
    return null;
  }

  const batchId = rawBatchId.trim();

  if (batchId.length === 0) {
    return null;
  }

  const rowNumberRaw = payload.rowNumber;
  const rowNumber =
    typeof rowNumberRaw === "number" && Number.isInteger(rowNumberRaw) && rowNumberRaw > 0
      ? rowNumberRaw
      : null;
  const fileName =
    typeof payload.fileName === "string" && payload.fileName.trim().length > 0
      ? payload.fileName.trim()
      : null;
  const format =
    typeof payload.format === "string" && payload.format.trim().length > 0
      ? payload.format.trim()
      : null;

  let defaultTrustLevel: LearnerRecordTrustLevel | null = null;

  if (
    payload.row !== null &&
    typeof payload.row === "object" &&
    !Array.isArray(payload.row) &&
    (payload.row as Record<string, unknown>).effectiveTrustLevel !== undefined
  ) {
    const effectiveTrustLevel = (payload.row as Record<string, unknown>).effectiveTrustLevel;

    if (
      effectiveTrustLevel === "issuer_verified" ||
      effectiveTrustLevel === "learner_supplemental"
    ) {
      defaultTrustLevel = effectiveTrustLevel;
    }
  }

  return {
    batchId,
    rowNumber,
    fileName,
    format,
    defaultTrustLevel,
  };
};

export const recordAuthMagicLinkRateLimitAttempt = async (
  db: SqlDatabase,
  input: RecordAuthMagicLinkRateLimitAttemptInput,
): Promise<void> => {
  await db
    .prepare(
      `
      INSERT INTO auth_magic_link_rate_limit_attempts (
        id,
        dimension_type,
        dimension_hash,
        occurred_at
      )
      VALUES (?, ?, ?, ?)
    `,
    )
    .bind(createPrefixedId("amlrl"), input.dimensionType, input.dimensionHash, input.occurredAt)
    .run();
};

export const countAuthMagicLinkRateLimitAttempts = async (
  db: SqlDatabase,
  input: CountAuthMagicLinkRateLimitAttemptsInput,
): Promise<number> => {
  const row = await db
    .prepare(
      `
      SELECT COUNT(*) AS count
      FROM auth_magic_link_rate_limit_attempts
      WHERE dimension_type = ?
        AND dimension_hash = ?
        AND occurred_at >= ?
    `,
    )
    .bind(input.dimensionType, input.dimensionHash, input.sinceIso)
    .first<{ count: number | string }>();

  if (row === null) {
    return 0;
  }

  const count = typeof row.count === "number" ? row.count : Number.parseInt(row.count, 10);
  return Number.isFinite(count) ? count : 0;
};

export const pruneAuthMagicLinkRateLimitAttempts = async (
  db: SqlDatabase,
  beforeIso: string,
): Promise<void> => {
  await db
    .prepare(
      `
      DELETE FROM auth_magic_link_rate_limit_attempts
      WHERE occurred_at < ?
    `,
    )
    .bind(beforeIso)
    .run();
};

export const enqueueJobQueueMessage = async (
  db: SqlDatabase,
  input: EnqueueJobQueueMessageInput,
): Promise<JobQueueMessageRecord> => {
  const messageId = createPrefixedId("job");
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
    status: "pending",
    createdAt: nowIso,
    updatedAt: nowIso,
  };
};

export const leaseJobQueueMessages = async (
  db: SqlDatabase,
  input: LeaseJobQueueMessagesInput,
): Promise<JobQueueMessageRecord[]> => {
  const leaseToken = createPrefixedId("lease");
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

export const listImportMigrationBatchQueueMessages = async (
  db: SqlDatabase,
  input: ListImportMigrationBatchQueueMessagesInput,
): Promise<ImportMigrationBatchQueueMessageRecord[]> => {
  const limit = input.limit ?? 200;
  const boundedLimit = Math.max(1, Math.min(limit, 1000));
  const result = await db
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
      WHERE tenant_id = ?
        AND job_type = 'import_migration_batch'
      ORDER BY created_at DESC
      LIMIT ?
    `,
    )
    .bind(input.tenantId, boundedLimit)
    .all<JobQueueMessageRow>();
  const parsedMessages: ImportMigrationBatchQueueMessageRecord[] = [];

  for (const row of result.results) {
    const payload = migrationBatchPayloadFromJson(row.payloadJson);

    if (payload === null) {
      continue;
    }

    if (input.source !== undefined && payload.source !== input.source) {
      continue;
    }

    parsedMessages.push({
      ...mapJobQueueMessageRow(row),
      source: payload.source,
      batchId: payload.batchId,
      rowNumber: payload.rowNumber,
      fileName: payload.fileName,
      format: payload.format,
    });
  }

  return parsedMessages;
};

export const retryFailedImportMigrationBatchQueueMessages = async (
  db: SqlDatabase,
  input: RetryFailedImportMigrationBatchQueueMessagesInput,
): Promise<RetryFailedImportMigrationBatchQueueMessagesResult> => {
  const nowIso = input.nowIso ?? new Date().toISOString();
  const rowNumberFilter = input.rowNumbers === undefined ? null : new Set<number>(input.rowNumbers);
  const candidateRows = await listImportMigrationBatchQueueMessages(db, {
    tenantId: input.tenantId,
    ...(input.source === undefined ? {} : { source: input.source }),
    limit: 1000,
  });
  let matched = 0;
  let retried = 0;
  let skippedNotFailed = 0;

  for (const row of candidateRows) {
    if (row.batchId !== input.batchId) {
      continue;
    }

    if (
      rowNumberFilter !== null &&
      (row.rowNumber === null || !rowNumberFilter.has(row.rowNumber))
    ) {
      continue;
    }

    matched += 1;

    if (row.status !== "failed") {
      skippedNotFailed += 1;
      continue;
    }

    await db
      .prepare(
        `
        UPDATE job_queue_messages
        SET status = 'pending',
            attempt_count = 0,
            available_at = ?,
            leased_until = NULL,
            lease_token = NULL,
            last_error = NULL,
            failed_at = NULL,
            updated_at = ?
        WHERE id = ?
          AND tenant_id = ?
          AND job_type = 'import_migration_batch'
      `,
      )
      .bind(nowIso, nowIso, row.id, input.tenantId)
      .run();
    retried += 1;
  }

  return {
    matched,
    retried,
    skippedNotFailed,
  };
};

export const listImportLearnerRecordBatchQueueMessages = async (
  db: SqlDatabase,
  input: ListImportLearnerRecordBatchQueueMessagesInput,
): Promise<ImportLearnerRecordBatchQueueMessageRecord[]> => {
  const limit = input.limit ?? 200;
  const boundedLimit = Math.max(1, Math.min(limit, 1000));
  const result = await db
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
      WHERE tenant_id = ?
        AND job_type = 'import_learner_record_batch'
      ORDER BY created_at DESC
      LIMIT ?
    `,
    )
    .bind(input.tenantId, boundedLimit)
    .all<JobQueueMessageRow>();
  const parsedMessages: ImportLearnerRecordBatchQueueMessageRecord[] = [];

  for (const row of result.results) {
    const payload = learnerRecordImportBatchPayloadFromJson(row.payloadJson);

    if (payload === null) {
      continue;
    }

    parsedMessages.push({
      ...mapJobQueueMessageRow(row),
      batchId: payload.batchId,
      rowNumber: payload.rowNumber,
      fileName: payload.fileName,
      format: payload.format,
      defaultTrustLevel: payload.defaultTrustLevel,
    });
  }

  return parsedMessages;
};

export const retryFailedImportLearnerRecordBatchQueueMessages = async (
  db: SqlDatabase,
  input: RetryFailedImportLearnerRecordBatchQueueMessagesInput,
): Promise<RetryFailedImportLearnerRecordBatchQueueMessagesResult> => {
  const nowIso = input.nowIso ?? new Date().toISOString();
  const rowNumberFilter = input.rowNumbers === undefined ? null : new Set<number>(input.rowNumbers);
  const candidateRows = await listImportLearnerRecordBatchQueueMessages(db, {
    tenantId: input.tenantId,
    limit: 1000,
  });
  let matched = 0;
  let retried = 0;
  let skippedNotFailed = 0;

  for (const row of candidateRows) {
    if (row.batchId !== input.batchId) {
      continue;
    }

    if (
      rowNumberFilter !== null &&
      (row.rowNumber === null || !rowNumberFilter.has(row.rowNumber))
    ) {
      continue;
    }

    matched += 1;

    if (row.status !== "failed") {
      skippedNotFailed += 1;
      continue;
    }

    await db
      .prepare(
        `
        UPDATE job_queue_messages
        SET status = 'pending',
            attempt_count = 0,
            available_at = ?,
            leased_until = NULL,
            lease_token = NULL,
            last_error = NULL,
            failed_at = NULL,
            updated_at = ?
        WHERE id = ?
          AND tenant_id = ?
          AND job_type = 'import_learner_record_batch'
      `,
      )
      .bind(nowIso, nowIso, row.id, input.tenantId)
      .run();
    retried += 1;
  }

  return {
    matched,
    retried,
    skippedNotFailed,
  };
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
      INSERT INTO revocations (
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
      ON CONFLICT DO NOTHING
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
    status: assertion.revokedAt === null ? "revoked" : "already_revoked",
    revokedAt: effectiveRevokedAt,
  };
};
