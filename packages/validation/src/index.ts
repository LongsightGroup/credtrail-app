import { z } from 'zod';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];

export interface JsonObject {
  [key: string]: JsonValue;
}

export const queueJobTypeSchema = z.enum([
  'issue_badge',
  'revoke_badge',
  'rebuild_verification_cache',
  'import_migration_batch',
]);

export const idempotencyKeySchema = z.string().min(1).max(128);

export const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([z.string(), z.number().finite(), z.boolean(), z.null(), z.array(jsonValueSchema), z.record(jsonValueSchema)]),
);

export const jsonObjectSchema: z.ZodType<JsonObject> = z.record(jsonValueSchema);

export const didWebSchema = z.string().startsWith('did:web:');

export const ed25519PublicJwkSchema = z.object({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  x: z.string().min(1),
  kid: z.string().min(1).optional(),
});

export const ed25519PrivateJwkSchema = ed25519PublicJwkSchema.extend({
  d: z.string().min(1),
});

export const p256PublicJwkSchema = z.object({
  kty: z.literal('EC'),
  crv: z.literal('P-256'),
  x: z.string().min(1),
  y: z.string().min(1),
  kid: z.string().min(1).optional(),
});

export const p256PrivateJwkSchema = p256PublicJwkSchema.extend({
  d: z.string().min(1),
});

const tenantSigningRegistryEntryEd25519Schema = z.object({
  tenantId: z.string().min(1),
  keyId: z.string().min(1),
  publicJwk: ed25519PublicJwkSchema,
  privateJwk: ed25519PrivateJwkSchema.optional(),
});

const tenantSigningRegistryEntryP256Schema = z.object({
  tenantId: z.string().min(1),
  keyId: z.string().min(1),
  publicJwk: p256PublicJwkSchema,
  privateJwk: p256PrivateJwkSchema.optional(),
});

export const tenantSigningRegistryEntrySchema = z.union([
  tenantSigningRegistryEntryEd25519Schema,
  tenantSigningRegistryEntryP256Schema,
]);

export const tenantSigningRegistrySchema = z.record(z.string().min(1), tenantSigningRegistryEntrySchema);

export const keyGenerationRequestSchema = z.object({
  did: didWebSchema,
  keyId: z.string().min(1).max(128).optional(),
});

export const signCredentialRequestSchema = z.object({
  did: didWebSchema,
  credential: jsonObjectSchema,
  proofType: z.enum(['Ed25519Signature2020', 'DataIntegrityProof']).optional(),
  cryptosuite: z.enum(['eddsa-rdfc-2022', 'ecdsa-sd-2023']).optional(),
}).superRefine((value, ctx) => {
  if (value.proofType === 'DataIntegrityProof' && value.cryptosuite === undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['cryptosuite'],
      message: 'cryptosuite is required when proofType is DataIntegrityProof',
    });
  }

  if (value.proofType !== 'DataIntegrityProof' && value.cryptosuite !== undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['cryptosuite'],
      message: 'cryptosuite is only allowed when proofType is DataIntegrityProof',
    });
  }
});

export const tenantIdSchema = z.string().min(1);
export const resourceIdSchema = z.string().min(1);
export const userIdSchema = z.string().min(1);
export const isoTimestampSchema = z.string().datetime();
export const tenantPlanTierSchema = z.enum(['free', 'team', 'institution', 'enterprise']);
export const tenantMembershipRoleSchema = z.enum(['owner', 'admin', 'issuer', 'viewer']);
export const recipientIdentityTypeSchema = z.enum(['email', 'email_sha256', 'did', 'url']);
export const recipientIdentifierTypeSchema = z.enum([
  'emailAddress',
  'sourcedId',
  'did',
  'nationalIdentityNumber',
  'studentId',
]);
export const recipientIdentifierSchema = z.object({
  identifierType: recipientIdentifierTypeSchema,
  identifier: z.string().trim().min(1).max(512),
});
export const badgeTemplateSlugSchema = z
  .string()
  .trim()
  .min(2)
  .max(96)
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
export const badgeTemplateTitleSchema = z.string().trim().min(1).max(200);
export const badgeTemplateDescriptionSchema = z.string().trim().min(1).max(2000);
export const badgeTemplateUriSchema = z.string().url().max(2048);

export const tenantPathParamsSchema = z.object({
  tenantId: tenantIdSchema,
});

export const badgeTemplatePathParamsSchema = tenantPathParamsSchema.extend({
  badgeTemplateId: resourceIdSchema,
});

export const tenantUserPathParamsSchema = tenantPathParamsSchema.extend({
  userId: userIdSchema,
});

export const credentialPathParamsSchema = z.object({
  credentialId: resourceIdSchema,
});

export const badgeTemplateListQuerySchema = z.object({
  includeArchived: z.preprocess((input) => {
    if (input === undefined) {
      return false;
    }

    if (input === 'true') {
      return true;
    }

    if (input === 'false') {
      return false;
    }

    return input;
  }, z.boolean()),
});

export const createBadgeTemplateRequestSchema = z.object({
  slug: badgeTemplateSlugSchema,
  title: badgeTemplateTitleSchema,
  description: badgeTemplateDescriptionSchema.optional(),
  criteriaUri: badgeTemplateUriSchema.optional(),
  imageUri: badgeTemplateUriSchema.optional(),
});

export const updateBadgeTemplateRequestSchema = z
  .object({
    slug: badgeTemplateSlugSchema.optional(),
    title: badgeTemplateTitleSchema.optional(),
    description: badgeTemplateDescriptionSchema.nullable().optional(),
    criteriaUri: badgeTemplateUriSchema.nullable().optional(),
    imageUri: badgeTemplateUriSchema.nullable().optional(),
  })
  .refine(
    (payload) =>
      payload.slug !== undefined ||
      payload.title !== undefined ||
      payload.description !== undefined ||
      payload.criteriaUri !== undefined ||
      payload.imageUri !== undefined,
    {
      message: 'At least one badge template field must be provided',
    },
  );

export const adminUpsertTenantRequestSchema = z.object({
  slug: z
    .string()
    .trim()
    .min(1)
    .max(96)
    .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  displayName: z.string().trim().min(1).max(200),
  planTier: tenantPlanTierSchema.optional(),
  issuerDomain: z.string().trim().min(1).max(255).optional(),
  isActive: z.boolean().optional(),
});

const adminUpsertTenantSigningRegistrationEd25519RequestSchema = z.object({
  keyId: z.string().trim().min(1).max(128),
  publicJwk: ed25519PublicJwkSchema,
  privateJwk: ed25519PrivateJwkSchema.optional(),
});

const adminUpsertTenantSigningRegistrationP256RequestSchema = z.object({
  keyId: z.string().trim().min(1).max(128),
  publicJwk: p256PublicJwkSchema,
  privateJwk: p256PrivateJwkSchema.optional(),
});

export const adminUpsertTenantSigningRegistrationRequestSchema = z.union([
  adminUpsertTenantSigningRegistrationEd25519RequestSchema,
  adminUpsertTenantSigningRegistrationP256RequestSchema,
]);

export const adminUpsertBadgeTemplateByIdRequestSchema = createBadgeTemplateRequestSchema;

export const adminUpsertTenantMembershipRoleRequestSchema = z.object({
  role: tenantMembershipRoleSchema,
});

export const adminUpsertLtiIssuerRegistrationRequestSchema = z.object({
  issuer: z.string().url(),
  tenantId: tenantIdSchema,
  authorizationEndpoint: z.string().url(),
  clientId: z.string().trim().min(1).max(255),
  allowUnsignedIdToken: z.boolean().optional(),
});

export const adminDeleteLtiIssuerRegistrationRequestSchema = z.object({
  issuer: z.string().url(),
});

export const magicLinkRequestSchema = z.object({
  tenantId: tenantIdSchema,
  email: z.string().email(),
});

export const magicLinkVerifyRequestSchema = z.object({
  token: z.string().min(20),
});

export const learnerIdentityLinkRequestSchema = z.object({
  email: z.string().email(),
});

export const learnerIdentityLinkVerifyRequestSchema = z.object({
  token: z.string().min(20),
});

export const issueBadgeRequestSchema = z.object({
  tenantId: tenantIdSchema,
  badgeTemplateId: resourceIdSchema,
  recipientIdentity: z.string().min(1),
  recipientIdentityType: recipientIdentityTypeSchema,
  recipientIdentifiers: z.array(recipientIdentifierSchema).max(10).optional(),
  requestedByUserId: userIdSchema.optional(),
  idempotencyKey: idempotencyKeySchema.optional(),
});

export const manualIssueBadgeRequestSchema = issueBadgeRequestSchema.omit({
  tenantId: true,
  requestedByUserId: true,
});

export const githubUsernameSchema = z
  .string()
  .trim()
  .min(1)
  .max(39)
  .regex(/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/);

export const issueSakaiCommitBadgeRequestSchema = z.object({
  badgeTemplateId: resourceIdSchema,
  githubUsername: githubUsernameSchema,
  idempotencyKey: idempotencyKeySchema.optional(),
});

export const revokeBadgeRequestSchema = z.object({
  tenantId: tenantIdSchema,
  assertionId: resourceIdSchema,
  reason: z.string().min(1).max(512),
  requestedByUserId: userIdSchema.optional(),
  idempotencyKey: idempotencyKeySchema.optional(),
});

export const processQueueRequestSchema = z.object({
  limit: z.number().int().min(1).max(100).optional(),
  leaseSeconds: z.number().int().min(1).max(300).optional(),
  retryDelaySeconds: z.number().int().min(1).max(3600).optional(),
});

export const issueBadgeJobPayloadSchema = z.object({
  assertionId: resourceIdSchema,
  badgeTemplateId: resourceIdSchema,
  recipientIdentity: z.string().min(1),
  recipientIdentityType: recipientIdentityTypeSchema,
  recipientIdentifiers: z.array(recipientIdentifierSchema).max(10).optional(),
  requestedAt: isoTimestampSchema,
  requestedByUserId: userIdSchema.optional(),
});

export const revokeBadgeJobPayloadSchema = z.object({
  revocationId: resourceIdSchema,
  assertionId: resourceIdSchema,
  reason: z.string().min(1).max(512),
  requestedAt: isoTimestampSchema,
  requestedByUserId: userIdSchema.optional(),
});

export const issueBadgeQueueJobSchema = z.object({
  jobType: z.literal('issue_badge'),
  tenantId: tenantIdSchema,
  payload: issueBadgeJobPayloadSchema,
  idempotencyKey: idempotencyKeySchema,
});

export const revokeBadgeQueueJobSchema = z.object({
  jobType: z.literal('revoke_badge'),
  tenantId: tenantIdSchema,
  payload: revokeBadgeJobPayloadSchema,
  idempotencyKey: idempotencyKeySchema,
});

export const rebuildVerificationCacheQueueJobSchema = z.object({
  jobType: z.literal('rebuild_verification_cache'),
  tenantId: tenantIdSchema,
  payload: z.record(z.string(), z.unknown()),
  idempotencyKey: idempotencyKeySchema,
});

export const importMigrationBatchQueueJobSchema = z.object({
  jobType: z.literal('import_migration_batch'),
  tenantId: tenantIdSchema,
  payload: z.record(z.string(), z.unknown()),
  idempotencyKey: idempotencyKeySchema,
});

export const queueJobSchema = z.discriminatedUnion('jobType', [
  issueBadgeQueueJobSchema,
  revokeBadgeQueueJobSchema,
  rebuildVerificationCacheQueueJobSchema,
  importMigrationBatchQueueJobSchema,
]);

export const queueEnvelopeSchema = z.object({
  jobType: queueJobTypeSchema,
  tenantId: z.string().min(1),
  payload: z.record(z.string(), z.unknown()),
  idempotencyKey: idempotencyKeySchema,
});

export type QueueJob = z.infer<typeof queueJobSchema>;
export type KeyGenerationRequest = z.infer<typeof keyGenerationRequestSchema>;
export type SignCredentialRequest = z.infer<typeof signCredentialRequestSchema>;
export type TenantSigningRegistry = z.infer<typeof tenantSigningRegistrySchema>;
export type TenantSigningRegistryEntry = z.infer<typeof tenantSigningRegistryEntrySchema>;
export type MagicLinkRequest = z.infer<typeof magicLinkRequestSchema>;
export type MagicLinkVerifyRequest = z.infer<typeof magicLinkVerifyRequestSchema>;
export type LearnerIdentityLinkRequest = z.infer<typeof learnerIdentityLinkRequestSchema>;
export type LearnerIdentityLinkVerifyRequest = z.infer<typeof learnerIdentityLinkVerifyRequestSchema>;
export type IssueBadgeRequest = z.infer<typeof issueBadgeRequestSchema>;
export type RevokeBadgeRequest = z.infer<typeof revokeBadgeRequestSchema>;
export type ProcessQueueRequest = z.infer<typeof processQueueRequestSchema>;
export type IssueBadgeQueueJob = z.infer<typeof issueBadgeQueueJobSchema>;
export type RevokeBadgeQueueJob = z.infer<typeof revokeBadgeQueueJobSchema>;
export type ManualIssueBadgeRequest = z.infer<typeof manualIssueBadgeRequestSchema>;
export type IssueSakaiCommitBadgeRequest = z.infer<typeof issueSakaiCommitBadgeRequestSchema>;
export type TenantPathParams = z.infer<typeof tenantPathParamsSchema>;
export type BadgeTemplatePathParams = z.infer<typeof badgeTemplatePathParamsSchema>;
export type CredentialPathParams = z.infer<typeof credentialPathParamsSchema>;
export type TenantUserPathParams = z.infer<typeof tenantUserPathParamsSchema>;
export type BadgeTemplateListQuery = z.infer<typeof badgeTemplateListQuerySchema>;
export type CreateBadgeTemplateRequest = z.infer<typeof createBadgeTemplateRequestSchema>;
export type UpdateBadgeTemplateRequest = z.infer<typeof updateBadgeTemplateRequestSchema>;
export type AdminUpsertTenantRequest = z.infer<typeof adminUpsertTenantRequestSchema>;
export type AdminUpsertTenantSigningRegistrationRequest = z.infer<
  typeof adminUpsertTenantSigningRegistrationRequestSchema
>;
export type AdminUpsertBadgeTemplateByIdRequest = z.infer<typeof adminUpsertBadgeTemplateByIdRequestSchema>;
export type AdminUpsertTenantMembershipRoleRequest = z.infer<
  typeof adminUpsertTenantMembershipRoleRequestSchema
>;
export type AdminUpsertLtiIssuerRegistrationRequest = z.infer<
  typeof adminUpsertLtiIssuerRegistrationRequestSchema
>;
export type AdminDeleteLtiIssuerRegistrationRequest = z.infer<
  typeof adminDeleteLtiIssuerRegistrationRequestSchema
>;

export const parseQueueJob = (input: unknown): QueueJob => {
  return queueJobSchema.parse(input);
};

export const parseKeyGenerationRequest = (input: unknown): KeyGenerationRequest => {
  return keyGenerationRequestSchema.parse(input);
};

export const parseSignCredentialRequest = (input: unknown): SignCredentialRequest => {
  return signCredentialRequestSchema.parse(input);
};

export const parseTenantSigningRegistry = (input: unknown): TenantSigningRegistry => {
  return tenantSigningRegistrySchema.parse(input);
};

export const parseTenantSigningRegistryEntry = (input: unknown): TenantSigningRegistryEntry => {
  return tenantSigningRegistryEntrySchema.parse(input);
};

export const parseMagicLinkRequest = (input: unknown): MagicLinkRequest => {
  return magicLinkRequestSchema.parse(input);
};

export const parseMagicLinkVerifyRequest = (input: unknown): MagicLinkVerifyRequest => {
  return magicLinkVerifyRequestSchema.parse(input);
};

export const parseLearnerIdentityLinkRequest = (input: unknown): LearnerIdentityLinkRequest => {
  return learnerIdentityLinkRequestSchema.parse(input);
};

export const parseLearnerIdentityLinkVerifyRequest = (
  input: unknown,
): LearnerIdentityLinkVerifyRequest => {
  return learnerIdentityLinkVerifyRequestSchema.parse(input);
};

export const parseIssueBadgeRequest = (input: unknown): IssueBadgeRequest => {
  return issueBadgeRequestSchema.parse(input);
};

export const parseRevokeBadgeRequest = (input: unknown): RevokeBadgeRequest => {
  return revokeBadgeRequestSchema.parse(input);
};

export const parseProcessQueueRequest = (input: unknown): ProcessQueueRequest => {
  return processQueueRequestSchema.parse(input);
};

export const parseManualIssueBadgeRequest = (input: unknown): ManualIssueBadgeRequest => {
  return manualIssueBadgeRequestSchema.parse(input);
};

export const parseIssueSakaiCommitBadgeRequest = (input: unknown): IssueSakaiCommitBadgeRequest => {
  return issueSakaiCommitBadgeRequestSchema.parse(input);
};

export const parseTenantPathParams = (input: unknown): TenantPathParams => {
  return tenantPathParamsSchema.parse(input);
};

export const parseBadgeTemplatePathParams = (input: unknown): BadgeTemplatePathParams => {
  return badgeTemplatePathParamsSchema.parse(input);
};

export const parseCredentialPathParams = (input: unknown): CredentialPathParams => {
  return credentialPathParamsSchema.parse(input);
};

export const parseTenantUserPathParams = (input: unknown): TenantUserPathParams => {
  return tenantUserPathParamsSchema.parse(input);
};

export const parseBadgeTemplateListQuery = (input: unknown): BadgeTemplateListQuery => {
  return badgeTemplateListQuerySchema.parse(input);
};

export const parseCreateBadgeTemplateRequest = (input: unknown): CreateBadgeTemplateRequest => {
  return createBadgeTemplateRequestSchema.parse(input);
};

export const parseUpdateBadgeTemplateRequest = (input: unknown): UpdateBadgeTemplateRequest => {
  return updateBadgeTemplateRequestSchema.parse(input);
};

export const parseAdminUpsertTenantRequest = (input: unknown): AdminUpsertTenantRequest => {
  return adminUpsertTenantRequestSchema.parse(input);
};

export const parseAdminUpsertTenantSigningRegistrationRequest = (
  input: unknown,
): AdminUpsertTenantSigningRegistrationRequest => {
  return adminUpsertTenantSigningRegistrationRequestSchema.parse(input);
};

export const parseAdminUpsertBadgeTemplateByIdRequest = (
  input: unknown,
): AdminUpsertBadgeTemplateByIdRequest => {
  return adminUpsertBadgeTemplateByIdRequestSchema.parse(input);
};

export const parseAdminUpsertTenantMembershipRoleRequest = (
  input: unknown,
): AdminUpsertTenantMembershipRoleRequest => {
  return adminUpsertTenantMembershipRoleRequestSchema.parse(input);
};

export const parseAdminUpsertLtiIssuerRegistrationRequest = (
  input: unknown,
): AdminUpsertLtiIssuerRegistrationRequest => {
  return adminUpsertLtiIssuerRegistrationRequestSchema.parse(input);
};

export const parseAdminDeleteLtiIssuerRegistrationRequest = (
  input: unknown,
): AdminDeleteLtiIssuerRegistrationRequest => {
  return adminDeleteLtiIssuerRegistrationRequestSchema.parse(input);
};
