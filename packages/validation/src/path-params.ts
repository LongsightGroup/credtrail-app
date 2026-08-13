import { z } from "zod";
import { resourceIdSchema, tenantIdSchema, userIdSchema } from "./primitives.js";

export const tenantPathParamsSchema = z.object({
  tenantId: tenantIdSchema,
});

export const ltiDynamicRegistrationPathParamsSchema = tenantPathParamsSchema.extend({
  inviteToken: z.string().min(1),
});

export const badgeTemplatePathParamsSchema = tenantPathParamsSchema.extend({
  badgeTemplateId: resourceIdSchema,
});

export const badgeTemplateImageRevisionPathParamsSchema = badgeTemplatePathParamsSchema.extend({
  revisionId: resourceIdSchema,
});

export const badgeTemplateImageGenerationPathParamsSchema = badgeTemplatePathParamsSchema.extend({
  generationId: resourceIdSchema,
});

export const tenantUserPathParamsSchema = tenantPathParamsSchema.extend({
  userId: userIdSchema,
});

export const tenantMemberPathParamsSchema = tenantUserPathParamsSchema;

export const tenantUserOrgUnitPathParamsSchema = tenantUserPathParamsSchema.extend({
  orgUnitId: resourceIdSchema,
});

export const tenantUserDelegatedGrantPathParamsSchema = tenantUserPathParamsSchema.extend({
  grantId: resourceIdSchema,
});

export const tenantApiKeyPathParamsSchema = tenantPathParamsSchema.extend({
  apiKeyId: resourceIdSchema,
});

export const tenantAuthProviderPathParamsSchema = tenantPathParamsSchema.extend({
  providerId: resourceIdSchema,
});

export const learnerRecordEntryPathParamsSchema = tenantPathParamsSchema.extend({
  entryId: resourceIdSchema,
});

export const learnerRecordImportBatchPathParamsSchema = tenantPathParamsSchema.extend({
  batchId: z.string().trim().min(1).max(128),
});

export const migrationBatchPathParamsSchema = tenantPathParamsSchema.extend({
  batchId: z.string().trim().min(1).max(128),
});

export const credentialPathParamsSchema = z.object({
  credentialId: resourceIdSchema,
});

export const assertionLifecycleStateSchema = z.enum(["active", "suspended", "revoked", "expired"]);

export const assertionLifecycleTransitionSourceSchema = z.enum(["manual", "automation"]);

export const assertionLifecycleReasonCodeSchema = z.enum([
  "administrative_hold",
  "policy_violation",
  "appeal_pending",
  "appeal_resolved",
  "credential_expired",
  "issuer_requested",
  "other",
]);

export const assertionPathParamsSchema = tenantPathParamsSchema.extend({
  assertionId: resourceIdSchema,
});
// --- inferred types and parsers ---
export type AssertionPathParams = z.infer<typeof assertionPathParamsSchema>;

export type AssertionLifecycleState = z.infer<typeof assertionLifecycleStateSchema>;

export type AssertionLifecycleReasonCode = z.infer<typeof assertionLifecycleReasonCodeSchema>;

export type AssertionLifecycleTransitionSource = z.infer<
  typeof assertionLifecycleTransitionSourceSchema
>;

export type TenantPathParams = z.infer<typeof tenantPathParamsSchema>;

export type LtiDynamicRegistrationPathParams = z.infer<
  typeof ltiDynamicRegistrationPathParamsSchema
>;

export type LearnerRecordImportBatchPathParams = z.infer<
  typeof learnerRecordImportBatchPathParamsSchema
>;

export type MigrationBatchPathParams = z.infer<typeof migrationBatchPathParamsSchema>;

export type BadgeTemplatePathParams = z.infer<typeof badgeTemplatePathParamsSchema>;

export type BadgeTemplateImageRevisionPathParams = z.infer<
  typeof badgeTemplateImageRevisionPathParamsSchema
>;

export type BadgeTemplateImageGenerationPathParams = z.infer<
  typeof badgeTemplateImageGenerationPathParamsSchema
>;

export type CredentialPathParams = z.infer<typeof credentialPathParamsSchema>;

export type TenantUserPathParams = z.infer<typeof tenantUserPathParamsSchema>;

export type TenantMemberPathParams = z.infer<typeof tenantMemberPathParamsSchema>;

export type TenantUserOrgUnitPathParams = z.infer<typeof tenantUserOrgUnitPathParamsSchema>;

export type TenantUserDelegatedGrantPathParams = z.infer<
  typeof tenantUserDelegatedGrantPathParamsSchema
>;

export type TenantApiKeyPathParams = z.infer<typeof tenantApiKeyPathParamsSchema>;

export type TenantAuthProviderPathParams = z.infer<typeof tenantAuthProviderPathParamsSchema>;

export type LearnerRecordEntryPathParams = z.infer<typeof learnerRecordEntryPathParamsSchema>;

export const parseAssertionPathParams = (input: unknown): AssertionPathParams => {
  return assertionPathParamsSchema.parse(input);
};

export const parseTenantPathParams = (input: unknown): TenantPathParams => {
  return tenantPathParamsSchema.parse(input);
};

export const parseLtiDynamicRegistrationPathParams = (
  input: unknown,
): LtiDynamicRegistrationPathParams => {
  return ltiDynamicRegistrationPathParamsSchema.parse(input);
};

export const parseMigrationBatchPathParams = (input: unknown): MigrationBatchPathParams => {
  return migrationBatchPathParamsSchema.parse(input);
};

export const parseBadgeTemplatePathParams = (input: unknown): BadgeTemplatePathParams => {
  return badgeTemplatePathParamsSchema.parse(input);
};

export const parseBadgeTemplateImageRevisionPathParams = (
  input: unknown,
): BadgeTemplateImageRevisionPathParams => {
  return badgeTemplateImageRevisionPathParamsSchema.parse(input);
};

export const parseBadgeTemplateImageGenerationPathParams = (
  input: unknown,
): BadgeTemplateImageGenerationPathParams => {
  return badgeTemplateImageGenerationPathParamsSchema.parse(input);
};

export const parseCredentialPathParams = (input: unknown): CredentialPathParams => {
  return credentialPathParamsSchema.parse(input);
};

export const parseTenantUserPathParams = (input: unknown): TenantUserPathParams => {
  return tenantUserPathParamsSchema.parse(input);
};

export const parseTenantMemberPathParams = (input: unknown): TenantMemberPathParams => {
  return tenantMemberPathParamsSchema.parse(input);
};

export const parseTenantUserOrgUnitPathParams = (input: unknown): TenantUserOrgUnitPathParams => {
  return tenantUserOrgUnitPathParamsSchema.parse(input);
};

export const parseTenantUserDelegatedGrantPathParams = (
  input: unknown,
): TenantUserDelegatedGrantPathParams => {
  return tenantUserDelegatedGrantPathParamsSchema.parse(input);
};

export const parseTenantApiKeyPathParams = (input: unknown): TenantApiKeyPathParams => {
  return tenantApiKeyPathParamsSchema.parse(input);
};

export const parseTenantAuthProviderPathParams = (input: unknown): TenantAuthProviderPathParams => {
  return tenantAuthProviderPathParamsSchema.parse(input);
};

export const parseLearnerRecordEntryPathParams = (input: unknown): LearnerRecordEntryPathParams => {
  return learnerRecordEntryPathParamsSchema.parse(input);
};

export const parseLearnerRecordImportBatchPathParams = (
  input: unknown,
): LearnerRecordImportBatchPathParams => {
  return learnerRecordImportBatchPathParamsSchema.parse(input);
};
