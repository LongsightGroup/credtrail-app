import { z } from "zod";

export const tenantIdSchema = z.string().min(1);
export const resourceIdSchema = z.string().min(1);
export const userIdSchema = z.string().min(1);
export const isoTimestampSchema = z.string().datetime();
export const tenantPlanTierSchema = z.enum(["free", "team", "institution", "enterprise"]);
export const tenantMembershipRoleSchema = z.enum(["owner", "admin", "issuer", "viewer"]);
export const tenantLoginModeSchema = z.enum(["local", "hybrid", "sso_required"]);
export const tenantAuthPolicyEnforceForRolesSchema = z.enum(["all_users", "admins_only"]);
export const tenantAuthProviderProtocolSchema = z.enum(["oidc"]);
export const recipientIdentityTypeSchema = z.enum(["email", "email_sha256", "did", "url"]);
export const learnerRecordTrustLevelSchema = z.enum(["issuer_verified", "learner_supplemental"]);
export const learnerRecordStatusSchema = z.enum(["active", "revoked", "expired"]);
export const learnerRecordSourceSystemSchema = z.enum([
  "credtrail_admin",
  "csv_import",
  "api",
  "migration",
  "badge_assertion",
  "learner_self_reported",
]);
export const bootstrapTenantRequestSchema = z.object({
  slug: z.string().trim().min(1).max(128),
  displayName: z.string().trim().min(1).max(200),
  planTier: tenantPlanTierSchema,
  issuerDomain: z.string().trim().min(1).max(255),
  isActive: z.boolean().optional(),
});
export const learnerRecordTypeSchema = z.enum([
  "badge",
  "course",
  "certificate",
  "license",
  "competency",
  "work_based_learning",
  "experience",
  "membership",
  "supplemental_artifact",
  "custom",
]);
export const learnerRecordEntryTypeSchema = z.enum([
  "course",
  "certificate",
  "license",
  "competency",
  "work_based_learning",
  "experience",
  "membership",
  "supplemental_artifact",
  "custom",
]);
export const recipientIdentifierTypeSchema = z.enum([
  "emailAddress",
  "sourcedId",
  "did",
  "nationalIdentityNumber",
  "studentId",
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
export const orgUnitTypeSchema = z.enum(["institution", "college", "department", "program"]);
export const tenantMembershipOrgUnitScopeRoleSchema = z.enum(["admin", "issuer", "viewer"]);
export const delegatedIssuingAuthorityActionSchema = z.enum([
  "issue_badge",
  "revoke_badge",
  "manage_lifecycle",
  "place_lti_badge",
  "configure_course_rule",
]);
export const orgUnitSlugSchema = z
  .string()
  .trim()
  .min(2)
  .max(96)
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
export const orgUnitDisplayNameSchema = z.string().trim().min(1).max(200);
export const badgeTemplateOwnershipReasonCodeSchema = z.enum([
  "initial_assignment",
  "administrative_transfer",
  "reorganization",
  "governance_policy_update",
  "other",
]);
export const badgeTemplateOwnershipTransferReasonCodeSchema = z.enum([
  "administrative_transfer",
  "reorganization",
  "governance_policy_update",
  "other",
]);
// --- inferred types and parsers ---
export type BootstrapTenantRequest = z.infer<typeof bootstrapTenantRequestSchema>;

export type RecipientIdentityType = z.infer<typeof recipientIdentityTypeSchema>;

export type LearnerRecordTrustLevel = z.infer<typeof learnerRecordTrustLevelSchema>;

export type LearnerRecordStatus = z.infer<typeof learnerRecordStatusSchema>;

export type LearnerRecordSourceSystem = z.infer<typeof learnerRecordSourceSystemSchema>;

export type LearnerRecordType = z.infer<typeof learnerRecordTypeSchema>;

export type LearnerRecordEntryType = z.infer<typeof learnerRecordEntryTypeSchema>;

export type OrgUnitType = z.infer<typeof orgUnitTypeSchema>;

export type TenantMembershipOrgUnitScopeRole = z.infer<
  typeof tenantMembershipOrgUnitScopeRoleSchema
>;

export type DelegatedIssuingAuthorityAction = z.infer<typeof delegatedIssuingAuthorityActionSchema>;

export type BadgeTemplateOwnershipReasonCode = z.infer<
  typeof badgeTemplateOwnershipReasonCodeSchema
>;

export type BadgeTemplateOwnershipTransferReasonCode = z.infer<
  typeof badgeTemplateOwnershipTransferReasonCodeSchema
>;

export const parseBootstrapTenantRequest = (input: unknown): BootstrapTenantRequest => {
  return bootstrapTenantRequestSchema.parse(input);
};
