import { z } from "zod";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];

export interface JsonObject {
  [key: string]: JsonValue;
}

export const queueJobTypeSchema = z.enum([
  "issue_badge",
  "revoke_badge",
  "rebuild_verification_cache",
  "import_migration_batch",
  "import_learner_record_batch",
]);

export const idempotencyKeySchema = z.string().min(1).max(128);

export const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().finite(),
    z.boolean(),
    z.null(),
    z.array(jsonValueSchema),
    z.record(jsonValueSchema),
  ]),
);

export const jsonObjectSchema: z.ZodType<JsonObject> = z.record(jsonValueSchema);

export const didWebSchema = z.string().startsWith("did:web:");

export const ed25519PublicJwkSchema = z.object({
  kty: z.literal("OKP"),
  crv: z.literal("Ed25519"),
  x: z.string().min(1),
  kid: z.string().min(1).optional(),
});

export const ed25519PrivateJwkSchema = ed25519PublicJwkSchema.extend({
  d: z.string().min(1),
});

export const p256PublicJwkSchema = z.object({
  kty: z.literal("EC"),
  crv: z.literal("P-256"),
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

export const tenantSigningRegistrySchema = z.record(
  z.string().min(1),
  tenantSigningRegistryEntrySchema,
);

export const keyGenerationRequestSchema = z.object({
  did: didWebSchema,
  keyId: z.string().min(1).max(128).optional(),
});

export const signCredentialRequestSchema = z
  .object({
    did: didWebSchema,
    credential: jsonObjectSchema,
    proofType: z.enum(["Ed25519Signature2020", "DataIntegrityProof"]).optional(),
    cryptosuite: z.enum(["eddsa-rdfc-2022", "ecdsa-sd-2023"]).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.proofType === "DataIntegrityProof" && value.cryptosuite === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["cryptosuite"],
        message: "cryptosuite is required when proofType is DataIntegrityProof",
      });
    }

    if (value.proofType !== "DataIntegrityProof" && value.cryptosuite !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["cryptosuite"],
        message: "cryptosuite is only allowed when proofType is DataIntegrityProof",
      });
    }
  });

export const tenantIdSchema = z.string().min(1);
export const resourceIdSchema = z.string().min(1);
export const userIdSchema = z.string().min(1);
export const isoTimestampSchema = z.string().datetime();
export const tenantPlanTierSchema = z.enum(["free", "team", "institution", "enterprise"]);
export const tenantMembershipRoleSchema = z.enum(["owner", "admin", "issuer", "viewer"]);
export const tenantLoginModeSchema = z.enum(["local", "hybrid", "sso_required"]);
export const tenantAuthPolicyEnforceForRolesSchema = z.enum(["all_users", "admins_only"]);
export const tenantAuthProviderProtocolSchema = z.enum(["oidc", "saml"]);
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

export const tenantPathParamsSchema = z.object({
  tenantId: tenantIdSchema,
});

export const badgeTemplatePathParamsSchema = tenantPathParamsSchema.extend({
  badgeTemplateId: resourceIdSchema,
});

export const tenantUserPathParamsSchema = tenantPathParamsSchema.extend({
  userId: userIdSchema,
});

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

export const tenantDedicatedDbProvisioningRequestPathParamsSchema = tenantPathParamsSchema.extend({
  requestId: resourceIdSchema,
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

export const badgeTemplateListQuerySchema = z.object({
  includeArchived: z.preprocess((input) => {
    if (input === undefined) {
      return false;
    }

    if (input === "true") {
      return true;
    }

    if (input === "false") {
      return false;
    }

    return input;
  }, z.boolean()),
});

export const tenantOrgUnitListQuerySchema = z.object({
  includeInactive: z.preprocess((input) => {
    if (input === undefined) {
      return false;
    }

    if (input === "true") {
      return true;
    }

    if (input === "false") {
      return false;
    }

    return input;
  }, z.boolean()),
});

export const delegatedIssuingAuthorityGrantListQuerySchema = z.object({
  includeRevoked: z.preprocess((input) => {
    if (input === undefined) {
      return false;
    }

    if (input === "true") {
      return true;
    }

    if (input === "false") {
      return false;
    }

    return input;
  }, z.boolean()),
  includeExpired: z.preprocess((input) => {
    if (input === undefined) {
      return false;
    }

    if (input === "true") {
      return true;
    }

    if (input === "false") {
      return false;
    }

    return input;
  }, z.boolean()),
});

export const tenantApiKeyListQuerySchema = z.object({
  includeRevoked: z.preprocess((input) => {
    if (input === undefined) {
      return false;
    }

    if (input === "true") {
      return true;
    }

    if (input === "false") {
      return false;
    }

    return input;
  }, z.boolean()),
});

export const learnerRecordEntryListQuerySchema = z.object({
  learnerProfileId: resourceIdSchema,
  trustLevel: learnerRecordTrustLevelSchema.optional(),
  status: learnerRecordStatusSchema.optional(),
});

export const adminLearnerRecordReviewQuerySchema = z
  .object({
    learnerProfileId: z
      .preprocess((input) => {
        if (typeof input !== "string") {
          return input;
        }

        const trimmed = input.trim();
        return trimmed.length === 0 ? undefined : trimmed;
      }, resourceIdSchema)
      .optional(),
    email: z
      .preprocess((input) => {
        if (typeof input !== "string") {
          return input;
        }

        const trimmed = input.trim();
        return trimmed.length === 0 ? undefined : trimmed;
      }, z.string().email().max(320))
      .optional(),
  })
  .superRefine((value, ctx) => {
    if (value.learnerProfileId !== undefined && value.email !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["learnerProfileId"],
        message: "Provide learnerProfileId or email, not both",
      });
    }
    if (value.learnerProfileId === undefined && value.email === undefined) {
      return;
    }
  });

export const learnerRecordExportProfileSchema = z.enum([
  "native_portable_json",
  "clr_alignment_json",
]);

export const learnerRecordStandardsSupportStatusSchema = z.enum([
  "native",
  "mapped",
  "unavailable",
]);

export const learnerRecordExportPathParamsSchema = tenantPathParamsSchema.extend({
  learnerProfileId: resourceIdSchema,
});

export const learnerRecordExportQuerySchema = z.object({
  profile: learnerRecordExportProfileSchema.default("native_portable_json"),
});

export const learnerRecordStandardsMappingQuerySchema = z.object({
  profile: learnerRecordExportProfileSchema.default("clr_alignment_json"),
});

export const tenantAssertionListQuerySchema = z.object({
  badgeTemplateId: resourceIdSchema.optional(),
  recipientQuery: z.string().trim().min(1).max(320).optional(),
  state: assertionLifecycleStateSchema.optional(),
  limit: z.preprocess((input) => {
    if (input === undefined || input === "") {
      return undefined;
    }

    return input;
  }, z.coerce.number().int().min(1).max(500).optional()),
});

const reportingDateSchema = z
  .string()
  .trim()
  .regex(/^\d{4}-\d{2}-\d{2}$/);

export const tenantAssertionLedgerExportQuerySchema = z
  .object({
    issuedFrom: reportingDateSchema.optional(),
    issuedTo: reportingDateSchema.optional(),
    badgeTemplateId: resourceIdSchema.optional(),
    orgUnitId: resourceIdSchema.optional(),
    state: assertionLifecycleStateSchema.optional(),
    recipientQuery: z.string().trim().min(1).max(320).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.issuedFrom === undefined || value.issuedTo === undefined) {
      return;
    }

    if (value.issuedFrom > value.issuedTo) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["issuedTo"],
        message: "issuedTo must be on or after issuedFrom",
      });
    }
  });

export const tenantReportingOverviewQuerySchema = z
  .object({
    issuedFrom: reportingDateSchema.optional(),
    issuedTo: reportingDateSchema.optional(),
    badgeTemplateId: resourceIdSchema.optional(),
    orgUnitId: resourceIdSchema.optional(),
    state: z.enum(["active", "suspended", "revoked", "expired", "pending_review"]).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.issuedFrom === undefined || value.issuedTo === undefined) {
      return;
    }

    if (value.issuedFrom > value.issuedTo) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["issuedTo"],
        message: "issuedTo must be on or after issuedFrom",
      });
    }
  });

const tenantReportingEngagementQueryRangeSchema = <T extends z.ZodRawShape>(shape: T) => {
  return z.object(shape).superRefine((value, ctx) => {
    if (value.from === undefined || value.to === undefined) {
      return;
    }

    if (value.from > value.to) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["to"],
        message: "to must be on or after from",
      });
    }
  });
};

export const tenantReportingTrendQuerySchema = tenantReportingEngagementQueryRangeSchema({
  from: reportingDateSchema.optional(),
  to: reportingDateSchema.optional(),
  badgeTemplateId: resourceIdSchema.optional(),
  orgUnitId: resourceIdSchema.optional(),
  state: z.enum(["active", "suspended", "revoked", "expired", "pending_review"]).optional(),
  bucket: z.enum(["day"]).default("day"),
});

export const tenantReportingComparisonQuerySchema = tenantReportingEngagementQueryRangeSchema({
  from: reportingDateSchema.optional(),
  to: reportingDateSchema.optional(),
  badgeTemplateId: resourceIdSchema.optional(),
  orgUnitId: resourceIdSchema.optional(),
  state: z.enum(["active", "suspended", "revoked", "expired", "pending_review"]).optional(),
  groupBy: z.enum(["badgeTemplate", "orgUnit"]).default("badgeTemplate"),
});

export const tenantReportingHierarchyQuerySchema = tenantReportingEngagementQueryRangeSchema({
  from: reportingDateSchema.optional(),
  to: reportingDateSchema.optional(),
  badgeTemplateId: resourceIdSchema.optional(),
  orgUnitId: resourceIdSchema.optional(),
  state: z.enum(["active", "suspended", "revoked", "expired", "pending_review"]).optional(),
  focusOrgUnitId: resourceIdSchema.optional(),
  level: orgUnitTypeSchema,
});

export const executiveDashboardAudienceSchema = z.enum([
  "system",
  "institution",
  "college",
  "department",
  "program",
]);

export const executiveDashboardWindowSchema = z.enum(["last-30-days", "last-90-days"]);

export const tenantExecutiveDashboardQuerySchema = z
  .object({
    issuedFrom: reportingDateSchema.optional(),
    issuedTo: reportingDateSchema.optional(),
    badgeTemplateId: resourceIdSchema.optional(),
    orgUnitId: resourceIdSchema.optional(),
    state: z.enum(["active", "suspended", "revoked", "expired", "pending_review"]).optional(),
    window: executiveDashboardWindowSchema.optional(),
    audience: executiveDashboardAudienceSchema.optional(),
    focusOrgUnitId: resourceIdSchema.optional(),
    comparisonLevel: orgUnitTypeSchema.optional(),
  })
  .superRefine((value, ctx) => {
    if (value.issuedFrom === undefined || value.issuedTo === undefined) {
      return;
    }

    if (value.issuedFrom > value.issuedTo) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["issuedTo"],
        message: "issuedTo must be on or after issuedFrom",
      });
    }
  });

export const createBadgeTemplateRequestSchema = z.object({
  slug: badgeTemplateSlugSchema,
  title: badgeTemplateTitleSchema,
  description: badgeTemplateDescriptionSchema.optional(),
  criteriaUri: badgeTemplateUriSchema.optional(),
  imageUri: badgeTemplateUriSchema.optional(),
  ownerOrgUnitId: resourceIdSchema.optional(),
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
      message: "At least one badge template field must be provided",
    },
  );

export const createTenantOrgUnitRequestSchema = z.object({
  unitType: orgUnitTypeSchema,
  slug: orgUnitSlugSchema,
  displayName: orgUnitDisplayNameSchema,
  parentOrgUnitId: resourceIdSchema.optional(),
});

export const learnerRecordProvenanceSchema = z.object({
  issuerName: z.string().trim().min(1).max(200),
  issuerUserId: userIdSchema.optional(),
  sourceSystem: learnerRecordSourceSystemSchema,
  sourceRecordId: resourceIdSchema.optional(),
  issuedAt: isoTimestampSchema,
  revisedAt: isoTimestampSchema.nullable().optional(),
  revokedAt: isoTimestampSchema.nullable().optional(),
  evidenceLinks: z.array(z.string().url().max(2048)).max(20),
});

const learnerRecordDetailsSchema = jsonObjectSchema;

const learnerRecordImportRowBaseSchema = z.object({
  learnerEmail: z.string().trim().email().max(320),
  learnerDisplayName: z.string().trim().min(1).max(200).optional(),
  title: z.string().trim().min(1).max(200),
  recordType: learnerRecordEntryTypeSchema,
  issuedAt: isoTimestampSchema,
  trustLevel: learnerRecordTrustLevelSchema.optional(),
  description: z.string().trim().min(1).max(4000).optional(),
  issuerName: z.string().trim().min(1).max(200).optional(),
  orgUnitId: resourceIdSchema.optional(),
  orgUnitSlug: orgUnitSlugSchema.optional(),
  badgeTemplateId: resourceIdSchema.optional(),
  badgeTemplateSlug: badgeTemplateSlugSchema.optional(),
  pathwayLabel: z.string().trim().min(1).max(200).optional(),
  sourceRecordId: z.string().trim().min(1).max(200).optional(),
  evidenceLinks: z.array(z.string().url().max(2048)).max(20).optional(),
});

export const learnerRecordImportRowSchema = learnerRecordImportRowBaseSchema.superRefine(
  (value, ctx) => {
    if (
      value.recordType === "supplemental_artifact" &&
      value.trustLevel !== undefined &&
      value.trustLevel !== "learner_supplemental"
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["trustLevel"],
        message: "supplemental_artifact import rows must use learner_supplemental trust",
      });
    }
  },
);

export const learnerRecordImportBatchDefaultsSchema = z.object({
  defaultTrustLevel: learnerRecordTrustLevelSchema.default("issuer_verified"),
  defaultIssuerName: z.string().trim().min(1).max(200).optional(),
});

const learnerRecordImportPreparedRowSchema = z.object({
  learnerEmail: z.string().trim().email().max(320),
  learnerDisplayName: z.string().trim().min(1).max(200).nullable(),
  title: z.string().trim().min(1).max(200),
  recordType: learnerRecordEntryTypeSchema,
  issuedAt: isoTimestampSchema,
  description: z.string().trim().min(1).max(4000).nullable(),
  sourceRecordId: z.string().trim().min(1).max(200).nullable(),
  evidenceLinks: z.array(z.string().url().max(2048)).max(20),
  effectiveTrustLevel: learnerRecordTrustLevelSchema,
  effectiveIssuerName: z.string().trim().min(1).max(200),
  smartContext: z.object({
    orgUnitId: resourceIdSchema.nullable(),
    badgeTemplateId: resourceIdSchema.nullable(),
    pathwayLabel: z.string().trim().min(1).max(200).nullable(),
    inferredFrom: z
      .array(z.enum(["row", "badge_template", "org_unit", "none"]))
      .min(1)
      .max(4),
  }),
});

export const createLearnerRecordEntryRequestSchema = z
  .object({
    learnerProfileId: resourceIdSchema,
    trustLevel: learnerRecordTrustLevelSchema,
    recordType: learnerRecordEntryTypeSchema,
    title: z.string().trim().min(1).max(200),
    description: z.string().trim().min(1).max(4000).optional(),
    status: learnerRecordStatusSchema.default("active"),
    provenance: learnerRecordProvenanceSchema,
    details: learnerRecordDetailsSchema.optional(),
  })
  .superRefine((value, ctx) => {
    if (
      value.trustLevel === "issuer_verified" &&
      value.provenance.sourceSystem === "learner_self_reported"
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["provenance", "sourceSystem"],
        message: "issuer-verified entries cannot use learner_self_reported as the sourceSystem",
      });
    }

    if (
      value.recordType === "supplemental_artifact" &&
      value.trustLevel !== "learner_supplemental"
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["trustLevel"],
        message: "supplemental_artifact entries must use learner_supplemental trust",
      });
    }

    if (
      value.status === "revoked" &&
      (value.provenance.revokedAt === undefined || value.provenance.revokedAt === null)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["provenance", "revokedAt"],
        message: "revoked entries must include provenance.revokedAt",
      });
    }
  });

export const patchLearnerRecordEntryRequestSchema = z
  .object({
    trustLevel: learnerRecordTrustLevelSchema.optional(),
    recordType: learnerRecordEntryTypeSchema.optional(),
    title: z.string().trim().min(1).max(200).optional(),
    description: z.string().trim().min(1).max(4000).nullable().optional(),
    status: learnerRecordStatusSchema.optional(),
    provenance: learnerRecordProvenanceSchema.optional(),
    details: learnerRecordDetailsSchema.optional(),
  })
  .refine(
    (payload) =>
      payload.trustLevel !== undefined ||
      payload.recordType !== undefined ||
      payload.title !== undefined ||
      payload.description !== undefined ||
      payload.status !== undefined ||
      payload.provenance !== undefined ||
      payload.details !== undefined,
    {
      message: "At least one learner-record field must be provided",
    },
  )
  .superRefine((value, ctx) => {
    const effectiveTrustLevel = value.trustLevel;
    const effectiveRecordType = value.recordType;
    const effectiveStatus = value.status;
    const provenance = value.provenance;

    if (
      effectiveTrustLevel === "issuer_verified" &&
      provenance !== undefined &&
      provenance.sourceSystem === "learner_self_reported"
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["provenance", "sourceSystem"],
        message: "issuer-verified entries cannot use learner_self_reported as the sourceSystem",
      });
    }

    if (
      effectiveRecordType === "supplemental_artifact" &&
      effectiveTrustLevel === "issuer_verified"
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["trustLevel"],
        message: "supplemental_artifact entries must use learner_supplemental trust",
      });
    }

    if (effectiveStatus === "revoked" && provenance === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["provenance"],
        message: "revoked entries must include provenance with revokedAt",
      });
    }

    if (
      effectiveStatus === "revoked" &&
      provenance !== undefined &&
      (provenance.revokedAt === undefined || provenance.revokedAt === null)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["provenance", "revokedAt"],
        message: "revoked entries must include provenance.revokedAt",
      });
    }
  });

export const upsertTenantMembershipOrgUnitScopeRequestSchema = z.object({
  role: tenantMembershipOrgUnitScopeRoleSchema,
});

export const createDelegatedIssuingAuthorityGrantRequestSchema = z
  .object({
    orgUnitId: resourceIdSchema,
    badgeTemplateIds: z.array(resourceIdSchema).min(1).max(100).optional(),
    allowedActions: z.array(delegatedIssuingAuthorityActionSchema).min(1).max(10),
    startsAt: isoTimestampSchema.optional(),
    endsAt: isoTimestampSchema,
    reason: z.string().trim().min(1).max(512).optional(),
  })
  .superRefine((value, ctx) => {
    const uniqueActions = new Set(value.allowedActions);

    if (uniqueActions.size !== value.allowedActions.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["allowedActions"],
        message: "allowedActions must not contain duplicates",
      });
    }

    if (value.badgeTemplateIds !== undefined) {
      const uniqueTemplateIds = new Set(value.badgeTemplateIds);

      if (uniqueTemplateIds.size !== value.badgeTemplateIds.length) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["badgeTemplateIds"],
          message: "badgeTemplateIds must not contain duplicates",
        });
      }
    }

    if (value.startsAt !== undefined) {
      const startsAtMs = Date.parse(value.startsAt);
      const endsAtMs = Date.parse(value.endsAt);

      if (Number.isFinite(startsAtMs) && Number.isFinite(endsAtMs) && endsAtMs <= startsAtMs) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["endsAt"],
          message: "endsAt must be after startsAt",
        });
      }
    }
  });

export const revokeDelegatedIssuingAuthorityGrantRequestSchema = z.object({
  reason: z.string().trim().min(1).max(512).optional(),
  revokedAt: isoTimestampSchema.optional(),
});

export const transferBadgeTemplateOwnershipRequestSchema = z.object({
  toOrgUnitId: resourceIdSchema,
  reasonCode: badgeTemplateOwnershipTransferReasonCodeSchema,
  reason: z.string().trim().min(1).max(512).optional(),
  governanceMetadata: jsonObjectSchema.optional(),
  transferredAt: isoTimestampSchema.optional(),
});

export const createTenantApiKeyRequestSchema = z.object({
  label: z.string().trim().min(1).max(120),
  scopes: z.array(z.string().trim().min(1).max(120)).min(1).max(20).optional(),
  expiresAt: isoTimestampSchema.optional(),
});

export const revokeTenantApiKeyRequestSchema = z.object({
  revokedAt: isoTimestampSchema.optional(),
});

export const upsertTenantAuthPolicyRequestSchema = z.object({
  loginMode: tenantLoginModeSchema,
  breakGlassEnabled: z.boolean().optional(),
  localMfaRequired: z.boolean().optional(),
  defaultProviderId: resourceIdSchema.nullable().optional(),
});

export const upsertTenantAuthProviderRequestSchema = z
  .object({
    protocol: tenantAuthProviderProtocolSchema,
    label: z.string().trim().min(1).max(120),
    enabled: z.boolean().optional(),
    isDefault: z.boolean().optional(),
    configJson: z.string().trim().min(2).max(64000),
  })
  .superRefine((value, ctx) => {
    try {
      const parsed = JSON.parse(value.configJson) as unknown;

      if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["configJson"],
          message: "configJson must encode a JSON object",
        });
      }
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["configJson"],
        message: "configJson must be valid JSON",
      });
    }
  });

export const createTenantBreakGlassAccountRequestSchema = z.object({
  email: z.string().trim().email().max(320),
  sendEnrollmentEmail: z.boolean().optional(),
});

export const upsertTenantSsoSamlConfigurationRequestSchema = z.object({
  idpEntityId: z.string().trim().min(1).max(512),
  ssoLoginUrl: z.string().url().max(2048),
  idpCertificatePem: z.string().trim().min(1).max(32000),
  idpMetadataUrl: z.string().url().max(2048).optional(),
  spEntityId: z.string().trim().min(1).max(512),
  assertionConsumerServiceUrl: z.string().url().max(2048),
  nameIdFormat: z.string().trim().min(1).max(255).optional(),
  enforced: z.boolean().optional(),
});

export const upsertTenantCanvasGradebookIntegrationRequestSchema = z.object({
  apiBaseUrl: z.string().url().max(2048),
  authorizationEndpoint: z.string().url().max(2048),
  tokenEndpoint: z.string().url().max(2048),
  clientId: z.string().trim().min(1).max(512),
  clientSecret: z.string().trim().min(1).max(2048),
  scope: z.string().trim().min(1).max(2048).optional(),
});

export const adminCanvasOAuthAuthorizeUrlRequestSchema = z.object({
  redirectUri: z.string().url().max(2048).optional(),
});

export const adminCanvasOAuthExchangeRequestSchema = z.object({
  code: z.string().trim().min(1).max(4096),
  state: z.string().trim().min(20).max(4096),
  redirectUri: z.string().url().max(2048).optional(),
});

export const tenantCanvasGradebookSnapshotQuerySchema = z.object({
  courseId: z.string().trim().min(1).max(255).optional(),
  learnerId: z.string().trim().min(1).max(255).optional(),
  assignmentId: z.string().trim().min(1).max(255).optional(),
});

export const badgeIssuanceRuleLmsProviderKindSchema = z.enum([
  "canvas",
  "moodle",
  "blackboard_ultra",
  "d2l_brightspace",
  "sakai",
]);

export const badgeIssuanceRuleValueListKindSchema = z.enum(["course_ids", "badge_template_ids"]);

const badgeIssuanceRuleCourseReferenceRefinement = (
  value: {
    courseId?: string | undefined;
    courseListId?: string | undefined;
  },
  ctx: z.RefinementCtx,
): void => {
  if (value.courseId === undefined && value.courseListId === undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Specify courseId or courseListId",
    });
    return;
  }

  if (value.courseId !== undefined && value.courseListId !== undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Specify courseId or courseListId, not both",
    });
  }
};

const badgeIssuanceRuleBadgeTemplateReferenceRefinement = (
  value: {
    badgeTemplateId?: string | undefined;
    badgeTemplateListId?: string | undefined;
  },
  ctx: z.RefinementCtx,
): void => {
  if (value.badgeTemplateId === undefined && value.badgeTemplateListId === undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Specify badgeTemplateId or badgeTemplateListId",
    });
    return;
  }

  if (value.badgeTemplateId !== undefined && value.badgeTemplateListId !== undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Specify badgeTemplateId or badgeTemplateListId, not both",
    });
  }
};

const badgeIssuanceRuleGradeThresholdConditionSchema = z
  .object({
    type: z.literal("grade_threshold"),
    courseId: z.string().trim().min(1).max(255).optional(),
    courseListId: resourceIdSchema.optional(),
    scoreField: z.enum(["final_score", "current_score"]).optional(),
    minScore: z.number().finite().min(0).max(100).optional(),
    maxScore: z.number().finite().min(0).max(100).optional(),
  })
  .superRefine((value, ctx) => {
    badgeIssuanceRuleCourseReferenceRefinement(value, ctx);

    if (value.minScore === undefined && value.maxScore === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "grade_threshold must include minScore or maxScore",
      });
    }
  });

const badgeIssuanceRuleCourseCompletionConditionSchema = z
  .object({
    type: z.literal("course_completion"),
    courseId: z.string().trim().min(1).max(255).optional(),
    courseListId: resourceIdSchema.optional(),
    requireCompleted: z.boolean().optional(),
    minCompletionPercent: z.number().finite().min(0).max(100).optional(),
  })
  .superRefine((value, ctx) => {
    badgeIssuanceRuleCourseReferenceRefinement(value, ctx);
  });

const badgeIssuanceRuleProgramCompletionConditionSchema = z
  .object({
    type: z.literal("program_completion"),
    courseIds: z.array(z.string().trim().min(1).max(255)).min(1).max(200).optional(),
    courseListId: resourceIdSchema.optional(),
    minimumCompleted: z.number().int().min(1).max(200).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.courseIds === undefined && value.courseListId === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "program_completion must include courseIds or courseListId",
      });
      return;
    }

    if (value.courseIds !== undefined && value.courseListId !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "program_completion must include courseIds or courseListId, not both",
      });
      return;
    }

    if (
      value.minimumCompleted !== undefined &&
      value.courseIds !== undefined &&
      value.minimumCompleted > value.courseIds.length
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "minimumCompleted must be less than or equal to the number of courseIds",
      });
    }
  });

const badgeIssuanceRuleAssignmentSubmissionConditionSchema = z.object({
  type: z.literal("assignment_submission"),
  courseId: z.string().trim().min(1).max(255),
  assignmentId: z.string().trim().min(1).max(255),
  minScore: z.number().finite().min(0).max(100).optional(),
  requireSubmitted: z.boolean().optional(),
  workflowStates: z.array(z.string().trim().min(1).max(64)).min(1).max(20).optional(),
});

const badgeIssuanceRuleTimeWindowConditionSchema = z
  .object({
    type: z.literal("time_window"),
    notBefore: isoTimestampSchema.optional(),
    notAfter: isoTimestampSchema.optional(),
  })
  .superRefine((value, ctx) => {
    if (value.notBefore === undefined && value.notAfter === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "time_window must include notBefore or notAfter",
      });
    }
  });

const badgeIssuanceRulePrerequisiteBadgeConditionSchema = z
  .object({
    type: z.literal("prerequisite_badge"),
    badgeTemplateId: resourceIdSchema.optional(),
    badgeTemplateListId: resourceIdSchema.optional(),
  })
  .superRefine((value, ctx) => {
    badgeIssuanceRuleBadgeTemplateReferenceRefinement(value, ctx);
  });

export type BadgeIssuanceRuleCondition =
  | {
      all: BadgeIssuanceRuleCondition[];
    }
  | {
      any: BadgeIssuanceRuleCondition[];
    }
  | {
      not: BadgeIssuanceRuleCondition;
    }
  | z.infer<typeof badgeIssuanceRuleGradeThresholdConditionSchema>
  | z.infer<typeof badgeIssuanceRuleCourseCompletionConditionSchema>
  | z.infer<typeof badgeIssuanceRuleProgramCompletionConditionSchema>
  | z.infer<typeof badgeIssuanceRuleAssignmentSubmissionConditionSchema>
  | z.infer<typeof badgeIssuanceRuleTimeWindowConditionSchema>
  | z.infer<typeof badgeIssuanceRulePrerequisiteBadgeConditionSchema>;

export const badgeIssuanceRuleConditionSchema: z.ZodType<BadgeIssuanceRuleCondition> = z.lazy(() =>
  z.union([
    z.object({
      all: z.array(badgeIssuanceRuleConditionSchema).min(1).max(50),
    }),
    z.object({
      any: z.array(badgeIssuanceRuleConditionSchema).min(1).max(50),
    }),
    z.object({
      not: badgeIssuanceRuleConditionSchema,
    }),
    badgeIssuanceRuleGradeThresholdConditionSchema,
    badgeIssuanceRuleCourseCompletionConditionSchema,
    badgeIssuanceRuleProgramCompletionConditionSchema,
    badgeIssuanceRuleAssignmentSubmissionConditionSchema,
    badgeIssuanceRuleTimeWindowConditionSchema,
    badgeIssuanceRulePrerequisiteBadgeConditionSchema,
  ]),
);

export const badgeIssuanceRuleDefinitionOptionsSchema = z.object({
  issuanceTiming: z.enum(["immediate", "manual", "end_of_term"]).optional(),
  reviewOnMissingFacts: z.boolean().optional(),
});

export const badgeIssuanceRuleDefinitionSchema = z.object({
  conditions: badgeIssuanceRuleConditionSchema,
  options: badgeIssuanceRuleDefinitionOptionsSchema.optional(),
});

export const badgeIssuanceRulePathParamsSchema = tenantPathParamsSchema.extend({
  ruleId: resourceIdSchema,
});

export const badgeIssuanceRuleVersionPathParamsSchema = badgeIssuanceRulePathParamsSchema.extend({
  versionId: resourceIdSchema,
});

export const badgeIssuanceRuleVersionDiffQuerySchema = z.object({
  baseVersionId: resourceIdSchema.optional(),
});

export const badgeIssuanceRuleAuditLogQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
});

const badgeIssuanceRuleApprovalChainStepSchema = z.object({
  requiredRole: tenantMembershipRoleSchema,
  label: z.string().trim().min(1).max(120).optional(),
});

const badgeIssuanceRuleApprovalChainSchema = z
  .array(badgeIssuanceRuleApprovalChainStepSchema)
  .min(1)
  .max(10);

export const createBadgeIssuanceRuleRequestSchema = z.object({
  name: z.string().trim().min(1).max(200),
  description: z.string().trim().min(1).max(2000).optional(),
  badgeTemplateId: resourceIdSchema,
  lmsProviderKind: badgeIssuanceRuleLmsProviderKindSchema,
  definition: badgeIssuanceRuleDefinitionSchema,
  approvalChain: badgeIssuanceRuleApprovalChainSchema.optional(),
  changeSummary: z.string().trim().min(1).max(1000).optional(),
});

export const createBadgeIssuanceRuleVersionRequestSchema = z.object({
  definition: badgeIssuanceRuleDefinitionSchema,
  approvalChain: badgeIssuanceRuleApprovalChainSchema.optional(),
  changeSummary: z.string().trim().min(1).max(1000).optional(),
});

export const decideBadgeIssuanceRuleVersionRequestSchema = z.object({
  decision: z.enum(["approved", "rejected"]),
  comment: z.string().trim().min(1).max(2000).optional(),
});

const badgeIssuanceRuleFactGradeSchema = z.object({
  courseId: z.string().trim().min(1).max(255),
  learnerId: z.string().trim().min(1).max(255),
  currentScore: z.number().finite().nullable().optional(),
  finalScore: z.number().finite().nullable().optional(),
});

const badgeIssuanceRuleFactCompletionSchema = z.object({
  courseId: z.string().trim().min(1).max(255),
  learnerId: z.string().trim().min(1).max(255),
  completed: z.boolean(),
  completionPercent: z.number().finite().nullable().optional(),
});

const badgeIssuanceRuleFactSubmissionSchema = z.object({
  courseId: z.string().trim().min(1).max(255),
  assignmentId: z.string().trim().min(1).max(255),
  learnerId: z.string().trim().min(1).max(255),
  score: z.number().finite().nullable().optional(),
  workflowState: z.string().trim().min(1).max(64).nullable().optional(),
  submittedAt: isoTimestampSchema.nullable().optional(),
});

export const badgeIssuanceRuleFactsSchema = z.object({
  nowIso: isoTimestampSchema.optional(),
  grades: z.array(badgeIssuanceRuleFactGradeSchema).optional(),
  completions: z.array(badgeIssuanceRuleFactCompletionSchema).optional(),
  submissions: z.array(badgeIssuanceRuleFactSubmissionSchema).optional(),
  earnedBadgeTemplateIds: z.array(resourceIdSchema).optional(),
});

export const evaluateBadgeIssuanceRuleRequestSchema = z.object({
  learnerId: z.string().trim().min(1).max(255),
  recipientIdentity: z.string().trim().min(1).max(512),
  recipientIdentityType: recipientIdentityTypeSchema,
  versionId: resourceIdSchema.optional(),
  dryRun: z.boolean().optional(),
  facts: badgeIssuanceRuleFactsSchema.optional(),
});

export const previewEvaluateBadgeIssuanceRuleRequestSchema = z.object({
  definition: badgeIssuanceRuleDefinitionSchema,
  lmsProviderKind: badgeIssuanceRuleLmsProviderKindSchema.default("canvas"),
  learnerId: z.string().trim().min(1).max(255),
  recipientIdentity: z.string().trim().min(1).max(512),
  recipientIdentityType: recipientIdentityTypeSchema,
  facts: badgeIssuanceRuleFactsSchema.optional(),
});

export const createBadgeIssuanceRuleValueListRequestSchema = z
  .object({
    label: z.string().trim().min(1).max(120),
    kind: badgeIssuanceRuleValueListKindSchema,
    values: z.array(z.string().trim().min(1).max(255)).min(1).max(500),
  })
  .superRefine((value, ctx) => {
    const normalizedValues = new Set(value.values.map((entry) => entry.trim().toLowerCase()));

    if (normalizedValues.size !== value.values.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["values"],
        message: "values must not contain duplicates",
      });
    }
  });

export const badgeIssuanceRuleValueListPathParamsSchema = tenantPathParamsSchema.extend({
  valueListId: resourceIdSchema,
});

export const badgeIssuanceRuleEvaluationPathParamsSchema = tenantPathParamsSchema.extend({
  evaluationId: resourceIdSchema,
});

export const badgeIssuanceRuleValueListQuerySchema = z.object({
  kind: badgeIssuanceRuleValueListKindSchema.optional(),
});

export const previewSimulateBadgeIssuanceRuleRequestSchema = z.object({
  definition: badgeIssuanceRuleDefinitionSchema,
  badgeTemplateId: resourceIdSchema,
  sampleLimit: z.number().int().min(1).max(100).optional(),
});

export const badgeIssuanceRuleReviewQueueQuerySchema = z.object({
  status: z.enum(["pending", "resolved"]).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

export const resolveBadgeIssuanceRuleReviewRequestSchema = z.object({
  decision: z.enum(["issue", "dismiss"]),
  comment: z.string().trim().min(1).max(2000).optional(),
});

export const createDedicatedDbProvisioningRequestSchema = z.object({
  targetRegion: z
    .string()
    .trim()
    .min(2)
    .max(64)
    .regex(/^[a-z0-9-]+$/),
  notes: z.string().trim().min(1).max(2000).optional(),
});

export const resolveDedicatedDbProvisioningRequestSchema = z.object({
  status: z.enum(["provisioned", "failed", "canceled"]),
  dedicatedDatabaseUrl: z.string().url().max(4096).optional(),
  notes: z.string().trim().min(1).max(2000).optional(),
  resolvedAt: isoTimestampSchema.optional(),
});

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
  platformJwksEndpoint: z.string().url().optional(),
  tokenEndpoint: z.string().url().optional(),
});

export const adminDeleteLtiIssuerRegistrationRequestSchema = z.object({
  issuer: z.string().url(),
});

export const adminAuditLogListQuerySchema = z.object({
  tenantId: tenantIdSchema,
  action: z
    .preprocess((input) => {
      if (typeof input !== "string") {
        return input;
      }

      const trimmed = input.trim();
      return trimmed.length === 0 ? undefined : trimmed;
    }, z.string().min(1).max(200))
    .optional(),
  limit: z.preprocess((input) => {
    if (input === undefined) {
      return undefined;
    }

    if (typeof input === "string") {
      const trimmed = input.trim();

      if (trimmed.length === 0) {
        return undefined;
      }

      const parsed = Number(trimmed);
      return Number.isNaN(parsed) ? input : parsed;
    }

    return input;
  }, z.number().int().min(1).max(200).default(100)),
});

export const magicLinkRequestSchema = z.object({
  tenantId: tenantIdSchema.optional(),
  email: z.string().email(),
  nextPath: z
    .string()
    .trim()
    .min(1)
    .max(2048)
    .refine((value) => value.startsWith("/"), {
      message: "nextPath must be a site-relative path",
    })
    .optional(),
  turnstileToken: z.string().trim().min(1).max(2048).optional(),
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

const isSupportedLearnerDidMethod = (value: string): boolean => {
  return (
    value.startsWith("did:key:") || value.startsWith("did:web:") || value.startsWith("did:ion:")
  );
};

export const learnerDidSettingsRequestSchema = z.object({
  did: z
    .string()
    .trim()
    .max(2048)
    .optional()
    .refine(
      (value) => value === undefined || value.length === 0 || isSupportedLearnerDidMethod(value),
      {
        message: "did must use did:key, did:web, or did:ion",
      },
    ),
});

export const presentationCreateRequestSchema = z
  .object({
    holderDid: z.string().trim().min(1).max(2048).startsWith("did:"),
    holderPrivateJwk: ed25519PrivateJwkSchema,
    credentialIds: z.array(resourceIdSchema).min(1).max(25),
  })
  .superRefine((value, ctx) => {
    const uniqueIds = new Set(value.credentialIds);

    if (uniqueIds.size !== value.credentialIds.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["credentialIds"],
        message: "credentialIds must not contain duplicates",
      });
    }
  });

export const presentationVerifyRequestSchema = z.object({
  presentation: jsonObjectSchema,
});

export const assertionLifecycleTransitionRequestSchema = z.object({
  toState: assertionLifecycleStateSchema,
  reasonCode: assertionLifecycleReasonCodeSchema,
  reason: z.string().trim().min(1).max(512).optional(),
  transitionSource: assertionLifecycleTransitionSourceSchema.default("manual"),
  transitionedAt: isoTimestampSchema.optional(),
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

export const programmaticIssueBadgeRequestSchema = issueBadgeRequestSchema
  .omit({
    requestedByUserId: true,
  })
  .extend({
    idempotencyKey: idempotencyKeySchema,
  });

export const githubUsernameSchema = z
  .string()
  .trim()
  .min(1)
  .max(39)
  .regex(/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/);

export const revokeBadgeRequestSchema = z.object({
  tenantId: tenantIdSchema,
  assertionId: resourceIdSchema,
  reason: z.string().min(1).max(512),
  requestedByUserId: userIdSchema.optional(),
  idempotencyKey: idempotencyKeySchema.optional(),
});

export const programmaticRevokeBadgeRequestSchema = revokeBadgeRequestSchema
  .omit({
    requestedByUserId: true,
  })
  .extend({
    idempotencyKey: idempotencyKeySchema,
  });

export const processQueueRequestSchema = z.object({
  limit: z.number().int().min(1).max(100).optional(),
  leaseSeconds: z.number().int().min(1).max(300).optional(),
  retryDelaySeconds: z.number().int().min(1).max(3600).optional(),
});

export const migrationBatchUploadQuerySchema = z.object({
  dryRun: z.preprocess((input) => {
    if (input === undefined) {
      return true;
    }

    if (input === "true") {
      return true;
    }

    if (input === "false") {
      return false;
    }

    return input;
  }, z.boolean()),
});

export const learnerRecordImportUploadQuerySchema = z.object({
  dryRun: z.preprocess((input) => {
    if (input === undefined) {
      return true;
    }

    if (input === "true") {
      return true;
    }

    if (input === "false") {
      return false;
    }

    return input;
  }, z.boolean()),
});

export const migrationProgressQuerySchema = z.object({
  source: z.preprocess(
    (input) => {
      if (input === undefined) {
        return "all";
      }

      return input;
    },
    z.enum(["all", "file_upload", "credly_export", "parchment_export"]),
  ),
  limit: z.preprocess((input) => {
    if (input === undefined) {
      return 50;
    }

    if (typeof input === "string") {
      const parsed = Number.parseInt(input, 10);

      return Number.isFinite(parsed) ? parsed : input;
    }

    return input;
  }, z.number().int().min(1).max(200)),
});

export const learnerRecordImportProgressQuerySchema = z.object({
  limit: z.preprocess((input) => {
    if (input === undefined) {
      return 25;
    }

    if (typeof input === "string") {
      const parsed = Number.parseInt(input, 10);
      return Number.isFinite(parsed) ? parsed : input;
    }

    return input;
  }, z.number().int().min(1).max(200)),
});

export const migrationBatchRetryRequestSchema = z.object({
  source: z.enum(["file_upload", "credly_export", "parchment_export"]).optional(),
  rowNumbers: z.array(z.number().int().min(1)).max(500).optional(),
});

export const learnerRecordImportRetryRequestSchema = z.object({
  rowNumbers: z.array(z.number().int().min(1)).max(500).optional(),
});

export const ob2ImportConversionRequestSchema = z
  .object({
    ob2Assertion: jsonObjectSchema.optional(),
    ob2BadgeClass: jsonObjectSchema.optional(),
    ob2Issuer: jsonObjectSchema.optional(),
    bakedBadgeImage: z.string().trim().min(1).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.ob2Assertion === undefined && value.bakedBadgeImage === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["ob2Assertion"],
        message: "Either ob2Assertion or bakedBadgeImage is required",
      });
    }
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
  jobType: z.literal("issue_badge"),
  tenantId: tenantIdSchema,
  payload: issueBadgeJobPayloadSchema,
  idempotencyKey: idempotencyKeySchema,
});

export const revokeBadgeQueueJobSchema = z.object({
  jobType: z.literal("revoke_badge"),
  tenantId: tenantIdSchema,
  payload: revokeBadgeJobPayloadSchema,
  idempotencyKey: idempotencyKeySchema,
});

export const rebuildVerificationCacheQueueJobSchema = z.object({
  jobType: z.literal("rebuild_verification_cache"),
  tenantId: tenantIdSchema,
  payload: z.record(z.string(), z.unknown()),
  idempotencyKey: idempotencyKeySchema,
});

export const importMigrationBatchQueueJobSchema = z.object({
  jobType: z.literal("import_migration_batch"),
  tenantId: tenantIdSchema,
  payload: z.record(z.string(), z.unknown()),
  idempotencyKey: idempotencyKeySchema,
});

export const learnerRecordImportQueuePayloadSchema = z.object({
  batchId: z.string().trim().min(1).max(128),
  rowNumber: z.number().int().min(1),
  fileName: z.string().trim().min(1).max(255),
  format: z.literal("csv"),
  requestedAt: isoTimestampSchema,
  requestedByUserId: userIdSchema.optional(),
  row: learnerRecordImportPreparedRowSchema,
});

export const learnerRecordImportBatchQueueJobSchema = z.object({
  jobType: z.literal("import_learner_record_batch"),
  tenantId: tenantIdSchema,
  payload: learnerRecordImportQueuePayloadSchema,
  idempotencyKey: idempotencyKeySchema,
});

export const queueJobSchema = z.discriminatedUnion("jobType", [
  issueBadgeQueueJobSchema,
  revokeBadgeQueueJobSchema,
  rebuildVerificationCacheQueueJobSchema,
  importMigrationBatchQueueJobSchema,
  learnerRecordImportBatchQueueJobSchema,
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
export type LearnerIdentityLinkVerifyRequest = z.infer<
  typeof learnerIdentityLinkVerifyRequestSchema
>;
export type LearnerDidSettingsRequest = z.infer<typeof learnerDidSettingsRequestSchema>;
export type PresentationCreateRequest = z.infer<typeof presentationCreateRequestSchema>;
export type PresentationVerifyRequest = z.infer<typeof presentationVerifyRequestSchema>;
export type AssertionLifecycleTransitionRequest = z.infer<
  typeof assertionLifecycleTransitionRequestSchema
>;
export type AssertionPathParams = z.infer<typeof assertionPathParamsSchema>;
export type AssertionLifecycleState = z.infer<typeof assertionLifecycleStateSchema>;
export type AssertionLifecycleReasonCode = z.infer<typeof assertionLifecycleReasonCodeSchema>;
export type AssertionLifecycleTransitionSource = z.infer<
  typeof assertionLifecycleTransitionSourceSchema
>;
export type RecipientIdentityType = z.infer<typeof recipientIdentityTypeSchema>;
export type LearnerRecordTrustLevel = z.infer<typeof learnerRecordTrustLevelSchema>;
export type LearnerRecordStatus = z.infer<typeof learnerRecordStatusSchema>;
export type LearnerRecordSourceSystem = z.infer<typeof learnerRecordSourceSystemSchema>;
export type LearnerRecordType = z.infer<typeof learnerRecordTypeSchema>;
export type LearnerRecordEntryType = z.infer<typeof learnerRecordEntryTypeSchema>;
export type LearnerRecordImportRow = z.infer<typeof learnerRecordImportRowSchema>;
export type LearnerRecordImportBatchDefaults = z.infer<
  typeof learnerRecordImportBatchDefaultsSchema
>;
export type IssueBadgeRequest = z.infer<typeof issueBadgeRequestSchema>;
export type RevokeBadgeRequest = z.infer<typeof revokeBadgeRequestSchema>;
export type ProgrammaticIssueBadgeRequest = z.infer<typeof programmaticIssueBadgeRequestSchema>;
export type ProgrammaticRevokeBadgeRequest = z.infer<typeof programmaticRevokeBadgeRequestSchema>;
export type ProcessQueueRequest = z.infer<typeof processQueueRequestSchema>;
export type MigrationBatchUploadQuery = z.infer<typeof migrationBatchUploadQuerySchema>;
export type LearnerRecordImportUploadQuery = z.infer<typeof learnerRecordImportUploadQuerySchema>;
export type MigrationProgressQuery = z.infer<typeof migrationProgressQuerySchema>;
export type LearnerRecordImportProgressQuery = z.infer<
  typeof learnerRecordImportProgressQuerySchema
>;
export type MigrationBatchRetryRequest = z.infer<typeof migrationBatchRetryRequestSchema>;
export type LearnerRecordImportRetryRequest = z.infer<typeof learnerRecordImportRetryRequestSchema>;
export type Ob2ImportConversionRequest = z.infer<typeof ob2ImportConversionRequestSchema>;
export type IssueBadgeQueueJob = z.infer<typeof issueBadgeQueueJobSchema>;
export type RevokeBadgeQueueJob = z.infer<typeof revokeBadgeQueueJobSchema>;
export type LearnerRecordImportBatchQueueJob = z.infer<
  typeof learnerRecordImportBatchQueueJobSchema
>;
export type ManualIssueBadgeRequest = z.infer<typeof manualIssueBadgeRequestSchema>;
export type TenantPathParams = z.infer<typeof tenantPathParamsSchema>;
export type LearnerRecordImportBatchPathParams = z.infer<
  typeof learnerRecordImportBatchPathParamsSchema
>;
export type MigrationBatchPathParams = z.infer<typeof migrationBatchPathParamsSchema>;
export type BadgeTemplatePathParams = z.infer<typeof badgeTemplatePathParamsSchema>;
export type CredentialPathParams = z.infer<typeof credentialPathParamsSchema>;
export type TenantUserPathParams = z.infer<typeof tenantUserPathParamsSchema>;
export type TenantUserOrgUnitPathParams = z.infer<typeof tenantUserOrgUnitPathParamsSchema>;
export type TenantUserDelegatedGrantPathParams = z.infer<
  typeof tenantUserDelegatedGrantPathParamsSchema
>;
export type TenantApiKeyPathParams = z.infer<typeof tenantApiKeyPathParamsSchema>;
export type TenantAuthProviderPathParams = z.infer<typeof tenantAuthProviderPathParamsSchema>;
export type LearnerRecordEntryPathParams = z.infer<typeof learnerRecordEntryPathParamsSchema>;
export type LearnerRecordExportPathParams = z.infer<typeof learnerRecordExportPathParamsSchema>;
export type TenantDedicatedDbProvisioningRequestPathParams = z.infer<
  typeof tenantDedicatedDbProvisioningRequestPathParamsSchema
>;
export type LearnerRecordEntryListQuery = z.infer<typeof learnerRecordEntryListQuerySchema>;
export type AdminLearnerRecordReviewQuery = z.infer<typeof adminLearnerRecordReviewQuerySchema>;
export type LearnerRecordExportProfile = z.infer<typeof learnerRecordExportProfileSchema>;
export type LearnerRecordStandardsSupportStatus = z.infer<
  typeof learnerRecordStandardsSupportStatusSchema
>;
export type LearnerRecordExportQuery = z.infer<typeof learnerRecordExportQuerySchema>;
export type LearnerRecordStandardsMappingQuery = z.infer<
  typeof learnerRecordStandardsMappingQuerySchema
>;
export type LearnerRecordProvenance = z.infer<typeof learnerRecordProvenanceSchema>;
export type CreateLearnerRecordEntryRequest = z.infer<typeof createLearnerRecordEntryRequestSchema>;
export type PatchLearnerRecordEntryRequest = z.infer<typeof patchLearnerRecordEntryRequestSchema>;
export type BadgeIssuanceRulePathParams = z.infer<typeof badgeIssuanceRulePathParamsSchema>;
export type BadgeIssuanceRuleVersionPathParams = z.infer<
  typeof badgeIssuanceRuleVersionPathParamsSchema
>;
export type BadgeIssuanceRuleValueListPathParams = z.infer<
  typeof badgeIssuanceRuleValueListPathParamsSchema
>;
export type BadgeIssuanceRuleEvaluationPathParams = z.infer<
  typeof badgeIssuanceRuleEvaluationPathParamsSchema
>;
export type BadgeIssuanceRuleVersionDiffQuery = z.infer<
  typeof badgeIssuanceRuleVersionDiffQuerySchema
>;
export type BadgeIssuanceRuleAuditLogQuery = z.infer<typeof badgeIssuanceRuleAuditLogQuerySchema>;
export type BadgeIssuanceRuleValueListQuery = z.infer<typeof badgeIssuanceRuleValueListQuerySchema>;
export type BadgeTemplateListQuery = z.infer<typeof badgeTemplateListQuerySchema>;
export type TenantOrgUnitListQuery = z.infer<typeof tenantOrgUnitListQuerySchema>;
export type DelegatedIssuingAuthorityGrantListQuery = z.infer<
  typeof delegatedIssuingAuthorityGrantListQuerySchema
>;
export type TenantApiKeyListQuery = z.infer<typeof tenantApiKeyListQuerySchema>;
export type TenantAssertionListQuery = z.infer<typeof tenantAssertionListQuerySchema>;
export type TenantAssertionLedgerExportQuery = z.infer<
  typeof tenantAssertionLedgerExportQuerySchema
>;
export type TenantReportingOverviewQuery = z.infer<typeof tenantReportingOverviewQuerySchema>;
export type TenantReportingTrendQuery = z.infer<typeof tenantReportingTrendQuerySchema>;
export type TenantReportingComparisonQuery = z.infer<typeof tenantReportingComparisonQuerySchema>;
export type TenantReportingHierarchyQuery = z.infer<typeof tenantReportingHierarchyQuerySchema>;
export type ExecutiveDashboardAudience = z.infer<typeof executiveDashboardAudienceSchema>;
export type ExecutiveDashboardWindow = z.infer<typeof executiveDashboardWindowSchema>;
export type TenantExecutiveDashboardQuery = z.infer<typeof tenantExecutiveDashboardQuerySchema>;
export type CreateBadgeTemplateRequest = z.infer<typeof createBadgeTemplateRequestSchema>;
export type UpdateBadgeTemplateRequest = z.infer<typeof updateBadgeTemplateRequestSchema>;
export type CreateTenantOrgUnitRequest = z.infer<typeof createTenantOrgUnitRequestSchema>;
export type UpsertTenantMembershipOrgUnitScopeRequest = z.infer<
  typeof upsertTenantMembershipOrgUnitScopeRequestSchema
>;
export type CreateDelegatedIssuingAuthorityGrantRequest = z.infer<
  typeof createDelegatedIssuingAuthorityGrantRequestSchema
>;
export type RevokeDelegatedIssuingAuthorityGrantRequest = z.infer<
  typeof revokeDelegatedIssuingAuthorityGrantRequestSchema
>;
export type TransferBadgeTemplateOwnershipRequest = z.infer<
  typeof transferBadgeTemplateOwnershipRequestSchema
>;
export type CreateTenantApiKeyRequest = z.infer<typeof createTenantApiKeyRequestSchema>;
export type RevokeTenantApiKeyRequest = z.infer<typeof revokeTenantApiKeyRequestSchema>;
export type UpsertTenantAuthPolicyRequest = z.infer<typeof upsertTenantAuthPolicyRequestSchema>;
export type UpsertTenantAuthProviderRequest = z.infer<typeof upsertTenantAuthProviderRequestSchema>;
export type CreateTenantBreakGlassAccountRequest = z.infer<
  typeof createTenantBreakGlassAccountRequestSchema
>;
export type UpsertTenantSsoSamlConfigurationRequest = z.infer<
  typeof upsertTenantSsoSamlConfigurationRequestSchema
>;
export type UpsertTenantCanvasGradebookIntegrationRequest = z.infer<
  typeof upsertTenantCanvasGradebookIntegrationRequestSchema
>;
export type AdminCanvasOAuthAuthorizeUrlRequest = z.infer<
  typeof adminCanvasOAuthAuthorizeUrlRequestSchema
>;
export type AdminCanvasOAuthExchangeRequest = z.infer<typeof adminCanvasOAuthExchangeRequestSchema>;
export type TenantCanvasGradebookSnapshotQuery = z.infer<
  typeof tenantCanvasGradebookSnapshotQuerySchema
>;
export type BadgeIssuanceRuleLmsProviderKind = z.infer<
  typeof badgeIssuanceRuleLmsProviderKindSchema
>;
export type BadgeIssuanceRuleValueListKind = z.infer<typeof badgeIssuanceRuleValueListKindSchema>;
export type BadgeIssuanceRuleDefinition = z.infer<typeof badgeIssuanceRuleDefinitionSchema>;
export type CreateBadgeIssuanceRuleRequest = z.infer<typeof createBadgeIssuanceRuleRequestSchema>;
export type CreateBadgeIssuanceRuleVersionRequest = z.infer<
  typeof createBadgeIssuanceRuleVersionRequestSchema
>;
export type CreateBadgeIssuanceRuleValueListRequest = z.infer<
  typeof createBadgeIssuanceRuleValueListRequestSchema
>;
export type DecideBadgeIssuanceRuleVersionRequest = z.infer<
  typeof decideBadgeIssuanceRuleVersionRequestSchema
>;
export type BadgeIssuanceRuleFacts = z.infer<typeof badgeIssuanceRuleFactsSchema>;
export type EvaluateBadgeIssuanceRuleRequest = z.infer<
  typeof evaluateBadgeIssuanceRuleRequestSchema
>;
export type PreviewEvaluateBadgeIssuanceRuleRequest = z.infer<
  typeof previewEvaluateBadgeIssuanceRuleRequestSchema
>;
export type PreviewSimulateBadgeIssuanceRuleRequest = z.infer<
  typeof previewSimulateBadgeIssuanceRuleRequestSchema
>;
export type BadgeIssuanceRuleReviewQueueQuery = z.infer<
  typeof badgeIssuanceRuleReviewQueueQuerySchema
>;
export type ResolveBadgeIssuanceRuleReviewRequest = z.infer<
  typeof resolveBadgeIssuanceRuleReviewRequestSchema
>;
export type CreateDedicatedDbProvisioningRequest = z.infer<
  typeof createDedicatedDbProvisioningRequestSchema
>;
export type ResolveDedicatedDbProvisioningRequest = z.infer<
  typeof resolveDedicatedDbProvisioningRequestSchema
>;
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
export type AdminUpsertTenantRequest = z.infer<typeof adminUpsertTenantRequestSchema>;
export type AdminUpsertTenantSigningRegistrationRequest = z.infer<
  typeof adminUpsertTenantSigningRegistrationRequestSchema
>;
export type AdminUpsertBadgeTemplateByIdRequest = z.infer<
  typeof adminUpsertBadgeTemplateByIdRequestSchema
>;
export type AdminUpsertTenantMembershipRoleRequest = z.infer<
  typeof adminUpsertTenantMembershipRoleRequestSchema
>;
export type AdminUpsertLtiIssuerRegistrationRequest = z.infer<
  typeof adminUpsertLtiIssuerRegistrationRequestSchema
>;
export type AdminDeleteLtiIssuerRegistrationRequest = z.infer<
  typeof adminDeleteLtiIssuerRegistrationRequestSchema
>;
export type AdminAuditLogListQuery = z.infer<typeof adminAuditLogListQuerySchema>;

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

export const parseLearnerDidSettingsRequest = (input: unknown): LearnerDidSettingsRequest => {
  return learnerDidSettingsRequestSchema.parse(input);
};

export const parsePresentationCreateRequest = (input: unknown): PresentationCreateRequest => {
  return presentationCreateRequestSchema.parse(input);
};

export const parsePresentationVerifyRequest = (input: unknown): PresentationVerifyRequest => {
  return presentationVerifyRequestSchema.parse(input);
};

export const parseAssertionLifecycleTransitionRequest = (
  input: unknown,
): AssertionLifecycleTransitionRequest => {
  return assertionLifecycleTransitionRequestSchema.parse(input);
};

export const parseAssertionPathParams = (input: unknown): AssertionPathParams => {
  return assertionPathParamsSchema.parse(input);
};

export const parseIssueBadgeRequest = (input: unknown): IssueBadgeRequest => {
  return issueBadgeRequestSchema.parse(input);
};

export const parseRevokeBadgeRequest = (input: unknown): RevokeBadgeRequest => {
  return revokeBadgeRequestSchema.parse(input);
};

export const parseProgrammaticIssueBadgeRequest = (
  input: unknown,
): ProgrammaticIssueBadgeRequest => {
  return programmaticIssueBadgeRequestSchema.parse(input);
};

export const parseProgrammaticRevokeBadgeRequest = (
  input: unknown,
): ProgrammaticRevokeBadgeRequest => {
  return programmaticRevokeBadgeRequestSchema.parse(input);
};

export const parseProcessQueueRequest = (input: unknown): ProcessQueueRequest => {
  return processQueueRequestSchema.parse(input);
};

export const parseMigrationBatchUploadQuery = (input: unknown): MigrationBatchUploadQuery => {
  return migrationBatchUploadQuerySchema.parse(input);
};

export const parseMigrationProgressQuery = (input: unknown): MigrationProgressQuery => {
  return migrationProgressQuerySchema.parse(input);
};

export const parseMigrationBatchRetryRequest = (input: unknown): MigrationBatchRetryRequest => {
  return migrationBatchRetryRequestSchema.parse(input);
};

export const parseOb2ImportConversionRequest = (input: unknown): Ob2ImportConversionRequest => {
  return ob2ImportConversionRequestSchema.parse(input);
};

export const parseManualIssueBadgeRequest = (input: unknown): ManualIssueBadgeRequest => {
  return manualIssueBadgeRequestSchema.parse(input);
};

export const parseTenantPathParams = (input: unknown): TenantPathParams => {
  return tenantPathParamsSchema.parse(input);
};

export const parseMigrationBatchPathParams = (input: unknown): MigrationBatchPathParams => {
  return migrationBatchPathParamsSchema.parse(input);
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

export const parseTenantDedicatedDbProvisioningRequestPathParams = (
  input: unknown,
): TenantDedicatedDbProvisioningRequestPathParams => {
  return tenantDedicatedDbProvisioningRequestPathParamsSchema.parse(input);
};

export const parseBadgeIssuanceRulePathParams = (input: unknown): BadgeIssuanceRulePathParams => {
  return badgeIssuanceRulePathParamsSchema.parse(input);
};

export const parseBadgeIssuanceRuleVersionPathParams = (
  input: unknown,
): BadgeIssuanceRuleVersionPathParams => {
  return badgeIssuanceRuleVersionPathParamsSchema.parse(input);
};

export const parseBadgeTemplateListQuery = (input: unknown): BadgeTemplateListQuery => {
  return badgeTemplateListQuerySchema.parse(input);
};

export const parseTenantOrgUnitListQuery = (input: unknown): TenantOrgUnitListQuery => {
  return tenantOrgUnitListQuerySchema.parse(input);
};

export const parseDelegatedIssuingAuthorityGrantListQuery = (
  input: unknown,
): DelegatedIssuingAuthorityGrantListQuery => {
  return delegatedIssuingAuthorityGrantListQuerySchema.parse(input);
};

export const parseTenantApiKeyListQuery = (input: unknown): TenantApiKeyListQuery => {
  return tenantApiKeyListQuerySchema.parse(input);
};

export const parseTenantAssertionListQuery = (input: unknown): TenantAssertionListQuery => {
  return tenantAssertionListQuerySchema.parse(input);
};

export const parseTenantAssertionLedgerExportQuery = (
  input: unknown,
): TenantAssertionLedgerExportQuery => {
  return tenantAssertionLedgerExportQuerySchema.parse(input);
};

export const parseTenantReportingOverviewQuery = (input: unknown): TenantReportingOverviewQuery => {
  return tenantReportingOverviewQuerySchema.parse(input);
};

export const parseTenantReportingTrendQuery = (input: unknown): TenantReportingTrendQuery => {
  return tenantReportingTrendQuerySchema.parse(input);
};

export const parseTenantReportingComparisonQuery = (
  input: unknown,
): TenantReportingComparisonQuery => {
  return tenantReportingComparisonQuerySchema.parse(input);
};

export const parseTenantReportingHierarchyQuery = (
  input: unknown,
): TenantReportingHierarchyQuery => {
  return tenantReportingHierarchyQuerySchema.parse(input);
};

export const parseTenantExecutiveDashboardQuery = (
  input: unknown,
): TenantExecutiveDashboardQuery => {
  return tenantExecutiveDashboardQuerySchema.parse(input);
};

export const parseCreateBadgeTemplateRequest = (input: unknown): CreateBadgeTemplateRequest => {
  return createBadgeTemplateRequestSchema.parse(input);
};

export const parseCreateTenantOrgUnitRequest = (input: unknown): CreateTenantOrgUnitRequest => {
  return createTenantOrgUnitRequestSchema.parse(input);
};

export const parseLearnerRecordEntryListQuery = (input: unknown): LearnerRecordEntryListQuery => {
  return learnerRecordEntryListQuerySchema.parse(input);
};

export const parseLearnerRecordImportRow = (input: unknown): LearnerRecordImportRow => {
  return learnerRecordImportRowSchema.parse(input);
};

export const parseLearnerRecordImportBatchDefaults = (
  input: unknown,
): LearnerRecordImportBatchDefaults => {
  return learnerRecordImportBatchDefaultsSchema.parse(input);
};

export const parseAdminLearnerRecordReviewQuery = (
  input: unknown,
): AdminLearnerRecordReviewQuery => {
  return adminLearnerRecordReviewQuerySchema.parse(input);
};

export const parseLearnerRecordEntryPathParams = (input: unknown): LearnerRecordEntryPathParams => {
  return learnerRecordEntryPathParamsSchema.parse(input);
};

export const parseLearnerRecordImportBatchPathParams = (
  input: unknown,
): LearnerRecordImportBatchPathParams => {
  return learnerRecordImportBatchPathParamsSchema.parse(input);
};

export const parseLearnerRecordExportPathParams = (
  input: unknown,
): LearnerRecordExportPathParams => {
  return learnerRecordExportPathParamsSchema.parse(input);
};

export const parseCreateLearnerRecordEntryRequest = (
  input: unknown,
): CreateLearnerRecordEntryRequest => {
  return createLearnerRecordEntryRequestSchema.parse(input);
};

export const parsePatchLearnerRecordEntryRequest = (
  input: unknown,
): PatchLearnerRecordEntryRequest => {
  return patchLearnerRecordEntryRequestSchema.parse(input);
};

export const parseLearnerRecordExportQuery = (input: unknown): LearnerRecordExportQuery => {
  return learnerRecordExportQuerySchema.parse(input);
};

export const parseLearnerRecordStandardsMappingQuery = (
  input: unknown,
): LearnerRecordStandardsMappingQuery => {
  return learnerRecordStandardsMappingQuerySchema.parse(input);
};

export const parseLearnerRecordImportUploadQuery = (
  input: unknown,
): LearnerRecordImportUploadQuery => {
  return learnerRecordImportUploadQuerySchema.parse(input);
};

export const parseLearnerRecordImportProgressQuery = (
  input: unknown,
): LearnerRecordImportProgressQuery => {
  return learnerRecordImportProgressQuerySchema.parse(input);
};

export const parseLearnerRecordImportRetryRequest = (
  input: unknown,
): LearnerRecordImportRetryRequest => {
  return learnerRecordImportRetryRequestSchema.parse(input);
};

export const parseUpsertTenantMembershipOrgUnitScopeRequest = (
  input: unknown,
): UpsertTenantMembershipOrgUnitScopeRequest => {
  return upsertTenantMembershipOrgUnitScopeRequestSchema.parse(input);
};

export const parseCreateDelegatedIssuingAuthorityGrantRequest = (
  input: unknown,
): CreateDelegatedIssuingAuthorityGrantRequest => {
  return createDelegatedIssuingAuthorityGrantRequestSchema.parse(input);
};

export const parseRevokeDelegatedIssuingAuthorityGrantRequest = (
  input: unknown,
): RevokeDelegatedIssuingAuthorityGrantRequest => {
  return revokeDelegatedIssuingAuthorityGrantRequestSchema.parse(input);
};

export const parseTransferBadgeTemplateOwnershipRequest = (
  input: unknown,
): TransferBadgeTemplateOwnershipRequest => {
  return transferBadgeTemplateOwnershipRequestSchema.parse(input);
};

export const parseCreateTenantApiKeyRequest = (input: unknown): CreateTenantApiKeyRequest => {
  return createTenantApiKeyRequestSchema.parse(input);
};

export const parseRevokeTenantApiKeyRequest = (input: unknown): RevokeTenantApiKeyRequest => {
  return revokeTenantApiKeyRequestSchema.parse(input);
};

export const parseUpsertTenantAuthPolicyRequest = (
  input: unknown,
): UpsertTenantAuthPolicyRequest => {
  return upsertTenantAuthPolicyRequestSchema.parse(input);
};

export const parseUpsertTenantAuthProviderRequest = (
  input: unknown,
): UpsertTenantAuthProviderRequest => {
  return upsertTenantAuthProviderRequestSchema.parse(input);
};

export const parseCreateTenantBreakGlassAccountRequest = (
  input: unknown,
): CreateTenantBreakGlassAccountRequest => {
  return createTenantBreakGlassAccountRequestSchema.parse(input);
};

export const parseUpsertTenantSsoSamlConfigurationRequest = (
  input: unknown,
): UpsertTenantSsoSamlConfigurationRequest => {
  return upsertTenantSsoSamlConfigurationRequestSchema.parse(input);
};

export const parseUpsertTenantCanvasGradebookIntegrationRequest = (
  input: unknown,
): UpsertTenantCanvasGradebookIntegrationRequest => {
  return upsertTenantCanvasGradebookIntegrationRequestSchema.parse(input);
};

export const parseAdminCanvasOAuthAuthorizeUrlRequest = (
  input: unknown,
): AdminCanvasOAuthAuthorizeUrlRequest => {
  return adminCanvasOAuthAuthorizeUrlRequestSchema.parse(input);
};

export const parseAdminCanvasOAuthExchangeRequest = (
  input: unknown,
): AdminCanvasOAuthExchangeRequest => {
  return adminCanvasOAuthExchangeRequestSchema.parse(input);
};

export const parseTenantCanvasGradebookSnapshotQuery = (
  input: unknown,
): TenantCanvasGradebookSnapshotQuery => {
  return tenantCanvasGradebookSnapshotQuerySchema.parse(input);
};

export const parseCreateBadgeIssuanceRuleRequest = (
  input: unknown,
): CreateBadgeIssuanceRuleRequest => {
  return createBadgeIssuanceRuleRequestSchema.parse(input);
};

export const parseBadgeIssuanceRuleVersionDiffQuery = (
  input: unknown,
): BadgeIssuanceRuleVersionDiffQuery => {
  return badgeIssuanceRuleVersionDiffQuerySchema.parse(input);
};

export const parseBadgeIssuanceRuleAuditLogQuery = (
  input: unknown,
): BadgeIssuanceRuleAuditLogQuery => {
  return badgeIssuanceRuleAuditLogQuerySchema.parse(input);
};

export const parseCreateBadgeIssuanceRuleValueListRequest = (
  input: unknown,
): CreateBadgeIssuanceRuleValueListRequest => {
  return createBadgeIssuanceRuleValueListRequestSchema.parse(input);
};

export const parseBadgeIssuanceRuleValueListPathParams = (
  input: unknown,
): BadgeIssuanceRuleValueListPathParams => {
  return badgeIssuanceRuleValueListPathParamsSchema.parse(input);
};

export const parseBadgeIssuanceRuleEvaluationPathParams = (
  input: unknown,
): BadgeIssuanceRuleEvaluationPathParams => {
  return badgeIssuanceRuleEvaluationPathParamsSchema.parse(input);
};

export const parseBadgeIssuanceRuleValueListQuery = (
  input: unknown,
): BadgeIssuanceRuleValueListQuery => {
  return badgeIssuanceRuleValueListQuerySchema.parse(input);
};

export const parseCreateBadgeIssuanceRuleVersionRequest = (
  input: unknown,
): CreateBadgeIssuanceRuleVersionRequest => {
  return createBadgeIssuanceRuleVersionRequestSchema.parse(input);
};

export const parseDecideBadgeIssuanceRuleVersionRequest = (
  input: unknown,
): DecideBadgeIssuanceRuleVersionRequest => {
  return decideBadgeIssuanceRuleVersionRequestSchema.parse(input);
};

export const parseEvaluateBadgeIssuanceRuleRequest = (
  input: unknown,
): EvaluateBadgeIssuanceRuleRequest => {
  return evaluateBadgeIssuanceRuleRequestSchema.parse(input);
};

export const parsePreviewEvaluateBadgeIssuanceRuleRequest = (
  input: unknown,
): PreviewEvaluateBadgeIssuanceRuleRequest => {
  return previewEvaluateBadgeIssuanceRuleRequestSchema.parse(input);
};

export const parsePreviewSimulateBadgeIssuanceRuleRequest = (
  input: unknown,
): PreviewSimulateBadgeIssuanceRuleRequest => {
  return previewSimulateBadgeIssuanceRuleRequestSchema.parse(input);
};

export const parseBadgeIssuanceRuleReviewQueueQuery = (
  input: unknown,
): BadgeIssuanceRuleReviewQueueQuery => {
  return badgeIssuanceRuleReviewQueueQuerySchema.parse(input);
};

export const parseResolveBadgeIssuanceRuleReviewRequest = (
  input: unknown,
): ResolveBadgeIssuanceRuleReviewRequest => {
  return resolveBadgeIssuanceRuleReviewRequestSchema.parse(input);
};

export const parseBadgeIssuanceRuleDefinition = (input: unknown): BadgeIssuanceRuleDefinition => {
  return badgeIssuanceRuleDefinitionSchema.parse(input);
};

export const parseCreateDedicatedDbProvisioningRequest = (
  input: unknown,
): CreateDedicatedDbProvisioningRequest => {
  return createDedicatedDbProvisioningRequestSchema.parse(input);
};

export const parseResolveDedicatedDbProvisioningRequest = (
  input: unknown,
): ResolveDedicatedDbProvisioningRequest => {
  return resolveDedicatedDbProvisioningRequestSchema.parse(input);
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

export const parseAdminAuditLogListQuery = (input: unknown): AdminAuditLogListQuery => {
  return adminAuditLogListQuerySchema.parse(input);
};
