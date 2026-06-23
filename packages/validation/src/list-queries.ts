import { z } from "zod";
import {
  learnerRecordStatusSchema,
  learnerRecordTrustLevelSchema,
  resourceIdSchema,
} from "./primitives.js";
import { assertionLifecycleStateSchema, tenantPathParamsSchema } from "./path-params.js";

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

const adminLearnerRecordReviewQueryFields = ["learnerProfileId", "email"] as const;

const normalizeAdminLearnerRecordReviewQuery = (input: unknown): unknown => {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return input;
  }

  const normalized: Record<string, unknown> = { ...(input as Record<string, unknown>) };

  for (const field of adminLearnerRecordReviewQueryFields) {
    const value = normalized[field];

    if (typeof value !== "string") {
      continue;
    }

    const trimmed = value.trim();

    if (trimmed.length === 0) {
      delete normalized[field];
      continue;
    }

    normalized[field] = trimmed;
  }

  return normalized;
};

export const adminLearnerRecordReviewQuerySchema = z.preprocess(
  normalizeAdminLearnerRecordReviewQuery,
  z
    .object({
      learnerProfileId: resourceIdSchema.optional(),
      email: z.string().email().max(320).optional(),
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
    }),
);

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

const optionalBlankStringToUndefined = (input: unknown): unknown => {
  if (typeof input !== "string") {
    return input;
  }

  const trimmed = input.trim();
  return trimmed.length === 0 ? undefined : trimmed;
};

const assertionListDateSchema = z.iso.date();

export const tenantAssertionListQuerySchema = z
  .object({
    issuedFrom: z.preprocess(optionalBlankStringToUndefined, assertionListDateSchema.optional()),
    issuedTo: z.preprocess(optionalBlankStringToUndefined, assertionListDateSchema.optional()),
    badgeTemplateId: z.preprocess(optionalBlankStringToUndefined, resourceIdSchema.optional()),
    orgUnitId: z.preprocess(optionalBlankStringToUndefined, resourceIdSchema.optional()),
    recipientQuery: z.preprocess(
      optionalBlankStringToUndefined,
      z.string().min(1).max(320).optional(),
    ),
    state: z.preprocess(optionalBlankStringToUndefined, assertionLifecycleStateSchema.optional()),
    limit: z.preprocess(
      optionalBlankStringToUndefined,
      z.coerce.number().int().min(1).max(500).optional(),
    ),
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
// --- inferred types and parsers ---
export type LearnerRecordExportPathParams = z.infer<typeof learnerRecordExportPathParamsSchema>;

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

export type BadgeTemplateListQuery = z.infer<typeof badgeTemplateListQuerySchema>;

export type TenantOrgUnitListQuery = z.infer<typeof tenantOrgUnitListQuerySchema>;

export type DelegatedIssuingAuthorityGrantListQuery = z.infer<
  typeof delegatedIssuingAuthorityGrantListQuerySchema
>;

export type TenantApiKeyListQuery = z.infer<typeof tenantApiKeyListQuerySchema>;

export type TenantAssertionListQuery = z.infer<typeof tenantAssertionListQuerySchema>;

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

export const parseLearnerRecordEntryListQuery = (input: unknown): LearnerRecordEntryListQuery => {
  return learnerRecordEntryListQuerySchema.parse(input);
};

export const parseAdminLearnerRecordReviewQuery = (
  input: unknown,
): AdminLearnerRecordReviewQuery => {
  return adminLearnerRecordReviewQuerySchema.parse(input);
};

export const parseLearnerRecordExportPathParams = (
  input: unknown,
): LearnerRecordExportPathParams => {
  return learnerRecordExportPathParamsSchema.parse(input);
};

export const parseLearnerRecordExportQuery = (input: unknown): LearnerRecordExportQuery => {
  return learnerRecordExportQuerySchema.parse(input);
};

export const parseLearnerRecordStandardsMappingQuery = (
  input: unknown,
): LearnerRecordStandardsMappingQuery => {
  return learnerRecordStandardsMappingQuerySchema.parse(input);
};
