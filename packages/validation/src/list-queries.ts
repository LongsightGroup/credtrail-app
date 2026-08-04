import { z } from "zod";
import {
  learnerRecordStatusSchema,
  learnerRecordTrustLevelSchema,
  resourceIdSchema,
} from "./primitives.js";
import { tenantPathParamsSchema } from "./path-params.js";
import {
  optionalBlankStringToUndefined,
  refineAssertionIssuedDateRange,
  tenantAssertionRecordFilterQueryShape,
} from "./assertion-record-filter-queries.js";

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

const adminLearnerRecordReviewQueryFields = ["learner"] as const;

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
  z.object({
    learner: z.string().min(1).max(320).optional(),
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

export const tenantAssertionListQuerySchema = z
  .object({
    ...tenantAssertionRecordFilterQueryShape,
    limit: z.preprocess(
      optionalBlankStringToUndefined,
      z.coerce.number().int().min(1).max(500).optional(),
    ),
  })
  .superRefine(refineAssertionIssuedDateRange);
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
