import { z } from "zod";
import { trustedCredentialMetadataSchema } from "./trusted-credential.js";
import {
  badgeTemplateDescriptionSchema,
  badgeTemplateSlugSchema,
  badgeTemplateTitleSchema,
  badgeTemplateUriSchema,
  resourceIdSchema,
} from "./primitives.js";

export const createBadgeTemplateRequestSchema = z.object({
  slug: badgeTemplateSlugSchema,
  title: badgeTemplateTitleSchema,
  description: badgeTemplateDescriptionSchema.optional(),
  criteriaUri: badgeTemplateUriSchema.optional(),
  imageUri: badgeTemplateUriSchema.optional(),
  trustedCredentialMetadata: trustedCredentialMetadataSchema.optional(),
  ownerOrgUnitId: resourceIdSchema.optional(),
});

export const updateBadgeTemplateRequestSchema = z
  .object({
    slug: badgeTemplateSlugSchema.optional(),
    title: badgeTemplateTitleSchema.optional(),
    description: badgeTemplateDescriptionSchema.nullable().optional(),
    criteriaUri: badgeTemplateUriSchema.nullable().optional(),
    imageUri: badgeTemplateUriSchema.nullable().optional(),
    trustedCredentialMetadata: trustedCredentialMetadataSchema.nullable().optional(),
  })
  .refine(
    (payload) =>
      payload.slug !== undefined ||
      payload.title !== undefined ||
      payload.description !== undefined ||
      payload.criteriaUri !== undefined ||
      payload.imageUri !== undefined ||
      payload.trustedCredentialMetadata !== undefined,
    {
      message: "At least one badge template field must be provided",
    },
  );

export const badgeTemplateImageGenerationStylePresetSchema = z.enum([
  "institutional",
  "technical",
  "academic",
  "open_source",
  "minimal",
]);

export const generateBadgeTemplateImageRequestSchema = z.object({
  stylePreset: badgeTemplateImageGenerationStylePresetSchema.default("institutional"),
  promptNotes: z.string().trim().max(1000).optional(),
  accentColor: z.string().trim().max(80).optional(),
});

export const applyBadgeTemplateImageDesignRequestSchema = z.object({
  imageUri: badgeTemplateUriSchema,
});
// --- inferred types and parsers ---
export type CreateBadgeTemplateRequest = z.infer<typeof createBadgeTemplateRequestSchema>;

export type UpdateBadgeTemplateRequest = z.infer<typeof updateBadgeTemplateRequestSchema>;

export type GenerateBadgeTemplateImageRequest = z.infer<
  typeof generateBadgeTemplateImageRequestSchema
>;

export type ApplyBadgeTemplateImageDesignRequest = z.infer<
  typeof applyBadgeTemplateImageDesignRequestSchema
>;

export const parseCreateBadgeTemplateRequest = (input: unknown): CreateBadgeTemplateRequest => {
  return createBadgeTemplateRequestSchema.parse(input);
};

export const parseUpdateBadgeTemplateRequest = (input: unknown): UpdateBadgeTemplateRequest => {
  return updateBadgeTemplateRequestSchema.parse(input);
};

export const parseGenerateBadgeTemplateImageRequest = (
  input: unknown,
): GenerateBadgeTemplateImageRequest => {
  return generateBadgeTemplateImageRequestSchema.parse(input);
};

export const parseApplyBadgeTemplateImageDesignRequest = (
  input: unknown,
): ApplyBadgeTemplateImageDesignRequest => {
  return applyBadgeTemplateImageDesignRequestSchema.parse(input);
};
