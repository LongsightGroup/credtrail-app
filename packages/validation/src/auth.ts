import { z } from "zod";
import { tenantIdSchema } from "./primitives.js";

export const magicLinkRequestSchema = z.object({
  tenantId: tenantIdSchema.optional(),
  email: z.string().email(),
  preferredLocale: z.string().trim().min(1).max(64).optional(),
  preferredTimeZone: z.string().trim().min(1).max(128).optional(),
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
// --- inferred types and parsers ---
export type MagicLinkRequest = z.infer<typeof magicLinkRequestSchema>;

export type MagicLinkVerifyRequest = z.infer<typeof magicLinkVerifyRequestSchema>;

export type LearnerIdentityLinkRequest = z.infer<typeof learnerIdentityLinkRequestSchema>;

export type LearnerIdentityLinkVerifyRequest = z.infer<
  typeof learnerIdentityLinkVerifyRequestSchema
>;

export type LearnerDidSettingsRequest = z.infer<typeof learnerDidSettingsRequestSchema>;

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
