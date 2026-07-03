import { z } from "zod";
import { jsonObjectSchema, idempotencyKeySchema } from "./json.js";
import { ed25519PrivateJwkSchema } from "./signing.js";
import {
  isoTimestampSchema,
  recipientIdentityTypeSchema,
  recipientIdentifierSchema,
  resourceIdSchema,
  tenantIdSchema,
  userIdSchema,
} from "./primitives.js";
import {
  assertionLifecycleReasonCodeSchema,
  assertionLifecycleStateSchema,
  assertionLifecycleTransitionSourceSchema,
} from "./path-params.js";

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

export const assertionIssuanceProvenanceSourceSchema = z.enum([
  "lti_roster",
  "rule_evaluate",
  "manual",
  "programmatic",
]);

export const assertionIssuanceProvenanceInputSchema = z.object({
  source: assertionIssuanceProvenanceSourceSchema,
  ruleId: resourceIdSchema.optional(),
  versionId: resourceIdSchema.optional(),
  provenanceJson: z.string().optional(),
});

export const issueBadgeRequestSchema = z.object({
  tenantId: tenantIdSchema,
  badgeTemplateId: resourceIdSchema,
  recipientIdentity: z.string().min(1),
  recipientIdentityType: recipientIdentityTypeSchema,
  recipientIdentifiers: z.array(recipientIdentifierSchema).max(10).optional(),
  recipientDisplayName: z.string().trim().min(1).max(200).optional(),
  issuerImageUri: z.string().trim().url().max(2048).optional(),
  requestedByUserId: userIdSchema.optional(),
  idempotencyKey: idempotencyKeySchema.optional(),
  issuanceProvenance: assertionIssuanceProvenanceInputSchema.optional(),
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
// --- inferred types and parsers ---
export type PresentationCreateRequest = z.infer<typeof presentationCreateRequestSchema>;

export type PresentationVerifyRequest = z.infer<typeof presentationVerifyRequestSchema>;

export type AssertionLifecycleTransitionRequest = z.infer<
  typeof assertionLifecycleTransitionRequestSchema
>;

export type AssertionIssuanceProvenanceInput = z.infer<
  typeof assertionIssuanceProvenanceInputSchema
>;

export type IssueBadgeRequest = z.infer<typeof issueBadgeRequestSchema>;

export type RevokeBadgeRequest = z.infer<typeof revokeBadgeRequestSchema>;

export type ProgrammaticIssueBadgeRequest = z.infer<typeof programmaticIssueBadgeRequestSchema>;

export type ProgrammaticRevokeBadgeRequest = z.infer<typeof programmaticRevokeBadgeRequestSchema>;

export type ManualIssueBadgeRequest = z.infer<typeof manualIssueBadgeRequestSchema>;

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

export const parseManualIssueBadgeRequest = (input: unknown): ManualIssueBadgeRequest => {
  return manualIssueBadgeRequestSchema.parse(input);
};
