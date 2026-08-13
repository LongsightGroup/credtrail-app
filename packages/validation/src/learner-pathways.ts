import { z } from "zod";
import { learnerRecordEntryTypeSchema, resourceIdSchema } from "./primitives.js";

const pathwayTextSchema = z.string().trim().min(1).max(200);
const pathwayRequirementDescriptionSchema = z.string().trim().min(1).max(2000).optional();

export const learnerPathwayRequirementSchema = z.discriminatedUnion("requirementKind", [
  z.object({
    requirementKind: z.literal("badge_template"),
    title: pathwayTextSchema,
    description: pathwayRequirementDescriptionSchema,
    badgeTemplateId: resourceIdSchema,
  }),
  z.object({
    requirementKind: z.literal("learner_record"),
    title: pathwayTextSchema,
    description: pathwayRequirementDescriptionSchema,
    learnerRecordType: learnerRecordEntryTypeSchema.exclude(["supplemental_artifact"]),
  }),
]);

export const createLearnerPathwayRequestSchema = z
  .object({
    ownerOrgUnitId: resourceIdSchema,
    title: pathwayTextSchema,
    learnerDescription: z.string().trim().min(1).max(4000),
    completionBehavior: z.enum(["mark_complete", "credential_eligible", "review_required"]),
    finalBadgeTemplateId: resourceIdSchema.optional(),
    requirements: z.array(learnerPathwayRequirementSchema).min(1).max(50),
  })
  .superRefine((value, context) => {
    const needsFinalCredential = value.completionBehavior !== "mark_complete";

    if (needsFinalCredential && value.finalBadgeTemplateId === undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["finalBadgeTemplateId"],
        message: "Choose the final credential for this completion behavior",
      });
    }

    if (!needsFinalCredential && value.finalBadgeTemplateId !== undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["finalBadgeTemplateId"],
        message: "A completion-only pathway cannot select a final credential",
      });
    }

    if (
      value.finalBadgeTemplateId !== undefined &&
      value.requirements.some(
        (requirement) =>
          requirement.requirementKind === "badge_template" &&
          requirement.badgeTemplateId === value.finalBadgeTemplateId,
      )
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["finalBadgeTemplateId"],
        message: "The final credential cannot also be a pathway requirement",
      });
    }
  });

export const enrollLearnerPathwayRequestSchema = z.object({
  learnerEmail: z.string().trim().email().max(320),
});

export const waiveLearnerPathwayRequirementRequestSchema = z.object({
  requirementId: resourceIdSchema,
  reason: z.string().trim().min(1).max(1000),
});

export const revokeLearnerPathwayRequirementWaiverRequestSchema = z.object({
  requirementId: resourceIdSchema,
  decision: z.literal("revoke_exception"),
});

export const retireLearnerPathwayRequestSchema = z.object({
  confirmation: z.literal("retire"),
});

export const learnerPathwayCompletionReviewRequestSchema = z.object({
  decision: z.literal("approve_for_issuance"),
});

export const learnerPathwayIssuanceQuerySchema = z.strictObject({
  pathwayHandoffId: resourceIdSchema,
  badgeTemplateId: resourceIdSchema,
});

export const learnerPathwayPathParamsSchema = z.object({
  tenantId: resourceIdSchema,
  pathwayId: resourceIdSchema,
});

export const learnerPathwayEnrollmentPathParamsSchema = z.object({
  tenantId: resourceIdSchema,
  enrollmentId: resourceIdSchema,
});

export const learnerPathwayVersionPathParamsSchema = z.object({
  tenantId: resourceIdSchema,
  pathwayId: resourceIdSchema,
  pathwayVersionId: resourceIdSchema,
});

export type CreateLearnerPathwayRequest = z.infer<typeof createLearnerPathwayRequestSchema>;

export const parseCreateLearnerPathwayRequest = (input: unknown): CreateLearnerPathwayRequest => {
  return createLearnerPathwayRequestSchema.parse(input);
};

export const parseEnrollLearnerPathwayRequest = (
  input: unknown,
): z.infer<typeof enrollLearnerPathwayRequestSchema> => {
  return enrollLearnerPathwayRequestSchema.parse(input);
};

export const parseWaiveLearnerPathwayRequirementRequest = (
  input: unknown,
): z.infer<typeof waiveLearnerPathwayRequirementRequestSchema> => {
  return waiveLearnerPathwayRequirementRequestSchema.parse(input);
};

export const parseRevokeLearnerPathwayRequirementWaiverRequest = (
  input: unknown,
): z.infer<typeof revokeLearnerPathwayRequirementWaiverRequestSchema> => {
  return revokeLearnerPathwayRequirementWaiverRequestSchema.parse(input);
};

export const parseRetireLearnerPathwayRequest = (
  input: unknown,
): z.infer<typeof retireLearnerPathwayRequestSchema> => {
  return retireLearnerPathwayRequestSchema.parse(input);
};

export const parseLearnerPathwayCompletionReviewRequest = (
  input: unknown,
): z.infer<typeof learnerPathwayCompletionReviewRequestSchema> => {
  return learnerPathwayCompletionReviewRequestSchema.parse(input);
};

/** Safely parses optional governed-pathway issuance context from a page query. */
export const safeParseLearnerPathwayIssuanceQuery = (
  input: unknown,
):
  | {
      readonly ok: true;
      readonly value: z.infer<typeof learnerPathwayIssuanceQuerySchema>;
    }
  | { readonly ok: false } => {
  const result = learnerPathwayIssuanceQuerySchema.safeParse(input);
  return result.success ? { ok: true, value: result.data } : { ok: false };
};

export const parseLearnerPathwayPathParams = (
  input: unknown,
): z.infer<typeof learnerPathwayPathParamsSchema> => {
  return learnerPathwayPathParamsSchema.parse(input);
};

export const parseLearnerPathwayEnrollmentPathParams = (
  input: unknown,
): z.infer<typeof learnerPathwayEnrollmentPathParamsSchema> => {
  return learnerPathwayEnrollmentPathParamsSchema.parse(input);
};

export const parseLearnerPathwayVersionPathParams = (
  input: unknown,
): z.infer<typeof learnerPathwayVersionPathParamsSchema> => {
  return learnerPathwayVersionPathParamsSchema.parse(input);
};
