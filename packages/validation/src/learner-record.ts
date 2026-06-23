import { z } from "zod";
import { jsonObjectSchema } from "./json.js";
import {
  badgeTemplateSlugSchema,
  isoTimestampSchema,
  learnerRecordEntryTypeSchema,
  learnerRecordSourceSystemSchema,
  learnerRecordStatusSchema,
  learnerRecordTrustLevelSchema,
  orgUnitSlugSchema,
  resourceIdSchema,
  userIdSchema,
} from "./primitives.js";

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

export const learnerRecordImportPreparedRowSchema = z.object({
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
// --- inferred types and parsers ---
export type LearnerRecordImportRow = z.infer<typeof learnerRecordImportRowSchema>;

export type LearnerRecordImportBatchDefaults = z.infer<
  typeof learnerRecordImportBatchDefaultsSchema
>;

export type LearnerRecordProvenance = z.infer<typeof learnerRecordProvenanceSchema>;

export type CreateLearnerRecordEntryRequest = z.infer<typeof createLearnerRecordEntryRequestSchema>;

export type PatchLearnerRecordEntryRequest = z.infer<typeof patchLearnerRecordEntryRequestSchema>;

export const parseLearnerRecordImportRow = (input: unknown): LearnerRecordImportRow => {
  return learnerRecordImportRowSchema.parse(input);
};

export const parseLearnerRecordImportBatchDefaults = (
  input: unknown,
): LearnerRecordImportBatchDefaults => {
  return learnerRecordImportBatchDefaultsSchema.parse(input);
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
