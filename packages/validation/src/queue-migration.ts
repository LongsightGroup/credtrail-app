import { z } from "zod";
import { jsonObjectSchema, idempotencyKeySchema, queueJobTypeSchema } from "./json.js";
import { assertionIssuanceProvenanceInputSchema } from "./credentials.js";
import {
  isoTimestampSchema,
  recipientIdentityTypeSchema,
  recipientIdentifierSchema,
  resourceIdSchema,
  tenantIdSchema,
  userIdSchema,
} from "./primitives.js";
import { badgeTemplateImageGenerationStylePresetSchema } from "./badge-template.js";
import { learnerRecordImportPreparedRowSchema } from "./learner-record.js";

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
  recipientDisplayName: z.string().trim().min(1).max(200).optional(),
  issuerImageUri: z.string().trim().url().max(2048).optional(),
  requestedAt: isoTimestampSchema,
  requestedByUserId: userIdSchema.optional(),
  issuanceProvenance: assertionIssuanceProvenanceInputSchema.default({ source: "programmatic" }),
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

export const generateBadgeTemplateImageJobPayloadSchema = z.object({
  generationId: resourceIdSchema,
  badgeTemplateId: resourceIdSchema,
  promptText: z.string().trim().min(1).max(4000),
  stylePreset: badgeTemplateImageGenerationStylePresetSchema,
  promptNotes: z.string().trim().max(1000).optional(),
  accentColor: z.string().trim().max(80).optional(),
  requestedAt: isoTimestampSchema,
  requestedByUserId: userIdSchema.optional(),
});

export const generateBadgeTemplateImageQueueJobSchema = z.object({
  jobType: z.literal("generate_badge_template_image"),
  tenantId: tenantIdSchema,
  payload: generateBadgeTemplateImageJobPayloadSchema,
  idempotencyKey: idempotencyKeySchema,
});

export const processBadgeRuleLifecycleJobPayloadSchema = z.object({
  scheduledFor: isoTimestampSchema,
});

export const processBadgeRuleLifecycleQueueJobSchema = z.object({
  jobType: z.literal("process_badge_rule_lifecycle"),
  tenantId: tenantIdSchema,
  payload: processBadgeRuleLifecycleJobPayloadSchema,
  idempotencyKey: idempotencyKeySchema,
});

export const processAutomatedBadgeRuleJobPayloadSchema = z
  .object({
    ruleId: resourceIdSchema,
    versionId: resourceIdSchema,
    scheduledFor: isoTimestampSchema,
  })
  .strict();

export const processAutomatedBadgeRuleQueueJobSchema = z.object({
  jobType: z.literal("process_automated_badge_rule"),
  tenantId: tenantIdSchema,
  payload: processAutomatedBadgeRuleJobPayloadSchema,
  idempotencyKey: idempotencyKeySchema,
});

const badgeRuleApprovalDecisionSchema = z.enum(["approved", "rejected", "changes_requested"]);

export const sendBadgeRuleApprovalSubmittedNotificationJobPayloadSchema = z
  .object({
    notificationType: z.literal("approval_submitted"),
    ruleId: resourceIdSchema,
    versionId: resourceIdSchema,
    targetStepNumber: z.number().int().min(1).nullable(),
  })
  .strict();

export const sendBadgeRuleApprovalDecisionNotificationJobPayloadSchema = z
  .object({
    notificationType: z.literal("approval_decision"),
    ruleId: resourceIdSchema,
    versionId: resourceIdSchema,
    decision: badgeRuleApprovalDecisionSchema,
    comment: z.string().trim().min(1).max(2000).nullable(),
    nextStepNumber: z.number().int().min(1).nullable(),
  })
  .strict();

export const sendBadgeRuleApprovalNotificationJobPayloadSchema = z.discriminatedUnion(
  "notificationType",
  [
    sendBadgeRuleApprovalSubmittedNotificationJobPayloadSchema,
    sendBadgeRuleApprovalDecisionNotificationJobPayloadSchema,
  ],
);

export const sendBadgeRuleApprovalNotificationQueueJobSchema = z.object({
  jobType: z.literal("send_badge_rule_approval_notification"),
  tenantId: tenantIdSchema,
  payload: sendBadgeRuleApprovalNotificationJobPayloadSchema,
  idempotencyKey: idempotencyKeySchema,
});

export const queueJobSchema = z.discriminatedUnion("jobType", [
  issueBadgeQueueJobSchema,
  revokeBadgeQueueJobSchema,
  rebuildVerificationCacheQueueJobSchema,
  importMigrationBatchQueueJobSchema,
  learnerRecordImportBatchQueueJobSchema,
  generateBadgeTemplateImageQueueJobSchema,
  processBadgeRuleLifecycleQueueJobSchema,
  processAutomatedBadgeRuleQueueJobSchema,
  sendBadgeRuleApprovalNotificationQueueJobSchema,
]);

export const queueEnvelopeSchema = z.object({
  jobType: queueJobTypeSchema,
  tenantId: z.string().min(1),
  payload: z.record(z.string(), z.unknown()),
  idempotencyKey: idempotencyKeySchema,
});
// --- inferred types and parsers ---
export type QueueJob = z.infer<typeof queueJobSchema>;

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

export type GenerateBadgeTemplateImageQueueJob = z.infer<
  typeof generateBadgeTemplateImageQueueJobSchema
>;

export type ProcessBadgeRuleLifecycleQueueJob = z.infer<
  typeof processBadgeRuleLifecycleQueueJobSchema
>;

export type ProcessAutomatedBadgeRuleQueueJob = z.infer<
  typeof processAutomatedBadgeRuleQueueJobSchema
>;

export type SendBadgeRuleApprovalNotificationQueueJob = z.infer<
  typeof sendBadgeRuleApprovalNotificationQueueJobSchema
>;

export const parseQueueJob = (input: unknown): QueueJob => {
  return queueJobSchema.parse(input);
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
