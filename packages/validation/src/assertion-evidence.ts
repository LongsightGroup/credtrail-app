import { z } from "zod";

import { assertionIssuanceProvenanceSourceSchema } from "./credentials.js";
import { isoTimestampSchema, resourceIdSchema, tenantIdSchema } from "./primitives.js";

export const assertionEvidenceIssuanceSourceSchema = assertionIssuanceProvenanceSourceSchema;

export const assertionEvidenceDetailRowSchema = z.object({
  label: z.string(),
  value: z.string(),
});

export const assertionEvidenceApprovalEntrySchema = z.object({
  occurredAt: isoTimestampSchema,
  actorLabel: z.string(),
  actorRole: z.string().nullable(),
  actionLabel: z.string(),
  comment: z.string().nullable(),
});

export const assertionEvidenceEvaluationOutcomeSchema = z.object({
  outcome: z.enum(["matched", "failed_condition", "missing_data", "group"]),
  detail: z.string(),
});

export const assertionEvidenceTimelineEntrySchema = z.object({
  id: z.string(),
  occurredAt: isoTimestampSchema,
  actorLabel: z.string(),
  summary: z.string(),
  detail: z.string(),
});

export const assertionEvidenceReviewSectionSchema = z.object({
  decision: z.string(),
  reviewerLabel: z.string(),
  reviewedAt: isoTimestampSchema,
  comment: z.string().nullable(),
});

export const assertionEvidenceResponseSchema = z.object({
  assertionId: resourceIdSchema,
  tenantId: tenantIdSchema,
  generatedAt: isoTimestampSchema,
  summary: z.object({
    badgeTitle: z.string(),
    recipientIdentity: z.string(),
    issuedAt: isoTimestampSchema,
    publicId: z.string().nullable(),
    lifecycleState: z.string(),
    attributedOrgUnitName: z.string().nullable(),
  }),
  issuance: z.object({
    source: assertionEvidenceIssuanceSourceSchema,
    sourceLabel: z.string(),
    issuerLabel: z.string().nullable(),
  }),
  rule: z
    .object({
      ruleId: resourceIdSchema,
      ruleName: z.string(),
      versionNumber: z.number().int().positive(),
      versionStatus: z.string(),
      versionId: resourceIdSchema,
      submittedAt: isoTimestampSchema.nullable(),
      approvedAt: isoTimestampSchema.nullable(),
      activatedAt: isoTimestampSchema.nullable(),
      changeSummary: z.string().nullable(),
    })
    .nullable(),
  approvalEntries: z.array(assertionEvidenceApprovalEntrySchema),
  factsSummary: z.array(z.string()),
  evaluationOutcomes: z.array(assertionEvidenceEvaluationOutcomeSchema),
  review: assertionEvidenceReviewSectionSchema.nullable(),
  changesAfterIssuance: z.array(assertionEvidenceTimelineEntrySchema),
  supportDetails: z.array(assertionEvidenceDetailRowSchema),
});

export type AssertionEvidenceResponse = z.infer<typeof assertionEvidenceResponseSchema>;

export interface BadgeIssuanceRuleEvidenceEvaluationNode {
  type: string;
  matched: boolean;
  detail: string;
  resultKind?: "matched" | "failed_condition" | "missing_data" | undefined;
  children?: BadgeIssuanceRuleEvidenceEvaluationNode[] | undefined;
}

export const badgeIssuanceRuleEvidenceEvaluationNodeSchema: z.ZodType<BadgeIssuanceRuleEvidenceEvaluationNode> =
  z.lazy(() =>
    z
      .object({
        type: z.string(),
        matched: z.boolean(),
        detail: z.string(),
        resultKind: z.enum(["matched", "failed_condition", "missing_data"]).optional(),
        children: z.array(badgeIssuanceRuleEvidenceEvaluationNodeSchema).optional(),
      })
      .strict(),
  );

export const badgeIssuanceRuleEvidenceFactsSchema = z
  .object({
    learnerId: z.string().default(""),
    nowIso: isoTimestampSchema.default("1970-01-01T00:00:00.000Z"),
    grades: z.array(z.unknown()).default([]),
    completions: z.array(z.unknown()).default([]),
    submissions: z.array(z.unknown()).default([]),
    surveyCompletions: z.array(z.unknown()).default([]),
    customFields: z.array(z.unknown()).default([]),
    earnedBadgeTemplateIds: z.array(z.unknown()).default([]),
  })
  .passthrough();

export const assertionEvidenceProvenanceSnapshotSchema = z
  .object({
    outcome: z.enum(["matched", "no_match"]),
    evaluation: z.object({
      matched: z.boolean(),
      tree: badgeIssuanceRuleEvidenceEvaluationNodeSchema,
    }),
    evaluationSummary: z.unknown().optional(),
    facts: badgeIssuanceRuleEvidenceFactsSchema,
    learnerId: z.string(),
    nowIso: isoTimestampSchema,
  })
  .strict();

export const assertionEvidenceEvaluationSnapshotSchema = z
  .object({
    evaluation: z.object({
      matched: z.boolean(),
      tree: badgeIssuanceRuleEvidenceEvaluationNodeSchema,
    }),
    facts: badgeIssuanceRuleEvidenceFactsSchema,
  })
  .passthrough();

export type BadgeIssuanceRuleEvidenceFacts = z.infer<typeof badgeIssuanceRuleEvidenceFactsSchema>;

export type AssertionEvidenceProvenanceSnapshot = z.infer<
  typeof assertionEvidenceProvenanceSnapshotSchema
>;

export type AssertionEvidenceEvaluationSnapshot = z.infer<
  typeof assertionEvidenceEvaluationSnapshotSchema
>;

export const parseAssertionEvidenceResponse = (input: unknown): AssertionEvidenceResponse => {
  return assertionEvidenceResponseSchema.parse(input);
};

export const parseAssertionEvidenceProvenanceSnapshot = (
  input: unknown,
): AssertionEvidenceProvenanceSnapshot | null => {
  const parsed = assertionEvidenceProvenanceSnapshotSchema.safeParse(input);

  return parsed.success ? parsed.data : null;
};

export const parseAssertionEvidenceProvenanceSnapshotJson = (
  input: string | null,
): AssertionEvidenceProvenanceSnapshot | null => {
  if (input === null || input.trim().length === 0) {
    return null;
  }

  try {
    return parseAssertionEvidenceProvenanceSnapshot(JSON.parse(input) as unknown);
  } catch {
    return null;
  }
};

export const parseAssertionEvidenceEvaluationSnapshotJson = (
  input: string | null,
): AssertionEvidenceEvaluationSnapshot | null => {
  if (input === null || input.trim().length === 0) {
    return null;
  }

  try {
    const parsed = assertionEvidenceEvaluationSnapshotSchema.safeParse(
      JSON.parse(input) as unknown,
    );

    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
};
