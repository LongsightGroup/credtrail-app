import { z } from "zod";

import { isoTimestampSchema } from "./primitives.js";

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
