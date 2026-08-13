import { z } from "zod";
import type {
  LearnerPathwayEvaluationRecord,
  LearnerPathwayEvaluationResult,
} from "./learner-pathway-types.js";

export interface LearnerPathwayEvaluationRow {
  id: string;
  enrollmentId: string;
  pathwayVersionId: string;
  sequenceNumber: number;
  result: LearnerPathwayEvaluationResult;
  requirementResultsJson: string;
  qualifyingEvidenceIdsJson: string;
  rationale: string;
  evaluatedAt: string;
}

const storedRequirementEvaluationSchema = z.strictObject({
  requirementId: z.string().min(1),
  position: z.number().int().positive(),
  title: z.string(),
  description: z.string().nullable(),
  state: z.enum(["met", "not_recorded", "in_review", "waived", "invalidated"]),
  evidenceIds: z.array(z.string()),
  rationale: z.string(),
});

const storedEvaluationPayloadSchema = z.strictObject({
  requirements: z.array(storedRequirementEvaluationSchema),
  qualifyingEvidenceIds: z.array(z.string()),
});

/** Parses a persisted pathway evaluation instead of trusting stored JSON casts. */
export const mapLearnerPathwayEvaluationRow = (
  row: LearnerPathwayEvaluationRow,
): LearnerPathwayEvaluationRecord => {
  const parsed = storedEvaluationPayloadSchema.parse({
    requirements: JSON.parse(row.requirementResultsJson),
    qualifyingEvidenceIds: JSON.parse(row.qualifyingEvidenceIdsJson),
  });

  return {
    id: row.id,
    enrollmentId: row.enrollmentId,
    pathwayVersionId: row.pathwayVersionId,
    sequenceNumber: Number(row.sequenceNumber),
    result: row.result,
    requirements: parsed.requirements,
    qualifyingEvidenceIds: parsed.qualifyingEvidenceIds,
    rationale: row.rationale,
    evaluatedAt: row.evaluatedAt,
  };
};
