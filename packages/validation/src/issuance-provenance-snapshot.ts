import type {
  BadgeIssuanceRuleEvidenceEvaluationNode,
  BadgeIssuanceRuleEvidenceFacts,
} from "./assertion-evidence.js";
import {
  assertionEvidenceEvaluationSnapshotSchema,
  assertionEvidenceProvenanceSnapshotSchema,
} from "./assertion-evidence.js";

export interface IssuanceProvenanceSnapshotInput {
  readonly outcome: "matched" | "no_match";
  readonly evaluation: {
    readonly matched: boolean;
    readonly tree: BadgeIssuanceRuleEvidenceEvaluationNode;
  };
  readonly evaluationSummary?: unknown;
  readonly facts: Record<string, unknown> & { learnerId: string; nowIso: string };
  readonly learnerId: string;
  readonly nowIso: string;
}

export interface ParsedIssuanceEvidenceSnapshot {
  readonly facts: BadgeIssuanceRuleEvidenceFacts | null;
  readonly tree: BadgeIssuanceRuleEvidenceEvaluationNode | null;
}

export const buildIssuanceProvenanceSnapshotJson = (
  input: IssuanceProvenanceSnapshotInput,
): string => {
  return JSON.stringify({
    outcome: input.outcome,
    evaluation: input.evaluation,
    ...(input.evaluationSummary === undefined
      ? {}
      : { evaluationSummary: input.evaluationSummary }),
    facts: input.facts,
    learnerId: input.learnerId,
    nowIso: input.nowIso,
  });
};

export const parseIssuanceEvidenceSnapshotJson = (
  input: string | null,
): ParsedIssuanceEvidenceSnapshot => {
  if (input === null || input.trim().length === 0) {
    return { facts: null, tree: null };
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(input) as unknown;
  } catch {
    return { facts: null, tree: null };
  }

  const provenanceSnapshot = assertionEvidenceProvenanceSnapshotSchema.safeParse(parsed);

  if (provenanceSnapshot.success) {
    return {
      facts: provenanceSnapshot.data.facts,
      tree: provenanceSnapshot.data.evaluation.tree,
    };
  }

  const evaluationSnapshot = assertionEvidenceEvaluationSnapshotSchema.safeParse(parsed);

  if (evaluationSnapshot.success) {
    return {
      facts: evaluationSnapshot.data.facts,
      tree: evaluationSnapshot.data.evaluation.tree,
    };
  }

  return { facts: null, tree: null };
};

export const buildIssuanceProvenanceSnapshotFromEvaluationJson = (input: {
  readonly matched: boolean;
  readonly evaluationJson: string;
  readonly learnerId: string;
  readonly evaluatedAt: string;
}): string => {
  const parsed = parseIssuanceEvidenceSnapshotJson(input.evaluationJson);

  if (parsed.tree === null || parsed.facts === null) {
    return input.evaluationJson;
  }

  let evaluationSummary: unknown;

  try {
    const raw = JSON.parse(input.evaluationJson) as Record<string, unknown>;
    evaluationSummary = raw.evaluationSummary;
  } catch {
    evaluationSummary = undefined;
  }

  return buildIssuanceProvenanceSnapshotJson({
    outcome: input.matched ? "matched" : "no_match",
    evaluation: {
      matched: input.matched,
      tree: parsed.tree,
    },
    ...(evaluationSummary === undefined ? {} : { evaluationSummary }),
    facts: parsed.facts,
    learnerId: input.learnerId,
    nowIso: input.evaluatedAt,
  });
};
