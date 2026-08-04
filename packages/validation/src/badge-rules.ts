import { z } from "zod";
import { isoTimestampSchema, recipientIdentityTypeSchema, resourceIdSchema } from "./primitives.js";
import { tenantPathParamsSchema } from "./path-params.js";

export const badgeIssuanceRuleLmsProviderKindSchema = z.enum([
  "canvas",
  "moodle",
  "blackboard_ultra",
  "d2l_brightspace",
  "sakai",
]);

export const badgeIssuanceRuleValueListKindSchema = z.enum(["course_ids", "badge_template_ids"]);

const badgeIssuanceRuleCourseReferenceRefinement = (
  value: {
    courseId?: string | undefined;
    courseListId?: string | undefined;
  },
  ctx: z.RefinementCtx,
): void => {
  if (value.courseId === undefined && value.courseListId === undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Specify courseId or courseListId",
    });
    return;
  }

  if (value.courseId !== undefined && value.courseListId !== undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Specify courseId or courseListId, not both",
    });
  }
};

const badgeIssuanceRuleBadgeTemplateReferenceRefinement = (
  value: {
    badgeTemplateId?: string | undefined;
    badgeTemplateListId?: string | undefined;
  },
  ctx: z.RefinementCtx,
): void => {
  if (value.badgeTemplateId === undefined && value.badgeTemplateListId === undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Specify badgeTemplateId or badgeTemplateListId",
    });
    return;
  }

  if (value.badgeTemplateId !== undefined && value.badgeTemplateListId !== undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Specify badgeTemplateId or badgeTemplateListId, not both",
    });
  }
};

const badgeIssuanceRuleGradeThresholdConditionSchema = z
  .object({
    type: z.literal("grade_threshold"),
    courseId: z.string().trim().min(1).max(255).optional(),
    courseListId: resourceIdSchema.optional(),
    scoreField: z.enum(["final_score", "current_score"]).optional(),
    minScore: z.number().finite().min(0).max(100).optional(),
    maxScore: z.number().finite().min(0).max(100).optional(),
  })
  .superRefine((value, ctx) => {
    badgeIssuanceRuleCourseReferenceRefinement(value, ctx);

    if (value.minScore === undefined && value.maxScore === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "grade_threshold must include minScore or maxScore",
      });
    }
  });

const normalizeBadgeIssuanceRuleCourseCompletionConditionInput = (input: unknown): unknown => {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return input;
  }

  const candidate = input as {
    type?: unknown;
    requireCompleted?: unknown;
    minCompletionPercent?: unknown;
  };

  if (candidate.type !== "course_completion") {
    return input;
  }

  const condition: {
    type?: unknown;
    requireCompleted?: unknown;
    minCompletionPercent?: unknown;
  } = { ...candidate };
  delete condition.requireCompleted;

  if (condition.minCompletionPercent !== undefined) {
    return condition;
  }

  return {
    ...condition,
    minCompletionPercent: candidate.requireCompleted === false ? 0 : 100,
  };
};

const badgeIssuanceRuleCourseCompletionConditionSchema = z.preprocess(
  normalizeBadgeIssuanceRuleCourseCompletionConditionInput,
  z
    .object({
      type: z.literal("course_completion"),
      courseId: z.string().trim().min(1).max(255).optional(),
      courseListId: resourceIdSchema.optional(),
      minCompletionPercent: z.number().finite().min(0).max(100),
    })
    .superRefine((value, ctx) => {
      badgeIssuanceRuleCourseReferenceRefinement(value, ctx);
    }),
);

const badgeIssuanceRuleProgramCompletionConditionSchema = z
  .object({
    type: z.literal("program_completion"),
    courseIds: z.array(z.string().trim().min(1).max(255)).min(1).max(200).optional(),
    courseListId: resourceIdSchema.optional(),
    minimumCompleted: z.number().int().min(1).max(200).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.courseIds === undefined && value.courseListId === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "program_completion must include courseIds or courseListId",
      });
      return;
    }

    if (value.courseIds !== undefined && value.courseListId !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "program_completion must include courseIds or courseListId, not both",
      });
      return;
    }

    if (
      value.minimumCompleted !== undefined &&
      value.courseIds !== undefined &&
      value.minimumCompleted > value.courseIds.length
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "minimumCompleted must be less than or equal to the number of courseIds",
      });
    }
  });

const badgeIssuanceRuleAssignmentSubmissionConditionSchema = z.object({
  type: z.literal("assignment_submission"),
  courseId: z.string().trim().min(1).max(255),
  assignmentId: z.string().trim().min(1).max(255),
  minScore: z.number().finite().min(0).max(100).optional(),
  requireSubmitted: z.boolean().optional(),
  workflowStates: z.array(z.string().trim().min(1).max(64)).min(1).max(20).optional(),
});

const badgeIssuanceRuleSurveyCompletionConditionSchema = z.object({
  type: z.literal("survey_completion"),
  surveyId: z.string().trim().min(1).max(255),
  source: z.string().trim().min(1).max(64).optional(),
  requireCompleted: z.boolean().optional(),
});

const badgeIssuanceRuleTimeWindowConditionSchema = z
  .object({
    type: z.literal("time_window"),
    notBefore: isoTimestampSchema.optional(),
    notAfter: isoTimestampSchema.optional(),
  })
  .superRefine((value, ctx) => {
    if (value.notBefore === undefined && value.notAfter === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "time_window must include notBefore or notAfter",
      });
    }
  });

const badgeIssuanceRulePrerequisiteBadgeConditionSchema = z
  .object({
    type: z.literal("prerequisite_badge"),
    badgeTemplateId: resourceIdSchema.optional(),
    badgeTemplateListId: resourceIdSchema.optional(),
  })
  .superRefine((value, ctx) => {
    badgeIssuanceRuleBadgeTemplateReferenceRefinement(value, ctx);
  });

const badgeIssuanceRuleCustomFieldValueSchema = z.union([
  z.string().trim().min(1).max(512),
  z.number().finite(),
  z.boolean(),
]);

const badgeIssuanceRuleCustomFieldConditionSchema = z.object({
  type: z.literal("custom_field"),
  fieldName: z.string().trim().min(1).max(255),
  operator: z
    .enum(["equals", "not_equals", "contains", "greater_than_or_equal", "less_than_or_equal"])
    .optional(),
  expectedValue: badgeIssuanceRuleCustomFieldValueSchema,
});

export type BadgeIssuanceRuleCondition =
  | {
      all: BadgeIssuanceRuleCondition[];
    }
  | {
      any: BadgeIssuanceRuleCondition[];
    }
  | {
      not: BadgeIssuanceRuleCondition;
    }
  | z.infer<typeof badgeIssuanceRuleGradeThresholdConditionSchema>
  | z.infer<typeof badgeIssuanceRuleCourseCompletionConditionSchema>
  | z.infer<typeof badgeIssuanceRuleProgramCompletionConditionSchema>
  | z.infer<typeof badgeIssuanceRuleAssignmentSubmissionConditionSchema>
  | z.infer<typeof badgeIssuanceRuleSurveyCompletionConditionSchema>
  | z.infer<typeof badgeIssuanceRuleTimeWindowConditionSchema>
  | z.infer<typeof badgeIssuanceRulePrerequisiteBadgeConditionSchema>
  | z.infer<typeof badgeIssuanceRuleCustomFieldConditionSchema>;

export const badgeIssuanceRuleConditionSchema: z.ZodType<BadgeIssuanceRuleCondition> = z.lazy(() =>
  z.union([
    z.object({
      all: z.array(badgeIssuanceRuleConditionSchema).min(1).max(50),
    }),
    z.object({
      any: z.array(badgeIssuanceRuleConditionSchema).min(1).max(50),
    }),
    z.object({
      not: badgeIssuanceRuleConditionSchema,
    }),
    badgeIssuanceRuleGradeThresholdConditionSchema,
    badgeIssuanceRuleCourseCompletionConditionSchema,
    badgeIssuanceRuleProgramCompletionConditionSchema,
    badgeIssuanceRuleAssignmentSubmissionConditionSchema,
    badgeIssuanceRuleSurveyCompletionConditionSchema,
    badgeIssuanceRuleTimeWindowConditionSchema,
    badgeIssuanceRulePrerequisiteBadgeConditionSchema,
    badgeIssuanceRuleCustomFieldConditionSchema,
  ]),
);

export const badgeIssuanceRuleDefinitionOptionsSchema = z.object({
  issuanceTiming: z.enum(["immediate", "manual", "end_of_term"]).optional(),
  reviewOnMissingFacts: z.boolean().optional(),
});

export const badgeIssuanceRuleDefinitionSchema = z.object({
  conditions: badgeIssuanceRuleConditionSchema,
  options: badgeIssuanceRuleDefinitionOptionsSchema.optional(),
});

export const badgeIssuanceRulePathParamsSchema = tenantPathParamsSchema.extend({
  ruleId: resourceIdSchema,
});

/** Canonical identity for one browser-authored badge-rule draft. */
export const badgeIssuanceRuleBuilderDraftIdSchema = z
  .string()
  .regex(/^brd_[A-Za-z0-9_-]+$/, "Invalid badge rule builder draft ID");

export const badgeIssuanceRuleBuilderDraftPathParamsSchema = tenantPathParamsSchema.extend({
  draftId: badgeIssuanceRuleBuilderDraftIdSchema,
});

export const badgeIssuanceRuleVersionPathParamsSchema = badgeIssuanceRulePathParamsSchema.extend({
  versionId: resourceIdSchema,
});

export const badgeIssuanceRuleVersionDiffQuerySchema = z.object({
  baseVersionId: resourceIdSchema.optional(),
});

export const badgeIssuanceRuleAuditLogQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
});

export const badgeTemplateAuditLogQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
});

export const createBadgeIssuanceRuleRequestSchema = z
  .object({
    name: z.string().trim().min(1).max(200),
    description: z.string().trim().min(1).max(2000).optional(),
    badgeTemplateId: resourceIdSchema,
    lmsConnectionId: resourceIdSchema,
    lmsProviderKind: badgeIssuanceRuleLmsProviderKindSchema.optional(),
    definition: badgeIssuanceRuleDefinitionSchema,
    changeSummary: z.string().trim().min(1).max(1000).optional(),
    builderDraftId: badgeIssuanceRuleBuilderDraftIdSchema.optional(),
    action: z.enum(["save_draft", "submit_for_approval"]),
  })
  .strict();

export const updateBadgeIssuanceRuleDraftRequestSchema = z
  .object({
    name: z.string().trim().min(1).max(200),
    description: z.string().trim().max(2000).optional(),
    badgeTemplateId: resourceIdSchema,
    lmsConnectionId: resourceIdSchema,
    definition: badgeIssuanceRuleDefinitionSchema,
    changeSummary: z.string().trim().min(1).max(1000).optional(),
    action: z.enum(["save_draft", "submit_for_approval"]),
  })
  .strict();

export const badgeIssuanceRuleBuilderDraftStepSchema = z.enum(["metadata", "conditions", "test"]);

/** Valid lifecycle targets for persisted badge-rule builder progress. */
export const badgeIssuanceRuleBuilderDraftTargetSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("unfinished"),
    })
    .strict(),
  z
    .object({
      kind: z.literal("formal_rule"),
      ruleId: resourceIdSchema,
      versionId: resourceIdSchema,
    })
    .strict(),
]);

export const badgeIssuanceRuleBuilderDraftBuilderStateSchema = z
  .object({
    rootLogic: z.enum(["all", "any"]).optional(),
    issuanceTiming: z.enum(["immediate", "manual", "end_of_term"]).optional(),
    changeSummary: z.string().trim().max(1000).optional(),
    reviewOnMissingFacts: z.boolean().optional(),
    lastTestSummary: z.string().trim().max(500).optional(),
  })
  .strict();

export const badgeIssuanceRuleBuilderDraftPayloadSchema = z
  .object({
    name: z.string().max(200).optional(),
    description: z.string().max(2000).optional(),
    badgeTemplateId: z.string().optional(),
    lmsConnectionId: z.string().optional(),
    lmsProviderKind: badgeIssuanceRuleLmsProviderKindSchema.optional(),
    definitionJson: z.string().max(100_000).optional(),
    builderState: badgeIssuanceRuleBuilderDraftBuilderStateSchema.optional(),
  })
  .strict();

export const saveBadgeIssuanceRuleBuilderDraftRequestSchema = z
  .object({
    target: badgeIssuanceRuleBuilderDraftTargetSchema,
    currentStep: badgeIssuanceRuleBuilderDraftStepSchema,
    name: z.string().trim().max(200).optional(),
    description: z.string().trim().max(2000).optional(),
    badgeTemplateId: resourceIdSchema.optional(),
    lmsConnectionId: resourceIdSchema.optional(),
    lmsProviderKind: badgeIssuanceRuleLmsProviderKindSchema.optional(),
    definitionJson: z.string().max(100_000).optional(),
    builderState: badgeIssuanceRuleBuilderDraftBuilderStateSchema.optional(),
  })
  .strict();

export const createBadgeIssuanceRuleVersionRequestSchema = z
  .object({
    definition: badgeIssuanceRuleDefinitionSchema,
    changeSummary: z.string().trim().min(1).max(1000).optional(),
  })
  .strict();

export const decideBadgeIssuanceRuleVersionRequestSchema = z
  .object({
    decision: z.enum(["approved", "rejected", "changes_requested"]),
    comment: z.string().trim().min(1).max(2000).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.decision === "changes_requested" && value.comment === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["comment"],
        message: "comment is required when requesting changes",
      });
    }
  });

export const reopenApprovedBadgeIssuanceRuleVersionRequestSchema = z
  .object({
    comment: z.string().trim().min(1).max(2000),
  })
  .strict();

const badgeIssuanceRuleFactGradeSchema = z.object({
  courseId: z.string().trim().min(1).max(255),
  learnerId: z.string().trim().min(1).max(255),
  currentScore: z.number().finite().nullable().optional(),
  finalScore: z.number().finite().nullable().optional(),
});

const badgeIssuanceRuleFactCompletionSchema = z.object({
  courseId: z.string().trim().min(1).max(255),
  learnerId: z.string().trim().min(1).max(255),
  completed: z.boolean(),
  completionPercent: z.number().finite().nullable().optional(),
});

const badgeIssuanceRuleFactSubmissionSchema = z.object({
  courseId: z.string().trim().min(1).max(255),
  assignmentId: z.string().trim().min(1).max(255),
  learnerId: z.string().trim().min(1).max(255),
  score: z.number().finite().nullable().optional(),
  workflowState: z.string().trim().min(1).max(64).nullable().optional(),
  submittedAt: isoTimestampSchema.nullable().optional(),
});

const badgeIssuanceRuleFactSurveyCompletionSchema = z.object({
  surveyId: z.string().trim().min(1).max(255),
  learnerId: z.string().trim().min(1).max(255),
  source: z.string().trim().min(1).max(64).optional(),
  completed: z.boolean(),
  completedAt: isoTimestampSchema.nullable().optional(),
});

const badgeIssuanceRuleFactCustomFieldSchema = z.object({
  learnerId: z.string().trim().min(1).max(255),
  fieldName: z.string().trim().min(1).max(255),
  value: badgeIssuanceRuleCustomFieldValueSchema.nullable(),
});

export const badgeIssuanceRuleFactsSchema = z.object({
  nowIso: isoTimestampSchema.optional(),
  grades: z.array(badgeIssuanceRuleFactGradeSchema).optional(),
  completions: z.array(badgeIssuanceRuleFactCompletionSchema).optional(),
  submissions: z.array(badgeIssuanceRuleFactSubmissionSchema).optional(),
  surveyCompletions: z.array(badgeIssuanceRuleFactSurveyCompletionSchema).optional(),
  customFields: z.array(badgeIssuanceRuleFactCustomFieldSchema).optional(),
  earnedBadgeTemplateIds: z.array(resourceIdSchema).optional(),
});

export const previewEvaluateBadgeIssuanceRuleRequestSchema = z
  .object({
    definition: badgeIssuanceRuleDefinitionSchema,
    lmsConnectionId: resourceIdSchema,
    lmsProviderKind: badgeIssuanceRuleLmsProviderKindSchema.default("canvas"),
    learnerId: z.string().trim().min(1).max(255),
    recipient: z
      .object({
        identity: z.string().trim().min(1).max(512),
        identityType: recipientIdentityTypeSchema,
      })
      .strict()
      .optional(),
    facts: badgeIssuanceRuleFactsSchema.optional(),
  })
  .strict();

export const createBadgeIssuanceRuleValueListRequestSchema = z
  .object({
    label: z.string().trim().min(1).max(120),
    kind: badgeIssuanceRuleValueListKindSchema,
    values: z.array(z.string().trim().min(1).max(255)).min(1).max(500),
  })
  .superRefine((value, ctx) => {
    const normalizedValues = new Set(value.values.map((entry) => entry.trim().toLowerCase()));

    if (normalizedValues.size !== value.values.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["values"],
        message: "values must not contain duplicates",
      });
    }
  });

export const badgeIssuanceRuleValueListPathParamsSchema = tenantPathParamsSchema.extend({
  valueListId: resourceIdSchema,
});

export const badgeIssuanceRuleEvaluationPathParamsSchema = tenantPathParamsSchema.extend({
  evaluationId: resourceIdSchema,
});

export const badgeIssuanceRuleValueListQuerySchema = z.object({
  kind: badgeIssuanceRuleValueListKindSchema.optional(),
});

export const previewSimulateBadgeIssuanceRuleRequestSchema = z.object({
  definition: badgeIssuanceRuleDefinitionSchema,
  badgeTemplateId: resourceIdSchema,
  sampleLimit: z.number().int().min(1).max(100).optional(),
});

export const badgeIssuanceRuleReviewQueueQuerySchema = z.object({
  status: z.enum(["pending", "resolved"]).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

export const resolveBadgeIssuanceRuleReviewRequestSchema = z.object({
  decision: z.enum(["issue", "dismiss"]),
  comment: z.string().trim().min(1).max(2000).optional(),
});

export const createDedicatedDbProvisioningRequestSchema = z.object({
  targetRegion: z
    .string()
    .trim()
    .min(2)
    .max(64)
    .regex(/^[a-z0-9-]+$/),
  notes: z.string().trim().min(1).max(2000).optional(),
});

export const resolveDedicatedDbProvisioningRequestSchema = z.object({
  status: z.enum(["provisioned", "failed", "canceled"]),
  dedicatedDatabaseUrl: z.string().url().max(4096).optional(),
  notes: z.string().trim().min(1).max(2000).optional(),
  resolvedAt: isoTimestampSchema.optional(),
});
// --- inferred types and parsers ---
export type BadgeIssuanceRulePathParams = z.infer<typeof badgeIssuanceRulePathParamsSchema>;

export type BadgeIssuanceRuleBuilderDraftPathParams = z.infer<
  typeof badgeIssuanceRuleBuilderDraftPathParamsSchema
>;

export type BadgeIssuanceRuleVersionPathParams = z.infer<
  typeof badgeIssuanceRuleVersionPathParamsSchema
>;

export type BadgeIssuanceRuleValueListPathParams = z.infer<
  typeof badgeIssuanceRuleValueListPathParamsSchema
>;

export type BadgeIssuanceRuleEvaluationPathParams = z.infer<
  typeof badgeIssuanceRuleEvaluationPathParamsSchema
>;

export type BadgeIssuanceRuleVersionDiffQuery = z.infer<
  typeof badgeIssuanceRuleVersionDiffQuerySchema
>;

export type BadgeIssuanceRuleAuditLogQuery = z.infer<typeof badgeIssuanceRuleAuditLogQuerySchema>;

export type BadgeTemplateAuditLogQuery = z.infer<typeof badgeTemplateAuditLogQuerySchema>;

export type BadgeIssuanceRuleValueListQuery = z.infer<typeof badgeIssuanceRuleValueListQuerySchema>;

export type BadgeIssuanceRuleLmsProviderKind = z.infer<
  typeof badgeIssuanceRuleLmsProviderKindSchema
>;

export type BadgeIssuanceRuleValueListKind = z.infer<typeof badgeIssuanceRuleValueListKindSchema>;

export type BadgeIssuanceRuleDefinition = z.infer<typeof badgeIssuanceRuleDefinitionSchema>;

export type CreateBadgeIssuanceRuleRequest = z.infer<typeof createBadgeIssuanceRuleRequestSchema>;

export type UpdateBadgeIssuanceRuleDraftRequest = z.infer<
  typeof updateBadgeIssuanceRuleDraftRequestSchema
>;

export type SaveBadgeIssuanceRuleBuilderDraftRequest = z.infer<
  typeof saveBadgeIssuanceRuleBuilderDraftRequestSchema
>;

/** Identifies whether builder progress creates a new rule or edits a formal rule. */
export type BadgeIssuanceRuleBuilderDraftTarget = z.infer<
  typeof badgeIssuanceRuleBuilderDraftTargetSchema
>;

export type BadgeIssuanceRuleBuilderDraftBuilderState = z.infer<
  typeof badgeIssuanceRuleBuilderDraftBuilderStateSchema
>;

export type BadgeIssuanceRuleBuilderDraftPayload = z.infer<
  typeof badgeIssuanceRuleBuilderDraftPayloadSchema
>;

export type CreateBadgeIssuanceRuleVersionRequest = z.infer<
  typeof createBadgeIssuanceRuleVersionRequestSchema
>;

export type CreateBadgeIssuanceRuleValueListRequest = z.infer<
  typeof createBadgeIssuanceRuleValueListRequestSchema
>;

export type DecideBadgeIssuanceRuleVersionRequest = z.infer<
  typeof decideBadgeIssuanceRuleVersionRequestSchema
>;

export type ReopenApprovedBadgeIssuanceRuleVersionRequest = z.infer<
  typeof reopenApprovedBadgeIssuanceRuleVersionRequestSchema
>;

export type BadgeIssuanceRuleFacts = z.infer<typeof badgeIssuanceRuleFactsSchema>;

export type PreviewEvaluateBadgeIssuanceRuleRequest = z.infer<
  typeof previewEvaluateBadgeIssuanceRuleRequestSchema
>;

export type PreviewSimulateBadgeIssuanceRuleRequest = z.infer<
  typeof previewSimulateBadgeIssuanceRuleRequestSchema
>;

export type BadgeIssuanceRuleReviewQueueQuery = z.infer<
  typeof badgeIssuanceRuleReviewQueueQuerySchema
>;

export type ResolveBadgeIssuanceRuleReviewRequest = z.infer<
  typeof resolveBadgeIssuanceRuleReviewRequestSchema
>;

export type CreateDedicatedDbProvisioningRequest = z.infer<
  typeof createDedicatedDbProvisioningRequestSchema
>;

export type ResolveDedicatedDbProvisioningRequest = z.infer<
  typeof resolveDedicatedDbProvisioningRequestSchema
>;

export const parseBadgeIssuanceRulePathParams = (input: unknown): BadgeIssuanceRulePathParams => {
  return badgeIssuanceRulePathParamsSchema.parse(input);
};

export const parseBadgeIssuanceRuleBuilderDraftPathParams = (
  input: unknown,
): BadgeIssuanceRuleBuilderDraftPathParams => {
  return badgeIssuanceRuleBuilderDraftPathParamsSchema.parse(input);
};

export const parseBadgeIssuanceRuleVersionPathParams = (
  input: unknown,
): BadgeIssuanceRuleVersionPathParams => {
  return badgeIssuanceRuleVersionPathParamsSchema.parse(input);
};

export const parseCreateBadgeIssuanceRuleRequest = (
  input: unknown,
): CreateBadgeIssuanceRuleRequest => {
  return createBadgeIssuanceRuleRequestSchema.parse(input);
};

export const parseUpdateBadgeIssuanceRuleDraftRequest = (
  input: unknown,
): UpdateBadgeIssuanceRuleDraftRequest => {
  return updateBadgeIssuanceRuleDraftRequestSchema.parse(input);
};

export const parseSaveBadgeIssuanceRuleBuilderDraftRequest = (
  input: unknown,
): SaveBadgeIssuanceRuleBuilderDraftRequest => {
  return saveBadgeIssuanceRuleBuilderDraftRequestSchema.parse(input);
};

export const serializeBadgeIssuanceRuleBuilderDraftPayload = (
  request: SaveBadgeIssuanceRuleBuilderDraftRequest,
): string => {
  const payload: BadgeIssuanceRuleBuilderDraftPayload = {
    name: request.name ?? "",
    description: request.description ?? "",
    badgeTemplateId: request.badgeTemplateId ?? "",
    lmsConnectionId: request.lmsConnectionId ?? "",
    ...(request.lmsProviderKind === undefined ? {} : { lmsProviderKind: request.lmsProviderKind }),
    definitionJson: request.definitionJson ?? "",
    builderState: request.builderState ?? {},
  };

  return JSON.stringify(payload);
};

export const parseBadgeIssuanceRuleBuilderDraftPayload = (
  input: unknown,
): BadgeIssuanceRuleBuilderDraftPayload | null => {
  const parsed = badgeIssuanceRuleBuilderDraftPayloadSchema.safeParse(input);

  return parsed.success ? parsed.data : null;
};

export const parseBadgeIssuanceRuleBuilderDraftJson = (
  draftJson: string,
): BadgeIssuanceRuleBuilderDraftPayload | null => {
  try {
    return parseBadgeIssuanceRuleBuilderDraftPayload(JSON.parse(draftJson) as unknown);
  } catch {
    return null;
  }
};

export const parseBadgeIssuanceRuleVersionDiffQuery = (
  input: unknown,
): BadgeIssuanceRuleVersionDiffQuery => {
  return badgeIssuanceRuleVersionDiffQuerySchema.parse(input);
};

export const parseBadgeIssuanceRuleAuditLogQuery = (
  input: unknown,
): BadgeIssuanceRuleAuditLogQuery => {
  return badgeIssuanceRuleAuditLogQuerySchema.parse(input);
};

export const parseBadgeTemplateAuditLogQuery = (input: unknown): BadgeTemplateAuditLogQuery => {
  return badgeTemplateAuditLogQuerySchema.parse(input);
};

export const parseCreateBadgeIssuanceRuleValueListRequest = (
  input: unknown,
): CreateBadgeIssuanceRuleValueListRequest => {
  return createBadgeIssuanceRuleValueListRequestSchema.parse(input);
};

export const parseBadgeIssuanceRuleValueListPathParams = (
  input: unknown,
): BadgeIssuanceRuleValueListPathParams => {
  return badgeIssuanceRuleValueListPathParamsSchema.parse(input);
};

export const parseBadgeIssuanceRuleEvaluationPathParams = (
  input: unknown,
): BadgeIssuanceRuleEvaluationPathParams => {
  return badgeIssuanceRuleEvaluationPathParamsSchema.parse(input);
};

export const parseBadgeIssuanceRuleValueListQuery = (
  input: unknown,
): BadgeIssuanceRuleValueListQuery => {
  return badgeIssuanceRuleValueListQuerySchema.parse(input);
};

export const parseCreateBadgeIssuanceRuleVersionRequest = (
  input: unknown,
): CreateBadgeIssuanceRuleVersionRequest => {
  return createBadgeIssuanceRuleVersionRequestSchema.parse(input);
};

export const parseDecideBadgeIssuanceRuleVersionRequest = (
  input: unknown,
): DecideBadgeIssuanceRuleVersionRequest => {
  return decideBadgeIssuanceRuleVersionRequestSchema.parse(input);
};

export const parseReopenApprovedBadgeIssuanceRuleVersionRequest = (
  input: unknown,
): ReopenApprovedBadgeIssuanceRuleVersionRequest => {
  return reopenApprovedBadgeIssuanceRuleVersionRequestSchema.parse(input);
};

export const parsePreviewEvaluateBadgeIssuanceRuleRequest = (
  input: unknown,
): PreviewEvaluateBadgeIssuanceRuleRequest => {
  return previewEvaluateBadgeIssuanceRuleRequestSchema.parse(input);
};

export const parsePreviewSimulateBadgeIssuanceRuleRequest = (
  input: unknown,
): PreviewSimulateBadgeIssuanceRuleRequest => {
  return previewSimulateBadgeIssuanceRuleRequestSchema.parse(input);
};

export const parseBadgeIssuanceRuleReviewQueueQuery = (
  input: unknown,
): BadgeIssuanceRuleReviewQueueQuery => {
  return badgeIssuanceRuleReviewQueueQuerySchema.parse(input);
};

export const parseResolveBadgeIssuanceRuleReviewRequest = (
  input: unknown,
): ResolveBadgeIssuanceRuleReviewRequest => {
  return resolveBadgeIssuanceRuleReviewRequestSchema.parse(input);
};

export const parseBadgeIssuanceRuleDefinition = (input: unknown): BadgeIssuanceRuleDefinition => {
  return badgeIssuanceRuleDefinitionSchema.parse(input);
};

export const parseCreateDedicatedDbProvisioningRequest = (
  input: unknown,
): CreateDedicatedDbProvisioningRequest => {
  return createDedicatedDbProvisioningRequestSchema.parse(input);
};

export const parseResolveDedicatedDbProvisioningRequest = (
  input: unknown,
): ResolveDedicatedDbProvisioningRequest => {
  return resolveDedicatedDbProvisioningRequestSchema.parse(input);
};
