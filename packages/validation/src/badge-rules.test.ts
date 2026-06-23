import { describe, expect, it } from "vitest";

import {
  parseBadgeIssuanceRuleAuditLogQuery,
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleReviewQueueQuery,
  parseBadgeIssuanceRuleVersionDiffQuery,
  parseBadgeIssuanceRuleVersionPathParams,
  parseCreateBadgeIssuanceRuleRequest,
  parseCreateBadgeIssuanceRuleValueListRequest,
  parseCreateBadgeIssuanceRuleVersionRequest,
  parseDecideBadgeIssuanceRuleVersionRequest,
  parseEvaluateBadgeIssuanceRuleRequest,
  parsePreviewEvaluateBadgeIssuanceRuleRequest,
  parsePreviewSimulateBadgeIssuanceRuleRequest,
  parseResolveBadgeIssuanceRuleReviewRequest,
  parseUpdateBadgeIssuanceRuleDraftRequest,
} from "./badge-rules.js";

describe("badge issuance rule parsers", () => {
  it("accepts valid create/version/evaluate payloads", () => {
    const createRequest = parseCreateBadgeIssuanceRuleRequest({
      name: "CS101 Excellence Rule",
      description: "Award badge for high performers",
      badgeTemplateId: "badge_template_cs101",
      lmsConnectionId: "lms_123",
      lmsProviderKind: "canvas",
      definition: {
        conditions: {
          all: [
            {
              type: "course_completion",
              courseId: "course_101",
              requireCompleted: true,
            },
            {
              type: "grade_threshold",
              courseId: "course_101",
              scoreField: "final_score",
              minScore: 80,
            },
            {
              any: [
                {
                  type: "assignment_submission",
                  courseId: "course_101",
                  assignmentId: "assignment_1",
                  minScore: 75,
                },
                {
                  type: "prerequisite_badge",
                  badgeTemplateId: "badge_template_foundations",
                },
              ],
            },
            {
              type: "survey_completion",
              source: "qualtrics",
              surveyId: "exit_survey",
            },
            {
              type: "custom_field",
              fieldName: "programStanding",
              operator: "equals",
              expectedValue: "eligible",
            },
          ],
        },
      },
      approvalChain: [
        {
          requiredRole: "issuer",
          label: "Department approval",
        },
        {
          requiredRole: "admin",
          label: "Registrar approval",
        },
      ],
      changeSummary: "Initial draft",
    });
    const versionRequest = parseCreateBadgeIssuanceRuleVersionRequest({
      definition: {
        conditions: {
          type: "time_window",
          notBefore: "2026-01-01T00:00:00.000Z",
        },
      },
      approvalChain: [
        {
          requiredRole: "admin",
        },
      ],
      changeSummary: "Limit issuance to spring term",
    });
    const updateDraftRequest = parseUpdateBadgeIssuanceRuleDraftRequest({
      name: "CS101 Excellence Rule Revised",
      description: "",
      badgeTemplateId: "badge_template_cs101",
      lmsConnectionId: "lms_123",
      definition: createRequest.definition,
      approvalChain: [
        {
          requiredRole: "admin",
          label: "Registrar approval",
        },
      ],
      changeSummary: "Tighten course completion rule",
    });
    const decisionRequest = parseDecideBadgeIssuanceRuleVersionRequest({
      decision: "approved",
      comment: "Meets institutional governance requirements",
    });
    const evaluateRequest = parseEvaluateBadgeIssuanceRuleRequest({
      learnerId: "learner_123",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
      dryRun: true,
      facts: {
        nowIso: "2026-02-17T00:00:00.000Z",
        grades: [
          {
            courseId: "course_101",
            learnerId: "learner_123",
            finalScore: 92,
          },
        ],
        surveyCompletions: [
          {
            surveyId: "exit_survey",
            learnerId: "learner_123",
            source: "qualtrics",
            completed: true,
          },
        ],
        customFields: [
          {
            learnerId: "learner_123",
            fieldName: "programStanding",
            value: "eligible",
          },
        ],
      },
    });
    const previewEvaluateRequest = parsePreviewEvaluateBadgeIssuanceRuleRequest({
      definition: {
        conditions: {
          all: [
            {
              type: "course_completion",
              courseId: "course_101",
            },
            {
              type: "grade_threshold",
              courseId: "course_101",
              minScore: 80,
            },
          ],
        },
      },
      lmsConnectionId: "lms_123",
      learnerId: "learner_123",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email",
      facts: {
        completions: [
          {
            courseId: "course_101",
            learnerId: "learner_123",
            completed: true,
          },
        ],
        grades: [
          {
            courseId: "course_101",
            learnerId: "learner_123",
            finalScore: 88,
          },
        ],
      },
    });

    expect(createRequest.lmsProviderKind).toBe("canvas");
    expect(createRequest.approvalChain?.[0]?.requiredRole).toBe("issuer");
    expect(JSON.stringify(createRequest.definition.conditions)).toContain("survey_completion");
    expect(JSON.stringify(createRequest.definition.conditions)).toContain("custom_field");
    expect(updateDraftRequest.name).toBe("CS101 Excellence Rule Revised");
    expect(updateDraftRequest.description).toBe("");
    expect(versionRequest.changeSummary).toContain("spring");
    expect(versionRequest.approvalChain).toHaveLength(1);
    expect(decisionRequest.decision).toBe("approved");
    expect(decisionRequest.comment).toContain("governance");
    expect(evaluateRequest.dryRun).toBe(true);
    expect(previewEvaluateRequest.definition.conditions).toHaveProperty("all");
    expect(JSON.stringify(createRequest.definition.conditions)).toContain(
      '"minCompletionPercent":100',
    );
    expect(JSON.stringify(createRequest.definition.conditions)).not.toContain("requireCompleted");
  });

  it("normalizes legacy course completion booleans to completion percentages", () => {
    const requireCompleteDefinition = parseCreateBadgeIssuanceRuleRequest({
      name: "Legacy complete rule",
      badgeTemplateId: "badge_template_cs101",
      lmsConnectionId: "lms_123",
      lmsProviderKind: "canvas",
      definition: {
        conditions: {
          type: "course_completion",
          courseId: "course_101",
          requireCompleted: true,
        },
      },
    }).definition;
    const requireStartedDefinition = parseCreateBadgeIssuanceRuleRequest({
      name: "Legacy started rule",
      badgeTemplateId: "badge_template_cs101",
      lmsConnectionId: "lms_123",
      lmsProviderKind: "canvas",
      definition: {
        conditions: {
          type: "course_completion",
          courseId: "course_101",
          requireCompleted: false,
        },
      },
    }).definition;

    expect(requireCompleteDefinition.conditions).toEqual({
      type: "course_completion",
      courseId: "course_101",
      minCompletionPercent: 100,
    });
    expect(requireStartedDefinition.conditions).toEqual({
      type: "course_completion",
      courseId: "course_101",
      minCompletionPercent: 0,
    });
  });

  it("rejects preview evaluation payloads without an LMS connection", () => {
    expect(() => {
      parsePreviewEvaluateBadgeIssuanceRuleRequest({
        definition: {
          conditions: {
            type: "grade_threshold",
            courseId: "course_101",
            minScore: 80,
          },
        },
        learnerId: "learner_123",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
      });
    }).toThrow(/./);
  });

  it("parses rule and rule-version path params", () => {
    const rulePathParams = parseBadgeIssuanceRulePathParams({
      tenantId: "tenant_123",
      ruleId: "brl_123",
    });
    const versionPathParams = parseBadgeIssuanceRuleVersionPathParams({
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
    });

    expect(rulePathParams.ruleId).toBe("brl_123");
    expect(versionPathParams.versionId).toBe("brv_123");
  });

  it("parses badge rule diff and audit-log query parameters", () => {
    const diffQuery = parseBadgeIssuanceRuleVersionDiffQuery({
      baseVersionId: "brv_122",
    });
    const auditLogQuery = parseBadgeIssuanceRuleAuditLogQuery({
      limit: "150",
    });
    const reviewQueueQuery = parseBadgeIssuanceRuleReviewQueueQuery({
      status: "resolved",
      limit: "25",
    });

    expect(diffQuery.baseVersionId).toBe("brv_122");
    expect(auditLogQuery.limit).toBe(150);
    expect(reviewQueueQuery.status).toBe("resolved");
    expect(reviewQueueQuery.limit).toBe(25);
  });

  it("accepts reusable-list rule conditions and simulation payloads", () => {
    const createRequest = parseCreateBadgeIssuanceRuleRequest({
      name: "Program path rule",
      badgeTemplateId: "badge_template_program",
      lmsConnectionId: "lms_123",
      lmsProviderKind: "canvas",
      definition: {
        conditions: {
          all: [
            {
              type: "program_completion",
              courseListId: "brvl_courses",
              minimumCompleted: 3,
            },
            {
              type: "prerequisite_badge",
              badgeTemplateListId: "brvl_badges",
            },
          ],
        },
        options: {
          reviewOnMissingFacts: true,
        },
      },
    });
    const valueListRequest = parseCreateBadgeIssuanceRuleValueListRequest({
      label: "Core CS sequence",
      kind: "course_ids",
      values: ["course_101", "course_102", "course_103"],
    });
    const simulationRequest = parsePreviewSimulateBadgeIssuanceRuleRequest({
      badgeTemplateId: "badge_template_program",
      sampleLimit: 20,
      definition: createRequest.definition,
    });
    const resolveReviewRequest = parseResolveBadgeIssuanceRuleReviewRequest({
      decision: "issue",
      comment: "Registrar review approved issuance.",
    });

    expect(createRequest.definition.options?.reviewOnMissingFacts).toBe(true);
    expect(valueListRequest.kind).toBe("course_ids");
    expect(simulationRequest.sampleLimit).toBe(20);
    expect(resolveReviewRequest.decision).toBe("issue");
  });

  it("rejects grade threshold conditions without a score boundary", () => {
    expect(() => {
      parseCreateBadgeIssuanceRuleRequest({
        name: "Invalid",
        badgeTemplateId: "badge_template_cs101",
        lmsConnectionId: "lms_123",
        lmsProviderKind: "canvas",
        definition: {
          conditions: {
            type: "grade_threshold",
            courseId: "course_101",
          },
        },
      });
    }).toThrow(/./);
  });

  it("rejects invalid time window condition payloads", () => {
    expect(() => {
      parseCreateBadgeIssuanceRuleVersionRequest({
        definition: {
          conditions: {
            type: "time_window",
          },
        },
      });
    }).toThrow(/./);
  });

  it("rejects rule conditions that provide both direct IDs and reusable list IDs", () => {
    expect(() => {
      parseCreateBadgeIssuanceRuleRequest({
        name: "Invalid list combination",
        badgeTemplateId: "badge_template_cs101",
        lmsConnectionId: "lms_123",
        lmsProviderKind: "canvas",
        definition: {
          conditions: {
            type: "course_completion",
            courseId: "course_101",
            courseListId: "brvl_courses",
          },
        },
      });
    }).toThrow(/./);
  });
});
