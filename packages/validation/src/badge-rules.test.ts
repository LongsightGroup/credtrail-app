import { describe, expect, it } from "vitest";

import {
  automatedBadgeRuleLifecycleWindowMatches,
  badgeIssuanceRuleHasCompleteLmsLearnerPopulation,
  parseBadgeIssuanceRuleAuditLogQuery,
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleReviewQueueQuery,
  parseBadgeIssuanceRuleVersionDiffQuery,
  parseBadgeIssuanceRuleVersionPathParams,
  parseLtiResourceLinkPlacementPathParams,
  parseRetireLtiResourceLinkPlacementRequest,
  parseCreateBadgeIssuanceRuleRequest,
  parseCreateBadgeIssuanceRuleValueListRequest,
  parseDecideBadgeIssuanceRuleVersionRequest,
  parsePreviewEvaluateBadgeIssuanceRuleRequest,
  parsePreviewSimulateBadgeIssuanceRuleRequest,
  parseReopenApprovedBadgeIssuanceRuleVersionRequest,
  parseResolveBadgeIssuanceRuleReviewRequest,
  parseSaveBadgeIssuanceRuleBuilderDraftRequest,
  parseUpdateBadgeIssuanceRuleDraftRequest,
  resolveAutomatedBadgeRuleIssuanceTiming,
} from "./badge-rules.js";

describe("badge issuance rule parsers", () => {
  it("requires LMS rosters to cover every possible automated-rule match", () => {
    expect(
      badgeIssuanceRuleHasCompleteLmsLearnerPopulation({
        conditions: {
          all: [
            { type: "course_completion", courseId: "course_101", minCompletionPercent: 100 },
            { type: "prerequisite_badge", badgeTemplateId: "badge_template_foundations" },
          ],
        },
      }),
    ).toBe(true);
    expect(
      badgeIssuanceRuleHasCompleteLmsLearnerPopulation({
        conditions: {
          any: [
            { type: "course_completion", courseId: "course_101", minCompletionPercent: 100 },
            { type: "prerequisite_badge", badgeTemplateId: "badge_template_foundations" },
          ],
        },
      }),
    ).toBe(false);
    expect(
      badgeIssuanceRuleHasCompleteLmsLearnerPopulation({
        conditions: {
          not: {
            type: "course_completion",
            courseId: "course_101",
            minCompletionPercent: 100,
          },
        },
      }),
    ).toBe(false);
  });

  it("derives automated evaluation behavior from the rule and lifecycle window", () => {
    expect(
      resolveAutomatedBadgeRuleIssuanceTiming({
        conditions: {
          type: "course_completion",
          courseId: "course_101",
          minCompletionPercent: 100,
        },
        options: { issuanceTiming: "manual" },
      }),
    ).toBeNull();
    expect(
      automatedBadgeRuleLifecycleWindowMatches({
        effectiveStartsAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-06-01T00:00:00.000Z",
        evaluatedAt: "2026-06-01T00:00:00.000Z",
        issuanceTiming: "end_of_term",
      }),
    ).toBe(true);
    expect(
      automatedBadgeRuleLifecycleWindowMatches({
        effectiveStartsAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-06-01T00:00:00.000Z",
        evaluatedAt: "2026-06-01T00:00:00.000Z",
        issuanceTiming: "immediate",
      }),
    ).toBe(false);
  });

  it("requires a reason when reopening an approved rule version", () => {
    expect(
      parseReopenApprovedBadgeIssuanceRuleVersionRequest({
        comment: "Approved before the final threshold check.",
      }),
    ).toEqual({
      comment: "Approved before the final threshold check.",
    });
    expect(() => parseReopenApprovedBadgeIssuanceRuleVersionRequest({ comment: " " })).toThrow(
      "Too small",
    );
  });

  it("accepts valid create, version, and preview payloads", () => {
    const createRequest = parseCreateBadgeIssuanceRuleRequest({
      name: "CS101 Excellence Rule",
      description: "Award badge for high performers",
      badgeTemplateId: "badge_template_cs101",
      badgeTemplateReuseAcknowledged: false,
      lmsConnectionId: "lms_123",
      lmsProviderKind: "canvas",
      action: "save_draft",
      definition: {
        conditions: {
          all: [
            {
              type: "course_completion",
              courseId: "course_101",
              minCompletionPercent: 100,
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
      changeSummary: "Initial draft",
    });
    const updateDraftRequest = parseUpdateBadgeIssuanceRuleDraftRequest({
      name: "CS101 Excellence Rule Revised",
      description: "",
      badgeTemplateId: "badge_template_cs101",
      badgeTemplateReuseAcknowledged: false,
      lmsConnectionId: "lms_123",
      action: "save_draft",
      definition: createRequest.definition,
      changeSummary: "Tighten course completion rule",
    });
    const decisionRequest = parseDecideBadgeIssuanceRuleVersionRequest({
      decision: "approved",
      comment: "Meets institutional governance requirements",
    });
    const previewEvaluateRequest = parsePreviewEvaluateBadgeIssuanceRuleRequest({
      definition: {
        conditions: {
          all: [
            {
              type: "course_completion",
              courseId: "course_101",
              minCompletionPercent: 100,
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
    expect(JSON.stringify(createRequest.definition.conditions)).toContain("survey_completion");
    expect(JSON.stringify(createRequest.definition.conditions)).toContain("custom_field");
    expect(updateDraftRequest.name).toBe("CS101 Excellence Rule Revised");
    expect(updateDraftRequest.description).toBe("");
    expect(decisionRequest.decision).toBe("approved");
    expect(decisionRequest.comment).toContain("governance");
    expect(previewEvaluateRequest.definition.conditions).toHaveProperty("all");
    expect(JSON.stringify(createRequest.definition.conditions)).toContain(
      '"minCompletionPercent":100',
    );
  });

  it("rejects the removed course completion boolean", () => {
    expect(() =>
      parseCreateBadgeIssuanceRuleRequest({
        name: "Invalid course completion rule",
        badgeTemplateId: "badge_template_cs101",
        badgeTemplateReuseAcknowledged: false,
        lmsConnectionId: "lms_123",
        lmsProviderKind: "canvas",
        action: "save_draft",
        definition: {
          conditions: {
            type: "course_completion",
            courseId: "course_101",
            minCompletionPercent: 100,
            requireCompleted: true,
          },
        },
      }),
    ).toThrow("Unrecognized key");
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
      });
    }).toThrow(/./);
  });

  it("accepts an optional recipient only in the current nested contract", () => {
    const definition = {
      conditions: {
        type: "prerequisite_badge" as const,
        badgeTemplateId: "badge_template_foundations",
      },
    };
    const parsed = parsePreviewEvaluateBadgeIssuanceRuleRequest({
      definition,
      lmsConnectionId: "lms_123",
      learnerId: "learner_123",
      recipient: {
        identity: "learner@example.edu",
        identityType: "email",
      },
    });

    expect(parsed.recipient?.identity).toBe("learner@example.edu");
    expect(() =>
      parsePreviewEvaluateBadgeIssuanceRuleRequest({
        definition,
        lmsConnectionId: "lms_123",
        learnerId: "learner_123",
        recipientIdentity: "learner@example.edu",
        recipientIdentityType: "email",
      }),
    ).toThrow(/unrecognized/i);
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

  it("parses placement retirement path and form identities", () => {
    const pathParams = parseLtiResourceLinkPlacementPathParams({
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
      placementId: "lti_place_123",
    });
    const request = parseRetireLtiResourceLinkPlacementRequest({
      placementId: "lti_place_123",
    });

    expect(pathParams.placementId).toBe("lti_place_123");
    expect(request).toEqual({ placementId: "lti_place_123" });
    expect(() => parseRetireLtiResourceLinkPlacementRequest({ placementId: "" })).toThrow(
      /too small/i,
    );
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
      badgeTemplateReuseAcknowledged: true,
      lmsConnectionId: "lms_123",
      lmsProviderKind: "canvas",
      action: "submit_for_approval",
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
        badgeTemplateReuseAcknowledged: false,
        lmsConnectionId: "lms_123",
        lmsProviderKind: "canvas",
        action: "save_draft",
        definition: {
          conditions: {
            type: "grade_threshold",
            courseId: "course_101",
          },
        },
      });
    }).toThrow(/./);
  });

  it("rejects author-supplied approval chains on badge rule commands", () => {
    expect(() => {
      parseCreateBadgeIssuanceRuleRequest({
        name: "Governed Rule",
        badgeTemplateId: "badge_template_cs101",
        badgeTemplateReuseAcknowledged: false,
        lmsConnectionId: "lms_123",
        action: "save_draft",
        definition: {
          conditions: {
            type: "grade_threshold",
            courseId: "course_101",
            minScore: 80,
          },
        },
        approvalChain: [{ requiredRole: "admin" }],
      });
    }).toThrow(/./);
  });

  it("rejects rule conditions that provide both direct IDs and reusable list IDs", () => {
    expect(() => {
      parseCreateBadgeIssuanceRuleRequest({
        name: "Invalid list combination",
        badgeTemplateId: "badge_template_cs101",
        badgeTemplateReuseAcknowledged: false,
        lmsConnectionId: "lms_123",
        lmsProviderKind: "canvas",
        action: "save_draft",
        definition: {
          conditions: {
            type: "course_completion",
            courseId: "course_101",
            courseListId: "brvl_courses",
            minCompletionPercent: 100,
          },
        },
      });
    }).toThrow(/./);
  });

  it.each(["changes_requested", "rejected"] as const)(
    "requires a reviewer comment when the decision is %s",
    (decision) => {
      expect(() => {
        parseDecideBadgeIssuanceRuleVersionRequest({ decision });
      }).toThrow("comment is required when returning or rejecting a version");
    },
  );

  it("allows approval without a reviewer comment", () => {
    expect(parseDecideBadgeIssuanceRuleVersionRequest({ decision: "approved" })).toEqual({
      decision: "approved",
    });
  });

  it("parses unfinished and formal-rule builder draft targets", () => {
    const unfinished = parseSaveBadgeIssuanceRuleBuilderDraftRequest({
      target: { kind: "unfinished" },
      currentStep: "test",
    });
    const formalRule = parseSaveBadgeIssuanceRuleBuilderDraftRequest({
      target: {
        kind: "formal_rule",
        ruleId: "brl_rule",
        versionId: "brv_version",
      },
      currentStep: "conditions",
    });

    expect(unfinished.target).toEqual({ kind: "unfinished" });
    expect(unfinished.currentStep).toBe("test");
    expect(formalRule.target).toEqual({
      kind: "formal_rule",
      ruleId: "brl_rule",
      versionId: "brv_version",
    });
  });

  it("requires an explicit authoring action", () => {
    expect(() => {
      parseCreateBadgeIssuanceRuleRequest({
        name: "Missing action",
        badgeTemplateId: "badge_template_cs101",
        badgeTemplateReuseAcknowledged: false,
        lmsConnectionId: "lms_123",
        definition: {
          conditions: {
            type: "course_completion",
            courseId: "course_101",
            minCompletionPercent: 100,
          },
        },
      });
    }).toThrow(/./);
  });

  it("rejects builder draft targets with only one formal identity", () => {
    expect(() => {
      parseSaveBadgeIssuanceRuleBuilderDraftRequest({
        target: {
          kind: "formal_rule",
          versionId: "brv_version",
        },
        currentStep: "metadata",
      });
    }).toThrow(/./);
    expect(() => {
      parseSaveBadgeIssuanceRuleBuilderDraftRequest({
        target: {
          kind: "formal_rule",
          ruleId: "brl_rule",
        },
        currentStep: "metadata",
      });
    }).toThrow(/./);
  });
});
