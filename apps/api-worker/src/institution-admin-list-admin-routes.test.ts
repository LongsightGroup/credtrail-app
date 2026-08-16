import { describe, expect, it } from "vitest";
import {
  createEnv,
  mockedCreateBadgeIssuanceRuleValueList,
  mockedFindBadgeIssuanceRuleById,
  mockedFindBadgeIssuanceRuleEvaluationById,
  mockedListBadgeIssuanceRuleEvaluations,
  mockedResolveBadgeIssuanceRuleEvaluationReview,
} from "./institution-admin-test-utils/rules-test-harness";
import { app } from "./index";

describe("POST /tenants/:tenantId/admin/rules/value-lists", () => {
  it("creates a value list and redirects with a signed flash cookie", async () => {
    const env = createEnv();

    const response = await app.request(
      "/tenants/tenant_123/admin/rules/value-lists",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          label: "Core CS sequence",
          kind: "course_ids",
          values: "CS101, CS102",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location") ?? "";
    expect(location).toBe("/tenants/tenant_123/admin/rules");
    expect(location).not.toContain("listNotice=");
    expect(mockedCreateBadgeIssuanceRuleValueList).toHaveBeenCalledTimes(1);

    const flashCookie = response.headers.get("set-cookie") ?? "";
    expect(flashCookie).toContain("ct_admin_flash_list_message_tenant_123");

    const pageResponse = await app.request(
      location,
      {
        headers: {
          Cookie: `better-auth.session_token=session-token; ${flashCookie.split(";")[0]}`,
        },
      },
      env,
    );
    const body = await pageResponse.text();

    expect(pageResponse.status).toBe(200);
    expect(body).not.toContain("Created reusable list");
    expect(body).not.toContain("Core CS sequence");
    expect(body).not.toContain('id="rule-value-list-form"');
  });
});

describe("POST /tenants/:tenantId/admin/operations/review-queue/resolve", () => {
  it("dismisses a pending review entry and redirects with flash feedback", async () => {
    const env = createEnv();

    const pendingEvaluation = {
      id: "bre_123",
      tenantId: "tenant_123",
      ruleId: "brl_123",
      versionId: "brv_123",
      learnerId: "learner_123",
      recipientIdentity: "learner@example.edu",
      recipientIdentityType: "email" as const,
      matched: false,
      issuanceStatus: "review_required",
      assertionId: null,
      evaluationJson: JSON.stringify({
        evaluation: {
          matched: false,
          tree: { type: "grade_threshold", matched: false },
        },
      }),
      reviewStatus: "pending" as const,
      reviewDecision: null,
      reviewComment: null,
      reviewedByUserId: null,
      reviewedAt: null,
      evaluatedAt: "2026-02-17T00:00:00.000Z",
      createdAt: "2026-02-17T00:00:00.000Z",
    };

    mockedListBadgeIssuanceRuleEvaluations.mockResolvedValueOnce([pendingEvaluation]);
    mockedFindBadgeIssuanceRuleEvaluationById.mockResolvedValueOnce(pendingEvaluation);
    mockedFindBadgeIssuanceRuleById.mockResolvedValueOnce({
      id: "brl_123",
      tenantId: "tenant_123",
      name: "CS101 Rule",
      description: "Issue badge for CS101 completion and grade threshold.",
      badgeTemplateId: "badge_template_001",
      orgUnitId: "tenant_123:org:institution",
      ownerOrgUnitId: "tenant_123:org:institution",
      lmsProviderKind: "canvas",
      lmsConnectionId: "lms_canvas",
      activeVersionId: "brv_123",
      createdByUserId: "usr_admin",
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });
    mockedResolveBadgeIssuanceRuleEvaluationReview.mockResolvedValueOnce({
      ...pendingEvaluation,
      issuanceStatus: "review_dismissed",
      reviewStatus: "resolved",
      reviewDecision: "dismiss",
      reviewComment: "Missing facts confirmed; no issue",
      reviewedByUserId: "usr_admin",
      reviewedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await app.request(
      "/tenants/tenant_123/admin/operations/review-queue/resolve",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({
          evaluationId: "bre_123",
          decision: "dismiss",
          comment: "Missing facts confirmed; no issue",
        }).toString(),
        redirect: "manual",
      },
      env,
    );

    expect(response.status).toBe(303);
    const location = response.headers.get("location") ?? "";
    expect(location).toBe("/tenants/tenant_123/admin/operations/review-queue");
    expect(location).not.toContain("listNotice=");
    expect(mockedResolveBadgeIssuanceRuleEvaluationReview).toHaveBeenCalledTimes(1);

    const flashCookie = response.headers.get("set-cookie") ?? "";
    expect(flashCookie).toContain("ct_admin_flash_list_message_tenant_123");

    const pageResponse = await app.request(
      location,
      {
        headers: {
          Cookie: `better-auth.session_token=session-token; ${flashCookie.split(";")[0]}`,
        },
      },
      env,
    );
    const body = await pageResponse.text();

    expect(pageResponse.status).toBe(200);
    expect(body).toContain("Dismissed review for learner@example.edu");
  });
});
