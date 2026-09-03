import type {
  AutomatedBadgeRuleEvaluationStatusRecord,
  LtiResourceLinkPlacementRecord,
} from "@credtrail/db";
import { describe, expect, it } from "vitest";
import {
  createEnv,
  fakeDb,
  mockedCreateAuditLogDb,
  mockedFindAutomatedBadgeRuleEvaluationStatusDb,
  mockedFindBadgeIssuanceRuleById,
  mockedFindTenantOrgUnitById,
  mockedFindTenantMembership,
  mockedListBadgeIssuanceRuleVersions,
  mockedListBadgeIssuanceRuleVersionApprovalStepsDb,
  mockedListBadgeIssuanceRuleValueLists,
  mockedListLtiResourceLinkPlacementsForRuleDb,
  mockedRequestManualAutomatedBadgeRuleEvaluationDb,
  mockedRetireLtiResourceLinkPlacementDb,
  sampleDetailRule,
  sampleDetailVersion,
  sampleMembership,
} from "./institution-admin-test-utils/rules-test-harness";
import { app } from "./index";
import { readScriptAssetSource } from "./page-asset-test-utils";
import { pageAssetPath } from "./ui/page-assets";

const INSTITUTION_ADMIN_RULE_VERSION_JS = readScriptAssetSource("institutionAdminRuleVersionJs");
const EVALUATION_REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000";

const sampleEvaluationStatus = (
  overrides: Partial<AutomatedBadgeRuleEvaluationStatusRecord> = {},
): AutomatedBadgeRuleEvaluationStatusRecord => ({
  tenantId: "tenant_123",
  ruleId: "brl_detail",
  versionId: "brv_detail_active",
  commandId: "job_evaluation_123",
  triggerKind: "hourly",
  status: "succeeded",
  queuedAt: "2026-09-02T18:00:00.000Z",
  startedAt: "2026-09-02T18:01:00.000Z",
  completedAt: "2026-09-02T18:01:05.000Z",
  candidateLearnerCount: 12,
  matchedLearnerCount: 4,
  issueJobsEnqueued: 3,
  learnersMissingEmail: 0,
  learnersAlreadyIssued: 1,
  learnersUnavailable: 0,
  learnerIdentityConflicts: 0,
  reasonTag: null,
  failureTag: null,
  updatedAt: "2026-09-02T18:01:05.000Z",
  ...overrides,
});

const samplePlacement = (
  overrides: Partial<Extract<LtiResourceLinkPlacementRecord, { status: "active" }>> = {},
): Extract<LtiResourceLinkPlacementRecord, { status: "active" }> => ({
  id: "lti_place_detail",
  tenantId: "tenant_123",
  issuer: "https://lms.example.test",
  clientId: "client_detail",
  deploymentId: "deployment_detail",
  contextId: "course_detail",
  resourceLinkId: "resource_detail",
  badgeTemplateId: "badge_template_001",
  ruleId: "brl_detail",
  createdByUserId: "usr_admin",
  status: "active",
  lastSeenAt: "2026-09-02T17:45:00.000Z",
  retiredAt: null,
  retiredByUserId: null,
  createdAt: "2026-09-01T17:45:00.000Z",
  updatedAt: "2026-09-02T17:45:00.000Z",
  ...overrides,
});

const sampleRetiredPlacement = (): Extract<
  LtiResourceLinkPlacementRecord,
  { status: "retired" }
> => ({
  ...samplePlacement(),
  id: "lti_place_retired",
  status: "retired",
  retiredAt: "2026-09-02T18:00:00.000Z",
  retiredByUserId: "usr_admin",
});

const requestRulePage = (path: string): Promise<Response> => {
  return Promise.resolve(
    app.request(
      path,
      {
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      },
      createEnv(),
    ),
  );
};

describe("GET /tenants/:tenantId/admin/rules/:ruleId", () => {
  it("redirects the stable rule URL to its active version", async () => {
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");
    const latestVersion = sampleDetailVersion("brv_detail_latest", 2, "draft");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([latestVersion, activeVersion]);

    const response = await requestRulePage("/tenants/tenant_123/admin/rules/brl_detail");

    expect(response.status).toBe(302);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active",
    );
  });

  it("supports selecting a saved version from the stable rule URL", async () => {
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");
    const latestVersion = sampleDetailVersion("brv_detail_latest", 2, "draft");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion, latestVersion]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail?versionId=brv_detail_latest",
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_latest",
    );
  });

  it("uses the latest version when the rule has no active version", async () => {
    const firstVersion = sampleDetailVersion("brv_detail_first", 1, "rejected");
    const latestVersion = sampleDetailVersion("brv_detail_latest", 2, "draft");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(null));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([firstVersion, latestVersion]);

    const response = await requestRulePage("/tenants/tenant_123/admin/rules/brl_detail");

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_latest",
    );
  });

  it("does not hide an invalid active-version reference", async () => {
    const latestVersion = sampleDetailVersion("brv_detail_latest", 2, "draft");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule("brv_detail_missing"));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([latestVersion]);

    const response = await requestRulePage("/tenants/tenant_123/admin/rules/brl_detail");

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "Badge rule version not found" });
  });

  it("reports an incomplete setup when a rule has no versions", async () => {
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(null));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([]);

    const response = await requestRulePage("/tenants/tenant_123/admin/rules/brl_detail");

    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "Badge rule setup is incomplete" });
  });
});

describe("GET /tenants/:tenantId/admin/rules/:ruleId/versions/:versionId", () => {
  it("gives an assigned reviewer the next approval action", async () => {
    const pendingVersion = {
      ...sampleDetailVersion("brv_detail_pending", 1, "pending_approval"),
      createdByUserId: "usr_author",
      submittedByUserId: "usr_author",
    };
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(null));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([pendingVersion]);
    mockedListBadgeIssuanceRuleVersionApprovalStepsDb.mockResolvedValue([
      {
        id: "approval_step_1",
        tenantId: "tenant_123",
        versionId: pendingVersion.id,
        stepNumber: 1,
        targetType: "role_threshold",
        requiredRole: "admin",
        targetUserId: null,
        targetApproverGroupId: null,
        orgUnitId: null,
        label: "Institution review",
        status: "pending",
        decidedByUserId: null,
        decidedAt: null,
        decisionComment: null,
        createdAt: "2026-09-02T12:00:00.000Z",
        updatedAt: "2026-09-02T12:00:00.000Z",
      },
    ]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_pending",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Review the submitted rule");
    expect(body).toContain("<dd>You</dd>");
    expect(body).toContain('data-rule-next-step="review_approval"');
    expect(body).toContain(
      'href="/tenants/tenant_123/admin/rules/approvals/brl_detail/versions/brv_detail_pending"',
    );
  });

  it("shows the submitter that an independent reviewer owns the next step", async () => {
    const pendingVersion = sampleDetailVersion("brv_detail_pending", 1, "pending_approval");
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(null));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([pendingVersion]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_pending",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Wait for an independent review");
    expect(body).toContain("<dd>Assigned reviewer</dd>");
    expect(body).toContain("Withdraw submission");
    expect(body).toContain('data-rule-next-step="await_approval"');
  });

  it("lists active and retired placements with row-owned retirement guidance", async () => {
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion]);
    mockedListLtiResourceLinkPlacementsForRuleDb.mockResolvedValue([
      samplePlacement(),
      sampleRetiredPlacement(),
    ]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("What happens next");
    expect(body).toContain("CredTrail is checking eligibility automatically");
    expect(body).toContain('href="#automatic-evaluation"');
    expect(body).toContain("LTI placements");
    expect(body).toContain("Only active placements backed by an active rule");
    expect(body).toContain("Retire placement");
    expect(body).toContain("will reactivate if launched again");
    expect(body).toContain("Advanced LMS identifiers");
    expect(body).toContain("course_detail");
    expect(body).not.toContain("https://lms.example.test");
  });

  it("shows the latest automatic evaluation outcome and recovery action", async () => {
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion]);
    mockedFindAutomatedBadgeRuleEvaluationStatusDb.mockResolvedValue(sampleEvaluationStatus());

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("What happens next");
    expect(body).toContain("Make the rule available in the LMS");
    expect(body).toContain('href="/tenants/tenant_123/admin/rules/brl_detail/availability"');
    expect(body).toContain("Issuance health");
    expect(body).toContain("Automatic evaluation");
    expect(body).toContain("Completed");
    expect(body).toContain("Learners checked");
    expect(body).toContain(">12<");
    expect(body).toContain("Awards queued");
    expect(body).toContain(">3<");
    expect(body).toContain("Run evaluation now");
    expect(body).toContain(
      'action="/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active/run-evaluation"',
    );
    expect(body).toMatch(/name="requestId" value="[0-9a-f-]{36}"/);
    expect(mockedFindAutomatedBadgeRuleEvaluationStatusDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_detail",
      versionId: "brv_detail_active",
    });
  });

  it("keeps health visible but hides run-now for instructor-confirmed versions", async () => {
    const activeVersion = {
      ...sampleDetailVersion("brv_detail_active", 1, "active"),
      ruleJson: JSON.stringify({
        conditions: {
          type: "course_completion",
          courseId: "course_101",
          minCompletionPercent: 100,
        },
        options: { issuanceTiming: "manual" },
      }),
    };
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("No automatic evaluation has been recorded for this version yet.");
    expect(body).not.toContain("Run evaluation now");
    expect(body).not.toContain("/run-evaluation");
  });

  it.each([
    {
      status: "queued" as const,
      label: "Queued",
      summary: "CredTrail will check eligible learners",
      startedAt: null,
      completedAt: null,
    },
    {
      status: "running" as const,
      label: "Checking learners",
      summary: "CredTrail is reading LMS facts",
      startedAt: "2026-09-02T18:01:00.000Z",
      completedAt: null,
    },
    {
      status: "retrying" as const,
      label: "Retrying",
      summary: "Some LMS facts were unavailable",
      startedAt: "2026-09-02T18:01:00.000Z",
      completedAt: null,
    },
    {
      status: "failed" as const,
      label: "Needs attention",
      summary: "saved command was invalid",
      startedAt: null,
      completedAt: "2026-09-02T18:01:05.000Z",
    },
    {
      status: "noop" as const,
      label: "No check needed",
      summary: "no longer belongs to the active rule version",
      startedAt: "2026-09-02T18:01:00.000Z",
      completedAt: "2026-09-02T18:01:05.000Z",
    },
  ])("renders the $status operational state in administrator language", async (state) => {
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion]);
    mockedFindAutomatedBadgeRuleEvaluationStatusDb.mockResolvedValue(
      sampleEvaluationStatus({
        status: state.status,
        startedAt: state.startedAt,
        completedAt: state.completedAt,
        candidateLearnerCount: state.status === "retrying" ? 12 : null,
        matchedLearnerCount: state.status === "retrying" ? 4 : null,
        issueJobsEnqueued: state.status === "retrying" ? 0 : null,
        learnersMissingEmail: state.status === "retrying" ? 0 : null,
        learnersAlreadyIssued: state.status === "retrying" ? 1 : null,
        learnersUnavailable: state.status === "retrying" ? 1 : null,
        learnerIdentityConflicts: state.status === "retrying" ? 0 : null,
        reasonTag:
          state.status === "retrying"
            ? "learner_evaluation_unavailable"
            : state.status === "noop"
              ? "rule_version_changed"
              : null,
        failureTag: state.status === "failed" ? "invalid_command" : null,
      }),
    );

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain(state.label);
    expect(body).toContain(state.summary);
  });

  it("renders the canonical read-only version record with scoped assets", async () => {
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");
    const latestVersion = sampleDetailVersion("brv_detail_latest", 2, "draft");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion, latestVersion]);
    mockedFindTenantOrgUnitById.mockResolvedValue({
      id: "tenant_123:org:cs",
      tenantId: "tenant_123",
      unitType: "department",
      slug: "computer-science",
      displayName: "Computer Science",
      parentOrgUnitId: "tenant_123:org:institution",
      createdByUserId: "usr_admin",
      isActive: true,
      createdAt: "2026-02-18T12:00:00.000Z",
      updatedAt: "2026-02-18T12:00:00.000Z",
    });

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_latest",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toContain("Advanced TypeScript Rule");
    expect(body).not.toContain("Mutable rule head name");
    expect(body).toContain("TypeScript Foundations");
    expect(body).toContain("Organization scope");
    expect(body).toContain("Computer Science (department)");
    expect(body).toContain('src="https://example.edu/badges/typescript.png"');
    expect(body).toContain("What this version requires");
    expect(body).toContain('data-rule-lms-reference="course"');
    expect(body).toContain('data-rule-lms-reference="assignment"');
    expect(body).toContain('data-rule-lms-label="">Course</span>');
    expect(body).toContain('data-rule-lms-label="">Assignment</span>');
    expect(body).toContain("ID: course_101");
    expect(body).toContain("ID: assignment_7");
    expect(body).toContain('data-rule-lms-label-status="" role="status" hidden=""');
    expect(body).toContain(
      'data-lms-labels-url="/v1/tenants/tenant_123/badge-rules/brl_detail/versions/brv_detail_latest/lms-reference-labels"',
    );
    expect(body).toContain('data-rule-version-navigation=""');
    expect(body).toContain('name="versionId"');
    expect(body).toContain(
      'data-version-url="/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active"',
    );
    expect(body).toContain(
      'data-version-url="/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_latest"',
    );
    expect(body).toContain("Version 1 — Active now");
    expect(body).toContain("Version 2 — Draft · latest version");
    expect(body).toContain("Version 2 of 2");
    expect(body).toContain("← Previous version");
    expect(body).toContain("Next version →");
    expect(body).toContain("Submit this draft for approval");
    expect(body).toContain("The rule is saved, but it cannot issue badges yet");
    expect(body).toContain("Version note:");
    expect(body).toContain("Technical details");
    expect(body).toContain("Rule ID");
    expect(body).toContain("brl_detail");
    expect(body).toContain("Version ID");
    expect(body).toContain("brv_detail_latest");
    expect(body).toContain(pageAssetPath("institutionAdminRuleVersionCss"));
    expect(body).toContain(pageAssetPath("institutionAdminRuleVersionJs"));
    expect(body).not.toContain(pageAssetPath("institutionAdminRuleApprovalReviewCss"));
    expect(body).not.toContain(pageAssetPath("institutionAdminRuleApprovalReviewJs"));
    expect(mockedFindTenantOrgUnitById).toHaveBeenCalledWith(
      expect.anything(),
      "tenant_123",
      "tenant_123:org:cs",
    );
    expect(INSTITUTION_ADMIN_RULE_VERSION_JS).toContain("window.location.assign(destination)");
  });

  it("renders historical metadata only from the selected version snapshot", async () => {
    const historicalVersion = {
      ...sampleDetailVersion("brv_detail_historical", 1, "active"),
      snapshot: {
        ...sampleDetailVersion("brv_detail_historical", 1, "active").snapshot,
        name: "Original course rule",
        description: "Original rule description.",
        badgeTemplateTitle: "Original course badge",
        badgeTemplateImageUri: "https://example.edu/badges/original.png",
        lmsProviderKind: "sakai" as const,
        lmsConnectionId: null,
      },
    };
    const currentRule = {
      ...sampleDetailRule(historicalVersion.id),
      name: "Replacement rule name",
      description: "Replacement description.",
      lmsProviderKind: "canvas" as const,
      lmsConnectionId: "lms_replacement",
    };
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(currentRule);
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([historicalVersion]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_historical",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Original course rule");
    expect(body).toContain("Original rule description.");
    expect(body).toContain("Original course badge");
    expect(body).toContain('src="https://example.edu/badges/original.png"');
    expect(body).toContain("Sakai");
    expect(body).not.toContain("Replacement rule name");
    expect(body).not.toContain("Replacement description.");
    expect(body).not.toContain("lms-reference-labels");
  });

  it("expands saved course lists into inspectable course requirements", async () => {
    const activeVersion = {
      ...sampleDetailVersion("brv_detail_active", 1, "active"),
      ruleJson: JSON.stringify({
        conditions: {
          type: "grade_threshold",
          courseListId: "brvl_courses",
          minScore: 80,
        },
      }),
    };
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion]);
    mockedListBadgeIssuanceRuleValueLists.mockResolvedValue([
      {
        id: "brvl_courses",
        tenantId: "tenant_123",
        label: "Required programming courses",
        kind: "course_ids",
        values: ["course_101", "course_202"],
        createdByUserId: "usr_admin",
        archivedAt: null,
        createdAt: "2026-08-01T00:00:00.000Z",
        updatedAt: "2026-08-01T00:00:00.000Z",
      },
    ]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('data-course-id="course_101"');
    expect(body).toContain('data-course-id="course_202"');
    expect(body).toContain("ID: course_101");
    expect(body).toContain("ID: course_202");
    expect(body).not.toContain("ID: brvl_courses");
  });

  it("rejects a version that does not belong to the rule", async () => {
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");

    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion]);

    const response = await requestRulePage(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_another_rule",
    );

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "Badge rule version not found" });
  });
});

describe("POST /tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/placements/:placementId/retire", () => {
  const requestRetirement = (
    input: {
      pathPlacementId?: string;
      formPlacementId?: string;
    } = {},
  ): Promise<Response> => {
    const pathPlacementId = input.pathPlacementId ?? "lti_place_detail";
    const formPlacementId = input.formPlacementId ?? pathPlacementId;
    const activeVersion = sampleDetailVersion("brv_detail_active", 1, "active");
    mockedFindBadgeIssuanceRuleById.mockResolvedValue(sampleDetailRule(activeVersion.id));
    mockedListBadgeIssuanceRuleVersions.mockResolvedValue([activeVersion]);

    return Promise.resolve(
      app.request(
        `/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active/placements/${pathPlacementId}/retire`,
        {
          method: "POST",
          headers: {
            Origin: "http://localhost",
            Cookie: "better-auth.session_token=session-token",
          },
          body: new URLSearchParams({ placementId: formPlacementId }),
        },
        createEnv(),
      ),
    );
  };

  it("retires an authorized tenant/rule-owned placement", async () => {
    mockedRetireLtiResourceLinkPlacementDb.mockResolvedValue({
      status: "retired",
      placement: sampleRetiredPlacement(),
    });

    const response = await requestRetirement();

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active",
    );
    expect(mockedRetireLtiResourceLinkPlacementDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_detail",
      placementId: "lti_place_detail",
      actorUserId: "usr_admin",
      actorRole: "admin",
    });
  });

  it("treats an already-retired replay as successful", async () => {
    mockedRetireLtiResourceLinkPlacementDb.mockResolvedValue({
      status: "already_retired",
      placement: sampleRetiredPlacement(),
    });

    const response = await requestRetirement();

    expect(response.status).toBe(303);
    expect(mockedRetireLtiResourceLinkPlacementDb).toHaveBeenCalledTimes(1);
  });

  it("rejects mismatched path and form identities before persistence", async () => {
    const response = await requestRetirement({ formPlacementId: "lti_place_other" });

    expect(response.status).toBe(303);
    expect(mockedRetireLtiResourceLinkPlacementDb).not.toHaveBeenCalled();
  });

  it("does not allow a non-admin member to retire a placement", async () => {
    mockedFindTenantMembership.mockResolvedValue(sampleMembership("viewer"));

    const response = await requestRetirement();

    expect(response.status).toBe(403);
    expect(mockedRetireLtiResourceLinkPlacementDb).not.toHaveBeenCalled();
  });
});

describe("POST /tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/run-evaluation", () => {
  const requestEvaluation = (): Promise<Response> =>
    Promise.resolve(
      app.request(
        "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active/run-evaluation",
        {
          method: "POST",
          headers: {
            Origin: "http://localhost",
            Cookie: "better-auth.session_token=session-token",
          },
          body: new URLSearchParams({ requestId: EVALUATION_REQUEST_ID }),
        },
        createEnv(),
      ),
    );

  it("queues an authorized request and records a safe audit event", async () => {
    const response = await requestEvaluation();

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active",
    );
    expect(mockedRequestManualAutomatedBadgeRuleEvaluationDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      ruleId: "brl_detail",
      versionId: "brv_detail_active",
      requestId: EVALUATION_REQUEST_ID,
      requestedAt: expect.any(String),
    });
    expect(mockedCreateAuditLogDb).toHaveBeenCalledWith(fakeDb, {
      tenantId: "tenant_123",
      actorUserId: "usr_admin",
      action: "badge_rule.automated_evaluation_requested",
      targetType: "badge_rule_version",
      targetId: "brv_detail_active",
      metadata: { role: "admin", ruleId: "brl_detail", trigger: "manual" },
    });
  });

  it("treats a replayed request as successful without duplicating its audit event", async () => {
    mockedRequestManualAutomatedBadgeRuleEvaluationDb.mockResolvedValue("duplicate");

    const response = await requestEvaluation();

    expect(response.status).toBe(303);
    expect(mockedCreateAuditLogDb).not.toHaveBeenCalled();
  });

  it("rejects an expired request token before touching the queue", async () => {
    const response = await app.request(
      "/tenants/tenant_123/admin/rules/brl_detail/versions/brv_detail_active/run-evaluation",
      {
        method: "POST",
        headers: {
          Origin: "http://localhost",
          Cookie: "better-auth.session_token=session-token",
        },
        body: new URLSearchParams({ requestId: "not-a-uuid" }),
      },
      createEnv(),
    );

    expect(response.status).toBe(303);
    expect(mockedRequestManualAutomatedBadgeRuleEvaluationDb).not.toHaveBeenCalled();
    expect(mockedCreateAuditLogDb).not.toHaveBeenCalled();
  });

  it("does not audit a version that is no longer eligible", async () => {
    mockedRequestManualAutomatedBadgeRuleEvaluationDb.mockResolvedValue("not_eligible");

    const response = await requestEvaluation();

    expect(response.status).toBe(303);
    expect(mockedCreateAuditLogDb).not.toHaveBeenCalled();
  });

  it("does not allow a non-admin member to request an evaluation", async () => {
    mockedFindTenantMembership.mockResolvedValue(sampleMembership("viewer"));

    const response = await requestEvaluation();

    expect(response.status).toBe(403);
    expect(mockedRequestManualAutomatedBadgeRuleEvaluationDb).not.toHaveBeenCalled();
    expect(mockedCreateAuditLogDb).not.toHaveBeenCalled();
  });
});
