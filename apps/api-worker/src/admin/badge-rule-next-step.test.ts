import type { BadgeIssuanceRuleRecord, BadgeIssuanceRuleVersionRecord } from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import { describe, expect, it } from "vitest";
import { buildBadgeRuleVersionRecord } from "../test-support/badge-rule-version";
import { buildBadgeRuleNextStepModel } from "./badge-rule-next-step";

const testRule = (
  activeVersionId: string | null,
  overrides: Partial<BadgeIssuanceRuleRecord> = {},
): BadgeIssuanceRuleRecord => ({
  id: "brl_next_step",
  tenantId: "tenant_123",
  name: "Course completion rule",
  description: "Award after course completion.",
  badgeTemplateId: "badge_template_001",
  orgUnitId: "tenant_123:org:institution",
  ownerOrgUnitId: "tenant_123:org:institution",
  lmsProviderKind: "canvas",
  lmsConnectionId: "lms_123",
  activeVersionId,
  createdByUserId: "usr_author",
  createdAt: "2026-09-01T12:00:00.000Z",
  updatedAt: "2026-09-02T12:00:00.000Z",
  ...overrides,
});

const testDefinition = (
  issuanceTiming: "immediate" | "manual" | "end_of_term" = "immediate",
): BadgeIssuanceRuleDefinition => ({
  conditions: {
    type: "course_completion",
    courseId: "course_101",
    minCompletionPercent: 100,
  },
  options: { issuanceTiming },
});

const testVersion = (
  status: BadgeIssuanceRuleVersionRecord["status"],
  overrides: Partial<BadgeIssuanceRuleVersionRecord> = {},
): BadgeIssuanceRuleVersionRecord =>
  buildBadgeRuleVersionRecord({
    id: `brv_${status}`,
    ruleId: "brl_next_step",
    status,
    snapshot: { name: "Course completion rule" },
    ...overrides,
  });

const nextStep = (input: {
  readonly version: BadgeIssuanceRuleVersionRecord;
  readonly rule?: BadgeIssuanceRuleRecord | undefined;
  readonly definition?: BadgeIssuanceRuleDefinition | undefined;
  readonly activePlacementCount?: number | undefined;
  readonly canReviewPendingVersion?: boolean | undefined;
}) =>
  buildBadgeRuleNextStepModel({
    userId: "usr_admin",
    rule: input.rule ?? testRule(null),
    selectedVersion: input.version,
    latestVersion: input.version,
    definition: input.definition ?? testDefinition(),
    activePlacementCount: input.activePlacementCount ?? 0,
    canReviewPendingVersion: input.canReviewPendingVersion ?? false,
  });

describe("badge rule next-step model", () => {
  it.each([
    ["draft", "submit_for_approval", "Submit this draft for approval"],
    ["rejected", "edit_rule", "Revise the rule before resubmitting"],
    ["approved", "activate", "Activate the approved rule"],
    ["suspended", "resume", "Resume issuance when the issue is resolved"],
    ["expired", "copy_rule", "Create the next rule"],
    ["deprecated", "copy_rule", "Create a new rule if this policy is needed again"],
  ] as const)("maps %s to the %s action", (status, actionTag, title) => {
    const model = nextStep({ version: testVersion(status) });

    expect(model.action._tag).toBe(actionTag);
    expect(model.title).toBe(title);
    expect(model.owner).not.toHaveLength(0);
    expect(model.outcome).not.toHaveLength(0);
  });

  it("sends a historical selection to the latest version before offering workflow actions", () => {
    const selectedVersion = testVersion("active", { id: "brv_active", versionNumber: 1 });
    const latestVersion = testVersion("draft", { id: "brv_draft", versionNumber: 2 });
    const model = buildBadgeRuleNextStepModel({
      userId: "usr_admin",
      rule: testRule(selectedVersion.id),
      selectedVersion,
      latestVersion,
      definition: testDefinition(),
      activePlacementCount: 1,
      canReviewPendingVersion: false,
    });

    expect(model.action._tag).toBe("view_latest");
    expect(model.title).toBe("Continue with version 2");
    expect(model.description).toContain("You are viewing version 1");
    expect(model.description).toContain("latest version, which is draft");
  });

  it("gives an authorized reviewer the pending decision", () => {
    const version = testVersion("pending_approval", {
      submittedByUserId: "usr_author",
    });
    const model = nextStep({ version, canReviewPendingVersion: true });

    expect(model.action._tag).toBe("review_approval");
    expect(model.title).toBe("Review the submitted rule");
    expect(model.owner).toBe("You");
  });

  it("keeps the submitter waiting while allowing withdrawal", () => {
    const version = testVersion("pending_approval", {
      submittedByUserId: "usr_admin",
    });
    const model = nextStep({ version });

    expect(model.action).toEqual({ _tag: "await_approval", canWithdraw: true });
    expect(model.title).toBe("Wait for an independent review");
    expect(model.owner).toBe("Assigned reviewer");
  });

  it("routes an active unplaced rule to course availability", () => {
    const version = testVersion("active");
    const model = nextStep({
      version,
      rule: testRule(version.id),
      activePlacementCount: 0,
    });

    expect(model.action._tag).toBe("configure_availability");
    expect(model.title).toBe("Make the rule available in the LMS");
  });

  it.each([
    ["immediate", "review_evaluation", "CredTrail is checking eligibility automatically"],
    ["manual", "review_availability", "Instructors confirm eligible learners"],
  ] as const)("explains the %s issuance owner for a placed active rule", (timing, tag, title) => {
    const version = testVersion("active");
    const model = nextStep({
      version,
      rule: testRule(version.id),
      definition: testDefinition(timing),
      activePlacementCount: 1,
    });

    expect(model.action._tag).toBe(tag);
    expect(model.title).toBe(title);
  });

  it("requires an end date before an end-of-term batch can run", () => {
    const version = testVersion("active", { expiresAt: null });
    const model = nextStep({
      version,
      rule: testRule(version.id),
      definition: testDefinition("end_of_term"),
      activePlacementCount: 1,
    });

    expect(model.action._tag).toBe("schedule_end_of_term");
    expect(model.title).toBe("Set the term end date");
  });

  it("hands a scheduled end-of-term batch to CredTrail", () => {
    const version = testVersion("active", { expiresAt: "2026-12-18T22:00:00.000Z" });
    const model = nextStep({
      version,
      rule: testRule(version.id),
      definition: testDefinition("end_of_term"),
      activePlacementCount: 1,
    });

    expect(model.action._tag).toBe("review_evaluation");
    expect(model.title).toBe("CredTrail will run the end-of-term batch");
    expect(model.owner).toBe("CredTrail");
  });
});
