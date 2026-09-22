import { describe, expect, it } from "vitest";
import type {
  BadgeRuleApprovalPolicyRecord,
  BadgeIssuanceRuleApprovalStepRecord,
  TenantMemberRecord,
} from "@credtrail/db";
import { buildBadgeRuleVersionRecord } from "../test-support/badge-rule-version";
import {
  badgeWorkflowAwarding,
  describeBadgeWorkflowPolicy,
  describeBadgeWorkflowApproval,
  buildBadgeWorkflowResponsibility,
  type BadgeWorkflowDirectory,
} from "./badge-workflow-responsibility";
const member = (userId: string, role: TenantMemberRecord["role"]): TenantMemberRecord => ({
  tenantId: "tenant_123",
  userId,
  role,
  email: `${userId}@example.edu`,
  createdAt: "2026-09-01",
  updatedAt: "2026-09-01",
});
const directory: BadgeWorkflowDirectory = {
  members: [member("author", "admin"), member("reviewer", "approver")],
  groups: [],
  orgUnits: [],
};
const policy: BadgeRuleApprovalPolicyRecord = {
  id: null,
  tenantId: "tenant_123",
  orgUnitId: null,
  approvalRequirement: "always",
  allowSelfCertification: false,
  recertificationIntervalMonths: null,
  approvalSteps: [
    {
      targetType: "user",
      targetUserId: "reviewer",
      targetApproverGroupId: null,
      requiredRole: null,
      orgUnitId: null,
      label: null,
    },
  ],
  createdByUserId: null,
  createdAt: "2026-09-01",
  updatedAt: "2026-09-01",
};
const step: BadgeIssuanceRuleApprovalStepRecord = {
  id: "step",
  tenantId: "tenant_123",
  versionId: "version",
  stepNumber: 1,
  targetType: "user",
  targetUserId: "reviewer",
  targetApproverGroupId: null,
  requiredRole: null,
  orgUnitId: null,
  label: null,
  status: "pending",
  decidedByUserId: null,
  decidedAt: null,
  decisionComment: null,
  createdAt: "2026-09-01",
  updatedAt: "2026-09-01",
};

describe("badge workflow responsibility", () => {
  it.each([
    ["immediate", "CredTrail awards automatically"],
    ["manual", "Instructor confirms the award"],
    ["end_of_term", "CredTrail awards at term end"],
  ])("explains %s before activation and without placement", (timing, label) => {
    const json = JSON.stringify({
      conditions: { type: "course_completion", minCompletionPercent: 100, courseId: "course" },
      options: { issuanceTiming: timing, reviewOnMissingFacts: true },
    });
    expect(badgeWorkflowAwarding(json, false)).toMatchObject({
      awarding: label,
      awardingDetail: expect.stringContaining("Once activated"),
    });
    expect(badgeWorkflowAwarding(json, true).awardingDetail).not.toContain("Once activated");
    expect(badgeWorkflowAwarding(json, false).awardingDetail).toContain(
      "Learners are flagged for review if missing information prevents CredTrail from confirming eligibility",
    );
  });
  it("distinguishes automatic approval from an independent reviewer", () => {
    expect(
      describeBadgeWorkflowPolicy(
        {
          ...policy,
          approvalRequirement: "never",
          allowSelfCertification: true,
          approvalSteps: [],
        },
        directory,
        ["author"],
      ),
    ).toMatchObject({
      kind: "automatic",
      detail: expect.stringContaining("administrator must then activate"),
    });
    expect(describeBadgeWorkflowPolicy(policy, directory, ["author"])).toMatchObject({
      kind: "review",
      label: "reviewer@example.edu",
    });
    expect(describeBadgeWorkflowPolicy(policy, directory, ["reviewer"])).toMatchObject({
      kind: "blocked",
    });
  });
  it("uses submitted steps instead of a subsequently changed policy and excludes self-review", () => {
    const version = buildBadgeRuleVersionRecord({
      status: "pending_approval",
      createdByUserId: "author",
      submittedByUserId: "author",
    });
    const input = {
      version,
      directory,
      steps: [step],
      policy: {
        ...policy,
        approvalRequirement: "never" as const,
        allowSelfCertification: true,
        approvalSteps: [],
      },
    };
    expect(describeBadgeWorkflowApproval({ ...input, actorUserId: "reviewer" })).toMatchObject({
      kind: "review",
      canReview: true,
      label: "Waiting for reviewer@example.edu",
    });
    expect(describeBadgeWorkflowApproval({ ...input, actorUserId: "author" }).canReview).toBe(
      false,
    );
    expect(
      describeBadgeWorkflowApproval({
        ...input,
        directory: { ...directory, members: [member("author", "admin")] },
        actorUserId: "author",
      }).kind,
    ).toBe("blocked");
  });
  it("does not call automatic approval a human review or guess an unknown creator", () => {
    const version = buildBadgeRuleVersionRecord({
      status: "approved",
      approvedAt: "2026-09-02",
      approvedByUserId: "author",
      createdByUserId: null,
    });
    const summary = buildBadgeWorkflowResponsibility({
      version,
      directory,
      policy,
      steps: [],
      current: false,
      actorUserId: "reviewer",
    });
    expect(summary.ruleAuthor).toBe("Creator not recorded");
    expect(summary.approval.label).toBe("Automatically approved under institution policy");
    expect(summary.approval.label).not.toContain("author");
  });
  it("keeps active and draft awarding modes separate", () => {
    const active = buildBadgeRuleVersionRecord({ status: "active" });
    const draft = buildBadgeRuleVersionRecord({
      versionNumber: 2,
      ruleJson: JSON.stringify({
        conditions: { type: "course_completion", minCompletionPercent: 100, courseId: "course" },
        options: { issuanceTiming: "manual" },
      }),
    });
    const input = { directory, policy, steps: [], actorUserId: "author" };
    expect(
      buildBadgeWorkflowResponsibility({ ...input, version: active, current: true }).awarding,
    ).toBe("CredTrail awards automatically");
    expect(
      buildBadgeWorkflowResponsibility({ ...input, version: draft, current: false }).awarding,
    ).toBe("Instructor confirms the award");
  });
});

it("names a multi-step group approval and rejects a group nonmember", () => {
  const groupDirectory: BadgeWorkflowDirectory = {
    ...directory,
    groups: [
      {
        id: "registrar",
        tenantId: "tenant_123",
        orgUnitId: null,
        name: "Registrar office",
        createdByUserId: null,
        createdAt: "2026-09-01",
        updatedAt: "2026-09-01",
        members: [
          {
            tenantId: "tenant_123",
            groupId: "registrar",
            userId: "reviewer",
            email: "reviewer@example.edu",
            role: "approver",
            createdByUserId: null,
            createdAt: "2026-09-01",
          },
        ],
      },
    ],
  };
  const groupStep: BadgeIssuanceRuleApprovalStepRecord = {
    ...step,
    targetType: "approver_group",
    targetUserId: null,
    targetApproverGroupId: "registrar",
    requiredRole: "approver",
  };
  const approval = describeBadgeWorkflowPolicy(
    { ...policy, approvalSteps: [...policy.approvalSteps, groupStep] },
    groupDirectory,
    ["author"],
  );
  expect(approval).toMatchObject({
    kind: "review",
    label: "reviewer@example.edu → Registrar office",
  });
  const version = buildBadgeRuleVersionRecord({
    status: "pending_approval",
    createdByUserId: "author",
    submittedByUserId: "author",
  });
  expect(
    describeBadgeWorkflowApproval({
      version,
      policy,
      directory: groupDirectory,
      steps: [groupStep],
      actorUserId: "outsider",
    }).canReview,
  ).toBe(false);
  expect(
    describeBadgeWorkflowApproval({
      version,
      policy,
      directory: groupDirectory,
      steps: [groupStep],
      actorUserId: "reviewer",
    }).canReview,
  ).toBe(true);
});

it.each(["expired", "deprecated", "suspended"] as const)(
  "does not promise activation of a %s version",
  (status) => {
    const summary = buildBadgeWorkflowResponsibility({
      version: buildBadgeRuleVersionRecord({ status }),
      directory,
      policy,
      steps: [],
      current: false,
      actorUserId: "author",
    });
    expect(summary.awardingDetail).not.toContain("Once activated");
    expect(summary.awardingDetail).toContain(
      status === "suspended" ? "paused" : "no longer awards",
    );
  },
);

it("keeps requested changes and reviewer feedback distinct from ordinary draft policy", () => {
  const input = {
    version: buildBadgeRuleVersionRecord({ status: "draft" }),
    policy,
    directory,
    actorUserId: "author",
    steps: [
      {
        ...step,
        status: "changes_requested" as const,
        decidedByUserId: "reviewer",
        decisionComment: "Require a final assessment.",
      },
    ],
  };
  expect(describeBadgeWorkflowApproval(input)).toMatchObject({
    kind: "changes_requested",
    label: "Changes requested",
    detail: "reviewer@example.edu: Require a final assessment.",
    submissionNotice: "Review the feedback, revise this rule, and resubmit it for approval.",
    canReview: false,
  });
  expect(
    describeBadgeWorkflowApproval({
      ...input,
      steps: [{ ...step, status: "changes_requested", decisionComment: null }],
    }).detail,
  ).toContain("Ask them what needs to change");
});
