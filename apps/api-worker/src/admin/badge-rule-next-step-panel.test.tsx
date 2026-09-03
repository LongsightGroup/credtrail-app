import type { BadgeIssuanceRuleRecord } from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import { describe, expect, it } from "vitest";
import { buildBadgeRuleVersionRecord } from "../test-support/badge-rule-version";
import { BadgeRuleNextStepPanel } from "./badge-rule-next-step-panel";

const rule = (activeVersionId: string | null): BadgeIssuanceRuleRecord => ({
  id: "brl_next_step",
  tenantId: "tenant_123",
  name: "Course completion rule",
  description: null,
  badgeTemplateId: "badge_template_001",
  orgUnitId: "tenant_123:org:institution",
  ownerOrgUnitId: "tenant_123:org:institution",
  lmsProviderKind: "canvas",
  lmsConnectionId: "lms_123",
  activeVersionId,
  createdByUserId: "usr_admin",
  createdAt: "2026-09-01T12:00:00.000Z",
  updatedAt: "2026-09-02T12:00:00.000Z",
});

const definition = (issuanceTiming: "immediate" | "end_of_term"): BadgeIssuanceRuleDefinition => ({
  conditions: {
    type: "course_completion",
    courseId: "course_101",
    minCompletionPercent: 100,
  },
  options: { issuanceTiming },
});

describe("BadgeRuleNextStepPanel", () => {
  it("renders a draft's primary submission action and secondary edit path", async () => {
    const version = buildBadgeRuleVersionRecord({
      id: "brv_draft",
      ruleId: "brl_next_step",
      status: "draft",
      snapshot: { name: "Course completion rule" },
    });
    const html = (
      await BadgeRuleNextStepPanel({
        tenantId: "tenant_123",
        userId: "usr_admin",
        rule: rule(null),
        selectedVersion: version,
        latestVersion: version,
        definition: definition("immediate"),
        activePlacementCount: 0,
        canReviewPendingVersion: false,
      })
    ).toString();

    expect(html).toContain("What happens next");
    expect(html).toContain("Submit this draft for approval");
    expect(html).toContain('data-rule-next-step="submit_for_approval"');
    expect(html).toContain(
      'action="/tenants/tenant_123/admin/rules/brl_next_step/versions/brv_draft/submit-approval"',
    );
    expect(html).toContain('href="/tenants/tenant_123/admin/rules/brl_next_step/edit"');
  });

  it("links an active automatic rule to its evaluation status", async () => {
    const version = buildBadgeRuleVersionRecord({
      id: "brv_active",
      ruleId: "brl_next_step",
      status: "active",
    });
    const html = (
      await BadgeRuleNextStepPanel({
        tenantId: "tenant_123",
        userId: "usr_admin",
        rule: rule(version.id),
        selectedVersion: version,
        latestVersion: version,
        definition: definition("immediate"),
        activePlacementCount: 1,
        canReviewPendingVersion: false,
      })
    ).toString();

    expect(html).toContain("CredTrail is checking eligibility automatically");
    expect(html).toContain("Next owner");
    expect(html).toContain(">CredTrail<");
    expect(html).toContain('href="#automatic-evaluation"');
  });

  it("renders a required end-date control for an unscheduled end-of-term rule", async () => {
    const version = buildBadgeRuleVersionRecord({
      id: "brv_end_of_term",
      ruleId: "brl_next_step",
      status: "active",
      expiresAt: null,
    });
    const html = (
      await BadgeRuleNextStepPanel({
        tenantId: "tenant_123",
        userId: "usr_admin",
        rule: rule(version.id),
        selectedVersion: version,
        latestVersion: version,
        definition: definition("end_of_term"),
        activePlacementCount: 1,
        canReviewPendingVersion: false,
      })
    ).toString();

    expect(html).toContain("Set the term end date");
    expect(html).toContain('name="expiresAt"');
    expect(html).toContain('type="datetime-local"');
    expect(html).toContain("required");
    expect(html).toContain("Schedule end-of-term batch");
  });
});
