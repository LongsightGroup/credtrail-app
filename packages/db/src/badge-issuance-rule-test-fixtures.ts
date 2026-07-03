import * as dbModule from "./index";
import type { BadgeRuleIntegrationFixture } from "./postgres-test-support";

export const createFixtureRule = async (
  fixture: BadgeRuleIntegrationFixture,
): Promise<dbModule.CreateBadgeIssuanceRuleResult> => {
  return dbModule.createBadgeIssuanceRule(fixture.db, {
    tenantId: fixture.tenantId,
    name: "CS101 Rule",
    description: "Award for CS101 completion.",
    badgeTemplateId: fixture.badgeTemplateId,
    lmsProviderKind: "canvas",
    lmsConnectionId: fixture.lmsConnectionId,
    ruleJson: '{"conditions":{"type":"grade_threshold","courseId":"course_101","minScore":80}}',
    changeSummary: "Initial draft",
    createdByUserId: fixture.userId,
  });
};

export const createFixtureTenantMember = async (
  fixture: BadgeRuleIntegrationFixture,
  input: {
    readonly role: dbModule.TenantMembershipRole;
  },
): Promise<string> => {
  const suffix = crypto.randomUUID().replace(/-/g, "");
  const userId = `usr_badge_rule_reviewer_${suffix}`;

  await fixture.db
    .prepare(
      `
      INSERT INTO users (id, email)
      VALUES (?, ?)
    `,
    )
    .bind(userId, `badge-rule-reviewer-${suffix}@example.edu`)
    .run();

  await fixture.db
    .prepare(
      `
      INSERT INTO memberships (tenant_id, user_id, role)
      VALUES (?, ?, ?)
    `,
    )
    .bind(fixture.tenantId, userId, input.role)
    .run();

  return userId;
};
