import { expect, it } from "vitest";

import * as dbModule from "./index";
import { createFixtureRule } from "./badge-issuance-rule-test-fixtures";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
} from "./postgres-test-support";
import type { BadgeRuleIntegrationFixture } from "./postgres-test-support";
import type { CreateBadgeIssuanceRuleResult } from "./badge-issuance-rule-types";

const activateRuleVersionForRecertification = async (
  fixture: BadgeRuleIntegrationFixture,
  created: CreateBadgeIssuanceRuleResult,
  recertificationDueAt: string,
): Promise<void> => {
  const activatedAt = "2026-06-01T00:00:00.000Z";

  await fixture.db
    .prepare(
      `
      UPDATE badge_issuance_rule_versions
      SET
        status = 'active',
        activated_by_user_id = ?,
        activated_at = ?,
        recertification_due_at = ?,
        recertification_reminder_sent_at = NULL
      WHERE tenant_id = ?
        AND rule_id = ?
        AND id = ?
    `,
    )
    .bind(
      fixture.userId,
      activatedAt,
      recertificationDueAt,
      fixture.tenantId,
      created.rule.id,
      created.version.id,
    )
    .run();

  await fixture.db
    .prepare(
      `
      UPDATE badge_issuance_rules
      SET active_version_id = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(created.version.id, fixture.tenantId, created.rule.id)
    .run();
};

describeDbIntegration("badge rule lifecycle governance with Postgres", () => {
  it("lists recertification reminders only for versions due after now and inside the reminder window", async () => {
    const fixture = await createBadgeRuleIntegrationFixture();

    try {
      const overdueRule = await createFixtureRule(fixture);
      const dueSoonRule = await createFixtureRule(fixture);
      const outsideWindowRule = await createFixtureRule(fixture);

      await activateRuleVersionForRecertification(fixture, overdueRule, "2026-06-14T00:00:00.000Z");
      await activateRuleVersionForRecertification(fixture, dueSoonRule, "2026-06-20T00:00:00.000Z");
      await activateRuleVersionForRecertification(
        fixture,
        outsideWindowRule,
        "2026-06-30T00:00:00.000Z",
      );

      const dueForReminder =
        await dbModule.listBadgeIssuanceRuleVersionsDueForRecertificationReminder(fixture.db, {
          tenantId: fixture.tenantId,
          nowIso: "2026-06-15T00:00:00.000Z",
          reminderWindowDays: 7,
        });

      expect(dueForReminder.map((version) => version.id)).toEqual([dueSoonRule.version.id]);
    } finally {
      await cleanupTestResources(fixture.db, {
        tenantIds: [fixture.tenantId],
        userIds: [fixture.userId],
      });
    }
  });
});
