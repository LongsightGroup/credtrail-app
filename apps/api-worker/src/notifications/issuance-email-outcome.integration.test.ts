import { createAuditLog } from "@credtrail/db";
import { afterEach, expect, it } from "vitest";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createTestPostgresDatabase,
  describeDbIntegration,
} from "../../../../packages/db/src/postgres-test-support";
import { loadIssuanceEmailOutcome, recordIssuanceEmailOutcome } from "./issuance-email-outcome";
const tenantIds: string[] = [];
const userIds: string[] = [];
afterEach(async () => {
  if (!tenantIds.length) return;
  await cleanupTestResources(createTestPostgresDatabase(), { tenantIds, userIds });
  tenantIds.length = 0;
  userIds.length = 0;
});
describeDbIntegration("persisted notification outcomes", () => {
  it("persists the result separately from issuance and scopes it to the tenant", async () => {
    const data = await createBadgeRuleIntegrationFixture();
    tenantIds.push(data.tenantId);
    userIds.push(data.userId);
    const assertionId = crypto.randomUUID();
    expect(await loadIssuanceEmailOutcome(data.db, data.tenantId, assertionId)).toBe("unrecorded");
    await recordIssuanceEmailOutcome({
      db: data.db,
      tenantId: data.tenantId,
      assertionId,
      status: "failed",
    });
    expect(await loadIssuanceEmailOutcome(data.db, data.tenantId, assertionId)).toBe("failed");
    expect(await loadIssuanceEmailOutcome(data.db, "another-tenant", assertionId)).toBe(
      "unrecorded",
    );
    await createAuditLog(data.db, {
      tenantId: data.tenantId,
      action: "assertion.issuance_email",
      targetType: "assertion",
      targetId: "invalid",
      metadata: { status: "delivered" },
    });
    expect(await loadIssuanceEmailOutcome(data.db, data.tenantId, "invalid")).toBe("unrecorded");
  });
});
