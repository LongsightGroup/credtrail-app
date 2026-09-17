import { expect, it } from "vitest";
import { listTenantAssertions } from "./assertion-tenant-queries";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedAssertion,
  seedBadgeTemplate,
} from "./postgres-test-support";

describeDbIntegration("badge record cursor pagination", () => {
  it("pages through timestamp ties without overlap and keeps the recipient filter", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Pagination" });
    try {
      const badgeTemplateId = await seedBadgeTemplate(fixture.db, { tenantId: fixture.tenantId });
      const base = {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        issuedAt: "2026-02-11T14:00:00.000Z",
      };
      const ids: string[] = [];
      for (let i = 0; i < 5; i++)
        ids.push(
          await seedAssertion(fixture.db, { ...base, recipientIdentity: "pages@example.edu" }),
        );
      await seedAssertion(fixture.db, { ...base, recipientIdentity: "other@example.edu" });
      const query = {
        tenantId: fixture.tenantId,
        recipientQuery: "pages@example.edu",
        limit: 2,
        includeLookahead: true,
      };
      const first = await listTenantAssertions(fixture.db, query);
      expect(first.map((row) => row.assertionId)).toEqual([...ids].sort().reverse().slice(0, 3));
      const boundary = first[1]!;
      await seedAssertion(fixture.db, {
        ...base,
        recipientIdentity: "pages@example.edu",
        issuedAt: "2026-02-12T14:00:00.000Z",
      });
      const older = await listTenantAssertions(fixture.db, {
        ...query,
        cursor: {
          issuedAt: boundary.issuedAt,
          assertionId: boundary.assertionId,
          direction: "older",
        },
      });
      expect(older.map((row) => row.assertionId)).toEqual([...ids].sort().reverse().slice(2));
      const newer = await listTenantAssertions(fixture.db, {
        ...query,
        cursor: {
          issuedAt: older[0]!.issuedAt,
          assertionId: older[0]!.assertionId,
          direction: "newer",
        },
      });
      expect(
        newer
          .slice(0, 2)
          .reverse()
          .map((row) => row.assertionId),
      ).toEqual(first.slice(0, 2).map((row) => row.assertionId));
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });
});
