import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { REPORTING_METRIC_DEFINITIONS } from "../../../apps/api-worker/src/reporting/metric-definitions";
import {
  ASSERTION_ENGAGEMENT_EVENT_TYPES,
  getTenantReportingEngagementCounts,
  getTenantReportingOverview,
  getTenantReportingTrends,
  findAssertionReportingAttributionByAssertionId,
  listTenantReportingComparisons,
  recordAssertionEngagementEvent,
  transferBadgeTemplateOwnership,
  upsertAssertionReportingAttribution,
} from "./index";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  seedAssertion,
  seedAssertionAttribution,
  seedBadgeTemplate,
  seedLifecycleEvent,
  seedTenantOrgUnit,
} from "./postgres-test-support";

describe("reporting foundation", () => {
  it("adds reporting attribution storage and a one-time historical repair", () => {
    const foundationSql = readFileSync(
      new URL("../migrations/0033_reporting_foundation.sql", import.meta.url),
      "utf8",
    );
    const backfillSql = readFileSync(
      new URL("../migrations/0077_backfill_assertion_reporting_attributions.sql", import.meta.url),
      "utf8",
    );

    expect(foundationSql).toContain("CREATE TABLE IF NOT EXISTS assertion_reporting_attributions");
    expect(foundationSql).toContain("idx_assertion_reporting_attributions_tenant_org");
    expect(foundationSql).toContain("idx_assertion_reporting_attributions_tenant_template");
    expect(backfillSql).toContain("INSERT INTO assertion_reporting_attributions");
    expect(backfillSql).toContain("LEFT JOIN LATERAL");
    expect(backfillSql).toContain(
      "ownership_events.transferred_at::timestamptz <= assertions.issued_at::timestamptz",
    );
    expect(backfillSql).toContain("historical_backfill");
    expect(backfillSql).toContain("current_owner_fallback");
    expect(backfillSql).toContain("ON CONFLICT (assertion_id) DO NOTHING");
  });

  it("keeps the engagement taxonomy and product-backed rate definitions explicit", () => {
    const sql = readFileSync(
      new URL("../migrations/0034_reporting_engagement_events.sql", import.meta.url),
      "utf8",
    );

    expect(ASSERTION_ENGAGEMENT_EVENT_TYPES).toEqual([
      "public_badge_view",
      "verification_view",
      "share_click",
      "learner_claim",
      "wallet_accept",
    ]);
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS assertion_engagement_events");
    expect(sql).toContain("idx_assertion_engagement_events_tenant_occurred_at");
    expect(REPORTING_METRIC_DEFINITIONS).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          key: "claimRate",
          available: true,
          source: "assertion_engagement_events + assertions",
        }),
        expect.objectContaining({
          key: "shareRate",
          available: true,
          source: "assertion_engagement_events + assertions",
        }),
      ]),
    );
  });
});

describeDbIntegration("reporting aggregates with Postgres", () => {
  it("does not read or overwrite attribution across tenant boundaries", async () => {
    const ownerFixture = await createTestTenantFixture({
      displayName: "Attribution Owner Tenant",
    });
    const otherFixture = await createTestTenantFixture({
      displayName: "Attribution Other Tenant",
    });
    const ownerBadgeTemplateId = await seedBadgeTemplate(ownerFixture.db, {
      tenantId: ownerFixture.tenantId,
      title: "Owner badge",
    });
    const otherBadgeTemplateId = await seedBadgeTemplate(otherFixture.db, {
      tenantId: otherFixture.tenantId,
      title: "Other badge",
    });
    const assertionId = await seedAssertion(ownerFixture.db, {
      tenantId: ownerFixture.tenantId,
      badgeTemplateId: ownerBadgeTemplateId,
      recipientIdentity: "scoped-attribution@example.edu",
      issuedAt: "2026-03-03T00:00:00.000Z",
    });

    try {
      await seedAssertionAttribution(ownerFixture.db, {
        assertionId,
        tenantId: ownerFixture.tenantId,
        badgeTemplateId: ownerBadgeTemplateId,
        orgUnitId: `${ownerFixture.tenantId}:org:institution`,
        attributionSource: "issuance_snapshot",
        attributedAt: "2026-03-03T00:00:00.000Z",
      });

      await expect(
        findAssertionReportingAttributionByAssertionId(
          otherFixture.db,
          otherFixture.tenantId,
          assertionId,
        ),
      ).resolves.toBeNull();
      await expect(
        upsertAssertionReportingAttribution(otherFixture.db, {
          assertionId,
          tenantId: otherFixture.tenantId,
          badgeTemplateId: otherBadgeTemplateId,
          orgUnitId: `${otherFixture.tenantId}:org:institution`,
          attributionSource: "current_owner_fallback",
          attributedAt: "2026-03-04T00:00:00.000Z",
        }),
      ).rejects.toThrow("Unable to load reporting attribution");

      await expect(
        findAssertionReportingAttributionByAssertionId(
          ownerFixture.db,
          ownerFixture.tenantId,
          assertionId,
        ),
      ).resolves.toMatchObject({
        tenantId: ownerFixture.tenantId,
        badgeTemplateId: ownerBadgeTemplateId,
        attributionSource: "issuance_snapshot",
        attributedAt: "2026-03-03T00:00:00.000Z",
      });
    } finally {
      await cleanupTestResources(ownerFixture.db, {
        tenantIds: [ownerFixture.tenantId, otherFixture.tenantId],
      });
    }
  });

  it("repairs missing attribution from ownership history without a reporting read", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Reporting Repair Tenant" });
    const badgeTemplateId = await seedBadgeTemplate(fixture.db, {
      tenantId: fixture.tenantId,
      title: "Historical ownership badge",
    });
    const institutionOrgUnitId = `${fixture.tenantId}:org:institution`;
    const collegeOrgUnitId = `${fixture.tenantId}:org:college`;

    try {
      await seedTenantOrgUnit(fixture.db, {
        tenantId: fixture.tenantId,
        id: collegeOrgUnitId,
        unitType: "college",
        slug: "college",
        displayName: "Test College",
        parentOrgUnitId: institutionOrgUnitId,
      });
      await transferBadgeTemplateOwnership(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        toOrgUnitId: collegeOrgUnitId,
        reasonCode: "administrative_transfer",
        transferredAt: "2026-03-02T00:00:00.000Z",
      });
      const assertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        recipientIdentity: "historical@example.edu",
        issuedAt: "2026-03-03T00:00:00.000Z",
      });
      await transferBadgeTemplateOwnership(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId,
        toOrgUnitId: institutionOrgUnitId,
        reasonCode: "administrative_transfer",
        transferredAt: "2026-03-04T00:00:00.000Z",
      });

      expect(
        await findAssertionReportingAttributionByAssertionId(
          fixture.db,
          fixture.tenantId,
          assertionId,
        ),
      ).toBeNull();

      const backfillSql = readFileSync(
        new URL(
          "../migrations/0077_backfill_assertion_reporting_attributions.sql",
          import.meta.url,
        ),
        "utf8",
      );
      await fixture.db.prepare(backfillSql).run();

      expect(
        await findAssertionReportingAttributionByAssertionId(
          fixture.db,
          fixture.tenantId,
          assertionId,
        ),
      ).toMatchObject({
        assertionId,
        tenantId: fixture.tenantId,
        badgeTemplateId,
        orgUnitId: collegeOrgUnitId,
        attributionSource: "historical_backfill",
        attributedAt: "2026-03-03T00:00:00.000Z",
      });
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });

  it("keeps backfilled reporting filters isolated to the requested tenant", async () => {
    const tenantA = await createTestTenantFixture({ displayName: "Reporting Tenant A" });
    const tenantB = await createTestTenantFixture({ displayName: "Reporting Tenant B" });
    const tenantATemplateId = await seedBadgeTemplate(tenantA.db, {
      tenantId: tenantA.tenantId,
      title: "Tenant A badge",
    });
    const tenantBTemplateId = await seedBadgeTemplate(tenantB.db, {
      tenantId: tenantB.tenantId,
      title: "Tenant B badge",
    });
    const tenantAOrgUnitId = `${tenantA.tenantId}:org:institution`;
    const tenantBOrgUnitId = `${tenantB.tenantId}:org:institution`;

    try {
      await seedAssertion(tenantA.db, {
        tenantId: tenantA.tenantId,
        badgeTemplateId: tenantATemplateId,
        recipientIdentity: "tenant-a@example.edu",
        issuedAt: "2026-03-03T00:00:00.000Z",
      });
      await seedAssertion(tenantB.db, {
        tenantId: tenantB.tenantId,
        badgeTemplateId: tenantBTemplateId,
        recipientIdentity: "tenant-b@example.edu",
        issuedAt: "2026-03-03T00:00:00.000Z",
      });

      const backfillSql = readFileSync(
        new URL(
          "../migrations/0077_backfill_assertion_reporting_attributions.sql",
          import.meta.url,
        ),
        "utf8",
      );
      await tenantA.db.prepare(backfillSql).run();

      const [tenantAReport, tenantAWithTenantBFilters, tenantBReport] = await Promise.all([
        getTenantReportingOverview(tenantA.db, {
          tenantId: tenantA.tenantId,
          badgeTemplateId: tenantATemplateId,
          orgUnitId: tenantAOrgUnitId,
        }),
        getTenantReportingOverview(tenantA.db, {
          tenantId: tenantA.tenantId,
          badgeTemplateId: tenantBTemplateId,
          orgUnitId: tenantBOrgUnitId,
        }),
        getTenantReportingOverview(tenantB.db, {
          tenantId: tenantB.tenantId,
          badgeTemplateId: tenantBTemplateId,
          orgUnitId: tenantBOrgUnitId,
        }),
      ]);

      expect(tenantAReport.counts.issued).toBe(1);
      expect(tenantAWithTenantBFilters.counts.issued).toBe(0);
      expect(tenantBReport.counts.issued).toBe(1);
    } finally {
      await cleanupTestResources(tenantA.db, {
        tenantIds: [tenantA.tenantId, tenantB.tenantId],
      });
    }
  });

  it("returns lifecycle, engagement, trend, and comparison aggregates without raw event rows", async () => {
    const fixture = await createTestTenantFixture({ displayName: "Reporting Aggregate Tenant" });
    const primaryTemplateId = await seedBadgeTemplate(fixture.db, {
      tenantId: fixture.tenantId,
      title: "Primary badge",
    });
    const secondaryTemplateId = await seedBadgeTemplate(fixture.db, {
      tenantId: fixture.tenantId,
      title: "Secondary badge",
    });
    const orgUnitId = `${fixture.tenantId}:org:institution`;

    try {
      const firstAssertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId: primaryTemplateId,
        recipientIdentity: "first@example.edu",
        issuedAt: "2026-03-01T00:30:00.000Z",
      });
      const secondAssertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId: primaryTemplateId,
        recipientIdentity: "second@example.edu",
        issuedAt: "2026-03-01T09:00:00.000Z",
      });
      const pendingAssertionId = await seedAssertion(fixture.db, {
        tenantId: fixture.tenantId,
        badgeTemplateId: secondaryTemplateId,
        recipientIdentity: "pending@example.edu",
        issuedAt: "2026-03-02T10:00:00.000Z",
      });

      await Promise.all(
        [
          {
            assertionId: firstAssertionId,
            badgeTemplateId: primaryTemplateId,
            attributedAt: "2026-03-01T00:30:00.000Z",
          },
          {
            assertionId: secondAssertionId,
            badgeTemplateId: primaryTemplateId,
            attributedAt: "2026-03-01T09:00:00.000Z",
          },
          {
            assertionId: pendingAssertionId,
            badgeTemplateId: secondaryTemplateId,
            attributedAt: "2026-03-02T10:00:00.000Z",
          },
        ].map(({ assertionId, badgeTemplateId, attributedAt }) =>
          seedAssertionAttribution(fixture.db, {
            assertionId,
            tenantId: fixture.tenantId,
            badgeTemplateId,
            orgUnitId,
            attributionSource: "issuance_snapshot",
            attributedAt,
          }),
        ),
      );
      await seedLifecycleEvent(fixture.db, {
        tenantId: fixture.tenantId,
        assertionId: pendingAssertionId,
        fromState: "active",
        toState: "suspended",
        reasonCode: "appeal_pending",
        reason: "Manual review requested",
        transitionedAt: "2026-03-02T12:00:00.000Z",
      });

      for (const event of [
        {
          assertionId: secondAssertionId,
          eventType: "public_badge_view" as const,
          occurredAt: "2026-03-02T13:00:00.000Z",
        },
        {
          assertionId: secondAssertionId,
          eventType: "verification_view" as const,
          occurredAt: "2026-03-02T14:00:00.000Z",
        },
        {
          assertionId: secondAssertionId,
          eventType: "share_click" as const,
          occurredAt: "2026-03-03T08:00:00.000Z",
        },
        {
          assertionId: secondAssertionId,
          eventType: "share_click" as const,
          occurredAt: "2026-03-03T09:00:00.000Z",
        },
        {
          assertionId: secondAssertionId,
          eventType: "learner_claim" as const,
          occurredAt: "2026-03-03T10:00:00.000Z",
        },
        {
          assertionId: secondAssertionId,
          eventType: "wallet_accept" as const,
          occurredAt: "2026-03-03T11:00:00.000Z",
        },
      ]) {
        await recordAssertionEngagementEvent(fixture.db, {
          tenantId: fixture.tenantId,
          assertionId: event.assertionId,
          eventType: event.eventType,
          actorType: "learner",
          occurredAt: event.occurredAt,
        });
      }

      const range = { from: "2026-03-01", to: "2026-03-03" } as const;
      const [overview, engagement, trends, comparisons, pendingOverview] = await Promise.all([
        getTenantReportingOverview(fixture.db, {
          tenantId: fixture.tenantId,
          issuedFrom: range.from,
          issuedTo: range.to,
        }),
        getTenantReportingEngagementCounts(fixture.db, {
          tenantId: fixture.tenantId,
          ...range,
        }),
        getTenantReportingTrends(fixture.db, {
          tenantId: fixture.tenantId,
          ...range,
          bucket: "day",
        }),
        listTenantReportingComparisons(fixture.db, {
          tenantId: fixture.tenantId,
          ...range,
          groupBy: "badgeTemplate",
        }),
        getTenantReportingOverview(fixture.db, {
          tenantId: fixture.tenantId,
          issuedFrom: range.from,
          issuedTo: range.to,
          state: "pending_review",
        }),
      ]);

      expect(overview.counts).toEqual({
        issued: 3,
        active: 2,
        suspended: 1,
        revoked: 0,
        pendingReview: 1,
        claimRate: 1 / 3,
        shareRate: 1 / 3,
      });
      expect(engagement).toEqual({
        issuedCount: 3,
        publicBadgeViewCount: 1,
        verificationViewCount: 1,
        shareClickCount: 2,
        learnerClaimCount: 1,
        walletAcceptCount: 1,
        claimRate: 1 / 3,
        shareRate: 1 / 3,
      });
      expect(trends.series).toEqual([
        expect.objectContaining({ bucketStart: "2026-03-01", issuedCount: 2 }),
        expect.objectContaining({
          bucketStart: "2026-03-02",
          issuedCount: 1,
          publicBadgeViewCount: 1,
          verificationViewCount: 1,
        }),
        expect.objectContaining({
          bucketStart: "2026-03-03",
          issuedCount: 0,
          shareClickCount: 2,
          learnerClaimCount: 1,
          walletAcceptCount: 1,
        }),
      ]);
      expect(comparisons).toEqual([
        expect.objectContaining({
          groupId: primaryTemplateId,
          issuedCount: 2,
          shareClickCount: 2,
          claimRate: 1 / 2,
          shareRate: 1 / 2,
        }),
        expect.objectContaining({
          groupId: secondaryTemplateId,
          issuedCount: 1,
          claimRate: 0,
          shareRate: 0,
        }),
      ]);
      expect(pendingOverview.counts).toMatchObject({
        issued: 1,
        active: 0,
        suspended: 1,
        pendingReview: 1,
      });

      const nonUtcSessionTrends = await fixture.db.transaction?.(async (transaction) => {
        await transaction.prepare("SET LOCAL TIME ZONE 'America/Los_Angeles'").run();
        return getTenantReportingTrends(transaction, {
          tenantId: fixture.tenantId,
          ...range,
          bucket: "day",
        });
      });

      expect(nonUtcSessionTrends?.series).toEqual(trends.series);
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });
});
