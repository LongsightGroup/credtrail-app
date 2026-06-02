import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  ASSERTION_ENGAGEMENT_EVENT_TYPES,
  resolveAssertionReportingAttribution,
  summarizeTenantReportingComparisonRows,
  summarizeTenantReportingOverviewRows,
  summarizeTenantReportingTrendRows,
} from "./index";
import { REPORTING_METRIC_DEFINITIONS } from "../../../apps/api-worker/src/reporting/metric-definitions";

describe("reporting foundation", () => {
  it("adds a reporting attribution migration with tenant and org indexes", () => {
    const sql = readFileSync(
      new URL("../migrations/0033_reporting_foundation.sql", import.meta.url),
      "utf8",
    );

    expect(sql).toContain("CREATE TABLE IF NOT EXISTS assertion_reporting_attributions");
    expect(sql).toContain("attribution_source");
    expect(sql).toContain("historical_backfill");
    expect(sql).toContain("idx_assertion_reporting_attributions_tenant_org");
    expect(sql).toContain("idx_assertion_reporting_attributions_tenant_template");
  });

  it("keeps historical reporting attribution stable when template ownership changes later", () => {
    const attribution = resolveAssertionReportingAttribution({
      issuedAt: "2026-03-05T15:00:00.000Z",
      currentOwnerOrgUnitId: "org_program",
      ownershipEvents: [
        {
          toOrgUnitId: "org_department",
          transferredAt: "2026-03-01T12:00:00.000Z",
        },
        {
          toOrgUnitId: "org_program",
          transferredAt: "2026-03-10T12:00:00.000Z",
        },
      ],
    });

    expect(attribution).toEqual({
      orgUnitId: "org_department",
      attributionSource: "historical_backfill",
      attributedAt: "2026-03-05T15:00:00.000Z",
    });
  });

  it("summarizes product-backed overview counts and marks engagement rate metrics as Phase 10-backed", () => {
    const rows = [
      {
        assertionId: "assertion_active",
        issuedAt: "2026-03-01T00:00:00.000Z",
        badgeTemplateId: "bt_1",
        orgUnitId: "org_1",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
      },
      {
        assertionId: "assertion_suspended_review",
        issuedAt: "2026-03-02T00:00:00.000Z",
        badgeTemplateId: "bt_1",
        orgUnitId: "org_1",
        revokedAt: null,
        latestToState: "suspended" as const,
        latestReasonCode: "appeal_pending" as const,
      },
      {
        assertionId: "assertion_revoked",
        issuedAt: "2026-03-03T00:00:00.000Z",
        badgeTemplateId: "bt_2",
        orgUnitId: "org_2",
        revokedAt: "2026-03-04T00:00:00.000Z",
        latestToState: "revoked" as const,
        latestReasonCode: "issuer_requested" as const,
      },
    ];

    expect(summarizeTenantReportingOverviewRows(rows)).toEqual({
      issued: 3,
      active: 1,
      suspended: 1,
      revoked: 1,
      pendingReview: 1,
    });

    expect(summarizeTenantReportingOverviewRows(rows, "pending_review")).toEqual({
      issued: 1,
      active: 0,
      suspended: 1,
      revoked: 0,
      pendingReview: 1,
    });

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

describe("engagement reporting foundation", () => {
  it("adds an engagement event migration with a narrow product-owned taxonomy", () => {
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
    expect(sql).toContain("CHECK (event_type IN");
    expect(sql).toContain("'public_badge_view'");
    expect(sql).toContain("'verification_view'");
    expect(sql).toContain("'share_click'");
    expect(sql).toContain("'learner_claim'");
    expect(sql).toContain("'wallet_accept'");
    expect(sql).toContain(
      "FOREIGN KEY (assertion_id) REFERENCES assertions (id) ON DELETE CASCADE",
    );
    expect(sql).toContain("idx_assertion_engagement_events_tenant_occurred_at");
    expect(sql).toContain("idx_assertion_engagement_events_assertion_type");
  });

  it("buckets issued assertions and engagement event counts over time for selected filters", () => {
    const rows = [
      {
        assertionId: "assertion_1",
        badgeTemplateId: "bt_blue",
        orgUnitId: "org_program",
        issuedAt: "2026-03-01T08:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: null,
        occurredAt: null,
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_blue",
        orgUnitId: "org_program",
        issuedAt: "2026-03-01T10:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "public_badge_view" as const,
        occurredAt: "2026-03-02T09:00:00.000Z",
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_blue",
        orgUnitId: "org_program",
        issuedAt: "2026-03-01T10:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "verification_view" as const,
        occurredAt: "2026-03-02T10:00:00.000Z",
      },
      {
        assertionId: "assertion_3",
        badgeTemplateId: "bt_blue",
        orgUnitId: "org_program",
        issuedAt: "2026-03-02T11:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "share_click" as const,
        occurredAt: "2026-03-03T12:00:00.000Z",
      },
      {
        assertionId: "assertion_4",
        badgeTemplateId: "bt_other",
        orgUnitId: "org_program",
        issuedAt: "2026-03-02T12:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "public_badge_view" as const,
        occurredAt: "2026-03-02T13:00:00.000Z",
      },
    ];

    expect(
      summarizeTenantReportingTrendRows(rows, {
        from: "2026-03-01",
        to: "2026-03-03",
        bucket: "day",
        badgeTemplateId: "bt_blue",
      }),
    ).toEqual([
      {
        bucketStart: "2026-03-01",
        issuedCount: 2,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 0,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
      },
      {
        bucketStart: "2026-03-02",
        issuedCount: 1,
        publicBadgeViewCount: 1,
        verificationViewCount: 1,
        shareClickCount: 0,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
      },
      {
        bucketStart: "2026-03-03",
        issuedCount: 0,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 1,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
      },
    ]);
  });

  it("computes comparison rates from distinct engaged assertions instead of raw event totals", () => {
    const rows = [
      {
        assertionId: "assertion_1",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_science",
        issuedAt: "2026-03-01T08:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: null,
        occurredAt: null,
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_science",
        issuedAt: "2026-03-01T09:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "share_click" as const,
        occurredAt: "2026-03-02T08:00:00.000Z",
      },
      {
        assertionId: "assertion_2",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_science",
        issuedAt: "2026-03-01T09:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "share_click" as const,
        occurredAt: "2026-03-02T09:00:00.000Z",
      },
      {
        assertionId: "assertion_3",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_science",
        issuedAt: "2026-03-01T10:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "learner_claim" as const,
        occurredAt: "2026-03-03T08:00:00.000Z",
      },
      {
        assertionId: "assertion_3",
        badgeTemplateId: "bt_science",
        orgUnitId: "org_science",
        issuedAt: "2026-03-01T10:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "wallet_accept" as const,
        occurredAt: "2026-03-03T09:00:00.000Z",
      },
      {
        assertionId: "assertion_4",
        badgeTemplateId: "bt_arts",
        orgUnitId: "org_arts",
        issuedAt: "2026-03-02T10:00:00.000Z",
        revokedAt: null,
        latestToState: null,
        latestReasonCode: null,
        eventType: "share_click" as const,
        occurredAt: "2026-03-04T08:00:00.000Z",
      },
    ];

    expect(
      summarizeTenantReportingComparisonRows(rows, {
        groupBy: "badgeTemplate",
      }),
    ).toEqual([
      {
        groupBy: "badgeTemplate",
        groupId: "bt_science",
        issuedCount: 3,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 2,
        learnerClaimCount: 1,
        walletAcceptCount: 1,
        shareRate: 1 / 3,
        claimRate: 1 / 3,
      },
      {
        groupBy: "badgeTemplate",
        groupId: "bt_arts",
        issuedCount: 1,
        publicBadgeViewCount: 0,
        verificationViewCount: 0,
        shareClickCount: 1,
        learnerClaimCount: 0,
        walletAcceptCount: 0,
        shareRate: 1,
        claimRate: 0,
      },
    ]);
  });
});
