import { expect, it } from "vitest";
import {
  createAuditLog,
  createBadgeIssuanceRuleEvaluation,
  listTenantAssertions,
  countTenantAssertionLedgerRows,
  listTenantAssertionLedgerExportRows,
} from "@credtrail/db";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  describeDbIntegration,
  seedAssertion,
  seedAssertionAttribution,
} from "../../../../packages/db/src/postgres-test-support";
import { createFixtureRule } from "../../../../packages/db/src/badge-issuance-rule-test-fixtures";
import { loadBadgeRuleReviewQueueEntries } from "../badge-rule-review-queue-workspace";
import { paginateReviewQueue, parseReviewQueuePageQuery } from "./review-queue-page-query";
import { renderRuleReviewQueuePanel } from "./institution-admin/review-queue-section";

describeDbIntegration("workflow follow-ups", () => {
  it("filters records and CSV by the latest notification outcome, with tenant isolation", async () => {
    const f = await createBadgeRuleIntegrationFixture();
    try {
      const id = await seedAssertion(f.db, {
        tenantId: f.tenantId,
        badgeTemplateId: f.badgeTemplateId,
        recipientIdentity: "attention@example.edu",
        issuedAt: "2026-09-01T00:00:00.000Z",
      });
      await seedAssertionAttribution(f.db, {
        assertionId: id,
        tenantId: f.tenantId,
        badgeTemplateId: f.badgeTemplateId,
        orgUnitId: `${f.tenantId}:org:institution`,
        attributionSource: "issuance_snapshot",
        attributedAt: "2026-09-01T00:00:00.000Z",
      });
      const filter = { tenantId: f.tenantId, notificationStatus: "failed" as const };
      const record = async (status: string, occurredAt: string): Promise<void> => {
        await createAuditLog(f.db, {
          tenantId: f.tenantId,
          action: "assertion.issuance_email",
          targetType: "assertion",
          targetId: id,
          metadata: { status },
          occurredAt,
        });
      };
      expect(await listTenantAssertions(f.db, filter)).toEqual([]);
      await record("failed", "2026-09-02T00:00:00.000Z");
      expect((await listTenantAssertions(f.db, filter)).map((row) => row.assertionId)).toEqual([
        id,
      ]);
      expect(await countTenantAssertionLedgerRows(f.db, filter)).toBe(1);
      const exported = await listTenantAssertionLedgerExportRows(f.db, filter);
      expect(exported).toMatchObject({
        status: "ok",
        rows: [expect.objectContaining({ assertionId: id })],
      });
      expect(await listTenantAssertions(f.db, { ...filter, tenantId: "other" })).toEqual([]);
      await record("pending", "2026-09-03T00:00:00.000Z");
      expect(await listTenantAssertions(f.db, filter)).toEqual([]);
      await record("failed", "2026-09-04T00:00:00.000Z");
      expect(await listTenantAssertions(f.db, filter)).toHaveLength(1);
      await record("accepted", "2026-09-05T00:00:00.000Z");
      expect(await listTenantAssertions(f.db, filter)).toEqual([]);
      expect(await countTenantAssertionLedgerRows(f.db, filter)).toBe(0);
      expect(await listTenantAssertionLedgerExportRows(f.db, filter)).toMatchObject({
        status: "ok",
        rows: [],
      });
    } finally {
      await cleanupTestResources(f.db, { tenantIds: [f.tenantId], userIds: [f.userId] });
    }
  });
  it("searches immutable badge names and pages review history in both directions without duplicates", async () => {
    const f = await createBadgeRuleIntegrationFixture();
    try {
      const rule = await createFixtureRule(f);
      const assertionId = await seedAssertion(f.db, {
        tenantId: f.tenantId,
        badgeTemplateId: f.badgeTemplateId,
        recipientIdentity: "history@example.edu",
        issuedAt: "2026-09-01T00:00:00.000Z",
      });
      for (let i = 0; i < 55; i++)
        await createBadgeIssuanceRuleEvaluation(f.db, {
          tenantId: f.tenantId,
          ruleId: rule.rule.id,
          versionId: rule.version.id,
          learnerId: `learner-${i}`,
          recipientIdentity: `history-${i}%@example.edu`,
          recipientIdentityType: "email",
          matched: false,
          issuanceStatus: "issued",
          reviewStatus: "resolved",
          reviewDecision: "issue",
          assertionId,
          reviewedByUserId: f.userId,
          reviewedAt: "2026-09-10T00:00:00.000Z",
          evaluatedAt: "2026-09-01T00:00:00.000Z",
          evaluationJson: "{}",
        });
      const query = parseReviewQueuePageQuery({ reviewStatus: "resolved", q: "history-" });
      const first = paginateReviewQueue(
        await loadBadgeRuleReviewQueueEntries(f.db, f.tenantId, {
          reviewStatus: "resolved",
          search: query.q,
          limit: 50,
          includeLookahead: true,
        }),
        query,
        50,
      );
      expect(first.entries).toHaveLength(50);
      expect(first.older).toBeDefined();
      const olderQuery = { ...query, cursor: first.older };
      const older = paginateReviewQueue(
        await loadBadgeRuleReviewQueueEntries(f.db, f.tenantId, {
          reviewStatus: "resolved",
          search: query.q,
          cursor: olderQuery.cursor,
          limit: 50,
          includeLookahead: true,
        }),
        olderQuery,
        50,
      );
      expect(older.entries).toHaveLength(5);
      expect(
        new Set([...first.entries, ...older.entries].map((entry) => entry.evaluationId)).size,
      ).toBe(55);
      const backQuery = { ...query, cursor: older.newer };
      const back = paginateReviewQueue(
        await loadBadgeRuleReviewQueueEntries(f.db, f.tenantId, {
          reviewStatus: "resolved",
          search: query.q,
          cursor: backQuery.cursor,
          limit: 50,
          includeLookahead: true,
        }),
        backQuery,
        50,
      );
      expect(back.entries.map((entry) => entry.evaluationId)).toEqual(
        first.entries.map((entry) => entry.evaluationId),
      );
      expect(
        await loadBadgeRuleReviewQueueEntries(f.db, f.tenantId, {
          reviewStatus: "resolved",
          search: rule.version.snapshot.badgeTemplateTitle ?? "missing",
        }),
      ).toHaveLength(50);
      expect(
        await loadBadgeRuleReviewQueueEntries(f.db, f.tenantId, {
          reviewStatus: "resolved",
          search: "0%",
        }),
      ).toHaveLength(6);
      expect(
        await loadBadgeRuleReviewQueueEntries(f.db, "other", {
          reviewStatus: "resolved",
          search: query.q,
        }),
      ).toEqual([]);
      const html = await renderRuleReviewQueuePanel({
        tenantId: f.tenantId,
        reviewQueueWorkspace: {
          query,
          reviewStatus: "resolved",
          selectedEntry: first.entries[0],
          entries: first.entries,
          listNotice: null,
          listError: null,
        },
      });
      expect(html.toString()).toContain("View issued badge");
      expect(html.toString()).toContain(encodeURIComponent(assertionId));
    } finally {
      await cleanupTestResources(f.db, { tenantIds: [f.tenantId], userIds: [f.userId] });
    }
  });
});
