import { describe, expect, it } from "vitest";
import type { AuditLogRecord, BadgeTemplateOwnershipEventRecord } from "@credtrail/db";
import {
  buildBadgeTemplateHistoryTimeline,
  formatBadgeTemplateAuditDetail,
  formatBadgeTemplateOwnershipDetail,
} from "./badge-template-history";

const sampleAuditLog = (overrides?: Partial<AuditLogRecord>): AuditLogRecord => {
  return {
    id: "aud_123",
    tenantId: "tenant_123",
    actorUserId: "usr_admin",
    action: "badge_template.updated",
    targetType: "badge_template",
    targetId: "badge_template_001",
    metadataJson: JSON.stringify({
      changes: [{ field: "title", from: "Old", to: "New" }],
    }),
    occurredAt: "2026-02-18T12:00:00.000Z",
    createdAt: "2026-02-18T12:00:00.000Z",
    ...overrides,
  };
};

const sampleOwnershipEvent = (
  overrides?: Partial<BadgeTemplateOwnershipEventRecord>,
): BadgeTemplateOwnershipEventRecord => {
  return {
    id: "btoe_123",
    tenantId: "tenant_123",
    badgeTemplateId: "badge_template_001",
    fromOrgUnitId: "tenant_123:org:institution",
    toOrgUnitId: "tenant_123:org:department-math",
    reasonCode: "administrative_transfer",
    reason: "Moved to Math governance",
    governanceMetadataJson: null,
    transferredByUserId: "usr_admin",
    transferredAt: "2026-02-19T12:00:00.000Z",
    createdAt: "2026-02-19T12:00:00.000Z",
    ...overrides,
  };
};

describe("badge template history", () => {
  it("formats audit detail from field-level changes", () => {
    expect(
      formatBadgeTemplateAuditDetail(
        JSON.stringify({
          changes: [{ field: "title", from: "Old title", to: "New title" }],
        }),
      ),
    ).toBe("Title: Old title → New title");
  });

  it("formats LMS placement policy changes in administrator-facing language", () => {
    expect(
      formatBadgeTemplateAuditDetail(
        JSON.stringify({
          changes: [
            {
              field: "ltiInstructorPlacement",
              from: "Not allowed",
              to: "Allowed",
            },
          ],
        }),
      ),
    ).toBe("LMS instructor placement: Not allowed → Allowed");
  });

  it("skips legacy title and slug metadata when field-level changes are present", () => {
    expect(
      formatBadgeTemplateAuditDetail(
        JSON.stringify({
          changes: [{ field: "title", from: "Old title", to: "New title" }],
          title: "New title",
          slug: "new-slug",
        }),
      ),
    ).toBe("Title: Old title → New title");
  });

  it("uses legacy title and slug metadata when field-level changes are absent", () => {
    expect(
      formatBadgeTemplateAuditDetail(
        JSON.stringify({
          title: "New title",
          slug: "new-slug",
        }),
      ),
    ).toBe("Title: New title · URL key: new-slug");
  });

  it("merges ownership events and audit logs without duplicate ownership audit rows", () => {
    const orgUnitLabelById = new Map([
      ["tenant_123:org:institution", "Institution"],
      ["tenant_123:org:department-math", "Math"],
    ]);
    const actorLabels = new Map([["usr_admin", "admin@example.edu"]]);
    const timeline = buildBadgeTemplateHistoryTimeline({
      logs: [
        sampleAuditLog(),
        sampleAuditLog({
          id: "aud_ownership",
          action: "badge_template.ownership_transferred",
          occurredAt: "2026-02-19T12:00:00.000Z",
          metadataJson: JSON.stringify({ eventId: "btoe_123" }),
        }),
      ],
      ownershipEvents: [sampleOwnershipEvent()],
      actorLabels,
      orgUnitLabelById,
    });

    expect(timeline).toHaveLength(2);
    expect(timeline[0]?.kind).toBe("ownership");
    expect(timeline[0]?.actorLabel).toBe("admin@example.edu");
    expect(timeline[1]?.kind).toBe("audit");
    expect(timeline.some((entry) => entry.summary === "Transferred template ownership")).toBe(true);
    expect(timeline.filter((entry) => entry.kind === "ownership")).toHaveLength(1);
  });

  it("limits merged timeline entries to the requested count", () => {
    const orgUnitLabelById = new Map<string, string>();
    const actorLabels = new Map([["usr_admin", "admin@example.edu"]]);
    const logs = Array.from({ length: 5 }, (_, index) =>
      sampleAuditLog({
        id: `aud_${String(index)}`,
        occurredAt: `2026-02-1${String(index)}T12:00:00.000Z`,
        metadataJson: JSON.stringify({
          changes: [{ field: "title", from: "Old", to: `New ${String(index)}` }],
        }),
      }),
    );
    const ownershipEvents = [
      sampleOwnershipEvent({
        id: "btoe_recent",
        transferredAt: "2026-02-20T12:00:00.000Z",
      }),
    ];
    const timeline = buildBadgeTemplateHistoryTimeline({
      logs,
      ownershipEvents,
      actorLabels,
      orgUnitLabelById,
      limit: 3,
    });

    expect(timeline).toHaveLength(3);
    expect(timeline[0]?.kind).toBe("ownership");
  });

  it("formats ownership detail with org unit labels", () => {
    const detail = formatBadgeTemplateOwnershipDetail(
      sampleOwnershipEvent(),
      new Map([
        ["tenant_123:org:institution", "Institution"],
        ["tenant_123:org:department-math", "Math"],
      ]),
    );

    expect(detail).toContain("Institution → Math");
    expect(detail).toContain("Moved to Math governance");
  });
});
