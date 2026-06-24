import type { BadgeTemplateImageRevisionRecord } from "@credtrail/db";
import { describe, expect, it } from "vitest";
import type { BadgeTemplateHistoryTimelineEntry } from "../badges/badge-template-history";
import {
  BadgeTemplateHistoryTimeline,
  BadgeTemplateImageRevisionList,
} from "./badge-template-history-panel";

const sampleTimelineEntry = (): BadgeTemplateHistoryTimelineEntry => {
  return {
    id: "audit_123",
    kind: "audit",
    summary: "Updated template",
    detail: "Title: Old → New",
    occurredAt: "2026-01-01T00:00:00.000Z",
    actorUserId: "usr_admin",
    actorLabel: "admin@example.edu",
  };
};

const sampleRevision = (): BadgeTemplateImageRevisionRecord => {
  return {
    id: "btir_123",
    tenantId: "tenant_123",
    badgeTemplateId: "badge_template_001",
    previousImageUri: "https://example.edu/old.png",
    newImageUri: "https://example.edu/new.png",
    sourceType: "upload",
    promptText: null,
    provider: null,
    model: null,
    metadataJson: null,
    createdByUserId: "usr_admin",
    createdAt: "2026-01-02T00:00:00.000Z",
  };
};

describe("BadgeTemplateHistoryTimeline", () => {
  it("renders audit items", () => {
    const html = (
      BadgeTemplateHistoryTimeline({ timeline: [sampleTimelineEntry()] }) as {
        toString(): string;
      }
    ).toString();

    expect(html).toContain("ct-admin__history-audit-item");
    expect(html).toContain("Updated template");
  });

  it("renders an empty-state message when there is no history", () => {
    const html = (
      BadgeTemplateHistoryTimeline({ timeline: [] }) as { toString(): string }
    ).toString();

    expect(html).toContain("ct-admin__empty");
    expect(html).toContain("No edit history is recorded for this badge template yet.");
  });
});

describe("BadgeTemplateImageRevisionList", () => {
  it("renders restore forms with list query context on the action URL", () => {
    const html = (
      BadgeTemplateImageRevisionList({
        revisions: [sampleRevision()],
        restorePathPrefix:
          "/tenants/tenant_123/admin/rules/templates/badge_template_001/image-revisions",
        listPageQuery: {
          searchQuery: "legacy",
          includeArchived: true,
          returnToRuleBuilder: false,
        },
      }) as { toString(): string }
    ).toString();

    expect(html).toContain('method="post"');
    expect(html).toContain("/restore?q=legacy&amp;includeArchived=1");
    expect(html).toContain("Restore");
    expect(html).toMatch(/class="[^"]*ct-admin__actions--end[^"]*ct-action-group/);
    expect(html).toContain("Uploaded");
  });
});
