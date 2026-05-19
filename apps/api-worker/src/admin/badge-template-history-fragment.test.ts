import { describe, expect, it } from "vitest";
import type { BadgeTemplateHistoryTimelineEntry } from "../badges/badge-template-history";
import { renderBadgeTemplateHistoryTimelineToString } from "./badge-template-history-fragment";

const sampleTimelineEntry = (
  overrides?: Partial<BadgeTemplateHistoryTimelineEntry>,
): BadgeTemplateHistoryTimelineEntry => {
  return {
    id: "aud_123",
    kind: "audit",
    occurredAt: "2026-02-18T12:00:00.000Z",
    actorUserId: "usr_admin",
    actorLabel: "admin@example.edu",
    summary: "Updated template",
    detail: "Title: Old → New",
    ...overrides,
  };
};

describe("renderBadgeTemplateHistoryTimelineToString", () => {
  it("renders timeline entries as admin history markup", () => {
    const html = renderBadgeTemplateHistoryTimelineToString([sampleTimelineEntry()]);

    expect(html).toContain("ct-admin__history-audit-item");
    expect(html).toContain("Updated template");
    expect(html).toContain("admin@example.edu");
    expect(html).toContain("Title: Old → New");
  });

  it("renders an empty-state message when there is no history", () => {
    const html = renderBadgeTemplateHistoryTimelineToString([]);

    expect(html).toContain("ct-admin__empty");
    expect(html).toContain("No edit history is recorded for this badge template yet.");
  });
});
