import { describe, expect, it } from "vitest";

import { buildAssertionRecordFilterSql } from "./assertion-record-filter-sql";

describe("assertion record filter SQL", () => {
  it("uses assertion badge template attribution for ledger filters", () => {
    const result = buildAssertionRecordFilterSql(
      {
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
      },
      { context: "ledger" },
    );

    expect(result.whereClauses).toContain("assertions.badge_template_id = ?");
    expect(result.whereClauses).not.toContain("attribution.badge_template_id = ?");
    expect(result.params).toEqual(["tenant_123", "badge_template_001"]);
  });

  it("uses reporting attribution badge template filters for reporting", () => {
    const result = buildAssertionRecordFilterSql(
      {
        tenantId: "tenant_123",
        badgeTemplateId: "badge_template_001",
      },
      { context: "reporting", includeLifecycleStatePredicate: false },
    );

    expect(result.whereClauses).toContain("attribution.badge_template_id = ?");
    expect(result.whereClauses).not.toContain("assertions.badge_template_id = ?");
    expect(result.params).toEqual(["tenant_123", "badge_template_001"]);
  });
});
