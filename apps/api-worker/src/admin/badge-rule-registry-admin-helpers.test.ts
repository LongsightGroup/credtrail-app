import { describe, expect, it } from "vitest";

import {
  badgeRuleRegistryPageUrl,
  badgeRuleRegistrySortUrl,
  buildBadgeRuleRegistryPageQuery,
  safeParseBadgeRuleRegistryPageQuery,
  type BadgeRuleRegistryPageQuery,
} from "./badge-rule-registry-admin-helpers";

const queryFixture = (): BadgeRuleRegistryPageQuery => ({
  searchQuery: "capstone",
  latestStatus: "active",
  sort: "rule",
  direction: "asc",
  limit: 50,
});

describe("badge rule registry admin helpers", () => {
  it("round-trips an opaque cursor tied to the selected ordering", () => {
    const query = queryFixture();
    const params = buildBadgeRuleRegistryPageQuery(query, {
      position: "after",
      boundary: { value: "capstone completion", ruleId: "brl_123" },
    });
    const parsed = safeParseBadgeRuleRegistryPageQuery(Object.fromEntries(params));

    expect(parsed).toEqual({
      ok: true,
      value: {
        ...query,
        cursor: {
          position: "after",
          boundary: { value: "capstone completion", ruleId: "brl_123" },
        },
      },
    });
  });

  it("rejects a cursor reused under a different sort", () => {
    const params = buildBadgeRuleRegistryPageQuery(queryFixture(), {
      position: "after",
      boundary: { value: "capstone completion", ruleId: "brl_123" },
    });
    params.set("sort", "latest_version");

    expect(safeParseBadgeRuleRegistryPageQuery(Object.fromEntries(params))).toEqual({ ok: false });
  });

  it("preserves filters in pagination and resets cursors when sorting", () => {
    const query = queryFixture();
    const pageUrl = badgeRuleRegistryPageUrl("tenant_123", query, {
      position: "before",
      boundary: { value: "capstone completion", ruleId: "brl_123" },
    });
    const sortUrl = badgeRuleRegistrySortUrl("tenant_123", query, "rule");

    expect(pageUrl).toContain("q=capstone");
    expect(pageUrl).toContain("before=");
    expect(sortUrl).not.toContain("direction=");
    expect(sortUrl).not.toContain("before=");
    expect(sortUrl).not.toContain("after=");
  });
});
