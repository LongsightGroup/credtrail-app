import { describe, expect, it } from "vitest";

import {
  parseDelegatedIssuingAuthorityGrantListQuery,
  parseTenantOrgUnitListQuery,
} from "./list-queries.js";

describe("list query parsers", () => {
  it("parses tenant org unit list query defaults and booleans", () => {
    const defaultQuery = parseTenantOrgUnitListQuery({});
    const explicitQuery = parseTenantOrgUnitListQuery({ includeInactive: "true" });

    expect(defaultQuery.includeInactive).toBe(false);
    expect(explicitQuery.includeInactive).toBe(true);
  });

  it("parses delegated authority grant list query defaults and booleans", () => {
    const defaultQuery = parseDelegatedIssuingAuthorityGrantListQuery({});
    const explicitQuery = parseDelegatedIssuingAuthorityGrantListQuery({
      includeRevoked: "true",
      includeExpired: "true",
    });

    expect(defaultQuery.includeRevoked).toBe(false);
    expect(defaultQuery.includeExpired).toBe(false);
    expect(explicitQuery.includeRevoked).toBe(true);
    expect(explicitQuery.includeExpired).toBe(true);
  });
});
