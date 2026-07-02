import type { TenantMembershipRole } from "@credtrail/db";
import { describe, expect, it } from "vitest";
import {
  ADMIN_ROLES,
  ISSUER_ROLES,
  canIssueBadgesAsTenantMember,
  isTenantAdminRole,
  membershipHasRole,
} from "./tenant-role-policy";

describe("tenant-role-policy", () => {
  it("checks membership against allowed role lists", () => {
    expect(membershipHasRole("issuer", ISSUER_ROLES)).toBe(true);
    expect(membershipHasRole("viewer", ISSUER_ROLES)).toBe(false);
  });

  it("identifies tenant admin roles", () => {
    for (const role of ADMIN_ROLES) {
      expect(isTenantAdminRole(role)).toBe(true);
    }

    expect(isTenantAdminRole("issuer")).toBe(false);
    expect(isTenantAdminRole("viewer")).toBe(false);
  });

  it("identifies badge-issuing tenant member roles", () => {
    for (const role of ISSUER_ROLES) {
      expect(canIssueBadgesAsTenantMember(role)).toBe(true);
    }

    expect(canIssueBadgesAsTenantMember("viewer")).toBe(false);
  });

  it("accepts readonly role lists", () => {
    const allowedRoles: readonly TenantMembershipRole[] = ["owner"];

    expect(membershipHasRole("owner", allowedRoles)).toBe(true);
    expect(membershipHasRole("admin", allowedRoles)).toBe(false);
  });
});
