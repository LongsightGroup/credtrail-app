import { describe, expect, it } from "vitest";
import { tenantMembershipRoleSatisfiesMinimumRole } from "./tenant-memberships";

describe("tenant membership role thresholds", () => {
  it("treats approver as a review capability rather than issuer-minus-one", () => {
    expect(tenantMembershipRoleSatisfiesMinimumRole("approver", "approver")).toBe(true);
    expect(tenantMembershipRoleSatisfiesMinimumRole("admin", "approver")).toBe(true);
    expect(tenantMembershipRoleSatisfiesMinimumRole("owner", "approver")).toBe(true);
    expect(tenantMembershipRoleSatisfiesMinimumRole("issuer", "approver")).toBe(false);
    expect(tenantMembershipRoleSatisfiesMinimumRole("viewer", "approver")).toBe(false);
  });

  it("keeps approver below issuer for issuing thresholds", () => {
    expect(tenantMembershipRoleSatisfiesMinimumRole("approver", "viewer")).toBe(true);
    expect(tenantMembershipRoleSatisfiesMinimumRole("approver", "issuer")).toBe(false);
  });
});
