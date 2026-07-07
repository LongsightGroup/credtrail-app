import type { InstitutionAdminViewDataNeeds } from "./view-content";

export type AccessSectionKind =
  | "apiKeys"
  | "lmsConnections"
  | "orgUnits"
  | "governanceGuide"
  | "ruleApproval"
  | "tenantMembers"
  | "membershipScope"
  | "approverGroups"
  | "delegations";

export const accessSectionKindsForDataNeeds = (
  needs: InstitutionAdminViewDataNeeds,
): ReadonlySet<AccessSectionKind> => {
  const kinds = new Set<AccessSectionKind>();

  if (needs.apiKeyRows) {
    kinds.add("apiKeys");
  }

  if (needs.lmsConnectionRows) {
    kinds.add("lmsConnections");
  }

  if (needs.orgUnitRows) {
    kinds.add("orgUnits");
  }

  if (needs.governanceTableRows) {
    kinds.add("governanceGuide");
    kinds.add("ruleApproval");
    kinds.add("approverGroups");
  }

  if (needs.scopedRoleRows) {
    kinds.add("membershipScope");
  }

  if (needs.delegatedGrantRows) {
    kinds.add("delegations");
  }

  if (needs.tenantMemberRows) {
    kinds.add("tenantMembers");
  }

  return kinds;
};

export const accessSectionEnabled = (
  kinds: ReadonlySet<AccessSectionKind>,
  kind: AccessSectionKind,
): boolean => {
  return kinds.has(kind);
};
