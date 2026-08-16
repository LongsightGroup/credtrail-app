import { beforeEach } from "vitest";
import { resetInstitutionAdminTestDefaults } from "./reset-defaults";

beforeEach(resetInstitutionAdminTestDefaults);

export {
  createEnv,
  fakeDb,
  mockedAddBadgeRuleApproverGroupMemberDb,
  mockedCreateAuditLogDb,
  mockedCreateBadgeRuleApproverGroupDb,
  mockedCreateDelegatedIssuingAuthorityGrantDb,
  mockedFindDelegatedIssuingAuthorityGrantByIdDb,
  mockedFindTenantById,
  mockedListDelegatedIssuingAuthorityGrants,
  mockedListTenantMembershipOrgUnitScopes,
  mockedRemoveBadgeRuleApproverGroupMemberDb,
  mockedRemoveTenantMembershipOrgUnitScopeDb,
  mockedResolveBadgeRuleApprovalPolicyDb,
  mockedResolveTenantDefaultBadgeRuleApprovalPolicyDb,
  mockedRevokeDelegatedIssuingAuthorityGrantDb,
  mockedUpsertBadgeRuleApprovalPolicyDb,
  mockedUpsertTenantMembershipOrgUnitScopeDb,
} from "./support";
