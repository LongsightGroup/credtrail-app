export const buildAccessMembersAdminPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/access/members`;
};

export const buildAccessGovernanceAdminPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/access/governance`;
};

export const buildAccessAuthenticationAdminPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/access/authentication`;
};

export const buildAccessGovernanceDelegationNewPath = (tenantId: string): string => {
  return `${buildAccessGovernanceAdminPath(tenantId)}/delegations/new`;
};

export const buildOperationsManualIssuePath = (tenantId: string): string => {
  return `${buildOperationsAdminPath(tenantId)}/issue`;
};

export const buildAccessOrgUnitsAdminPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/access/org-units`;
};

export const buildRulesAdminPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/rules`;
};

export const buildOperationsAdminPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/operations`;
};

export const tenantAccessMemberCreatePath = (tenantId: string): string => {
  return `${buildAccessMembersAdminPath(tenantId)}/create`;
};

export const tenantAccessMemberRolePath = (tenantId: string, userId: string): string => {
  return `${buildAccessMembersAdminPath(tenantId)}/${encodeURIComponent(userId)}/role`;
};

export const tenantAccessMemberInvitePath = (tenantId: string, userId: string): string => {
  return `${buildAccessMembersAdminPath(tenantId)}/${encodeURIComponent(userId)}/invite`;
};

export const tenantAccessMemberRemovePath = (tenantId: string, userId: string): string => {
  return `${buildAccessMembersAdminPath(tenantId)}/${encodeURIComponent(userId)}/remove`;
};

export const tenantAccessMembershipScopeSavePath = (tenantId: string): string => {
  return `${buildAccessGovernanceAdminPath(tenantId)}/scopes`;
};

export const tenantAccessMembershipScopeRemovePath = (tenantId: string): string => {
  return `${buildAccessGovernanceAdminPath(tenantId)}/scopes/remove`;
};

export const tenantAccessDelegatedGrantCreatePath = (tenantId: string): string => {
  return `${buildAccessGovernanceAdminPath(tenantId)}/delegations`;
};

export const tenantAccessDelegatedGrantRevokePath = (tenantId: string): string => {
  return `${buildAccessGovernanceAdminPath(tenantId)}/delegations/revoke`;
};

export const tenantAccessOrgUnitCreatePath = (tenantId: string): string => {
  return `${buildAccessOrgUnitsAdminPath(tenantId)}/create`;
};

export const tenantBadgeRuleApproveDraftAdminPath = (
  tenantId: string,
  ruleId: string,
  versionId: string,
): string => {
  return `${buildRulesAdminPath(tenantId)}/${encodeURIComponent(ruleId)}/versions/${encodeURIComponent(versionId)}/approve-draft`;
};

export const tenantBadgeRuleDecisionAdminPath = (
  tenantId: string,
  ruleId: string,
  versionId: string,
): string => {
  return `${buildRulesAdminPath(tenantId)}/${encodeURIComponent(ruleId)}/versions/${encodeURIComponent(versionId)}/decision`;
};

export const tenantBadgeRuleActivateAdminPath = (
  tenantId: string,
  ruleId: string,
  versionId: string,
): string => {
  return `${buildRulesAdminPath(tenantId)}/${encodeURIComponent(ruleId)}/versions/${encodeURIComponent(versionId)}/activate`;
};

export const tenantBadgeRuleDeleteAdminPath = (tenantId: string, ruleId: string): string => {
  return `${buildRulesAdminPath(tenantId)}/${encodeURIComponent(ruleId)}/delete`;
};

export const tenantAccessEnterpriseAuthPolicyPath = (tenantId: string): string => {
  return `${buildAccessAuthenticationAdminPath(tenantId)}/policy`;
};

export const tenantAccessEnterpriseAuthProviderSavePath = (tenantId: string): string => {
  return `${buildAccessAuthenticationAdminPath(tenantId)}/providers`;
};

export const tenantAccessEnterpriseAuthProviderDeletePath = (tenantId: string): string => {
  return `${buildAccessAuthenticationAdminPath(tenantId)}/providers/delete`;
};

export const tenantAccessBreakGlassAccountCreatePath = (tenantId: string): string => {
  return `${buildAccessAuthenticationAdminPath(tenantId)}/break-glass-accounts`;
};

export const tenantAccessBreakGlassAccountRevokePath = (tenantId: string): string => {
  return `${buildAccessAuthenticationAdminPath(tenantId)}/break-glass-accounts/revoke`;
};

export const tenantOperationsManualIssuePath = (tenantId: string): string => {
  return buildOperationsManualIssuePath(tenantId);
};

export const accessGovernancePageUrl = (
  tenantId: string,
  extra?: Record<string, string>,
): string => {
  const path = buildAccessGovernanceAdminPath(tenantId);

  if (extra === undefined || Object.keys(extra).length === 0) {
    return path;
  }

  return `${path}?${new URLSearchParams(extra).toString()}`;
};

export const accessAuthenticationPageUrl = (
  tenantId: string,
  extra?: Record<string, string>,
): string => {
  const path = buildAccessAuthenticationAdminPath(tenantId);

  if (extra === undefined || Object.keys(extra).length === 0) {
    return path;
  }

  return `${path}?${new URLSearchParams(extra).toString()}`;
};
