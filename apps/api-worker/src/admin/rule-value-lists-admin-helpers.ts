export const buildRuleValueListsAdminPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/rules`;
};

export const tenantRuleValueListsAdminCreatePath = (tenantId: string): string => {
  return `${buildRuleValueListsAdminPath(tenantId)}/value-lists`;
};

export const ruleValueListsPageUrl = (tenantId: string, extra?: Record<string, string>): string => {
  const path = buildRuleValueListsAdminPath(tenantId);

  if (extra === undefined || Object.keys(extra).length === 0) {
    return path;
  }

  return `${path}?${new URLSearchParams(extra).toString()}`;
};
