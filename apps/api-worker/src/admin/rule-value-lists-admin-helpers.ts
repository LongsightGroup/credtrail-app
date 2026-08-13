export const buildRuleValueListsAdminPath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/rules`;
};

export const tenantRuleValueListsAdminCreatePath = (tenantId: string): string => {
  return `${buildRuleValueListsAdminPath(tenantId)}/value-lists`;
};
