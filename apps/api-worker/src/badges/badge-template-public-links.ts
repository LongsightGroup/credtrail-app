export const tenantBadgeShowcaseHref = (tenantId: string): string => {
  return `/showcase/${encodeURIComponent(tenantId)}`;
};

export const tenantBadgeCriteriaRegistryHref = (tenantId: string): string => {
  return `/showcase/${encodeURIComponent(tenantId)}/criteria`;
};

export const badgeTemplateShowcaseHref = (tenantId: string, badgeTemplateId: string): string => {
  return `${tenantBadgeShowcaseHref(tenantId)}?badgeTemplateId=${encodeURIComponent(
    badgeTemplateId,
  )}`;
};

export const badgeTemplateCriteriaRegistryHref = (
  tenantId: string,
  badgeTemplateId: string,
): string => {
  return `${tenantBadgeCriteriaRegistryHref(tenantId)}?badgeTemplateId=${encodeURIComponent(
    badgeTemplateId,
  )}`;
};
