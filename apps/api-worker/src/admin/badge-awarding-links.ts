import { tenantOperationsManualIssuePath } from "./access-admin-helpers";

export const issuePreparedBadgePath = (
  tenantId: string,
  badgeTemplateId: string,
  pathwayHandoffId?: string,
): string => {
  const query = new URLSearchParams({ badgeTemplateId });
  if (pathwayHandoffId !== undefined) query.set("pathwayHandoffId", pathwayHandoffId);
  return `${tenantOperationsManualIssuePath(tenantId)}?${query}`;
};

export const automaticBadgeAwardingPath = (tenantId: string, badgeTemplateId: string): string =>
  `/tenants/${encodeURIComponent(tenantId)}/admin/rules/new?${new URLSearchParams({ badgeTemplateId })}`;
