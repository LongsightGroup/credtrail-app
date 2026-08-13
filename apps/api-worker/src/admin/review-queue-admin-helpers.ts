export const buildReviewQueuePagePath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/operations/review-queue`;
};

export const tenantReviewQueueAdminResolvePath = (tenantId: string): string => {
  return `${buildReviewQueuePagePath(tenantId)}/resolve`;
};
