export const buildReviewQueuePagePath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/operations/review-queue`;
};

export const tenantReviewQueueAdminResolvePath = (tenantId: string): string => {
  return `${buildReviewQueuePagePath(tenantId)}/resolve`;
};

export const reviewQueuePageUrl = (tenantId: string, extra?: Record<string, string>): string => {
  const path = buildReviewQueuePagePath(tenantId);

  if (extra === undefined || Object.keys(extra).length === 0) {
    return path;
  }

  return `${path}?${new URLSearchParams(extra).toString()}`;
};
