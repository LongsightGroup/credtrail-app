export const buildLmsConnectionsPagePath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/access/lms-connections`;
};

export const lmsConnectionsPageUrl = (
  tenantId: string,
  extra?: Record<string, string>,
): string => {
  const path = buildLmsConnectionsPagePath(tenantId);
  const query = new URLSearchParams();

  if (extra !== undefined) {
    for (const [key, value] of Object.entries(extra)) {
      if (value.length > 0) {
        query.set(key, value);
      }
    }
  }

  const queryString = query.toString();

  return queryString.length > 0 ? `${path}?${queryString}` : path;
};

export const tenantLmsConnectionAdminSavePath = (tenantId: string): string => {
  return buildLmsConnectionsPagePath(tenantId);
};
