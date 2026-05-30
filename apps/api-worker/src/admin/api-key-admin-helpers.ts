export const buildApiKeysPagePath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/access/api-keys`;
};

export const apiKeysPageUrl = (tenantId: string, extra?: Record<string, string>): string => {
  const path = buildApiKeysPagePath(tenantId);
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

export const tenantApiKeyAdminRevokePath = (tenantId: string, apiKeyId: string): string => {
  return `${buildApiKeysPagePath(tenantId)}/${encodeURIComponent(apiKeyId)}/revoke`;
};

export const tenantApiKeyAdminCreatePath = (tenantId: string): string => {
  return buildApiKeysPagePath(tenantId);
};
