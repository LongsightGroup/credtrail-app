export const buildApiKeysPagePath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/access/api-keys`;
};

export const tenantApiKeyAdminRevokePath = (tenantId: string, apiKeyId: string): string => {
  return `${buildApiKeysPagePath(tenantId)}/${encodeURIComponent(apiKeyId)}/revoke`;
};

export const tenantApiKeyAdminCreatePath = (tenantId: string): string => {
  return buildApiKeysPagePath(tenantId);
};
