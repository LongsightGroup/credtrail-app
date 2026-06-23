import type { TenantLmsConnectionRecord } from "@credtrail/db";

export const buildLmsConnectionsPagePath = (tenantId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/access/lms-connections`;
};

export const buildLmsConnectionNewPath = (tenantId: string): string => {
  return `${buildLmsConnectionsPagePath(tenantId)}/new`;
};

export const buildLmsConnectionEditPath = (tenantId: string, connectionId: string): string => {
  return `${buildLmsConnectionsPagePath(tenantId)}/${encodeURIComponent(connectionId)}/edit`;
};

export const lmsConnectionsPageUrl = (tenantId: string, extra?: Record<string, string>): string => {
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

export const isLmsConnectionReady = (connection: TenantLmsConnectionRecord): boolean => {
  if (connection.accessToken !== null && connection.accessToken.length > 0) {
    return true;
  }

  return (
    connection.providerKind === "sakai" &&
    connection.clientId !== null &&
    connection.clientId.length > 0 &&
    connection.clientSecret !== null &&
    connection.clientSecret.length > 0
  );
};
