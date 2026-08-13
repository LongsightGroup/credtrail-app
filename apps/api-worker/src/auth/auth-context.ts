export type AuthMethod = "better_auth";

export interface AuthenticatedPrincipal {
  userId: string;
  authSessionId: string;
  authMethod: AuthMethod;
  expiresAt: string;
}

export interface RequestedTenantContext {
  tenantId: string;
}

export interface AuthContextVariables {
  authenticatedPrincipal: AuthenticatedPrincipal | null | undefined;
  requestedTenantContext: RequestedTenantContext | null | undefined;
}
