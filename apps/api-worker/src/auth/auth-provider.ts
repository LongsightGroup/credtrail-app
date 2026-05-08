import type { AuthenticatedPrincipal, RequestedTenantContext } from "./auth-context";

export interface LtiSessionInput {
  tenantId: string;
  userId: string;
}

export interface LtiAuthenticatedPrincipal extends AuthenticatedPrincipal {
  browserSessionToken?: string | undefined;
}

export interface RequestMagicLinkInput {
  tenantId: string;
  email: string;
  nextPath?: string | undefined;
  preferredLocale?: string | undefined;
  preferredTimeZone?: string | undefined;
}

export interface RequestMagicLinkResult {
  tenantId: string;
  email: string;
  deliveryStatus: "sent" | "skipped" | "failed";
  expiresAt?: string | undefined;
  debugMagicLinkToken?: string | undefined;
  debugMagicLinkUrl?: string | undefined;
}

export interface InternalAuthProvider<ContextType> {
  requestMagicLink(
    context: ContextType,
    input: RequestMagicLinkInput,
  ): Promise<RequestMagicLinkResult>;
  createMagicLinkSession(
    context: ContextType,
    token: string,
  ): Promise<AuthenticatedPrincipal | null>;
  createLtiSession(
    context: ContextType,
    input: LtiSessionInput,
  ): Promise<LtiAuthenticatedPrincipal>;
  resolveAuthenticatedPrincipal(context: ContextType): Promise<AuthenticatedPrincipal | null>;
  resolveRequestedTenantContext(context: ContextType): Promise<RequestedTenantContext | null>;
  revokeCurrentSession(context: ContextType): Promise<void>;
}
