import {
  createAuthIdentityLink,
  findAuthIdentityLinkByAuthUserId,
  findAuthIdentityLinkByCredtrailUserId,
  upsertUserByEmail,
  type SqlDatabase,
} from "@credtrail/db";
import type { AuthenticatedPrincipal, RequestedTenantContext } from "./auth-context";
import type {
  InternalAuthProvider,
  LtiAuthenticatedPrincipal,
  LtiSessionInput,
  RequestMagicLinkInput,
  RequestMagicLinkResult,
} from "./auth-provider";

export interface BetterAuthResolvedUser {
  id: string;
  email: string | null;
  emailVerified: boolean;
}

export interface BetterAuthResolvedSession {
  sessionId: string;
  sessionToken?: string | undefined;
  accountId: string | null;
  expiresAt: string;
  user: BetterAuthResolvedUser | null;
}

export interface BetterAuthAdapterContext<BindingsType> {
  env: BindingsType;
}

export interface BetterAuthAdapterInput<
  ContextType extends BetterAuthAdapterContext<BindingsType>,
  BindingsType,
> {
  resolveDatabase: (bindings: BindingsType) => SqlDatabase;
  requestMagicLink: (
    context: ContextType,
    input: RequestMagicLinkInput,
  ) => Promise<RequestMagicLinkResult>;
  createMagicLinkSession?: (
    context: ContextType,
    token: string,
  ) => Promise<BetterAuthResolvedSession | null>;
  createLtiSession?: (
    context: ContextType,
    input: LtiSessionInput,
  ) => Promise<BetterAuthResolvedSession>;
  resolveSession: (context: ContextType) => Promise<BetterAuthResolvedSession | null>;
  revokeSession: (context: ContextType) => Promise<void>;
  resolveRequestedTenantContext?: (context: ContextType) => Promise<RequestedTenantContext | null>;
  cacheAuthenticatedPrincipal?: (
    context: ContextType,
    principal: AuthenticatedPrincipal | null,
  ) => void;
  cacheRequestedTenantContext?: (
    context: ContextType,
    requestedTenant: RequestedTenantContext | null,
  ) => void;
  authSystem?: string | undefined;
}

const normalizeVerifiedEmail = (session: BetterAuthResolvedSession | null): string | null => {
  const email = session?.user?.email?.trim();

  if (session?.user?.emailVerified !== true || email === undefined || email.length === 0) {
    return null;
  }

  return email;
};

const resolveCredtrailUserId = async (
  db: SqlDatabase,
  session: BetterAuthResolvedSession,
  authSystem: string,
): Promise<string | null> => {
  const authUserId = session.user?.id?.trim();

  if (authUserId === undefined || authUserId.length === 0) {
    return null;
  }

  const existingLink = await findAuthIdentityLinkByAuthUserId(db, authSystem, authUserId);

  if (existingLink !== null) {
    return existingLink.credtrailUserId;
  }

  const verifiedEmail = normalizeVerifiedEmail(session);

  if (verifiedEmail === null) {
    return null;
  }

  const user = await upsertUserByEmail(db, verifiedEmail);

  const conflictingLink = await findAuthIdentityLinkByCredtrailUserId(db, authSystem, user.id);

  if (conflictingLink !== null && conflictingLink.authUserId !== authUserId) {
    return null;
  }

  await createAuthIdentityLink(db, {
    authSystem,
    authUserId,
    authAccountId: session.accountId,
    credtrailUserId: user.id,
    emailSnapshot: verifiedEmail,
  });

  return user.id;
};

export const resolveAuthenticatedPrincipalFromSession = async (input: {
  db: SqlDatabase;
  session: BetterAuthResolvedSession;
  authSystem?: string | undefined;
}): Promise<AuthenticatedPrincipal | null> => {
  const authSessionId = input.session.sessionId.trim();

  if (authSessionId.length === 0) {
    return null;
  }

  const userId = await resolveCredtrailUserId(
    input.db,
    input.session,
    input.authSystem ?? "better_auth",
  );

  if (userId === null) {
    return null;
  }

  return {
    userId,
    authSessionId,
    authMethod: "better_auth",
    expiresAt: input.session.expiresAt,
  };
};

export const resolveAuthenticatedPrincipal = async <
  ContextType extends BetterAuthAdapterContext<BindingsType>,
  BindingsType,
>(
  context: ContextType,
  input: BetterAuthAdapterInput<ContextType, BindingsType>,
): Promise<AuthenticatedPrincipal | null> => {
  const session = await input.resolveSession(context);

  if (session === null) {
    input.cacheAuthenticatedPrincipal?.(context, null);
    return null;
  }

  const authSessionId = session.sessionId.trim();

  if (authSessionId.length === 0) {
    input.cacheAuthenticatedPrincipal?.(context, null);
    return null;
  }

  const principal = await resolveAuthenticatedPrincipalFromSession({
    db: input.resolveDatabase(context.env),
    session,
    authSystem: input.authSystem,
  });

  if (principal === null) {
    input.cacheAuthenticatedPrincipal?.(context, null);
    return null;
  }

  input.cacheAuthenticatedPrincipal?.(context, principal);
  return principal;
};

export const resolveRequestedTenantContext = async <
  ContextType extends BetterAuthAdapterContext<BindingsType>,
  BindingsType,
>(
  context: ContextType,
  input: BetterAuthAdapterInput<ContextType, BindingsType>,
): Promise<RequestedTenantContext | null> => {
  const requestedTenant = (await input.resolveRequestedTenantContext?.(context)) ?? null;
  input.cacheRequestedTenantContext?.(context, requestedTenant);
  return requestedTenant;
};

export const revokeCurrentSession = async <
  ContextType extends BetterAuthAdapterContext<BindingsType>,
  BindingsType,
>(
  context: ContextType,
  input: BetterAuthAdapterInput<ContextType, BindingsType>,
): Promise<void> => {
  await input.revokeSession(context);
  input.cacheAuthenticatedPrincipal?.(context, null);
  input.cacheRequestedTenantContext?.(context, null);
};

export const createMagicLinkSession = async <
  ContextType extends BetterAuthAdapterContext<BindingsType>,
  BindingsType,
>(
  context: ContextType,
  token: string,
  input: BetterAuthAdapterInput<ContextType, BindingsType>,
): Promise<AuthenticatedPrincipal | null> => {
  if (input.createMagicLinkSession === undefined) {
    throw new Error("Better Auth magic-link verification is not wired yet");
  }

  const session = await input.createMagicLinkSession(context, token);

  if (session === null) {
    input.cacheAuthenticatedPrincipal?.(context, null);
    return null;
  }

  const principal = await resolveAuthenticatedPrincipalFromSession({
    db: input.resolveDatabase(context.env),
    session,
    authSystem: input.authSystem,
  });

  if (principal === null) {
    input.cacheAuthenticatedPrincipal?.(context, null);
    return null;
  }

  input.cacheAuthenticatedPrincipal?.(context, principal);
  return principal;
};

export const createLtiSession = async <
  ContextType extends BetterAuthAdapterContext<BindingsType>,
  BindingsType,
>(
  context: ContextType,
  sessionInput: LtiSessionInput,
  input: BetterAuthAdapterInput<ContextType, BindingsType>,
): Promise<LtiAuthenticatedPrincipal> => {
  if (input.createLtiSession === undefined) {
    throw new Error("Better Auth LTI session creation is not wired yet");
  }

  const session = await input.createLtiSession(context, sessionInput);
  const principal = await resolveAuthenticatedPrincipalFromSession({
    db: input.resolveDatabase(context.env),
    session,
    authSystem: input.authSystem,
  });

  if (principal === null) {
    input.cacheAuthenticatedPrincipal?.(context, null);
    throw new Error("Better Auth LTI session could not be linked to a CredTrail user");
  }

  const ltiPrincipal: LtiAuthenticatedPrincipal = {
    ...principal,
    ...(session.sessionToken === undefined ? {} : { browserSessionToken: session.sessionToken }),
  };

  input.cacheAuthenticatedPrincipal?.(context, ltiPrincipal);
  return ltiPrincipal;
};

export const createBetterAuthProvider = <
  ContextType extends BetterAuthAdapterContext<BindingsType>,
  BindingsType,
>(
  input: BetterAuthAdapterInput<ContextType, BindingsType>,
): InternalAuthProvider<ContextType> => {
  return {
    requestMagicLink: (context, request) => {
      return input.requestMagicLink(context, request);
    },
    createMagicLinkSession: (context, token) => {
      return createMagicLinkSession(context, token, input);
    },
    createLtiSession: (context, sessionInput) => {
      return createLtiSession(context, sessionInput, input);
    },
    resolveAuthenticatedPrincipal: (context) => {
      return resolveAuthenticatedPrincipal(context, input);
    },
    resolveRequestedTenantContext: (context) => {
      return resolveRequestedTenantContext(context, input);
    },
    revokeCurrentSession: (context) => {
      return revokeCurrentSession(context, input);
    },
  };
};
