import type { SqlDatabase } from "@credtrail/db";
import type {
  LtiAuthorizedLaunch,
  LtiLaunchVerificationResult,
  LTISession,
  LtiToolPort,
  LtiVerifyLaunchOptions,
} from "@longsightgroup/lti-tool";
import { LtiLaunchMessageResolutionError } from "@longsightgroup/lti-tool";
import { customLaunchRouteHandler } from "@longsightgroup/lti-tool/hono";
import type { AppBindings, AppContext } from "../app";
import type { LtiAuthenticatedPrincipal, LtiSessionInput } from "../auth/auth-provider";
import { createCredTrailLtiTool, type CreateCredTrailLtiToolInput } from "./credtrail-lti-tool";
import { createLtiHonoLogger } from "./hono-logger";
import {
  LtiLaunchMessageError,
  resolveLtiLaunchMessage,
  type ResolvedLtiLaunchMessage,
} from "./launch-message";
import { handleVerifiedLtiLaunch, type HandleVerifiedLtiLaunch } from "./launch-product-flow";
import {
  authorizeVerifiedLaunchForRegistry,
  ltiLaunchVerificationErrorFromCoreError,
  LtiLaunchVerificationError,
  type LtiLaunchAuthorization,
  type ResolvedLtiLaunch,
} from "./launch-verification";
import type { LtiIssuerRegistry } from "./lti-helpers";

type CreateCredTrailLtiToolForLaunch = (input: CreateCredTrailLtiToolInput) => Promise<LtiToolPort>;

export interface HandleLtiLaunchPostInput {
  c: AppContext;
  resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  sha256Hex: (value: string) => Promise<string>;
  createLtiSession: (
    context: AppContext,
    input: LtiSessionInput,
  ) => Promise<LtiAuthenticatedPrincipal>;
  handleVerifiedLtiLaunch?: HandleVerifiedLtiLaunch;
  createLtiTool?: CreateCredTrailLtiToolForLaunch;
}

const loadLtiLaunchRegistry = async (
  c: AppContext,
  resolveLtiIssuerRegistry: HandleLtiLaunchPostInput["resolveLtiIssuerRegistry"],
): Promise<LtiIssuerRegistry> => {
  try {
    return await resolveLtiIssuerRegistry(c);
  } catch {
    throw new Error("LTI issuer registry configuration is invalid");
  }
};

const isPackageValidationError = (error: unknown): boolean => {
  return error instanceof Error && error.name === "ZodError";
};

export const handleLtiLaunchFailureResponse = (c: AppContext, error: unknown): Response => {
  if (error instanceof LtiLaunchVerificationError) {
    return c.json(
      {
        error: error.message,
        ...(error.detail === undefined ? {} : { detail: error.detail }),
      },
      error.status,
    );
  }

  if (error instanceof LtiLaunchMessageError) {
    return c.json({ error: error.message }, error.status);
  }

  if (error instanceof LtiLaunchMessageResolutionError) {
    return c.json({ error: error.message }, 400);
  }

  if (isPackageValidationError(error)) {
    return c.json(
      {
        error: "Invalid launch parameters",
      },
      400,
    );
  }

  return c.json(
    {
      error: "Internal server error",
    },
    500,
  );
};

const createVerificationThrowingLtiTool = (ltiTool: LtiToolPort): LtiToolPort => {
  async function verifyLaunchOrThrow(
    idToken: string,
    state: string,
  ): Promise<LtiLaunchVerificationResult>;
  async function verifyLaunchOrThrow<TAuthorization>(
    idToken: string,
    state: string,
    options: LtiVerifyLaunchOptions<TAuthorization>,
  ): Promise<LtiLaunchVerificationResult<LtiAuthorizedLaunch<TAuthorization>>>;
  async function verifyLaunchOrThrow<TAuthorization>(
    idToken: string,
    state: string,
    options?: LtiVerifyLaunchOptions<TAuthorization>,
  ): Promise<
    LtiLaunchVerificationResult | LtiLaunchVerificationResult<LtiAuthorizedLaunch<TAuthorization>>
  > {
    const verificationResult =
      options === undefined
        ? await ltiTool.verifyLaunch(idToken, state)
        : await ltiTool.verifyLaunch(idToken, state, options);

    if (!verificationResult.success) {
      throw ltiLaunchVerificationErrorFromCoreError(verificationResult.error);
    }

    return verificationResult;
  }

  return {
    getJWKS: () => ltiTool.getJWKS(),
    handleLogin: (params) => ltiTool.handleLogin(params),
    verifyLaunch: verifyLaunchOrThrow,
    createSessionFromVerifiedLaunch: (launch) => ltiTool.createSessionFromVerifiedLaunch(launch),
    getSession: (sessionId) => ltiTool.getSession(sessionId),
    createAdvantage: (session) => ltiTool.createAdvantage(session),
  };
};

const resolvedLaunchFromAuthorizedContext = (input: {
  launch: LtiAuthorizedLaunch<LtiLaunchAuthorization>;
  session: LTISession;
  ltiTool: LtiToolPort;
}): ResolvedLtiLaunch => {
  return {
    issuer: input.launch.authorization.issuer,
    issuerEntry: input.launch.authorization.entry,
    launchClaims: input.launch.payload,
    ltiLaunchSession: input.session,
    ltiTool: input.ltiTool,
  };
};

const handleAuthorizedPackageLaunch = async (input: {
  c: AppContext;
  db: SqlDatabase;
  ltiTool: LtiToolPort;
  launch: LtiAuthorizedLaunch<LtiLaunchAuthorization>;
  session: LTISession;
  launchMessage: ResolvedLtiLaunchMessage;
  sha256Hex: (value: string) => Promise<string>;
  createLtiSession: HandleLtiLaunchPostInput["createLtiSession"];
  handleVerifiedLtiLaunch: HandleVerifiedLtiLaunch;
}): Promise<Response> => {
  const resolvedLaunch = resolvedLaunchFromAuthorizedContext({
    launch: input.launch,
    session: input.session,
    ltiTool: input.ltiTool,
  });

  return input.handleVerifiedLtiLaunch({
    c: input.c,
    db: input.db,
    tenantId: resolvedLaunch.issuerEntry.tenantId,
    resolvedLaunch,
    launchMessage: input.launchMessage,
    sha256Hex: input.sha256Hex,
    createLtiSession: input.createLtiSession,
  });
};

export const handleLtiLaunchPost = async (input: HandleLtiLaunchPostInput): Promise<Response> => {
  const runVerifiedLaunch = input.handleVerifiedLtiLaunch ?? handleVerifiedLtiLaunch;

  let registry: LtiIssuerRegistry;

  try {
    registry = await loadLtiLaunchRegistry(input.c, input.resolveLtiIssuerRegistry);
  } catch {
    return input.c.json(
      {
        error: "LTI issuer registry configuration is invalid",
      },
      500,
    );
  }

  const db = input.resolveDatabase(input.c.env);
  const ltiTool = await (input.createLtiTool ?? createCredTrailLtiTool)({
    db,
    env: input.c.env,
  });
  const protocolTool = createVerificationThrowingLtiTool(ltiTool);
  const handler = customLaunchRouteHandler<LtiLaunchAuthorization>({
    ltiTool: protocolTool,
    logger: createLtiHonoLogger({ c: input.c }),
    authorizeLaunch: (launch) => authorizeVerifiedLaunchForRegistry(registry, launch),
    renderResourceLink: (context) => {
      return handleAuthorizedPackageLaunch({
        c: input.c,
        db,
        ltiTool,
        launch: context.launch,
        session: context.session,
        launchMessage: resolveLtiLaunchMessage(context.launch.payload),
        sha256Hex: input.sha256Hex,
        createLtiSession: input.createLtiSession,
        handleVerifiedLtiLaunch: runVerifiedLaunch,
      });
    },
    renderDeepLinkingRequest: (context) => {
      return handleAuthorizedPackageLaunch({
        c: input.c,
        db,
        ltiTool,
        launch: context.launch,
        session: context.session,
        launchMessage: resolveLtiLaunchMessage(context.launch.payload),
        sha256Hex: input.sha256Hex,
        createLtiSession: input.createLtiSession,
        handleVerifiedLtiLaunch: runVerifiedLaunch,
      });
    },
    onError: ({ error }) => handleLtiLaunchFailureResponse(input.c, error),
  });

  return handler(input.c, async () => undefined);
};
