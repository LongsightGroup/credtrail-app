import type { SqlDatabase } from "@credtrail/db";
import { isValidationParseError } from "@credtrail/validation";
import type {
  LtiAuthorizedLaunch,
  LtiLaunchVerificationError as CoreLtiLaunchVerificationError,
  LTISession,
  LtiToolPort,
} from "@longsightgroup/lti-tool";
import { LtiLaunchMessageResolutionError } from "@longsightgroup/lti-tool";
import { customLaunchRouteHandler } from "@longsightgroup/lti-tool/hono";
import type { AppContext } from "../app";
import type { ResolveDatabase } from "../app/route-deps";
import type { LtiAuthenticatedPrincipal, LtiSessionInput } from "../auth/auth-provider";
import { jsonError } from "../http/json-responses";
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
  LtiLaunchVerificationError,
  type LtiLaunchAuthorization,
  type ResolvedLtiLaunch,
  ltiLaunchVerificationErrorFromCoreError,
} from "./launch-verification";
import type { LtiIssuerRegistry } from "./lti-issuer-registry";

type CreateCredTrailLtiToolForLaunch = (input: CreateCredTrailLtiToolInput) => Promise<LtiToolPort>;

export interface HandleLtiLaunchPostInput {
  c: AppContext;
  resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: ResolveDatabase;
  sha256Hex: (value: string) => Promise<string>;
  createLtiSession: (
    context: AppContext,
    input: LtiSessionInput,
  ) => Promise<LtiAuthenticatedPrincipal>;
  handleVerifiedLtiLaunch?: HandleVerifiedLtiLaunch;
  createLtiTool?: CreateCredTrailLtiToolForLaunch;
}

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
    return jsonError(c, error.status, error.message);
  }

  if (error instanceof LtiLaunchMessageResolutionError) {
    return jsonError(c, 400, error.message);
  }

  if (isValidationParseError(error)) {
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

const handleLtiLaunchVerificationFailureResponse = (
  c: AppContext,
  error: CoreLtiLaunchVerificationError,
): Response => {
  return handleLtiLaunchFailureResponse(c, ltiLaunchVerificationErrorFromCoreError(error));
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
    registry = await input.resolveLtiIssuerRegistry(input.c);
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

  const renderAuthorizedPackageLaunch = (context: {
    launch: LtiAuthorizedLaunch<LtiLaunchAuthorization>;
    session: LTISession;
  }): Promise<Response> => {
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
  };

  const handler = customLaunchRouteHandler<LtiLaunchAuthorization>({
    ltiTool,
    logger: createLtiHonoLogger({ c: input.c }),
    authorizeLaunch: (launch) => authorizeVerifiedLaunchForRegistry(registry, launch),
    onVerificationFailure: ({ error }) =>
      handleLtiLaunchVerificationFailureResponse(input.c, error),
    renderResourceLink: renderAuthorizedPackageLaunch,
    renderDeepLinkingRequest: renderAuthorizedPackageLaunch,
    onError: ({ error }) => handleLtiLaunchFailureResponse(input.c, error),
  });

  return handler(input.c, async () => undefined);
};
