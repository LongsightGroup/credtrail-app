import type { SqlDatabase } from "@credtrail/db";
import type { AppBindings, AppContext } from "../app";
import type { LtiAuthenticatedPrincipal, LtiSessionInput } from "../auth/auth-provider";
import {
  LtiLaunchMessageError,
  resolveLtiLaunchMessage,
  type ResolvedLtiLaunchMessage,
} from "./launch-message";
import { handleVerifiedLtiLaunch, type HandleVerifiedLtiLaunch } from "./launch-product-flow";
import {
  LtiLaunchVerificationError,
  resolveLtiLaunch,
  type ResolvedLtiLaunch,
} from "./launch-verification";
import { ltiLaunchFormInputFromRequest, type LtiIssuerRegistry } from "./lti-helpers";

type LtiLaunchPostFormInput = {
  idToken: string | null;
  state: string | null;
};

interface LtiLaunchPostProtocolHandlers {
  readLaunchForm: (c: AppContext) => Promise<LtiLaunchPostFormInput>;
  resolveLaunch: typeof resolveLtiLaunch;
  resolveLaunchMessage: typeof resolveLtiLaunchMessage;
}

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
  protocolHandlers?: Partial<LtiLaunchPostProtocolHandlers>;
}

interface ValidatedLtiLaunchPostForm {
  idToken: string;
  state: string;
}

const ltiLaunchVerificationErrorResponse = (
  c: AppContext,
  error: LtiLaunchVerificationError,
): Response => {
  return c.json(
    {
      error: error.message,
      ...(error.detail === undefined ? {} : { detail: error.detail }),
    },
    error.status,
  );
};

const validateLtiLaunchPostForm = (
  c: AppContext,
  formInput: {
    idToken: string | null;
    state: string | null;
  },
): Response | ValidatedLtiLaunchPostForm => {
  if (formInput.idToken === null || formInput.idToken.trim().length === 0) {
    return c.json(
      {
        error: "id_token is required",
      },
      400,
    );
  }

  if (formInput.state === null || formInput.state.trim().length === 0) {
    return c.json(
      {
        error: "state is required",
      },
      400,
    );
  }

  return {
    idToken: formInput.idToken,
    state: formInput.state,
  };
};

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

const verifyLtiLaunchPost = async (input: {
  c: AppContext;
  form: ValidatedLtiLaunchPostForm;
  registry: LtiIssuerRegistry;
  db: SqlDatabase;
  resolveLaunch: typeof resolveLtiLaunch;
}): Promise<ResolvedLtiLaunch> => {
  return input.resolveLaunch({
    idToken: input.form.idToken,
    state: input.form.state,
    registry: input.registry,
    db: input.db,
    env: input.c.env,
  });
};

const defaultProtocolHandlers: LtiLaunchPostProtocolHandlers = {
  readLaunchForm: ltiLaunchFormInputFromRequest,
  resolveLaunch: resolveLtiLaunch,
  resolveLaunchMessage: resolveLtiLaunchMessage,
};

export const handleLtiLaunchPost = async (input: HandleLtiLaunchPostInput): Promise<Response> => {
  const runVerifiedLaunch = input.handleVerifiedLtiLaunch ?? handleVerifiedLtiLaunch;
  const protocolHandlers = {
    ...defaultProtocolHandlers,
    ...input.protocolHandlers,
  };
  const formValidation = validateLtiLaunchPostForm(
    input.c,
    await protocolHandlers.readLaunchForm(input.c),
  );

  if (formValidation instanceof Response) {
    return formValidation;
  }

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

  let resolvedLaunch: ResolvedLtiLaunch;

  try {
    resolvedLaunch = await verifyLtiLaunchPost({
      c: input.c,
      form: formValidation,
      registry,
      db,
      resolveLaunch: protocolHandlers.resolveLaunch,
    });
  } catch (error) {
    if (error instanceof LtiLaunchVerificationError) {
      return ltiLaunchVerificationErrorResponse(input.c, error);
    }

    throw error;
  }

  let launchMessage: ResolvedLtiLaunchMessage;

  try {
    launchMessage = protocolHandlers.resolveLaunchMessage(resolvedLaunch.launchClaims);
  } catch (error) {
    if (error instanceof LtiLaunchMessageError) {
      return input.c.json({ error: error.message }, error.status);
    }

    throw error;
  }

  return runVerifiedLaunch({
    c: input.c,
    db,
    tenantId: resolvedLaunch.issuerEntry.tenantId,
    resolvedLaunch,
    launchMessage,
    sha256Hex: input.sha256Hex,
    createLtiSession: input.createLtiSession,
  });
};
