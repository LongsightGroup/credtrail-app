import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import type { SqlDatabase } from "@credtrail/db";
import {
  LTI_DYNAMIC_REGISTRATION_COMPLETE_ROUTE_PATH,
  LTI_DYNAMIC_REGISTRATION_ROUTE_PATH,
  completeLtiDynamicRegistration,
  initiateLtiDynamicRegistration,
  ltiDynamicRegistrationFailureStatusCode,
  openLtiDynamicRegistrationContext,
  type LtiDynamicRegistrationContext,
  type LtiDynamicRegistrationFailure,
} from "./dynamic-registration-service";

interface RegisterLtiDynamicRegistrationRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
}

const respondWithLtiDynamicRegistrationFailure = (
  c: AppContext,
  failure: LtiDynamicRegistrationFailure,
): Response => {
  return c.json(
    {
      error: failure.message,
    },
    ltiDynamicRegistrationFailureStatusCode(failure.reason),
  );
};

const handleLtiDynamicRegistrationRequest = async (
  c: AppContext,
  resolveDatabase: (bindings: AppBindings) => SqlDatabase,
  run: (context: LtiDynamicRegistrationContext) => Promise<Response | { html: string }>,
): Promise<Response> => {
  const contextResult = await openLtiDynamicRegistrationContext({
    db: resolveDatabase(c.env),
    env: c.env,
    rawPathParams: c.req.param(),
  });

  if (!contextResult.ok) {
    return respondWithLtiDynamicRegistrationFailure(c, contextResult.failure);
  }

  const actionResult = await run(contextResult.value);

  if (actionResult instanceof Response) {
    return actionResult;
  }

  c.header("Cache-Control", "no-store");
  return c.body(actionResult.html, 200, {
    "Content-Type": "text/html; charset=UTF-8",
  });
};

export const registerLtiDynamicRegistrationRoutes = (
  input: RegisterLtiDynamicRegistrationRoutesInput,
): void => {
  const { app, resolveDatabase } = input;

  app.get(LTI_DYNAMIC_REGISTRATION_ROUTE_PATH, async (c): Promise<Response> => {
    return handleLtiDynamicRegistrationRequest(c, resolveDatabase, async (context) => {
      const initiateResult = await initiateLtiDynamicRegistration(context, c.req.query());

      if (!initiateResult.ok) {
        return respondWithLtiDynamicRegistrationFailure(c, initiateResult.failure);
      }

      return {
        html: initiateResult.value,
      };
    });
  });

  app.post(LTI_DYNAMIC_REGISTRATION_COMPLETE_ROUTE_PATH, async (c): Promise<Response> => {
    const form = await c.req.formData();

    return handleLtiDynamicRegistrationRequest(c, resolveDatabase, async (context) => {
      const completeResult = await completeLtiDynamicRegistration(context, form);

      if (!completeResult.ok) {
        return respondWithLtiDynamicRegistrationFailure(c, completeResult.failure);
      }

      return {
        html: completeResult.value,
      };
    });
  });
};
