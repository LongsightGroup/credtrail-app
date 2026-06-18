import {
  DynamicRegistrationFormSchema,
  RegistrationRequestSchema,
  type LTIConfig,
} from "@lti-tool/core";
import { isLtiIssuerTenantConflictError, type SqlDatabase } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import { parseLtiDynamicRegistrationPathParams } from "@credtrail/validation";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";
import { LTI_LAUNCH_PATH, LTI_OIDC_LOGIN_PATH } from "./constants";
import {
  ltiDynamicRegistrationPath,
  verifyLtiDynamicRegistrationInviteToken,
} from "./dynamic-registration-invite";

type DynamicRegistrationConfig = NonNullable<LTIConfig["dynamicRegistration"]>;

interface RegisterLtiDynamicRegistrationRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
}

const LTI_DYNAMIC_REGISTRATION_ROUTE_PATH =
  "/v1/tenants/:tenantId/lti/dynamic-registration/:inviteToken";
const LTI_DYNAMIC_REGISTRATION_COMPLETE_ROUTE_PATH = `${LTI_DYNAMIC_REGISTRATION_ROUTE_PATH}/complete`;

const publicPlatformOrigin = (platformDomain: string): string => {
  const trimmed = platformDomain.trim();
  const baseUrl = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  return new URL("/", baseUrl).origin;
};

const publicPlatformUrl = (env: Pick<AppBindings, "PLATFORM_DOMAIN">, path: string): string => {
  return new URL(path, publicPlatformOrigin(env.PLATFORM_DOMAIN)).toString();
};

const ltiDynamicRegistrationConfig = (
  env: Pick<AppBindings, "PLATFORM_DOMAIN">,
): DynamicRegistrationConfig => {
  const launchUrl = publicPlatformUrl(env, LTI_LAUNCH_PATH);

  return {
    url: launchUrl,
    name: "CredTrail",
    description: "CredTrail badge and credential issuing for LMS courses.",
    loginUri: publicPlatformUrl(env, LTI_OIDC_LOGIN_PATH),
    launchUri: launchUrl,
    jwksUri: publicPlatformUrl(env, "/v1/lti/jwks"),
    deepLinkingUri: launchUrl,
    platforms: {
      canvas: {
        privacyLevel: "public",
        vendor: "CredTrail",
        resourceLinkPlacements: ["course_navigation"],
      },
    },
  };
};

const verifyDynamicRegistrationInviteForRequest = async (
  c: AppContext,
): Promise<
  | Response
  | {
      tenantId: string;
      inviteToken: string;
    }
> => {
  let pathParams: ReturnType<typeof parseLtiDynamicRegistrationPathParams>;

  try {
    pathParams = parseLtiDynamicRegistrationPathParams(c.req.param());
  } catch {
    return c.json(
      {
        error: "Invalid LTI dynamic registration path",
      },
      400,
    );
  }

  let invite;

  try {
    invite = await verifyLtiDynamicRegistrationInviteToken(c.env, pathParams.inviteToken);
  } catch {
    return c.json(
      {
        error: "LTI dynamic registration is not configured",
      },
      500,
    );
  }

  if (invite === null || invite.tenantId !== pathParams.tenantId) {
    return c.json(
      {
        error: "Invalid or expired LTI dynamic registration link",
      },
      403,
    );
  }

  return {
    tenantId: pathParams.tenantId,
    inviteToken: pathParams.inviteToken,
  };
};

export const registerLtiDynamicRegistrationRoutes = (
  input: RegisterLtiDynamicRegistrationRoutesInput,
): void => {
  const { app, resolveDatabase } = input;

  app.get(LTI_DYNAMIC_REGISTRATION_ROUTE_PATH, async (c): Promise<Response> => {
    const verifiedInvite = await verifyDynamicRegistrationInviteForRequest(c);

    if (verifiedInvite instanceof Response) {
      return verifiedInvite;
    }

    let registrationRequest;

    try {
      registrationRequest = RegistrationRequestSchema.parse(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid LTI dynamic registration request",
        },
        400,
      );
    }

    const db = resolveDatabase(c.env);
    const ltiTool = await createCredTrailLtiTool({
      db,
      env: c.env,
      defaultTenantId: verifiedInvite.tenantId,
      dynamicRegistration: ltiDynamicRegistrationConfig(c.env),
    });

    try {
      const responseHtml = await ltiTool.initiateDynamicRegistration(
        registrationRequest,
        ltiDynamicRegistrationPath(verifiedInvite.tenantId, verifiedInvite.inviteToken),
      );
      c.header("Cache-Control", "no-store");
      return c.body(responseHtml, 200, {
        "Content-Type": "text/html; charset=UTF-8",
      });
    } catch (error) {
      return c.json(
        {
          error:
            error instanceof Error ? error.message : "Unable to initiate LTI dynamic registration",
        },
        400,
      );
    }
  });

  app.post(LTI_DYNAMIC_REGISTRATION_COMPLETE_ROUTE_PATH, async (c): Promise<Response> => {
    const verifiedInvite = await verifyDynamicRegistrationInviteForRequest(c);

    if (verifiedInvite instanceof Response) {
      return verifiedInvite;
    }

    const form = await c.req.formData();
    const services = form.getAll("services");
    let dynamicRegistrationForm;

    try {
      dynamicRegistrationForm = DynamicRegistrationFormSchema.parse({
        services,
        sessionToken: form.get("sessionToken"),
      });
    } catch {
      return c.json(
        {
          error: "Invalid LTI dynamic registration completion",
        },
        400,
      );
    }

    const db = resolveDatabase(c.env);
    const ltiTool = await createCredTrailLtiTool({
      db,
      env: c.env,
      defaultTenantId: verifiedInvite.tenantId,
      dynamicRegistration: ltiDynamicRegistrationConfig(c.env),
    });

    try {
      const responseHtml = await ltiTool.completeDynamicRegistration(dynamicRegistrationForm);
      c.header("Cache-Control", "no-store");
      return c.body(responseHtml, 200, {
        "Content-Type": "text/html; charset=UTF-8",
      });
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unable to complete LTI dynamic registration";

      if (isLtiIssuerTenantConflictError(error)) {
        return c.json(
          {
            error: errorMessage,
          },
          409,
        );
      }

      return c.json(
        {
          error: errorMessage,
        },
        400,
      );
    }
  });
};
