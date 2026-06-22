import {
  DynamicRegistrationFormSchema,
  RegistrationRequestSchema,
  type LTITool,
  type LTIConfig,
} from "@lti-tool/core";
import { isLtiIssuerTenantConflictError, type SqlDatabase } from "@credtrail/db";
import { parseLtiDynamicRegistrationPathParams } from "@credtrail/validation";
import type { AppBindings } from "../app";
import { LTI_LAUNCH_PATH, LTI_OIDC_LOGIN_PATH } from "./constants";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";
import {
  createLtiDynamicRegistrationInviteToken,
  ltiDynamicRegistrationPath,
  ltiDynamicRegistrationUrl,
  verifyLtiDynamicRegistrationInviteToken,
} from "./dynamic-registration-invite";

type DynamicRegistrationConfig = NonNullable<LTIConfig["dynamicRegistration"]>;

export const LTI_DYNAMIC_REGISTRATION_ROUTE_PATH =
  "/v1/tenants/:tenantId/lti/dynamic-registration/:inviteToken";
export const LTI_DYNAMIC_REGISTRATION_COMPLETE_ROUTE_PATH = `${LTI_DYNAMIC_REGISTRATION_ROUTE_PATH}/complete`;

export type LtiDynamicRegistrationFailureReason =
  | "invalid_path"
  | "not_configured"
  | "invalid_invite"
  | "invalid_initiate_request"
  | "invalid_completion"
  | "initiate_failed"
  | "complete_failed"
  | "issuer_tenant_conflict";

export interface LtiDynamicRegistrationFailure {
  reason: LtiDynamicRegistrationFailureReason;
  message: string;
}

export type LtiDynamicRegistrationServiceResult<TValue> =
  | {
      ok: true;
      value: TValue;
    }
  | {
      ok: false;
      failure: LtiDynamicRegistrationFailure;
    };

export interface LtiDynamicRegistrationContext {
  tenantId: string;
  inviteToken: string;
  registrationCallbackPath: string;
  ltiTool: LTITool;
}

const serviceFailure = (
  reason: LtiDynamicRegistrationFailureReason,
  message: string,
): LtiDynamicRegistrationServiceResult<never> => {
  return {
    ok: false,
    failure: {
      reason,
      message,
    },
  };
};

const serviceSuccess = <TValue>(value: TValue): LtiDynamicRegistrationServiceResult<TValue> => {
  return {
    ok: true,
    value,
  };
};

const publicPlatformOrigin = (platformDomain: string): string => {
  const trimmed = platformDomain.trim();
  const baseUrl = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  return new URL("/", baseUrl).origin;
};

const publicPlatformUrl = (env: Pick<AppBindings, "PLATFORM_DOMAIN">, path: string): string => {
  return new URL(path, publicPlatformOrigin(env.PLATFORM_DOMAIN)).toString();
};

export const buildLtiDynamicRegistrationConfig = (
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

export const buildTenantLtiDynamicRegistrationInviteUrl = async (
  env: AppBindings,
  tenantId: string,
): Promise<string | null> => {
  const signingSecret = env.LTI_STATE_SIGNING_SECRET?.trim();

  if (signingSecret === undefined || signingSecret.length === 0) {
    return null;
  }

  const inviteToken = await createLtiDynamicRegistrationInviteToken(env, {
    tenantId,
  });

  return ltiDynamicRegistrationUrl({
    platformDomain: env.PLATFORM_DOMAIN,
    tenantId,
    inviteToken,
  });
};

export const ltiDynamicRegistrationFailureStatusCode = (
  reason: LtiDynamicRegistrationFailureReason,
): 400 | 403 | 409 | 500 => {
  switch (reason) {
    case "invalid_invite":
      return 403;
    case "not_configured":
      return 500;
    case "issuer_tenant_conflict":
      return 409;
    case "invalid_path":
    case "invalid_initiate_request":
    case "invalid_completion":
    case "initiate_failed":
    case "complete_failed":
      return 400;
  }
};

export const openLtiDynamicRegistrationContext = async (input: {
  db: SqlDatabase;
  env: AppBindings;
  rawPathParams: Record<string, string>;
}): Promise<LtiDynamicRegistrationServiceResult<LtiDynamicRegistrationContext>> => {
  let pathParams: ReturnType<typeof parseLtiDynamicRegistrationPathParams>;

  try {
    pathParams = parseLtiDynamicRegistrationPathParams(input.rawPathParams);
  } catch {
    return serviceFailure("invalid_path", "Invalid LTI dynamic registration path");
  }

  let invite;

  try {
    invite = await verifyLtiDynamicRegistrationInviteToken(input.env, pathParams.inviteToken);
  } catch {
    return serviceFailure("not_configured", "LTI dynamic registration is not configured");
  }

  if (invite === null || invite.tenantId !== pathParams.tenantId) {
    return serviceFailure("invalid_invite", "Invalid or expired LTI dynamic registration link");
  }

  const ltiTool = await createCredTrailLtiTool({
    db: input.db,
    env: input.env,
    defaultTenantId: pathParams.tenantId,
    dynamicRegistration: buildLtiDynamicRegistrationConfig(input.env),
  });

  return serviceSuccess({
    tenantId: pathParams.tenantId,
    inviteToken: pathParams.inviteToken,
    registrationCallbackPath: ltiDynamicRegistrationPath(
      pathParams.tenantId,
      pathParams.inviteToken,
    ),
    ltiTool,
  });
};

export const initiateLtiDynamicRegistration = async (
  context: LtiDynamicRegistrationContext,
  query: Record<string, string>,
): Promise<LtiDynamicRegistrationServiceResult<string>> => {
  let registrationRequest;

  try {
    registrationRequest = RegistrationRequestSchema.parse(query);
  } catch {
    return serviceFailure("invalid_initiate_request", "Invalid LTI dynamic registration request");
  }

  try {
    const responseHtml = await context.ltiTool.initiateDynamicRegistration(
      registrationRequest,
      context.registrationCallbackPath,
    );

    return serviceSuccess(responseHtml);
  } catch (error) {
    return serviceFailure(
      "initiate_failed",
      error instanceof Error ? error.message : "Unable to initiate LTI dynamic registration",
    );
  }
};

export const completeLtiDynamicRegistration = async (
  context: LtiDynamicRegistrationContext,
  form: FormData,
): Promise<LtiDynamicRegistrationServiceResult<string>> => {
  const services = form.getAll("services");
  let dynamicRegistrationForm;

  try {
    dynamicRegistrationForm = DynamicRegistrationFormSchema.parse({
      services,
      sessionToken: form.get("sessionToken"),
    });
  } catch {
    return serviceFailure("invalid_completion", "Invalid LTI dynamic registration completion");
  }

  try {
    const responseHtml = await context.ltiTool.completeDynamicRegistration(dynamicRegistrationForm);
    return serviceSuccess(responseHtml);
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Unable to complete LTI dynamic registration";

    if (isLtiIssuerTenantConflictError(error)) {
      return serviceFailure("issuer_tenant_conflict", errorMessage);
    }

    return serviceFailure("complete_failed", errorMessage);
  }
};
