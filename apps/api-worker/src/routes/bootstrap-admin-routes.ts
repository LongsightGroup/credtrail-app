import { createDidDocument, createDidWeb, type Ed25519PublicJwk } from "@credtrail/core-domain";
import {
  upsertTenantSigningRegistration,
  type SqlDatabase,
  type TenantSigningRegistrationRecord,
} from "@credtrail/db";
import {
  isValidationParseError,
  parseBootstrapSigningRegistrationRequest,
  type BootstrapSigningRegistrationRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app";

interface RegisterBootstrapAdminRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppContext["env"]) => SqlDatabase;
}

const authorizeBootstrapAdminRequest = (c: AppContext): Response | null => {
  const configuredToken = c.env.BOOTSTRAP_ADMIN_TOKEN?.trim();

  if (configuredToken === undefined || configuredToken.length === 0) {
    return c.json(
      {
        error: "Route unavailable",
      },
      404,
    );
  }

  if (c.req.header("authorization") !== `Bearer ${configuredToken}`) {
    return c.json(
      {
        error: "Unauthorized",
      },
      401,
    );
  }

  return null;
};

const readSigningRegistrationRequest = async (
  c: AppContext,
): Promise<BootstrapSigningRegistrationRequest | Response> => {
  const payload = await c.req.json<unknown>();

  try {
    return parseBootstrapSigningRegistrationRequest(payload);
  } catch (error) {
    if (isValidationParseError(error)) {
      return c.json(
        {
          error: "Invalid signing registration payload",
          details: error.issues.map((issue) => ({
            path: issue.path.map((segment) => String(segment)),
            message: issue.message,
          })),
        },
        400,
      );
    }

    throw error;
  }
};

const coreDomainPublicJwk = (
  publicJwk: BootstrapSigningRegistrationRequest["publicJwk"],
): Ed25519PublicJwk => {
  return {
    kty: publicJwk.kty,
    crv: publicJwk.crv,
    x: publicJwk.x,
    ...(publicJwk.kid === undefined ? {} : { kid: publicJwk.kid }),
  };
};

const signingRegistrationResponse = (input: {
  did: string;
  registration: TenantSigningRegistrationRecord;
  request: BootstrapSigningRegistrationRequest;
}): Record<string, unknown> => {
  return {
    tenantId: input.registration.tenantId,
    did: input.registration.did,
    keyId: input.registration.keyId,
    didDocument: createDidDocument({
      did: input.did,
      keyId: input.request.keyId,
      publicJwk: coreDomainPublicJwk(input.request.publicJwk),
    }),
  };
};

export const registerBootstrapAdminRoutes = (input: RegisterBootstrapAdminRoutesInput): void => {
  const { app, resolveDatabase } = input;

  app.put("/v1/admin/platform/signing-registration", async (c): Promise<Response> => {
    const authorizationFailure = authorizeBootstrapAdminRequest(c);

    if (authorizationFailure !== null) {
      return authorizationFailure;
    }

    const request = await readSigningRegistrationRequest(c);

    if (request instanceof Response) {
      return request;
    }

    const did = createDidWeb({ host: c.env.PLATFORM_DOMAIN });
    const registration = await upsertTenantSigningRegistration(resolveDatabase(c.env), {
      tenantId: "platform",
      did,
      keyId: request.keyId,
      publicJwkJson: JSON.stringify(request.publicJwk),
      ...(request.privateJwk === undefined
        ? {}
        : { privateJwkJson: JSON.stringify(request.privateJwk) }),
    });

    return c.json(signingRegistrationResponse({ did, registration, request }), 201);
  });

  app.put("/v1/admin/tenants/:tenantId/signing-registration", async (c): Promise<Response> => {
    const authorizationFailure = authorizeBootstrapAdminRequest(c);

    if (authorizationFailure !== null) {
      return authorizationFailure;
    }

    const request = await readSigningRegistrationRequest(c);

    if (request instanceof Response) {
      return request;
    }

    const tenantId = c.req.param("tenantId");
    const did = createDidWeb({ host: c.env.PLATFORM_DOMAIN, pathSegments: [tenantId] });
    const registration = await upsertTenantSigningRegistration(resolveDatabase(c.env), {
      tenantId,
      did,
      keyId: request.keyId,
      publicJwkJson: JSON.stringify(request.publicJwk),
      ...(request.privateJwk === undefined
        ? {}
        : { privateJwkJson: JSON.stringify(request.privateJwk) }),
    });

    return c.json(signingRegistrationResponse({ did, registration, request }), 201);
  });
};
