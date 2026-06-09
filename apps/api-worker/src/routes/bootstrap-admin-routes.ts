import { createDidDocument, createDidWeb, type Ed25519PublicJwk } from "@credtrail/core-domain";
import {
  upsertBadgeTemplateById,
  upsertTenantSigningRegistration,
  upsertTenant,
  type BadgeTemplateRecord,
  type SqlDatabase,
  type TenantRecord,
  type TenantSigningRegistrationRecord,
} from "@credtrail/db";
import {
  isValidationParseError,
  parseBootstrapTenantRequest,
  parseBootstrapSigningRegistrationRequest,
  parseCreateBadgeTemplateRequest,
  type BootstrapTenantRequest,
  type BootstrapSigningRegistrationRequest,
  type CreateBadgeTemplateRequest,
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

const validationErrorResponse = (
  c: AppContext,
  input: {
    error: string;
    issues: { path: (string | number | symbol)[]; message: string }[];
  },
): Response => {
  return c.json(
    {
      error: input.error,
      details: input.issues.map((issue) => ({
        path: issue.path.map((segment) => String(segment)),
        message: issue.message,
      })),
    },
    400,
  );
};

const readBootstrapTenantRequest = async (
  c: AppContext,
): Promise<BootstrapTenantRequest | Response> => {
  const payload = await c.req.json<unknown>();

  try {
    return parseBootstrapTenantRequest(payload);
  } catch (error) {
    if (isValidationParseError(error)) {
      return validationErrorResponse(c, {
        error: "Invalid tenant bootstrap payload",
        issues: error.issues,
      });
    }

    throw error;
  }
};

const readBadgeTemplateRequest = async (
  c: AppContext,
): Promise<CreateBadgeTemplateRequest | Response> => {
  const payload = await c.req.json<unknown>();

  try {
    return parseCreateBadgeTemplateRequest(payload);
  } catch (error) {
    if (isValidationParseError(error)) {
      return validationErrorResponse(c, {
        error: "Invalid badge template bootstrap payload",
        issues: error.issues,
      });
    }

    throw error;
  }
};

const readSigningRegistrationRequest = async (
  c: AppContext,
): Promise<BootstrapSigningRegistrationRequest | Response> => {
  const payload = await c.req.json<unknown>();

  try {
    return parseBootstrapSigningRegistrationRequest(payload);
  } catch (error) {
    if (isValidationParseError(error)) {
      return validationErrorResponse(c, {
        error: "Invalid signing registration payload",
        issues: error.issues,
      });
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

const tenantBootstrapResponse = (tenant: TenantRecord): Record<string, unknown> => {
  return {
    tenantId: tenant.id,
    slug: tenant.slug,
    displayName: tenant.displayName,
    planTier: tenant.planTier,
    issuerDomain: tenant.issuerDomain,
    didWeb: tenant.didWeb,
    isActive: tenant.isActive,
    createdAt: tenant.createdAt,
    updatedAt: tenant.updatedAt,
  };
};

const badgeTemplateBootstrapResponse = (template: BadgeTemplateRecord): Record<string, unknown> => {
  return {
    id: template.id,
    tenantId: template.tenantId,
    slug: template.slug,
    title: template.title,
    description: template.description,
    criteriaUri: template.criteriaUri,
    imageUri: template.imageUri,
    ownerOrgUnitId: template.ownerOrgUnitId,
    isArchived: template.isArchived,
    createdAt: template.createdAt,
    updatedAt: template.updatedAt,
  };
};

export const registerBootstrapAdminRoutes = (input: RegisterBootstrapAdminRoutesInput): void => {
  const { app, resolveDatabase } = input;

  app.put("/v1/admin/tenants/:tenantId", async (c): Promise<Response> => {
    const authorizationFailure = authorizeBootstrapAdminRequest(c);

    if (authorizationFailure !== null) {
      return authorizationFailure;
    }

    const request = await readBootstrapTenantRequest(c);

    if (request instanceof Response) {
      return request;
    }

    const tenantId = c.req.param("tenantId");
    const did = createDidWeb({ host: c.env.PLATFORM_DOMAIN, pathSegments: [tenantId] });
    const tenant = await upsertTenant(resolveDatabase(c.env), {
      id: tenantId,
      slug: request.slug,
      displayName: request.displayName,
      planTier: request.planTier,
      issuerDomain: request.issuerDomain,
      didWeb: did,
      isActive: request.isActive ?? true,
    });

    return c.json(tenantBootstrapResponse(tenant), 201);
  });

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
    const db = resolveDatabase(c.env);
    await upsertTenant(db, {
      id: "platform",
      slug: "platform",
      displayName: "CredTrail Platform",
      planTier: "enterprise",
      issuerDomain: c.env.PLATFORM_DOMAIN,
      didWeb: did,
      isActive: true,
    });
    const registration = await upsertTenantSigningRegistration(db, {
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

  app.put(
    "/v1/admin/tenants/:tenantId/badge-templates/:badgeTemplateId",
    async (c): Promise<Response> => {
      const authorizationFailure = authorizeBootstrapAdminRequest(c);

      if (authorizationFailure !== null) {
        return authorizationFailure;
      }

      const request = await readBadgeTemplateRequest(c);

      if (request instanceof Response) {
        return request;
      }

      const template = await upsertBadgeTemplateById(resolveDatabase(c.env), {
        id: c.req.param("badgeTemplateId"),
        tenantId: c.req.param("tenantId"),
        slug: request.slug,
        title: request.title,
        ...(request.description === undefined ? {} : { description: request.description }),
        ...(request.criteriaUri === undefined ? {} : { criteriaUri: request.criteriaUri }),
        ...(request.imageUri === undefined ? {} : { imageUri: request.imageUri }),
        ...(request.trustedCredentialMetadata === undefined
          ? {}
          : { trustedCredentialMetadataJson: JSON.stringify(request.trustedCredentialMetadata) }),
        ...(request.ownerOrgUnitId === undefined ? {} : { ownerOrgUnitId: request.ownerOrgUnitId }),
      });

      return c.json(badgeTemplateBootstrapResponse(template), 201);
    },
  );
};
