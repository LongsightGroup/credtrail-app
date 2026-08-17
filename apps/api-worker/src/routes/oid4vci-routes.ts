import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import {
  consumeOid4vciPreAuthorizedCode,
  createOid4vciAccessToken,
  createOid4vciPreAuthorizedCode,
  findActiveOid4vciAccessTokenByHash,
  recordAssertionEngagementEvent,
  type SqlDatabase,
} from "@credtrail/db";
import type { Hono } from "hono";
import { z } from "zod";
import type { AppContext, AppEnv } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import type { PublicBadgeViewModel, VerificationViewModel } from "../badges/public-badge-model";
import { VC_DATA_MODEL_CONTEXT_URL } from "../credentials/verification-checks";
import { canonicalAppRequestUrl } from "../http/canonical-app-url";

const PRE_AUTHORIZED_CODE_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const OID4VCI_TOKEN_ENDPOINT_PATH = "/credentials/v1/token";
const OID4VCI_CREDENTIAL_ENDPOINT_PATH = "/credentials/v1/credentials";
const DCC_VCAPI_EXCHANGE_ENDPOINT_PREFIX = "/credentials/v1/dcc/exchanges";
const oid4vciOfferRequestSchema = z.strictObject({
  badgeIdentifier: z.string().trim().min(1),
});
const oid4vciCredentialRequestSchema = z.strictObject({
  format: z.string().trim().min(1).optional(),
  credential_identifier: z.string().trim().min(1).optional(),
});

const publicRequestUrl = (c: AppContext): string => {
  return canonicalAppRequestUrl(c.env.PUBLIC_APP_ORIGIN, c.req.url);
};

interface RegisterOid4vciRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  loadPublicBadgeViewModel: (
    db: SqlDatabase,
    badgeObjects: ImmutableCredentialStore,
    badgeIdentifier: string,
  ) => Promise<
    | {
        status: "not_found";
      }
    | {
        status: "ok";
        value: PublicBadgeViewModel;
      }
  >;
  loadVerificationViewModel: (
    db: SqlDatabase,
    badgeObjects: ImmutableCredentialStore,
    credentialId: string,
  ) => Promise<
    | {
        status: "invalid_id" | "not_found";
      }
    | {
        status: "ok";
        value: VerificationViewModel;
      }
  >;
  walletCredentialOfferPayload: (
    requestUrl: string,
    model: PublicBadgeViewModel,
    options: {
      preAuthorizedCode: string;
      offerExpiresAt: string;
      tokenEndpointPath: string;
      credentialEndpointPath: string;
    },
  ) => Record<string, unknown>;
  asNonEmptyString: (value: unknown) => string | null;
  generateOpaqueToken: () => string;
  sha256Hex: (value: string) => Promise<string>;
  addSecondsToIso: (isoTimestamp: string, seconds: number) => string;
  preAuthorizedCodeTtlSeconds: number;
  accessTokenTtlSeconds: number;
}

interface Oid4vciErrorPayload {
  error: string;
  error_description?: string | undefined;
}

const oid4vciErrorJson = (
  c: AppContext,
  status: 400 | 401 | 403 | 404,
  error: string,
  errorDescription?: string,
): Response => {
  const payload: Oid4vciErrorPayload =
    errorDescription === undefined
      ? { error }
      : {
          error,
          error_description: errorDescription,
        };

  if (status === 401) {
    c.header("WWW-Authenticate", `Bearer error="${error}"`);
  }

  return c.json(payload, status);
};

const extractBearerToken = (authorizationHeader: string | undefined): string | null => {
  if (authorizationHeader === undefined) {
    return null;
  }

  const [scheme, token] = authorizationHeader.trim().split(/\s+/, 2);

  if (scheme !== "Bearer" || token === undefined || token.length === 0) {
    return null;
  }

  return token;
};

export const registerOid4vciRoutes = (input: RegisterOid4vciRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    loadPublicBadgeViewModel,
    loadVerificationViewModel,
    walletCredentialOfferPayload,
    asNonEmptyString,
    generateOpaqueToken,
    sha256Hex,
    addSecondsToIso,
    preAuthorizedCodeTtlSeconds,
    accessTokenTtlSeconds,
  } = input;

  const buildIssuerMetadata = (requestUrl: string): Record<string, unknown> => {
    const baseUrl = new URL(requestUrl);
    const credentialEndpoint = new URL(OID4VCI_CREDENTIAL_ENDPOINT_PATH, baseUrl).toString();
    const tokenEndpoint = new URL(OID4VCI_TOKEN_ENDPOINT_PATH, baseUrl).toString();

    return {
      credential_issuer: baseUrl.origin,
      credential_endpoint: credentialEndpoint,
      token_endpoint: tokenEndpoint,
      credential_configurations_supported: {
        OpenBadgeCredential: {
          format: "ldp_vc",
          scope: "OpenBadgeCredential",
          credential_definition: {
            "@context": [VC_DATA_MODEL_CONTEXT_URL],
            type: ["VerifiableCredential", "OpenBadgeCredential"],
          },
        },
      },
      credentials_supported: [
        {
          id: "OpenBadgeCredential",
          format: "ldp_vc",
          types: ["VerifiableCredential", "OpenBadgeCredential"],
        },
      ],
      grants_supported: [PRE_AUTHORIZED_CODE_GRANT],
      x_credtrail: {
        credential_offer_create_endpoint: new URL("/credentials/offer", baseUrl).toString(),
      },
    };
  };

  const loadCanonicalPublicBadgeByIdentifier = async (
    db: SqlDatabase,
    badgeObjects: ImmutableCredentialStore,
    badgeIdentifier: string,
  ): Promise<
    | {
        status: 404;
      }
    | {
        status: 200;
        canonicalBadgeIdentifier: string;
        model: PublicBadgeViewModel;
      }
  > => {
    const result = await loadPublicBadgeViewModel(db, badgeObjects, badgeIdentifier);

    if (result.status === "not_found") {
      return {
        status: 404,
      };
    }

    return {
      status: 200,
      canonicalBadgeIdentifier: result.value.assertion.publicId,
      model: result.value,
    };
  };

  const createOfferResponse = async (
    requestUrl: string,
    db: SqlDatabase,
    badgeObjects: ImmutableCredentialStore,
    badgeIdentifier: string,
  ): Promise<
    | {
        status: 404;
      }
    | {
        status: 200;
        canonicalBadgeIdentifier: string;
        payload: Record<string, unknown>;
      }
  > => {
    const canonicalBadge = await loadCanonicalPublicBadgeByIdentifier(
      db,
      badgeObjects,
      badgeIdentifier,
    );

    if (canonicalBadge.status === 404) {
      return canonicalBadge;
    }

    const nowIso = new Date().toISOString();
    const preAuthorizedCode = `oid4vci_pc_${generateOpaqueToken()}`;
    const offerExpiresAt = addSecondsToIso(nowIso, preAuthorizedCodeTtlSeconds);
    const publicBadgeId = canonicalBadge.canonicalBadgeIdentifier;

    await createOid4vciPreAuthorizedCode(db, {
      codeHash: await sha256Hex(preAuthorizedCode),
      tenantId: canonicalBadge.model.assertion.tenantId,
      assertionId: canonicalBadge.model.assertion.id,
      publicBadgeId,
      expiresAt: offerExpiresAt,
    });

    return {
      status: 200,
      canonicalBadgeIdentifier: publicBadgeId,
      payload: walletCredentialOfferPayload(requestUrl, canonicalBadge.model, {
        preAuthorizedCode,
        offerExpiresAt,
        tokenEndpointPath: OID4VCI_TOKEN_ENDPOINT_PATH,
        credentialEndpointPath: OID4VCI_CREDENTIAL_ENDPOINT_PATH,
      }),
    };
  };

  const handleOfferByBadgeIdentifier = async (
    requestUrl: string,
    db: SqlDatabase,
    badgeObjects: ImmutableCredentialStore,
    badgeIdentifier: string,
  ): Promise<Response> => {
    const result = await createOfferResponse(requestUrl, db, badgeObjects, badgeIdentifier);

    if (result.status === 404) {
      return new Response(JSON.stringify({ error: "Badge not found" }), {
        status: 404,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
        },
      });
    }

    return new Response(JSON.stringify(result.payload), {
      status: 200,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  };

  const handleTokenRequest = async (c: AppContext): Promise<Response> => {
    const contentType = c.req.header("content-type")?.toLowerCase() ?? "";

    if (!contentType.includes("application/x-www-form-urlencoded")) {
      return oid4vciErrorJson(
        c,
        400,
        "invalid_request",
        "Token requests must use application/x-www-form-urlencoded",
      );
    }

    const formData = new URLSearchParams(await c.req.text());
    const grantType = asNonEmptyString(formData.get("grant_type"));
    const preAuthorizedCode = asNonEmptyString(formData.get("pre-authorized_code"));

    if (grantType !== PRE_AUTHORIZED_CODE_GRANT) {
      return oid4vciErrorJson(
        c,
        400,
        "unsupported_grant_type",
        "Only pre-authorized code flow is supported",
      );
    }

    if (preAuthorizedCode === null) {
      return oid4vciErrorJson(c, 400, "invalid_request", "pre-authorized_code is required");
    }

    const nowIso = new Date().toISOString();
    const consumedCode = await consumeOid4vciPreAuthorizedCode(resolveDatabase(c.env), {
      codeHash: await sha256Hex(preAuthorizedCode),
      nowIso,
    });

    if (consumedCode === null) {
      return oid4vciErrorJson(
        c,
        400,
        "invalid_grant",
        "pre-authorized_code is invalid, expired, or already used",
      );
    }

    const accessToken = `oid4vci_at_${generateOpaqueToken()}`;
    await createOid4vciAccessToken(resolveDatabase(c.env), {
      accessTokenHash: await sha256Hex(accessToken),
      tenantId: consumedCode.tenantId,
      assertionId: consumedCode.assertionId,
      expiresAt: addSecondsToIso(nowIso, accessTokenTtlSeconds),
    });

    c.header("Cache-Control", "no-store");
    return c.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: accessTokenTtlSeconds,
      c_nonce: generateOpaqueToken(),
      c_nonce_expires_in: accessTokenTtlSeconds,
    });
  };

  const handleCredentialRequest = async (c: AppContext): Promise<Response> => {
    const db = resolveDatabase(c.env);
    const bearerToken = extractBearerToken(c.req.header("authorization"));

    if (bearerToken === null) {
      return oid4vciErrorJson(c, 401, "invalid_token", "Bearer access token is required");
    }

    const tokenRecord = await findActiveOid4vciAccessTokenByHash(db, {
      accessTokenHash: await sha256Hex(bearerToken),
      nowIso: new Date().toISOString(),
    });

    if (tokenRecord === null) {
      return oid4vciErrorJson(c, 401, "invalid_token", "Access token is invalid or expired");
    }

    const contentType = c.req.header("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("application/json")) {
      return oid4vciErrorJson(
        c,
        400,
        "invalid_request",
        "Credential requests must use application/json",
      );
    }

    const requestPayload = await c.req.json<unknown>().catch(() => null);
    const parsedRequest = oid4vciCredentialRequestSchema.safeParse(requestPayload);

    if (!parsedRequest.success) {
      return oid4vciErrorJson(
        c,
        400,
        "invalid_request",
        "Credential request must be a JSON object with supported fields",
      );
    }

    const requestedFormat = parsedRequest.data.format ?? null;

    if (requestedFormat !== null && requestedFormat !== "ldp_vc") {
      return oid4vciErrorJson(
        c,
        400,
        "unsupported_credential_format",
        "Only ldp_vc format is supported",
      );
    }

    const requestedCredentialIdentifier = parsedRequest.data.credential_identifier ?? null;

    if (
      requestedCredentialIdentifier !== null &&
      requestedCredentialIdentifier !== tokenRecord.assertionId
    ) {
      return oid4vciErrorJson(
        c,
        400,
        "invalid_credential_request",
        "credential_identifier does not match authorized credential",
      );
    }

    const verification = await loadVerificationViewModel(
      db,
      c.env.BADGE_OBJECTS,
      tokenRecord.assertionId,
    );

    if (verification.status !== "ok") {
      return oid4vciErrorJson(c, 404, "invalid_token", "Credential not found for this token");
    }

    await recordAssertionEngagementEvent(db, {
      tenantId: verification.value.assertion.tenantId,
      assertionId: verification.value.assertion.id,
      eventType: "wallet_accept",
      actorType: "wallet",
      channel: "oid4vci",
      occurredAt: new Date().toISOString(),
    });

    c.header("Cache-Control", "no-store");
    return c.json({
      format: "ldp_vc",
      credential: verification.value.credential,
      credential_identifier: verification.value.assertion.id,
    });
  };

  const handleDccVcApiExchange = async (
    c: AppContext,
    badgeIdentifier: string,
  ): Promise<Response> => {
    const canonicalBadge = await loadCanonicalPublicBadgeByIdentifier(
      resolveDatabase(c.env),
      c.env.BADGE_OBJECTS,
      badgeIdentifier,
    );

    c.header("Cache-Control", "no-store");

    if (canonicalBadge.status === 404) {
      return c.json(
        {
          error: "Badge not found",
        },
        404,
      );
    }

    const publicBadgePath = `/badges/${encodeURIComponent(canonicalBadge.canonicalBadgeIdentifier)}`;

    return c.json({
      credentialRequestOrigin: new URL(publicRequestUrl(c)).origin,
      verifiablePresentation: {
        "@context": [VC_DATA_MODEL_CONTEXT_URL],
        type: ["VerifiablePresentation"],
        verifiableCredential: [canonicalBadge.model.credential],
      },
      redirectUrl: new URL(publicBadgePath, publicRequestUrl(c)).toString(),
    });
  };

  app.get("/.well-known/openid-credential-issuer", (c) => {
    c.header("Cache-Control", "no-store");
    return c.json(buildIssuerMetadata(publicRequestUrl(c)));
  });

  app.get("/credentials/v1/offers/:badgeIdentifier", async (c) => {
    return handleOfferByBadgeIdentifier(
      publicRequestUrl(c),
      resolveDatabase(c.env),
      c.env.BADGE_OBJECTS,
      c.req.param("badgeIdentifier"),
    );
  });

  app.post("/credentials/offer", async (c) => {
    const requestPayload = await c.req.json<unknown>().catch(() => null);
    const parsedRequest = oid4vciOfferRequestSchema.safeParse(requestPayload);

    if (!parsedRequest.success) {
      return oid4vciErrorJson(
        c,
        400,
        "invalid_request",
        "badgeIdentifier is required to create an offer",
      );
    }

    const result = await createOfferResponse(
      publicRequestUrl(c),
      resolveDatabase(c.env),
      c.env.BADGE_OBJECTS,
      parsedRequest.data.badgeIdentifier,
    );

    c.header("Cache-Control", "no-store");

    if (result.status === 404) {
      return oid4vciErrorJson(c, 404, "invalid_request", "Badge not found");
    }

    const credentialOfferUri = new URL(
      `/credentials/v1/offers/${encodeURIComponent(result.canonicalBadgeIdentifier)}`,
      publicRequestUrl(c),
    ).toString();

    return c.json(
      {
        credential_offer_uri: credentialOfferUri,
        credential_offer: result.payload,
      },
      201,
    );
  });

  app.get("/credentials/v1/dcc/request/:badgeIdentifier", async (c) => {
    const canonicalBadge = await loadCanonicalPublicBadgeByIdentifier(
      resolveDatabase(c.env),
      c.env.BADGE_OBJECTS,
      c.req.param("badgeIdentifier"),
    );

    c.header("Cache-Control", "no-store");

    if (canonicalBadge.status === 404) {
      return c.json(
        {
          error: "Badge not found",
        },
        404,
      );
    }

    const exchangeUrl = new URL(
      `${DCC_VCAPI_EXCHANGE_ENDPOINT_PREFIX}/${encodeURIComponent(canonicalBadge.canonicalBadgeIdentifier)}`,
      publicRequestUrl(c),
    ).toString();
    const requestPayload = {
      credentialRequestOrigin: new URL(publicRequestUrl(c)).origin,
      protocols: {
        vcapi: exchangeUrl,
      },
    };
    const appLinkDeepLinkUrl = new URL("https://lcw.app/request");
    appLinkDeepLinkUrl.searchParams.set("request", JSON.stringify(requestPayload));
    const customProtocolDeepLinkUrl = new URL("dccrequest://");
    customProtocolDeepLinkUrl.searchParams.set("request", JSON.stringify(requestPayload));

    return c.json({
      ...requestPayload,
      app_link_deep_link_url: appLinkDeepLinkUrl.toString(),
      custom_protocol_deep_link_url: customProtocolDeepLinkUrl.toString(),
    });
  });

  app.post("/credentials/v1/dcc/exchanges/:badgeIdentifier", async (c) => {
    return handleDccVcApiExchange(c, c.req.param("badgeIdentifier"));
  });

  app.post(OID4VCI_TOKEN_ENDPOINT_PATH, async (c) => {
    return handleTokenRequest(c);
  });

  app.post(OID4VCI_CREDENTIAL_ENDPOINT_PATH, async (c) => {
    return handleCredentialRequest(c);
  });
};
