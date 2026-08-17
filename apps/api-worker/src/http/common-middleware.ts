import type { ObservabilityContext } from "@credtrail/core-domain";
import type { Hono } from "hono";
import type { AppBindings, AppEnv } from "../app/types";
import {
  createAppLogger,
  observabilityContext as defaultObservabilityContext,
  optionalAppLogger,
} from "../app/observability";
import { canonicalAppOrigin, canonicalAppRequestUrl } from "./canonical-app-url";
import { validateCsrfRequestOrigin } from "./csrf-protection";
import { canonicalPlatformDomain } from "./platform-domain";
import { applyResponseCachePolicy } from "./response-cache-policy";
import { applySecurityHeaders } from "./security-headers";

interface RegisterCommonMiddlewareInput {
  app: Hono<AppEnv>;
  observabilityContext: (bindings: AppBindings) => ObservabilityContext;
}

const JSON_PRETTY_PRINT_SPACES = 2;
const REQUEST_ID_HEADER = "x-request-id";

const isIssuerIdentityPath = (pathname: string): boolean => {
  return (
    pathname === "/.well-known/did.json" ||
    pathname === "/.well-known/jwks.json" ||
    /^\/[^/]+\/(?:did|jwks)\.json$/u.test(pathname)
  );
};

const isAllowedProductionRequestOrigin = (input: {
  readonly requestUrl: URL;
  readonly canonicalOrigin: URL;
  readonly platformDomain: string;
}): boolean => {
  if (input.requestUrl.origin === input.canonicalOrigin.origin) {
    return true;
  }

  return (
    isIssuerIdentityPath(input.requestUrl.pathname) &&
    input.requestUrl.protocol === "https:" &&
    input.requestUrl.host.toLowerCase() === input.platformDomain.trim().toLowerCase()
  );
};

const prettifyJsonResponse = async (response: Response): Promise<Response> => {
  const contentType = response.headers.get("content-type");

  if (!contentType?.toLowerCase().includes("json")) {
    return response;
  }

  const responseClone = response.clone();
  const responseBody = await responseClone.text();

  if (responseBody.length === 0) {
    return response;
  }

  let parsedBody: unknown;

  try {
    parsedBody = JSON.parse(responseBody);
  } catch {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.delete("content-length");

  return new Response(JSON.stringify(parsedBody, null, JSON_PRETTY_PRINT_SPACES), {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
};

const requestIdFromHeader = (headerValue: string | undefined): string => {
  const normalized = headerValue?.trim();

  if (normalized !== undefined && normalized.length > 0) {
    return normalized;
  }

  return crypto.randomUUID();
};

const applyRequestHeaders = (response: Response, requestId: string): Response => {
  response.headers.set(REQUEST_ID_HEADER, requestId);
  return response;
};

const applyResponsePolicies = (input: {
  response: Response;
  requestUrl: URL;
  env: AppBindings;
  requestId: string;
}): Response => {
  applyResponseCachePolicy(input.response.headers);
  applySecurityHeaders(input.response.headers, input.env, input.requestUrl);
  return applyRequestHeaders(input.response, input.requestId);
};

export const registerCommonMiddleware = (input: RegisterCommonMiddlewareInput): void => {
  const { app, observabilityContext } = input;

  app.use("*", async (c, next) => {
    const startedAt = Date.now();
    const requestUrl = new URL(c.req.url);
    const canonicalOrigin = new URL(canonicalAppOrigin(c.env.PUBLIC_APP_ORIGIN));
    const platformDomain = canonicalPlatformDomain(c.env.PLATFORM_DOMAIN);
    const requestId = requestIdFromHeader(c.req.header(REQUEST_ID_HEADER));
    const appLogger = createAppLogger({
      context: observabilityContext(c.env),
      fields: {
        requestId,
        method: c.req.method,
        path: requestUrl.pathname,
      },
    });

    c.set("requestId", requestId);
    c.set("appLogger", appLogger);

    if (
      !validateCsrfRequestOrigin({
        method: c.req.method,
        requestUrl,
        cookieHeader: c.req.header("cookie"),
        originHeader: c.req.header("origin"),
        refererHeader: c.req.header("referer"),
      })
    ) {
      const response = c.json({ error: "Invalid request origin" }, 403);
      return applyResponsePolicies({
        response,
        requestUrl,
        env: c.env,
        requestId,
      });
    }

    if (
      c.env.APP_ENV === "production" &&
      !isAllowedProductionRequestOrigin({
        requestUrl,
        canonicalOrigin,
        platformDomain,
      })
    ) {
      const canonicalUrl = new URL(canonicalAppRequestUrl(c.env.PUBLIC_APP_ORIGIN, c.req.url));
      const response = c.redirect(canonicalUrl.toString(), 308);
      return applyResponsePolicies({
        response,
        requestUrl: canonicalUrl,
        env: c.env,
        requestId,
      });
    }

    await next();
    c.res = await prettifyJsonResponse(c.res);
    applyResponsePolicies({
      response: c.res,
      requestUrl,
      env: c.env,
      requestId,
    });
    const elapsedMs = Date.now() - startedAt;

    appLogger.info("http_request", {
      status: c.res.status,
      elapsedMs,
    });
  });

  app.onError(async (error, c) => {
    const requestUrl = new URL(c.req.url);
    const details = error instanceof Error ? error.message : "Unknown error";
    const requestId = c.get("requestId") ?? requestIdFromHeader(c.req.header(REQUEST_ID_HEADER));
    const appLogger =
      optionalAppLogger(c) ??
      createAppLogger({
        context: defaultObservabilityContext(c.env),
        fields: {
          requestId,
          method: c.req.method,
          path: requestUrl.pathname,
        },
      });

    appLogger.error("api_error", {
      detail: details,
    });

    const response = c.json(
      {
        error: "Internal server error",
      },
      500,
    );
    return applyResponsePolicies({
      response,
      requestUrl,
      env: c.env,
      requestId,
    });
  });

  app.get("/healthz", (c) => {
    return c.json({
      service: "api-worker",
      status: "ok",
      environment: c.env.APP_ENV,
    });
  });
};
