import type { ObservabilityContext } from "@credtrail/core-domain";
import type { Hono } from "hono";
import type { AppBindings, AppEnv } from "../app";
import {
  createAppLogger,
  observabilityContext as defaultObservabilityContext,
  optionalAppLogger,
} from "../app/observability";
import { validateCsrfRequestOrigin } from "./csrf-protection";
import { applySecurityHeaders } from "./security-headers";

interface RegisterCommonMiddlewareInput {
  app: Hono<AppEnv>;
  observabilityContext: (bindings: AppBindings) => ObservabilityContext;
}

const JSON_PRETTY_PRINT_SPACES = 2;
const REQUEST_ID_HEADER = "x-request-id";

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

export const registerCommonMiddleware = (input: RegisterCommonMiddlewareInput): void => {
  const { app, observabilityContext } = input;

  app.use("*", async (c, next) => {
    const startedAt = Date.now();
    const requestUrl = new URL(c.req.url);
    const canonicalHost = c.env.PLATFORM_DOMAIN.toLowerCase();
    const requestHost = requestUrl.hostname.toLowerCase();
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
      applySecurityHeaders(response.headers, c.env, requestUrl);
      return applyRequestHeaders(response, requestId);
    }

    if (requestHost === `www.${canonicalHost}` || requestHost === `badges.${canonicalHost}`) {
      requestUrl.hostname = canonicalHost;
      requestUrl.port = "";
      const response = c.redirect(requestUrl.toString(), 308);
      applySecurityHeaders(response.headers, c.env, requestUrl);
      return applyRequestHeaders(response, requestId);
    }

    await next();
    c.res = await prettifyJsonResponse(c.res);
    applySecurityHeaders(c.res.headers, c.env, requestUrl);
    applyRequestHeaders(c.res, requestId);
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
    applySecurityHeaders(response.headers, c.env, requestUrl);
    return applyRequestHeaders(response, requestId);
  });

  app.get("/healthz", (c) => {
    return c.json({
      service: "api-worker",
      status: "ok",
      environment: c.env.APP_ENV,
    });
  });
};
