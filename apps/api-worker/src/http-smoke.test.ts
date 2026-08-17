import { describe, expect, it } from "vitest";
import { app } from "./index";
import type { AppBindings } from "./app/types";
import type { JsonObject } from "@credtrail/core-domain";

const asJsonObject = (value: unknown): JsonObject | null => {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : null;
};

const asString = (value: unknown): string | null => {
  return typeof value === "string" ? value : null;
};

const cspDirectives = (response: Response): Map<string, string[]> => {
  const csp = response.headers.get("content-security-policy");

  expect(csp).not.toBeNull();

  return new Map(
    (csp ?? "").split(";").map((directive) => {
      const [name, ...values] = directive.trim().split(/\s+/);
      return [name ?? "", values] as const;
    }),
  );
};

const expectDirectiveContains = (
  directives: Map<string, string[]>,
  name: string,
  value: string,
): void => {
  expect(directives.get(name) ?? []).toContain(value);
};

const expectDirectiveOmits = (
  directives: Map<string, string[]>,
  name: string,
  value: string,
): void => {
  expect(directives.get(name) ?? []).not.toContain(value);
};

const createEnv = (appEnv = "test"): AppBindings => {
  return {
    APP_ENV: appEnv,
    PLATFORM_DOMAIN: "credtrail.test",
    PUBLIC_APP_ORIGIN: "https://credtrail.test",
    BADGE_OBJECTS: {} as R2Bucket,
  };
};

describe("app root route", () => {
  it("keeps the app root route available without marketing-specific proxy behavior", async () => {
    const env = createEnv();
    const response = await app.fetch(new Request("https://credtrail.test/"), env);

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/login");
  });
});

describe("canonical host redirects", () => {
  it("redirects www host requests to the canonical platform domain", async () => {
    const env = createEnv("production");
    const response = await app.fetch(
      new Request(
        "https://www.credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22?utm=test",
      ),
      env,
    );

    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(
      "https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22?utm=test",
    );
  });

  it("redirects legacy badges subdomain requests to the canonical platform domain", async () => {
    const env = createEnv("production");
    const response = await app.fetch(new Request("https://badges.credtrail.test/healthz"), env);

    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe("https://credtrail.test/healthz");
  });
});

describe("security headers", () => {
  it("applies the baseline browser security headers to handled responses", async () => {
    const env = createEnv();
    const response = await app.fetch(new Request("https://credtrail.test/healthz"), env);
    const directives = cspDirectives(response);

    expectDirectiveContains(directives, "default-src", "'self'");
    expectDirectiveContains(directives, "base-uri", "'none'");
    expectDirectiveContains(directives, "object-src", "'none'");
    expectDirectiveContains(directives, "script-src", "'self'");
    expectDirectiveContains(directives, "script-src", "'report-sample'");
    expectDirectiveContains(directives, "script-src", "https://static.cloudflareinsights.com");
    expectDirectiveContains(directives, "script-src-attr", "'none'");
    expectDirectiveContains(directives, "style-src", "'self'");
    expectDirectiveContains(directives, "connect-src", "https://cloudflareinsights.com");
    expectDirectiveOmits(directives, "script-src", "https://challenges.cloudflare.com");
    expectDirectiveOmits(directives, "style-src", "'unsafe-inline'");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
    expect(response.headers.get("strict-transport-security")).toBe(
      "max-age=31536000; includeSubDomains",
    );
  });

  it("keeps HSTS out of local development responses", async () => {
    const env = createEnv("development");
    const response = await app.fetch(new Request("http://localhost/healthz"), env);

    expectDirectiveContains(cspDirectives(response), "default-src", "'self'");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("strict-transport-security")).toBeNull();
  });

  it("applies the baseline browser security headers to canonical redirects", async () => {
    const env = createEnv("production");
    const response = await app.fetch(new Request("https://www.credtrail.test/healthz"), env);

    expect(response.status).toBe(308);
    expectDirectiveContains(cspDirectives(response), "default-src", "'self'");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("strict-transport-security")).toBe(
      "max-age=31536000; includeSubDomains",
    );
  });

  it("scopes Cloudflare Turnstile CSP access to the login page", async () => {
    const env = {
      ...createEnv(),
      TURNSTILE_SITE_KEY: "turnstile-site-key",
    };
    const response = await app.fetch(new Request("https://credtrail.test/login"), env);
    const directives = cspDirectives(response);

    expect(response.status).toBe(200);
    expectDirectiveContains(directives, "script-src", "https://challenges.cloudflare.com");
    expectDirectiveContains(directives, "connect-src", "https://challenges.cloudflare.com");
    expectDirectiveContains(directives, "frame-src", "https://challenges.cloudflare.com");
    expectDirectiveOmits(directives, "style-src", "'unsafe-inline'");
  });

  it("scopes inline style CSP access to reporting pages that still render dynamic bars", async () => {
    const env = createEnv();
    const response = await app.fetch(
      new Request("https://credtrail.test/tenants/tenant_123/admin/reporting"),
      env,
    );
    const directives = cspDirectives(response);

    expectDirectiveContains(directives, "style-src", "'unsafe-inline'");
    expectDirectiveOmits(directives, "script-src", "https://challenges.cloudflare.com");
  });
});

describe("private response caching", () => {
  it.each([
    "/login",
    "/auth/local/reset-password?tenantId=tenant_123&token=reset-token-1234567890",
    "/v1/auth/session",
  ])("marks %s as no-store", async (path) => {
    const response = await app.fetch(new Request(`https://credtrail.test${path}`), createEnv());

    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("marks generated private signing material as no-store without relying on credentials", async () => {
    const response = await app.fetch(
      new Request("https://credtrail.test/v1/signing/keys/generate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          did: "did:web:credtrail.test:issuers:tenant_123",
        }),
      }),
      createEnv(),
    );

    expect(response.status).toBe(201);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});

describe("CSRF origin validation", () => {
  it("rejects cross-origin state-changing requests that carry the browser session cookie", async () => {
    const env = createEnv();
    const response = await app.fetch(
      new Request("https://credtrail.test/healthz", {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
          Origin: "https://attacker.example",
        },
      }),
      env,
    );
    const body = await response.json<JsonObject>();

    expect(response.status).toBe(403);
    expect(asString(body.error)).toBe("Invalid request origin");
  });

  it("allows same-origin state-changing requests that carry the browser session cookie", async () => {
    const env = createEnv();
    const response = await app.fetch(
      new Request("https://credtrail.test/healthz", {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
          Origin: "https://credtrail.test",
        },
      }),
      env,
    );

    expect(response.status).toBe(404);
  });

  it("falls back to Referer when Origin is absent", async () => {
    const env = createEnv();
    const response = await app.fetch(
      new Request("https://credtrail.test/healthz", {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
          Referer: "https://attacker.example/csrf",
        },
      }),
      env,
    );

    expect(response.status).toBe(403);
  });

  it("rejects browser-session state-changing requests when origin evidence is absent", async () => {
    const env = createEnv();
    const response = await app.fetch(
      new Request("https://credtrail.test/healthz", {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
        },
      }),
      env,
    );

    expect(response.status).toBe(403);
  });

  it("does not apply browser-session CSRF checks to non-cookie requests", async () => {
    const env = createEnv();
    const response = await app.fetch(
      new Request("https://credtrail.test/healthz", {
        method: "POST",
        headers: {
          Origin: "https://attacker.example",
        },
      }),
      env,
    );

    expect(response.status).toBe(404);
  });

  it("exempts cross-site LTI launch protocol posts from browser-session CSRF checks", async () => {
    const env = createEnv();
    const response = await app.fetch(
      new Request("https://credtrail.test/v1/lti/launch", {
        method: "POST",
        headers: {
          Cookie: "better-auth.session_token=session-token",
          Origin: "https://canvas.example.edu",
        },
      }),
      env,
    );

    expect(response.status).not.toBe(403);
  });
});

describe("GET /ims/ob/v3p0/discovery", () => {
  it("returns a public OB3 service description document with OAuth metadata", async () => {
    const env = createEnv();
    const response = await app.fetch(
      new Request("https://unexpected-worker.example/ims/ob/v3p0/discovery"),
      env,
    );
    const body = await response.json<JsonObject>();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(response.headers.get("cache-control")).toBe("public, max-age=300");
    expect(asString(body.openapi)).toBe("3.0.1");

    const info = asJsonObject(body.info);
    expect(asString(info?.title)).toBe("CredTrail Open Badges API");
    expect(asString(info?.termsOfService)).toBe("https://credtrail.test/terms");
    expect(asString(info?.["x-imssf-privacyPolicyUrl"])).toBe("https://credtrail.test/privacy");
    expect(asString(info?.["x-imssf-image"])).toBe("https://credtrail.test/credtrail-logo.png");

    const servers = body.servers;
    expect(Array.isArray(servers)).toBe(true);
    const firstServer =
      Array.isArray(servers) && servers.length > 0 && typeof servers[0] === "object"
        ? asJsonObject(servers[0])
        : null;
    expect(asString(firstServer?.url)).toBe("https://credtrail.test/ims/ob/v3p0");

    const paths = asJsonObject(body.paths);
    expect(asJsonObject(paths?.["/discovery"])).not.toBeNull();
    const credentialsPath = asJsonObject(paths?.["/credentials"]);
    expect(credentialsPath).not.toBeNull();
    expect(asJsonObject(paths?.["/profile"])).not.toBeNull();

    const getCredentials = asJsonObject(credentialsPath?.get);
    const credentialParameters = Array.isArray(getCredentials?.parameters)
      ? getCredentials.parameters
      : [];
    const limitParameter = credentialParameters
      .map((parameter) => asJsonObject(parameter))
      .find((parameter) => asString(parameter?.name) === "limit");
    const offsetParameter = credentialParameters
      .map((parameter) => asJsonObject(parameter))
      .find((parameter) => asString(parameter?.name) === "offset");
    const sinceParameter = credentialParameters
      .map((parameter) => asJsonObject(parameter))
      .find((parameter) => asString(parameter?.name) === "since");

    expect(asString(limitParameter?.in)).toBe("query");
    expect(asString(offsetParameter?.in)).toBe("query");
    expect(asString(sinceParameter?.in)).toBe("query");

    const components = asJsonObject(body.components);
    const headers = asJsonObject(components?.headers);
    expect(asJsonObject(headers?.["X-Total-Count"])).not.toBeNull();

    const links = asJsonObject(components?.links);
    const nextLink = asJsonObject(links?.next);
    const nextLinkParameters = asJsonObject(nextLink?.parameters);
    expect(asString(nextLinkParameters?.limit)).toBe("$request.query.limit");
    expect(asString(nextLinkParameters?.offset)).toBe("$request.query.offset");

    const securitySchemes = asJsonObject(components?.securitySchemes);
    const oauthScheme = asJsonObject(securitySchemes?.OAuth2ACG);
    expect(asString(oauthScheme?.type)).toBe("oauth2");
    expect(asString(oauthScheme?.["x-imssf-registrationUrl"])).toBe(
      "https://credtrail.test/ims/ob/v3p0/oauth/register",
    );

    const flows = asJsonObject(oauthScheme?.flows);
    const authorizationCode = asJsonObject(flows?.authorizationCode);
    expect(asString(authorizationCode?.authorizationUrl)).toBe(
      "https://credtrail.test/ims/ob/v3p0/oauth/authorize",
    );
    expect(asString(authorizationCode?.tokenUrl)).toBe(
      "https://credtrail.test/ims/ob/v3p0/oauth/token",
    );
    expect(asString(authorizationCode?.refreshUrl)).toBe(
      "https://credtrail.test/ims/ob/v3p0/oauth/refresh",
    );

    const scopes = asJsonObject(authorizationCode?.scopes);
    expect(
      asString(scopes?.["https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly"]),
    ).toContain("Permission");
    expect(
      asString(scopes?.["https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.upsert"]),
    ).toContain("Permission");
    expect(
      asString(scopes?.["https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly"]),
    ).toContain("Permission");
    expect(
      asString(scopes?.["https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.update"]),
    ).toContain("Permission");
  });
});
