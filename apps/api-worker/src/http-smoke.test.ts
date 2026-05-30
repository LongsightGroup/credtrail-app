import { describe, expect, it } from "vitest";
import { app } from "./index";
import type { AppBindings } from "./app";
import type { JsonObject } from "@credtrail/core-domain";
import { CONTENT_SECURITY_POLICY } from "./http/security-headers";

const asJsonObject = (value: unknown): JsonObject | null => {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : null;
};

const asString = (value: unknown): string | null => {
  return typeof value === "string" ? value : null;
};

const createEnv = (appEnv = "test"): AppBindings => {
  return {
    APP_ENV: appEnv,
    PLATFORM_DOMAIN: "credtrail.test",
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
    const env = createEnv();
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
    const env = createEnv();
    const response = await app.fetch(new Request("https://badges.credtrail.test/healthz"), env);

    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe("https://credtrail.test/healthz");
  });
});

describe("security headers", () => {
  it("applies the baseline browser security headers to handled responses", async () => {
    const env = createEnv();
    const response = await app.fetch(new Request("https://credtrail.test/healthz"), env);

    expect(response.headers.get("content-security-policy")).toBe(CONTENT_SECURITY_POLICY);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("strict-transport-security")).toBe(
      "max-age=31536000; includeSubDomains",
    );
  });

  it("keeps HSTS out of local development responses", async () => {
    const env = createEnv("development");
    const response = await app.fetch(new Request("http://localhost/healthz"), env);

    expect(response.headers.get("content-security-policy")).toBe(CONTENT_SECURITY_POLICY);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("strict-transport-security")).toBeNull();
  });

  it("applies the baseline browser security headers to canonical redirects", async () => {
    const env = createEnv();
    const response = await app.fetch(new Request("https://www.credtrail.test/healthz"), env);

    expect(response.status).toBe(308);
    expect(response.headers.get("content-security-policy")).toBe(CONTENT_SECURITY_POLICY);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("strict-transport-security")).toBe(
      "max-age=31536000; includeSubDomains",
    );
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
      new Request("https://credtrail.test/ims/ob/v3p0/discovery"),
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
    expect(asJsonObject(paths?.["/credentials"])).not.toBeNull();
    expect(asJsonObject(paths?.["/profile"])).not.toBeNull();

    const components = asJsonObject(body.components);
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
