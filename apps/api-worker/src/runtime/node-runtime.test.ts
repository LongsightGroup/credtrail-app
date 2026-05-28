import { describe, expect, it } from "vitest";
import {
  createNodeRuntimeBindings,
  parseNodeRuntimePort,
  parsePositiveIntegerEnv,
} from "./node-runtime";

describe("parseNodeRuntimePort", () => {
  it("uses default port when PORT is not set", () => {
    expect(parseNodeRuntimePort({})).toBe(8787);
  });

  it("parses explicit port values", () => {
    expect(parseNodeRuntimePort({ PORT: "3000" })).toBe(3000);
  });

  it("throws for invalid port values", () => {
    expect(() => parseNodeRuntimePort({ PORT: "abc" })).toThrowError(
      "PORT must be an integer between 1 and 65535",
    );
  });
});

describe("parsePositiveIntegerEnv", () => {
  it("uses fallback when missing", () => {
    expect(parsePositiveIntegerEnv({}, "JOB_POLL_INTERVAL_MS", 1000)).toBe(1000);
  });

  it("parses positive integers", () => {
    expect(
      parsePositiveIntegerEnv({ JOB_POLL_INTERVAL_MS: "2500" }, "JOB_POLL_INTERVAL_MS", 1000),
    ).toBe(2500);
  });
});

describe("createNodeRuntimeBindings", () => {
  it("maps required and optional env values into bindings", () => {
    const bindings = createNodeRuntimeBindings({
      APP_ENV: "production",
      PLATFORM_DOMAIN: "badges.example.edu",
      DATABASE_URL: "postgres://example/db",
      JOB_PROCESSOR_TOKEN: "job-token",
      BETTER_AUTH_SECRET: "better-auth-secret",
      BETTER_AUTH_TRUSTED_ORIGINS: "https://badges.example.edu,https://admin.example.edu",
      BADGE_IMAGE_GENERATION_MODEL: "@cf/black-forest-labs/flux-2-klein-4b",
      S3_BUCKET: "credtrail-badges",
      S3_REGION: "us-east-1",
      S3_ENDPOINT: "http://minio:9000",
      S3_FORCE_PATH_STYLE: "true",
      AWS_ACCESS_KEY_ID: "access",
      AWS_SECRET_ACCESS_KEY: "secret",
    });

    expect(bindings.APP_ENV).toBe("production");
    expect(bindings.PLATFORM_DOMAIN).toBe("badges.example.edu");
    expect(bindings.DATABASE_URL).toBe("postgres://example/db");
    expect(bindings.JOB_PROCESSOR_TOKEN).toBe("job-token");
    expect(bindings.BETTER_AUTH_SECRET).toBe("better-auth-secret");
    expect(bindings.BETTER_AUTH_TRUSTED_ORIGINS).toBe(
      "https://badges.example.edu,https://admin.example.edu",
    );
    expect(bindings.BADGE_IMAGE_GENERATION_MODEL).toBe("@cf/black-forest-labs/flux-2-klein-4b");
    expect(typeof bindings.BADGE_OBJECTS.head).toBe("function");
    expect(typeof bindings.BADGE_OBJECTS.get).toBe("function");
    expect(typeof bindings.BADGE_OBJECTS.put).toBe("function");
  });

  it("throws when required S3 variables are missing", () => {
    expect(() =>
      createNodeRuntimeBindings({
        S3_REGION: "us-east-1",
        AWS_ACCESS_KEY_ID: "access",
        AWS_SECRET_ACCESS_KEY: "secret",
      }),
    ).toThrowError("S3_BUCKET is required");
  });
});
