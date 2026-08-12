import { describe, expect, it } from "vitest";
import type { AppBindings } from "../app";
import {
  buildTenantLtiDynamicRegistrationInviteUrl,
  ltiDynamicRegistrationFailureStatusCode,
} from "./dynamic-registration-service";

const env = {
  APP_ENV: "test",
  DATABASE_URL: "postgres://credtrail-test.local/db",
  BADGE_OBJECTS: {} as AppBindings["BADGE_OBJECTS"],
  PLATFORM_DOMAIN: "credtrail.test",
  PUBLIC_APP_ORIGIN: "https://credtrail.test",
  LTI_STATE_SIGNING_SECRET: "test-lti-state-signing-secret",
} satisfies AppBindings;

describe("LTI dynamic registration service", () => {
  it("maps failure reasons to HTTP status codes", () => {
    expect(ltiDynamicRegistrationFailureStatusCode("invalid_invite")).toBe(403);
    expect(ltiDynamicRegistrationFailureStatusCode("not_configured")).toBe(500);
    expect(ltiDynamicRegistrationFailureStatusCode("issuer_tenant_conflict")).toBe(409);
    expect(ltiDynamicRegistrationFailureStatusCode("invalid_path")).toBe(400);
    expect(ltiDynamicRegistrationFailureStatusCode("complete_failed")).toBe(400);
  });

  it("builds tenant invite URLs when signing is configured", async () => {
    const inviteUrl = await buildTenantLtiDynamicRegistrationInviteUrl(env, "tenant-a");

    expect(inviteUrl).toContain(
      "https://credtrail.test/v1/tenants/tenant-a/lti/dynamic-registration/",
    );
  });

  it("returns null when LTI signing is not configured", async () => {
    await expect(
      buildTenantLtiDynamicRegistrationInviteUrl(
        {
          ...env,
          LTI_STATE_SIGNING_SECRET: "",
        },
        "tenant-a",
      ),
    ).resolves.toBeNull();
  });
});
