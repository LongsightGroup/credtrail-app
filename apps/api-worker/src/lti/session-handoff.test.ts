import { describe, expect, it } from "vitest";
import { createLtiSessionHandoffToken, verifyLtiSessionHandoffToken } from "./session-handoff";

const env = {
  PLATFORM_DOMAIN: "credtrail.test",
  LTI_STATE_SIGNING_SECRET: "test-lti-state-secret",
};

describe("LTI session handoff tokens", () => {
  it("round-trips a signed session handoff payload", async () => {
    const token = await createLtiSessionHandoffToken(env, {
      tenantId: "tenant_123",
      sessionToken: "better-auth-session-token",
      ttlSeconds: 60,
    });

    const payload = await verifyLtiSessionHandoffToken(env, token);

    expect(payload).toMatchObject({
      tenantId: "tenant_123",
      sessionToken: "better-auth-session-token",
    });
  });

  it("rejects tampered handoff payloads", async () => {
    const token = await createLtiSessionHandoffToken(env, {
      tenantId: "tenant_123",
      sessionToken: "better-auth-session-token",
      ttlSeconds: 60,
    });
    const tamperedToken = `${token.slice(0, -1)}${token.endsWith("a") ? "b" : "a"}`;

    expect(await verifyLtiSessionHandoffToken(env, tamperedToken)).toBeNull();
  });
});
