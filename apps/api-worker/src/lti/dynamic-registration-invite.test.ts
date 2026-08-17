import { describe, expect, it } from "vitest";
import type { AppBindings } from "../app/types";
import {
  createLtiDynamicRegistrationInviteToken,
  ltiDynamicRegistrationPath,
  ltiDynamicRegistrationUrl,
  verifyLtiDynamicRegistrationInviteToken,
} from "./dynamic-registration-invite";

const env = {
  LTI_STATE_SIGNING_SECRET: "test-lti-state-signing-secret",
} satisfies Pick<AppBindings, "LTI_STATE_SIGNING_SECRET">;

describe("LTI dynamic registration invite tokens", () => {
  it("verifies a valid tenant-scoped token", async () => {
    const token = await createLtiDynamicRegistrationInviteToken(env, {
      tenantId: "tenant-a",
    });

    const verified = await verifyLtiDynamicRegistrationInviteToken(env, token);

    expect(verified).not.toBeNull();
    expect(verified?.tenantId).toBe("tenant-a");
    expect(typeof verified?.exp).toBe("number");
  });

  it("rejects expired tokens", async () => {
    const token = await createLtiDynamicRegistrationInviteToken(env, {
      tenantId: "tenant-a",
      ttlSeconds: -60,
    });

    await expect(verifyLtiDynamicRegistrationInviteToken(env, token)).resolves.toBeNull();
  });

  it("rejects tampered tokens", async () => {
    const token = await createLtiDynamicRegistrationInviteToken(env, {
      tenantId: "tenant-a",
    });
    const replacement = token.endsWith("a") ? "b" : "a";
    const tampered = `${token.slice(0, -1)}${replacement}`;

    await expect(verifyLtiDynamicRegistrationInviteToken(env, tampered)).resolves.toBeNull();
  });

  it("preserves tenant identity so callers can reject wrong-tenant links", async () => {
    const token = await createLtiDynamicRegistrationInviteToken(env, {
      tenantId: "tenant-a",
    });

    const verified = await verifyLtiDynamicRegistrationInviteToken(env, token);

    expect(verified?.tenantId).not.toBe("tenant-b");
  });

  it("rejects malformed tokens", async () => {
    await expect(
      verifyLtiDynamicRegistrationInviteToken(env, "not-a-registration-token"),
    ).resolves.toBeNull();
    await expect(
      verifyLtiDynamicRegistrationInviteToken(env, "payload.signature.extra"),
    ).resolves.toBeNull();
  });

  it("builds tenant dynamic registration URLs on the canonical platform domain", async () => {
    const token = await createLtiDynamicRegistrationInviteToken(env, {
      tenantId: "tenant-a",
    });

    expect(ltiDynamicRegistrationPath("tenant-a", token)).toBe(
      `/v1/tenants/tenant-a/lti/dynamic-registration/${encodeURIComponent(token)}`,
    );
    expect(
      ltiDynamicRegistrationUrl({
        publicAppOrigin: "https://credtrail.test",
        tenantId: "tenant-a",
        inviteToken: token,
      }),
    ).toBe(
      `https://credtrail.test/v1/tenants/tenant-a/lti/dynamic-registration/${encodeURIComponent(
        token,
      )}`,
    );
  });
});
