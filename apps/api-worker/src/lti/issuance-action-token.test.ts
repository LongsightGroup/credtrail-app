import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createLtiIssuanceActionToken,
  verifyLtiIssuanceActionToken,
} from "./issuance-action-token";

const env = {
  PLATFORM_DOMAIN: "credtrail.test",
  LTI_STATE_SIGNING_SECRET: "test-lti-state-secret",
};

const validInput = {
  tenantId: "tenant_123",
  ltiSessionId: "lti-session-123",
  issuer: "https://trysakai.example.edu",
  clientId: "client-123",
  deploymentId: "deployment-123",
  contextId: "course-123",
  resourceLinkId: "resource-link-123",
  badgeTemplateId: "badge_template_001",
  issuedByUserId: "usr_123",
  ttlSeconds: 600,
};

afterEach(() => {
  vi.useRealTimers();
});

describe("LTI issuance action token", () => {
  it("round-trips signed action payloads", async () => {
    const token = await createLtiIssuanceActionToken(env, validInput);
    const payload = await verifyLtiIssuanceActionToken(env, token);

    expect(payload).toMatchObject({
      tenantId: validInput.tenantId,
      ltiSessionId: validInput.ltiSessionId,
      issuer: validInput.issuer,
      clientId: validInput.clientId,
      deploymentId: validInput.deploymentId,
      contextId: validInput.contextId,
      resourceLinkId: validInput.resourceLinkId,
      badgeTemplateId: validInput.badgeTemplateId,
      issuedByUserId: validInput.issuedByUserId,
    });
  });

  it("rejects tampered tokens", async () => {
    const token = await createLtiIssuanceActionToken(env, validInput);
    const tampered = `${token.slice(0, -1)}${token.endsWith("a") ? "b" : "a"}`;

    await expect(verifyLtiIssuanceActionToken(env, tampered)).resolves.toBeNull();
  });

  it("rejects expired tokens", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-01T12:00:00.000Z"));
    const token = await createLtiIssuanceActionToken(env, {
      ...validInput,
      ttlSeconds: 1,
    });

    vi.setSystemTime(new Date("2026-05-01T12:00:02.000Z"));

    await expect(verifyLtiIssuanceActionToken(env, token)).resolves.toBeNull();
  });
});
