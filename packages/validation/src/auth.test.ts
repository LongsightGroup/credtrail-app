import { describe, expect, it } from "vitest";

import {
  parseLearnerDidSettingsRequest,
  parseLearnerIdentityLinkRequest,
  parseLearnerIdentityLinkVerifyRequest,
  parseMagicLinkRequest,
  parseMagicLinkVerifyRequest,
} from "./auth.js";

describe("magic link request parsers", () => {
  it("accepts a valid magic link request", () => {
    const request = parseMagicLinkRequest({
      tenantId: "tenant_123",
      email: "learner@example.edu",
      nextPath: "/auth/resolve",
    });

    expect(request.tenantId).toBe("tenant_123");
    expect(request.email).toBe("learner@example.edu");
    expect(request.nextPath).toBe("/auth/resolve");
  });

  it("accepts browser date-time preferences for magic link email formatting", () => {
    const request = parseMagicLinkRequest({
      tenantId: "tenant_123",
      email: "learner@example.edu",
      preferredLocale: "en-US",
      preferredTimeZone: "America/New_York",
    });

    expect(request.preferredLocale).toBe("en-US");
    expect(request.preferredTimeZone).toBe("America/New_York");
  });

  it("accepts email-only magic link requests for tenant discovery", () => {
    const request = parseMagicLinkRequest({
      email: "learner@example.edu",
    });

    expect(request.tenantId).toBeUndefined();
    expect(request.email).toBe("learner@example.edu");
  });

  it("rejects invalid email values", () => {
    expect(() => {
      parseMagicLinkRequest({
        tenantId: "tenant_123",
        email: "not-an-email",
      });
    }).toThrow(/./);
  });

  it("accepts a valid magic link verify payload", () => {
    const verify = parseMagicLinkVerifyRequest({
      token: "0123456789012345678901234567890123456789",
    });

    expect(verify.token.length).toBeGreaterThan(20);
  });
});

describe("learner identity link parsers", () => {
  it("accepts a valid learner identity link request", () => {
    const request = parseLearnerIdentityLinkRequest({
      email: "learner@gmail.com",
    });

    expect(request.email).toBe("learner@gmail.com");
  });

  it("accepts a valid learner identity link verify payload", () => {
    const request = parseLearnerIdentityLinkVerifyRequest({
      token: "0123456789012345678901234567890123456789",
    });

    expect(request.token.length).toBeGreaterThan(20);
  });

  it("rejects invalid learner identity link email values", () => {
    expect(() => {
      parseLearnerIdentityLinkRequest({
        email: "invalid",
      });
    }).toThrow(/./);
  });
});

describe("learner DID settings parser", () => {
  it("accepts supported DID methods and empty clear value", () => {
    const keyDid = parseLearnerDidSettingsRequest({
      did: "did:key:z6MkhY1pD8x7Jk9hN8YvKQxN5f3qU8d9sF4A2B3C4D5E6F7",
    });
    const webDid = parseLearnerDidSettingsRequest({ did: "did:web:wallet.example.edu:alice" });
    const ionDid = parseLearnerDidSettingsRequest({ did: "did:ion:EiAxyz123" });
    const clearDid = parseLearnerDidSettingsRequest({ did: "" });

    expect(keyDid.did).toContain("did:key:");
    expect(webDid.did).toContain("did:web:");
    expect(ionDid.did).toContain("did:ion:");
    expect(clearDid.did).toBe("");
  });

  it("rejects unsupported DID methods", () => {
    expect(() => {
      parseLearnerDidSettingsRequest({
        did: "did:example:123",
      });
    }).toThrow(/./);
  });
});
