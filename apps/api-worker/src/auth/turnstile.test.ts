import { describe, expect, it } from "vitest";
import { createTurnstileVerifier } from "./turnstile";

const verificationInput = {
  secretKey: "secret-key",
  token: "challenge-token",
  remoteIp: "203.0.113.10",
  idempotencyKey: "request-123",
} as const;

describe("createTurnstileVerifier", () => {
  it("accepts a schema-valid successful verification response", async () => {
    const requestedBodies: string[] = [];
    const verifier = createTurnstileVerifier({
      fetchRequest: (_url, init) => {
        if (typeof init.body !== "string") {
          throw new Error("Expected Turnstile request body to be JSON text");
        }

        requestedBodies.push(init.body);
        return Promise.resolve(Response.json({ success: true, hostname: "credtrail.org" }));
      },
    });

    const accepted = await verifier.verify(verificationInput);

    expect(accepted).toBe(true);
    expect(requestedBodies).toEqual([
      JSON.stringify({
        secret: "secret-key",
        response: "challenge-token",
        idempotency_key: "request-123",
        remoteip: "203.0.113.10",
      }),
    ]);
  });

  it.each([
    ["malformed JSON", new Response("not-json")],
    ["invalid schema", Response.json({ success: "yes" })],
    ["non-success status", new Response(null, { status: 503 })],
  ])("fails closed for %s", async (_description, response) => {
    const verifier = createTurnstileVerifier({
      fetchRequest: () => Promise.resolve(response),
    });

    await expect(verifier.verify(verificationInput)).resolves.toBe(false);
  });

  it("fails closed when the network request rejects", async () => {
    const verifier = createTurnstileVerifier({
      fetchRequest: () => Promise.reject(new Error("network unavailable")),
    });

    await expect(verifier.verify(verificationInput)).resolves.toBe(false);
  });

  it("aborts requests that exceed the configured timeout", async () => {
    const verifier = createTurnstileVerifier({
      timeoutMs: 1,
      fetchRequest: (_url, init) => {
        return new Promise((_resolve, reject) => {
          init.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
        });
      },
    });

    await expect(verifier.verify(verificationInput)).resolves.toBe(false);
  });
});
