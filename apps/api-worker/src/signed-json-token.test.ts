import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createSignedJsonToken,
  namespacedSigningSecret,
  signedJsonTokenExpiry,
  verifySignedJsonToken,
} from "./signed-json-token";

interface TestPayload {
  tenantId: string;
  exp: number;
}

const parseTestPayload = (value: unknown): TestPayload | null => {
  if (value === null || typeof value !== "object") {
    return null;
  }

  const candidate = value as Partial<TestPayload>;

  if (
    typeof candidate.tenantId !== "string" ||
    candidate.tenantId.length === 0 ||
    typeof candidate.exp !== "number" ||
    !Number.isInteger(candidate.exp)
  ) {
    return null;
  }

  return {
    tenantId: candidate.tenantId,
    exp: candidate.exp,
  };
};

afterEach(() => {
  vi.useRealTimers();
});

describe("signed JSON token helper", () => {
  it("namespaces signing secrets when a namespace is provided", () => {
    expect(namespacedSigningSecret("base-secret")).toBe("base-secret");
    expect(namespacedSigningSecret("base-secret", "issuance-action")).toBe(
      "base-secret:issuance-action",
    );
  });

  it("round-trips signed payloads", async () => {
    const token = await createSignedJsonToken("base-secret", {
      tenantId: "tenant-a",
      exp: signedJsonTokenExpiry(60),
    });

    const verified = await verifySignedJsonToken("base-secret", token, parseTestPayload);

    expect(verified).toEqual({
      tenantId: "tenant-a",
      exp: expect.any(Number),
    });
  });

  it("rejects tokens signed with a different secret", async () => {
    const token = await createSignedJsonToken("base-secret", {
      tenantId: "tenant-a",
      exp: signedJsonTokenExpiry(60),
    });

    await expect(
      verifySignedJsonToken("other-secret", token, parseTestPayload),
    ).resolves.toBeNull();
  });

  it("rejects tampered tokens", async () => {
    const token = await createSignedJsonToken("base-secret", {
      tenantId: "tenant-a",
      exp: signedJsonTokenExpiry(60),
    });
    const tampered = `${token.slice(0, -1)}${token.endsWith("a") ? "b" : "a"}`;

    await expect(
      verifySignedJsonToken("base-secret", tampered, parseTestPayload),
    ).resolves.toBeNull();
  });

  it("rejects expired tokens", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-01T12:00:00.000Z"));

    const token = await createSignedJsonToken("base-secret", {
      tenantId: "tenant-a",
      exp: signedJsonTokenExpiry(1),
    });

    vi.setSystemTime(new Date("2026-05-01T12:00:02.000Z"));

    await expect(verifySignedJsonToken("base-secret", token, parseTestPayload)).resolves.toBeNull();
  });

  it("rejects malformed tokens", async () => {
    await expect(
      verifySignedJsonToken("base-secret", "not-a-token", parseTestPayload),
    ).resolves.toBeNull();
    await expect(
      verifySignedJsonToken("base-secret", "payload.signature.extra", parseTestPayload),
    ).resolves.toBeNull();
  });
});
