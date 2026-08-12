import { describe, expect, it } from "vitest";
import { canonicalPlatformDomain } from "./platform-domain";

describe("canonicalPlatformDomain", () => {
  it("normalizes a configured hostname", () => {
    expect(canonicalPlatformDomain(" Badges.Example.EDU ")).toBe("badges.example.edu");
  });

  it.each([
    ["", "PLATFORM_DOMAIN must be configured"],
    [
      "https://badges.example.edu",
      "PLATFORM_DOMAIN must be a hostname without a scheme, path, or port",
    ],
    [
      "badges.example.edu/path",
      "PLATFORM_DOMAIN must be a hostname without a scheme, path, or port",
    ],
    [
      "badges.example.edu:443",
      "PLATFORM_DOMAIN must be a hostname without a scheme, path, or port",
    ],
    [
      "user@badges.example.edu",
      "PLATFORM_DOMAIN must be a hostname without a scheme, path, or port",
    ],
    [
      "badges.example.edu?mode=issuer",
      "PLATFORM_DOMAIN must be a hostname without a scheme, path, or port",
    ],
    [
      "badges.example.edu#issuer",
      "PLATFORM_DOMAIN must be a hostname without a scheme, path, or port",
    ],
    ["badges..example.edu", "PLATFORM_DOMAIN must be a valid hostname"],
    ["-badges.example.edu", "PLATFORM_DOMAIN must be a valid hostname"],
  ])("rejects a value that is not a bare hostname: %s", (value, message) => {
    expect(() => canonicalPlatformDomain(value)).toThrow(message);
  });
});
