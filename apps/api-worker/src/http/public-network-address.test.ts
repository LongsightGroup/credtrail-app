import { describe, expect, it } from "vitest";
import {
  isBlockedNetworkHostname,
  isPublicNetworkAddress,
  literalNetworkAddress,
} from "./public-network-address";

describe("public outbound network address policy", () => {
  it.each([
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.0.0.1",
    "192.0.2.1",
    "192.168.0.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
  ])("rejects non-public IPv4 address %s", (address) => {
    expect(isPublicNetworkAddress({ address, family: 4 })).toBe(false);
  });

  it.each(["1.1.1.1", "8.8.8.8", "93.184.216.34"])("allows public IPv4 address %s", (address) => {
    expect(isPublicNetworkAddress({ address, family: 4 })).toBe(true);
  });

  it.each([
    "::",
    "::1",
    "::ffff:127.0.0.1",
    "fc00::1",
    "fe80::1",
    "ff00::1",
    "2001:db8::1",
    "2002::1",
  ])("rejects non-public IPv6 address %s", (address) => {
    expect(isPublicNetworkAddress({ address, family: 6 })).toBe(false);
  });

  it.each(["2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8"])(
    "allows public IPv6 address %s",
    (address) => {
      expect(isPublicNetworkAddress({ address, family: 6 })).toBe(true);
    },
  );

  it("parses normalized IPv4 and IPv6 literals", () => {
    expect(literalNetworkAddress("93.184.216.34")).toEqual({
      address: "93.184.216.34",
      family: 4,
    });
    expect(literalNetworkAddress("[2606:4700:4700::1111]")).toEqual({
      address: "2606:4700:4700::1111",
      family: 6,
    });
    expect(literalNetworkAddress("schemas.example.edu")).toBeNull();
  });

  it.each(["localhost", "api.localhost.", "service.local", "db.internal", "host.home.arpa"])(
    "rejects reserved hostname %s",
    (hostname) => {
      expect(isBlockedNetworkHostname(hostname)).toBe(true);
    },
  );
});
