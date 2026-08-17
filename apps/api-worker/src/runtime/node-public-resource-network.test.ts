import { describe, expect, it } from "vitest";
import { createNodePublicResourceNetwork } from "./node-public-resource-network";

describe("Node public JSON network", () => {
  it("returns addresses from the injected DNS resolver", async () => {
    const network = createNodePublicResourceNetwork({
      lookupHostname: () => Promise.resolve([{ address: "93.184.216.34", family: 4 }]),
    });

    await expect(
      network.resolveHostname("schemas.example.edu", { signal: new AbortController().signal }),
    ).resolves.toEqual([{ address: "93.184.216.34", family: 4 }]);
  });

  it("stops waiting for DNS when the caller cancels", async () => {
    const network = createNodePublicResourceNetwork({
      lookupHostname: () => new Promise(() => undefined),
    });
    const abortController = new AbortController();
    const resolution = network.resolveHostname("schemas.example.edu", {
      signal: abortController.signal,
    });

    abortController.abort("test-cancellation");

    await expect(resolution).rejects.toThrow("DNS resolution was cancelled");
  });

  it("revalidates supplied addresses before opening a connection", async () => {
    const network = createNodePublicResourceNetwork();

    await expect(
      network.request({
        url: new URL("https://schemas.example.edu/credential.json"),
        headers: new Headers({ accept: "application/json" }),
        resolvedAddresses: [{ address: "10.0.0.8", family: 4 }],
        maxResponseBytes: 1_024,
        signal: new AbortController().signal,
      }),
    ).rejects.toThrow("reject non-public addresses");
  });
});
