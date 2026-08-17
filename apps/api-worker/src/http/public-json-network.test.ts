import { describe, expect, it } from "vitest";
import {
  createFetchPublicJsonNetwork,
  loadPublicJsonFromUrl,
  type PublicJsonNetwork,
  type PublicJsonNetworkResponse,
  type ResolvedNetworkAddress,
} from "./public-json-network";

const PUBLIC_IPV4: ResolvedNetworkAddress = { address: "93.184.216.34", family: 4 };

class RecordingPublicJsonNetwork implements PublicJsonNetwork {
  readonly requestedUrls: string[] = [];

  constructor(
    private readonly responses: PublicJsonNetworkResponse[],
    private readonly addressesByHostname = new Map<string, readonly ResolvedNetworkAddress[]>(),
  ) {}

  resolveHostname(hostname: string): Promise<readonly ResolvedNetworkAddress[]> {
    return Promise.resolve(this.addressesByHostname.get(hostname) ?? [PUBLIC_IPV4]);
  }

  request(input: { readonly url: URL }): Promise<PublicJsonNetworkResponse> {
    this.requestedUrls.push(input.url.toString());
    const response = this.responses.shift();

    if (response === undefined) {
      throw new Error("Test network has no response queued");
    }

    return Promise.resolve(response);
  }
}

const jsonResponse = (value: unknown): PublicJsonNetworkResponse => ({
  status: "received",
  statusCode: 200,
  location: null,
  bodyBytes: new TextEncoder().encode(JSON.stringify(value)),
});

const load = (network: PublicJsonNetwork, resourceUrl: string) => {
  return loadPublicJsonFromUrl(network, {
    resourceUrl,
    headers: new Headers({ accept: "application/json" }),
  });
};

describe("public verifier JSON loading", () => {
  it.each([
    "http://127.0.0.1/metadata",
    "http://2130706433/metadata",
    "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.1/private",
    "http://[::1]/private",
    "http://[::ffff:7f00:1]/private",
    "http://[fc00::1]/private",
    "http://[fe80::1]/private",
    "http://[2001:db8::1]/private",
    "http://localhost/private",
    "http://service.internal/private",
    "ftp://example.com/file.json",
    "https://user:password@example.com/schema.json",
  ])("rejects non-public destination %s before requesting it", async (resourceUrl) => {
    const network = new RecordingPublicJsonNetwork([jsonResponse({ ok: true })]);

    await expect(load(network, resourceUrl)).resolves.toEqual({
      status: "error",
      error: expect.objectContaining({
        kind: expect.stringMatching(/invalid_url|blocked_destination/u),
      }),
    });
    expect(network.requestedUrls).toEqual([]);
  });

  it("rejects a public hostname when DNS returns any private address", async () => {
    const network = new RecordingPublicJsonNetwork(
      [jsonResponse({ ok: true })],
      new Map([
        [
          "schemas.example.edu",
          [PUBLIC_IPV4, { address: "10.0.0.8", family: 4 } satisfies ResolvedNetworkAddress],
        ],
      ]),
    );

    await expect(load(network, "https://schemas.example.edu/credential.json")).resolves.toEqual({
      status: "error",
      error: { kind: "blocked_destination" },
    });
    expect(network.requestedUrls).toEqual([]);
  });

  it("revalidates redirect destinations", async () => {
    const network = new RecordingPublicJsonNetwork([
      {
        status: "received",
        statusCode: 302,
        location: "http://127.0.0.1/admin",
        bodyBytes: new Uint8Array(),
      },
    ]);

    await expect(load(network, "https://schemas.example.edu/credential.json")).resolves.toEqual({
      status: "error",
      error: { kind: "blocked_destination" },
    });
    expect(network.requestedUrls).toEqual(["https://schemas.example.edu/credential.json"]);
  });

  it("returns parsed JSON from a valid public destination", async () => {
    const network = new RecordingPublicJsonNetwork([jsonResponse({ title: "Credential schema" })]);

    await expect(load(network, "https://schemas.example.edu/credential.json")).resolves.toEqual({
      status: "ok",
      value: { title: "Credential schema" },
    });
  });

  it("enforces the response byte limit in the fetch adapter", async () => {
    const requestedUrls: string[] = [];
    const network = createFetchPublicJsonNetwork((url) => {
      requestedUrls.push(url);
      return Promise.resolve(
        new Response(JSON.stringify({ payload: "x".repeat(64) }), {
          headers: { "content-type": "application/json" },
        }),
      );
    });

    await expect(
      loadPublicJsonFromUrl(network, {
        resourceUrl: "https://schemas.example.edu/credential.json",
        headers: new Headers({ accept: "application/json" }),
        maxResponseBytes: 32,
      }),
    ).resolves.toEqual({
      status: "error",
      error: { kind: "response_too_large" },
    });
    expect(requestedUrls).toEqual(["https://schemas.example.edu/credential.json"]);
  });
});
