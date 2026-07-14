import { describe, expect, it } from "vitest";
import { CREDTRAIL_OUTBOUND_USER_AGENT } from "../http/outbound-user-agent";
import { exchangeCanvasAuthorizationCode, refreshCanvasAccessToken } from "./canvas-oauth";

const createCanvasTokenFetch = (): {
  fetchImpl: typeof fetch;
  requests: Request[];
} => {
  const requests: Request[] = [];

  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    requests.push(request);

    return new Response(
      JSON.stringify({
        access_token: "canvas-access-token",
        expires_in: 3600,
      }),
      {
        headers: {
          "content-type": "application/json",
        },
      },
    );
  };

  return { fetchImpl, requests };
};

describe("Canvas OAuth", () => {
  it("identifies authorization-code exchanges to Canvas", async () => {
    const { fetchImpl, requests } = createCanvasTokenFetch();

    await expect(
      exchangeCanvasAuthorizationCode({
        tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
        clientId: "canvas-client-id",
        clientSecret: "canvas-client-secret",
        code: "authorization-code",
        redirectUri: "https://credtrail.org/oauth/callback",
        fetchImpl,
      }),
    ).resolves.toMatchObject({ accessToken: "canvas-access-token" });

    expect(requests).toHaveLength(1);
    expect(requests[0]?.headers.get("user-agent")).toBe(CREDTRAIL_OUTBOUND_USER_AGENT);
  });

  it("identifies token refreshes to Canvas", async () => {
    const { fetchImpl, requests } = createCanvasTokenFetch();

    await expect(
      refreshCanvasAccessToken({
        tokenEndpoint: "https://canvas.example.edu/login/oauth2/token",
        clientId: "canvas-client-id",
        clientSecret: "canvas-client-secret",
        refreshToken: "refresh-token",
        fetchImpl,
      }),
    ).resolves.toMatchObject({ accessToken: "canvas-access-token" });

    expect(requests).toHaveLength(1);
    expect(requests[0]?.headers.get("user-agent")).toBe(CREDTRAIL_OUTBOUND_USER_AGENT);
  });
});
