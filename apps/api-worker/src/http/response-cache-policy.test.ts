import { describe, expect, it } from "vitest";
import { applyResponseCachePolicy } from "./response-cache-policy";

const applyPolicy = (input: { responseHeaders?: HeadersInit }): Headers => {
  const responseHeaders = new Headers(input.responseHeaders);
  applyResponseCachePolicy(responseHeaders);
  return responseHeaders;
};

describe("applyResponseCachePolicy", () => {
  it("defaults responses to no-store", () => {
    const headers = applyPolicy({});

    expect(headers.get("Cache-Control")).toBe("no-store");
  });

  it("preserves an explicit public cache policy", () => {
    const headers = applyPolicy({
      responseHeaders: { "Cache-Control": "public, max-age=31536000, immutable" },
    });

    expect(headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
  });

  it("overrides public caching when the response sets a cookie", () => {
    const headers = applyPolicy({
      responseHeaders: {
        "Cache-Control": "public, max-age=31536000, immutable",
        "Set-Cookie": "session=value",
      },
    });

    expect(headers.get("Cache-Control")).toBe("no-store");
  });
});
