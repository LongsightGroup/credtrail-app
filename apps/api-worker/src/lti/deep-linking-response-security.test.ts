import { describe, expect, it } from "vitest";
import { secureLtiDeepLinkingHtmlResponse } from "./deep-linking-response-security";

describe("secureLtiDeepLinkingHtmlResponse", () => {
  it("allows only the expected auto-submit script and platform return origin", async () => {
    const response = new Response(
      `<!DOCTYPE html>
<html>
<body>
  <form method="POST" action="https://lms.example.edu/deep-link-return"></form>
  <script>
    document.getElementById('deepLinkingForm').submit();
  </script>
</body>
</html>`,
      {
        headers: {
          "cache-control": "no-store",
          "content-type": "text/html; charset=utf-8",
        },
      },
    );

    const secured = await secureLtiDeepLinkingHtmlResponse(
      response,
      "https://lms.example.edu/deep-link-return?state=opaque",
    );

    expect(secured.headers.get("content-security-policy")).toMatch(
      /^default-src 'none'; base-uri 'none'; object-src 'none'; script-src 'sha256-[A-Za-z0-9+/]+=*'; form-action https:\/\/lms\.example\.edu$/,
    );
    expect(secured.headers.get("content-security-policy")).not.toContain("unsafe-inline");
    expect(secured.headers.get("cache-control")).toBe("no-store");
    await expect(secured.text()).resolves.toContain("deepLinkingForm");
  });

  it("fails closed when the dependency response does not contain the known script", async () => {
    const response = new Response("<!DOCTYPE html><html><body>Continue</body></html>");

    const secured = await secureLtiDeepLinkingHtmlResponse(
      response,
      "https://lms.example.edu/deep-link-return",
    );

    expect(secured.headers.get("content-security-policy")).toContain("script-src 'none'");
  });

  it("rejects non-HTTP platform return URLs", async () => {
    const response = new Response("<!DOCTYPE html><html><body></body></html>");

    await expect(secureLtiDeepLinkingHtmlResponse(response, "javascript:alert(1)")).rejects.toThrow(
      "LTI Deep Linking return URL must use HTTP or HTTPS",
    );
  });
});
