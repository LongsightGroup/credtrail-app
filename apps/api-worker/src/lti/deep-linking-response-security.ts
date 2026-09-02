const LTI_DEEP_LINKING_AUTO_SUBMIT_SCRIPT =
  "\n    document.getElementById('deepLinkingForm').submit();\n  ";

const base64Encode = (bytes: Uint8Array): string => {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
};

const sha256CspSource = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return `'sha256-${base64Encode(new Uint8Array(digest))}'`;
};

const httpOrigin = (returnUrl: string): string => {
  const url = new URL(returnUrl);

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new TypeError("LTI Deep Linking return URL must use HTTP or HTTPS");
  }

  return url.origin;
};

/**
 * Narrows the one-time Deep Linking response policy to its exact auto-submit
 * script and the verified platform return origin.
 */
export const secureLtiDeepLinkingHtmlResponse = async (
  response: Response,
  returnUrl: string,
): Promise<Response> => {
  const html = await response.text();
  const expectedScriptElement = `<script>${LTI_DEEP_LINKING_AUTO_SUBMIT_SCRIPT}</script>`;
  const scriptSource = html.includes(expectedScriptElement)
    ? await sha256CspSource(LTI_DEEP_LINKING_AUTO_SUBMIT_SCRIPT)
    : "'none'";
  const headers = new Headers(response.headers);

  headers.set(
    "Content-Security-Policy",
    [
      "default-src 'none'",
      "base-uri 'none'",
      "object-src 'none'",
      `script-src ${scriptSource}`,
      `form-action ${httpOrigin(returnUrl)}`,
    ].join("; "),
  );

  return new Response(html, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
};
