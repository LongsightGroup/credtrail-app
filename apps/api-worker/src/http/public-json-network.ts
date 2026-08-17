import {
  isBlockedNetworkHostname,
  isPublicNetworkAddress,
  literalNetworkAddress,
  normalizeNetworkHostname,
  type ResolvedNetworkAddress,
} from "./public-network-address";

export type { ResolvedNetworkAddress } from "./public-network-address";

const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
const DEFAULT_REQUEST_TIMEOUT_MS = 5_000;
const MAX_REDIRECTS = 4;

/** One bounded HTTP response returned by a runtime-specific public-network adapter. */
export type PublicJsonNetworkResponse =
  | {
      readonly status: "received";
      readonly statusCode: number;
      readonly location: string | null;
      readonly bodyText: string;
    }
  | { readonly status: "response_too_large" };

/** Runtime-specific outbound network operations used by public credential verification. */
export interface PublicJsonNetwork {
  /** Resolves a hostname when the runtime must pin the subsequent connection to validated addresses. */
  resolveHostname(
    hostname: string,
    options: { readonly signal: AbortSignal },
  ): Promise<readonly ResolvedNetworkAddress[] | null>;
  /** Performs one redirect-disabled, bounded request to a previously validated URL. */
  request(input: {
    readonly url: URL;
    readonly headers: Headers;
    readonly resolvedAddresses: readonly ResolvedNetworkAddress[];
    readonly maxResponseBytes: number;
    readonly signal: AbortSignal;
  }): Promise<PublicJsonNetworkResponse>;
}

/** Typed outcome from loading untrusted public JSON for credential verification. */
export type PublicJsonLoadResult =
  | { readonly status: "ok"; readonly value: unknown }
  | {
      readonly status: "error";
      readonly error:
        | { readonly kind: "invalid_url" }
        | { readonly kind: "blocked_destination" }
        | { readonly kind: "request_failed" }
        | { readonly kind: "response_too_large" }
        | { readonly kind: "too_many_redirects" }
        | { readonly kind: "http_error"; readonly statusCode: number }
        | { readonly kind: "invalid_json" };
    };

const redirectStatus = (statusCode: number): boolean => {
  return (
    statusCode === 301 ||
    statusCode === 302 ||
    statusCode === 303 ||
    statusCode === 307 ||
    statusCode === 308
  );
};

const parseCandidateUrl = (
  value: string,
  baseUrl?: URL,
): { readonly status: "ok"; readonly url: URL } | { readonly status: "error" } => {
  let url: URL;

  try {
    url = baseUrl === undefined ? new URL(value) : new URL(value, baseUrl);
  } catch {
    return { status: "error" };
  }

  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    isBlockedNetworkHostname(url.hostname)
  ) {
    return { status: "error" };
  }

  return { status: "ok", url };
};

const resolvedAddressesForUrl = async (
  network: PublicJsonNetwork,
  url: URL,
  signal: AbortSignal,
): Promise<readonly ResolvedNetworkAddress[] | null> => {
  const literal = literalNetworkAddress(url.hostname);

  if (literal !== null) {
    return isPublicNetworkAddress(literal) ? [literal] : [];
  }

  const resolved = await network.resolveHostname(normalizeNetworkHostname(url.hostname), {
    signal,
  });

  if (resolved === null) {
    return null;
  }

  if (resolved.length === 0 || resolved.some((address) => !isPublicNetworkAddress(address))) {
    return [];
  }

  return resolved;
};

const readBoundedResponseText = async (
  response: Response,
  maxResponseBytes: number,
): Promise<
  { readonly status: "ok"; readonly bodyText: string } | { readonly status: "too_large" }
> => {
  const contentLength = response.headers.get("content-length");

  if (contentLength !== null) {
    const parsedContentLength = Number.parseInt(contentLength, 10);

    if (Number.isFinite(parsedContentLength) && parsedContentLength > maxResponseBytes) {
      await response.body?.cancel();
      return { status: "too_large" };
    }
  }

  if (response.body === null) {
    return { status: "ok", bodyText: "" };
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  while (true) {
    const next = await reader.read();

    if (next.done) {
      break;
    }

    totalBytes += next.value.byteLength;

    if (totalBytes > maxResponseBytes) {
      await reader.cancel();
      return { status: "too_large" };
    }

    chunks.push(next.value);
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;

  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return { status: "ok", bodyText: new TextDecoder().decode(bytes) };
};

/** Creates a strict-public network adapter around a runtime fetch implementation. */
export const createFetchPublicJsonNetwork = (
  fetchRequest: (url: string, init: RequestInit) => Promise<Response>,
): PublicJsonNetwork => {
  return {
    resolveHostname: async () => null,
    request: async (input) => {
      const response = await fetchRequest(input.url.toString(), {
        method: "GET",
        redirect: "manual",
        headers: input.headers,
        signal: input.signal,
      });

      if (redirectStatus(response.status)) {
        await response.body?.cancel();
        return {
          status: "received",
          statusCode: response.status,
          location: response.headers.get("location"),
          bodyText: "",
        };
      }

      const body = await readBoundedResponseText(response, input.maxResponseBytes);
      return body.status === "too_large"
        ? { status: "response_too_large" }
        : {
            status: "received",
            statusCode: response.status,
            location: response.headers.get("location"),
            bodyText: body.bodyText,
          };
    },
  };
};

/** Public-internet adapter for the Cloudflare Worker runtime. */
export const workerPublicJsonNetwork = createFetchPublicJsonNetwork((url, init) =>
  fetch(url, init),
);

/** Loads JSON through a runtime adapter while rejecting private destinations and unsafe redirects. */
export const loadPublicJsonFromUrl = async (
  network: PublicJsonNetwork,
  input: {
    readonly resourceUrl: string;
    readonly headers: Headers;
    readonly maxResponseBytes?: number;
    readonly timeoutMs?: number;
  },
): Promise<PublicJsonLoadResult> => {
  const initial = parseCandidateUrl(input.resourceUrl);

  if (initial.status === "error") {
    return { status: "error", error: { kind: "invalid_url" } };
  }

  const abortController = new AbortController();
  const timeoutHandle = setTimeout(
    () => abortController.abort("public-json-request-timeout"),
    input.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
  );
  let currentUrl = initial.url;

  try {
    for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
      const resolvedAddresses = await resolvedAddressesForUrl(
        network,
        currentUrl,
        abortController.signal,
      );

      if (resolvedAddresses !== null && resolvedAddresses.length === 0) {
        return { status: "error", error: { kind: "blocked_destination" } };
      }

      let response: PublicJsonNetworkResponse;

      try {
        response = await network.request({
          url: currentUrl,
          headers: input.headers,
          resolvedAddresses: resolvedAddresses ?? [],
          maxResponseBytes: input.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
          signal: abortController.signal,
        });
      } catch {
        return { status: "error", error: { kind: "request_failed" } };
      }

      if (response.status === "response_too_large") {
        return { status: "error", error: { kind: "response_too_large" } };
      }

      if (redirectStatus(response.statusCode) && response.location !== null) {
        if (redirectCount === MAX_REDIRECTS) {
          return { status: "error", error: { kind: "too_many_redirects" } };
        }

        const redirect = parseCandidateUrl(response.location, currentUrl);

        if (redirect.status === "error") {
          return { status: "error", error: { kind: "blocked_destination" } };
        }

        currentUrl = redirect.url;
        continue;
      }

      if (response.statusCode < 200 || response.statusCode >= 300) {
        return {
          status: "error",
          error: { kind: "http_error", statusCode: response.statusCode },
        };
      }

      let value: unknown;

      try {
        value = JSON.parse(response.bodyText) as unknown;
      } catch {
        return { status: "error", error: { kind: "invalid_json" } };
      }

      return { status: "ok", value };
    }

    return { status: "error", error: { kind: "too_many_redirects" } };
  } catch {
    return { status: "error", error: { kind: "request_failed" } };
  } finally {
    clearTimeout(timeoutHandle);
  }
};
