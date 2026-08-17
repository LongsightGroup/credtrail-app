import { lookup } from "node:dns/promises";
import type { LookupFunction } from "node:net";
import { Agent, request } from "undici";
import { isPublicNetworkAddress } from "../http/public-network-address";
import type {
  PublicResourceNetwork,
  PublicResourceNetworkResponse,
} from "../http/public-resource-network";
import type { ResolvedNetworkAddress } from "../http/public-network-address";

const NODE_PUBLIC_JSON_CONNECT_TIMEOUT_MS = 3_000;
const NODE_PUBLIC_JSON_HEADERS_TIMEOUT_MS = 5_000;
const NODE_PUBLIC_JSON_BODY_TIMEOUT_MS = 5_000;

const pinnedLookup = (addresses: readonly ResolvedNetworkAddress[]): LookupFunction => {
  return (_hostname, options, callback): void => {
    const matchingAddresses =
      options.family === 4 || options.family === 6
        ? addresses.filter((address) => address.family === options.family)
        : addresses;
    const selectedAddresses = matchingAddresses.length === 0 ? addresses : matchingAddresses;
    const first = selectedAddresses[0];

    if (first === undefined) {
      callback(new Error("No validated public address is available"), "", 0);
      return;
    }

    if (options.all === true) {
      callback(
        null,
        selectedAddresses.map((address) => ({
          address: address.address,
          family: address.family,
        })),
      );
      return;
    }

    callback(null, first.address, first.family);
  };
};

const responseHeader = (
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | null => {
  const value = headers[name];

  if (Array.isArray(value)) {
    return value[0] ?? null;
  }

  return value ?? null;
};

const readBoundedBodyBytes = async (
  body: Awaited<ReturnType<typeof request>>["body"],
  maxResponseBytes: number,
): Promise<
  { readonly status: "ok"; readonly bodyBytes: Uint8Array } | { readonly status: "too_large" }
> => {
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  for await (const chunk of body) {
    totalBytes += chunk.byteLength;

    if (totalBytes > maxResponseBytes) {
      body.destroy();
      return { status: "too_large" };
    }

    chunks.push(chunk);
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;

  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return { status: "ok", bodyBytes: bytes };
};

const requestWithPinnedAddresses = async (input: {
  readonly url: URL;
  readonly headers: Headers;
  readonly resolvedAddresses: readonly ResolvedNetworkAddress[];
  readonly maxResponseBytes: number;
  readonly signal: AbortSignal;
}): Promise<PublicResourceNetworkResponse> => {
  if (input.resolvedAddresses.length === 0) {
    throw new Error("Node verifier requests require a validated public address");
  }

  if (input.resolvedAddresses.some((address) => !isPublicNetworkAddress(address))) {
    throw new Error("Node verifier requests reject non-public addresses");
  }

  const dispatcher = new Agent({
    connect: {
      lookup: pinnedLookup(input.resolvedAddresses),
      timeout: NODE_PUBLIC_JSON_CONNECT_TIMEOUT_MS,
    },
    headersTimeout: NODE_PUBLIC_JSON_HEADERS_TIMEOUT_MS,
    bodyTimeout: NODE_PUBLIC_JSON_BODY_TIMEOUT_MS,
    maxResponseSize: input.maxResponseBytes,
  });

  try {
    const response = await request(input.url, {
      dispatcher,
      method: "GET",
      headers: input.headers,
      signal: input.signal,
    });
    const location = responseHeader(response.headers, "location");

    if (
      response.statusCode === 301 ||
      response.statusCode === 302 ||
      response.statusCode === 303 ||
      response.statusCode === 307 ||
      response.statusCode === 308
    ) {
      await response.body.dump();
      return {
        status: "received",
        statusCode: response.statusCode,
        location,
        bodyBytes: new Uint8Array(),
      };
    }

    const contentLength = responseHeader(response.headers, "content-length");

    if (contentLength !== null) {
      const parsedContentLength = Number.parseInt(contentLength, 10);

      if (Number.isFinite(parsedContentLength) && parsedContentLength > input.maxResponseBytes) {
        response.body.destroy();
        return { status: "response_too_large" };
      }
    }

    const body = await readBoundedBodyBytes(response.body, input.maxResponseBytes);
    return body.status === "too_large"
      ? { status: "response_too_large" }
      : {
          status: "received",
          statusCode: response.statusCode,
          location,
          bodyBytes: body.bodyBytes,
        };
  } finally {
    await dispatcher.close();
  }
};

/** Creates the DNS-pinning public-network adapter for the Node self-host runtime. */
export const createNodePublicResourceNetwork = (input?: {
  readonly lookupHostname?: (hostname: string) => Promise<readonly ResolvedNetworkAddress[]>;
}): PublicResourceNetwork => {
  const lookupHostname =
    input?.lookupHostname ??
    (async (hostname: string): Promise<readonly ResolvedNetworkAddress[]> => {
      const addresses = await lookup(hostname, { all: true, order: "verbatim" });
      return addresses.flatMap((address): readonly ResolvedNetworkAddress[] => {
        if (address.family !== 4 && address.family !== 6) {
          return [];
        }

        return [{ address: address.address, family: address.family }];
      });
    });

  return {
    resolveHostname: async (hostname, options) => {
      if (options.signal.aborted) {
        throw new Error("Node verifier DNS resolution was cancelled", {
          cause: options.signal.reason,
        });
      }

      return new Promise((resolve, reject) => {
        const abort = (): void => {
          reject(
            new Error("Node verifier DNS resolution was cancelled", {
              cause: options.signal.reason,
            }),
          );
        };

        options.signal.addEventListener("abort", abort, { once: true });
        lookupHostname(hostname).then(
          (addresses) => {
            options.signal.removeEventListener("abort", abort);
            resolve(addresses);
          },
          (error: unknown) => {
            options.signal.removeEventListener("abort", abort);
            reject(error);
          },
        );
      });
    },
    request: requestWithPinnedAddresses,
  };
};
