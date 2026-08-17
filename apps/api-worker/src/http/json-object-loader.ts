import type { JsonObject } from "@credtrail/core-domain";
import { canonicalAppOrigin } from "./canonical-app-url";
import { withCredTrailUserAgent } from "./outbound-user-agent";
import {
  loadPublicJsonFromUrl,
  type PublicJsonLoadResult,
  type PublicJsonNetwork,
} from "./public-json-network";

interface CreateJsonObjectLoaderInput<BindingsType> {
  appRequest: (
    pathWithQuery: string,
    init: RequestInit,
    bindings: BindingsType,
  ) => Promise<Response>;
  asJsonObject: (value: unknown) => JsonObject | null;
  publicAppOrigin: (bindings: BindingsType) => string;
  publicJsonNetwork: (bindings: BindingsType) => PublicJsonNetwork;
}

type JsonObjectLoadResult =
  | {
      status: "ok";
      value: JsonObject;
    }
  | {
      status: "error";
      reason: string;
    };

const publicJsonLoadErrorReason = (
  result: Extract<PublicJsonLoadResult, { status: "error" }>,
): string => {
  switch (result.error.kind) {
    case "invalid_url":
      return "URL is invalid or unsupported";
    case "blocked_destination":
      return "URL destination is not public";
    case "request_failed":
      return "request failed";
    case "response_too_large":
      return "response exceeds the verification size limit";
    case "too_many_redirects":
      return "request exceeded the redirect limit";
    case "http_error":
      return `HTTP ${String(result.error.statusCode)}`;
    case "invalid_json":
      return "response is not valid JSON";
  }
};

export const createLoadJsonObjectFromUrl = <BindingsType>(
  input: CreateJsonObjectLoaderInput<BindingsType>,
) => {
  return async (
    context: { env: BindingsType },
    resourceUrl: string,
    acceptHeader: string,
  ): Promise<JsonObjectLoadResult> => {
    let parsedResourceUrl: URL;

    try {
      parsedResourceUrl = new URL(resourceUrl);
    } catch {
      return {
        status: "error",
        reason: "URL is invalid",
      };
    }

    let response: Response;

    try {
      const publicOrigin = canonicalAppOrigin(input.publicAppOrigin(context.env));

      if (parsedResourceUrl.origin === publicOrigin) {
        const pathWithQuery = `${parsedResourceUrl.pathname}${parsedResourceUrl.search}`;
        response = await input.appRequest(
          pathWithQuery,
          {
            method: "GET",
            headers: withCredTrailUserAgent({
              accept: acceptHeader,
            }),
          },
          context.env,
        );
      } else {
        const loaded = await loadPublicJsonFromUrl(input.publicJsonNetwork(context.env), {
          resourceUrl,
          headers: withCredTrailUserAgent({ accept: acceptHeader }),
        });

        if (loaded.status === "error") {
          return {
            status: "error",
            reason: publicJsonLoadErrorReason(loaded),
          };
        }

        const responseObject = input.asJsonObject(loaded.value);

        if (responseObject === null) {
          return {
            status: "error",
            reason: "response is not a JSON object",
          };
        }

        return {
          status: "ok",
          value: responseObject,
        };
      }
    } catch {
      return {
        status: "error",
        reason: "request failed",
      };
    }

    if (!response.ok) {
      return {
        status: "error",
        reason: `HTTP ${String(response.status)}`,
      };
    }

    const responseBody = await response.json<unknown>().catch(() => null);
    const responseObject = input.asJsonObject(responseBody);

    if (responseObject === null) {
      return {
        status: "error",
        reason: "response is not a JSON object",
      };
    }

    return {
      status: "ok",
      value: responseObject,
    };
  };
};
