import type { JsonObject } from "@credtrail/core-domain";
import { canonicalAppOrigin } from "./canonical-app-url";
import { withCredTrailUserAgent } from "./outbound-user-agent";

interface CreateJsonObjectLoaderInput<BindingsType> {
  appRequest: (
    pathWithQuery: string,
    init: RequestInit,
    bindings: BindingsType,
  ) => Promise<Response>;
  asJsonObject: (value: unknown) => JsonObject | null;
  publicAppOrigin: (bindings: BindingsType) => string;
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
        response = await fetch(resourceUrl, {
          headers: withCredTrailUserAgent({
            accept: acceptHeader,
          }),
        });
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
