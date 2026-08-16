import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";
import { withCredTrailUserAgent } from "../http/outbound-user-agent";
import { gradebookProviderRequestError } from "./gradebook-provider-error";
import type { GradebookRequestOptions } from "./gradebook-types";

const parseCanvasTokenResponse = (
  input: unknown,
): {
  accessToken: string;
  refreshToken?: string | undefined;
  expiresInSeconds?: number | undefined;
  refreshTokenExpiresInSeconds?: number | undefined;
  scope?: string | undefined;
} => {
  const payload = asJsonObject(input);

  if (payload === null) {
    throw new Error("Canvas token response must be a JSON object");
  }

  const accessToken = asNonEmptyString(payload.access_token);

  if (accessToken === null) {
    throw new Error("Canvas token response is missing access_token");
  }

  const refreshToken = asNonEmptyString(payload.refresh_token) ?? undefined;
  const scope = asNonEmptyString(payload.scope) ?? undefined;

  const expiresInRaw = payload.expires_in;
  const refreshTokenExpiresInRaw = payload.refresh_token_expires_in;
  let expiresInSeconds: number | undefined;
  let refreshTokenExpiresInSeconds: number | undefined;

  if (typeof expiresInRaw === "number" && Number.isFinite(expiresInRaw) && expiresInRaw > 0) {
    expiresInSeconds = Math.floor(expiresInRaw);
  }

  if (
    typeof refreshTokenExpiresInRaw === "number" &&
    Number.isFinite(refreshTokenExpiresInRaw) &&
    refreshTokenExpiresInRaw > 0
  ) {
    refreshTokenExpiresInSeconds = Math.floor(refreshTokenExpiresInRaw);
  }

  return {
    accessToken,
    ...(refreshToken === undefined ? {} : { refreshToken }),
    ...(expiresInSeconds === undefined ? {} : { expiresInSeconds }),
    ...(refreshTokenExpiresInSeconds === undefined ? {} : { refreshTokenExpiresInSeconds }),
    ...(scope === undefined ? {} : { scope }),
  };
};

export const refreshCanvasAccessToken = async (
  input: {
    tokenEndpoint: string;
    clientId: string;
    clientSecret: string;
    refreshToken: string;
    fetchImpl?: typeof fetch;
  },
  options: GradebookRequestOptions = {},
): Promise<{
  accessToken: string;
  refreshToken?: string | undefined;
  expiresInSeconds?: number | undefined;
  refreshTokenExpiresInSeconds?: number | undefined;
  scope?: string | undefined;
}> => {
  const fetchImpl = input.fetchImpl ?? fetch;
  let response: Response;

  try {
    response = await fetchImpl(input.tokenEndpoint, {
      method: "POST",
      headers: withCredTrailUserAgent({
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      }),
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: input.clientId,
        client_secret: input.clientSecret,
        refresh_token: input.refreshToken,
      }).toString(),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
  } catch (cause: unknown) {
    throw gradebookProviderRequestError({
      providerKind: "canvas",
      operation: "connection",
      cause,
      options,
    });
  }

  if (!response.ok) {
    throw new Error(`Canvas token refresh failed (${String(response.status)})`);
  }

  let responseBody: unknown;

  try {
    responseBody = await response.json<unknown>();
  } catch (cause: unknown) {
    if (options.signal?.aborted === true) {
      throw gradebookProviderRequestError({
        providerKind: "canvas",
        operation: "connection",
        cause,
        options,
      });
    }

    responseBody = null;
  }

  return parseCanvasTokenResponse(responseBody);
};
