import { z } from "zod";
import { withCredTrailUserAgent } from "../http/outbound-user-agent";

const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const DEFAULT_TURNSTILE_TIMEOUT_MS = 2_500;

const turnstileSiteverifyResponseSchema = z.object({
  success: z.boolean(),
});

/** Values required to verify one Cloudflare Turnstile challenge token. */
export interface VerifyTurnstileTokenInput {
  readonly secretKey?: string | undefined;
  readonly token?: string | undefined;
  readonly remoteIp?: string | undefined;
  readonly idempotencyKey: string;
}

/** Cancellation options for one Turnstile verification request. */
export interface VerifyTurnstileTokenOptions {
  readonly signal?: AbortSignal;
}

/** Narrow capability used by authentication routes to verify Turnstile tokens. */
export interface TurnstileVerifier {
  verify(input: VerifyTurnstileTokenInput, options?: VerifyTurnstileTokenOptions): Promise<boolean>;
}

/** Returns whether a non-empty Turnstile secret is configured. */
export const turnstileConfigured = (secretKey?: string): boolean => {
  return secretKey !== undefined && secretKey.trim().length > 0;
};

/** Creates a bounded Turnstile verifier around an injected HTTP request function. */
export const createTurnstileVerifier = (input: {
  readonly fetchRequest: (url: string, init: RequestInit) => Promise<Response>;
  readonly timeoutMs?: number;
}): TurnstileVerifier => {
  const timeoutMs = input.timeoutMs ?? DEFAULT_TURNSTILE_TIMEOUT_MS;

  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error("Turnstile request timeout must be a positive integer");
  }

  return {
    verify: async (verificationInput, options = {}) => {
      const secret = verificationInput.secretKey?.trim();
      const token = verificationInput.token?.trim();

      if (
        secret === undefined ||
        secret.length === 0 ||
        token === undefined ||
        token.length === 0
      ) {
        return false;
      }

      const timeoutController = new AbortController();
      const timeoutHandle = setTimeout(() => timeoutController.abort(), timeoutMs);
      const signal =
        options.signal === undefined
          ? timeoutController.signal
          : AbortSignal.any([options.signal, timeoutController.signal]);

      try {
        const response = await input.fetchRequest(TURNSTILE_SITEVERIFY_URL, {
          method: "POST",
          headers: withCredTrailUserAgent({
            "content-type": "application/json",
          }),
          body: JSON.stringify({
            secret,
            response: token,
            idempotency_key: verificationInput.idempotencyKey,
            ...(verificationInput.remoteIp === undefined || verificationInput.remoteIp.length === 0
              ? {}
              : { remoteip: verificationInput.remoteIp }),
          }),
          signal,
        });

        if (!response.ok) {
          return false;
        }

        const responseBody: unknown = await response.json();
        const parsedResponse = turnstileSiteverifyResponseSchema.safeParse(responseBody);
        return parsedResponse.success && parsedResponse.data.success;
      } catch {
        return false;
      } finally {
        clearTimeout(timeoutHandle);
      }
    },
  };
};
