const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

interface TurnstileSiteverifyResponse {
  success?: boolean;
  challenge_ts?: string;
  hostname?: string;
  "error-codes"?: string[];
  action?: string;
  cdata?: string;
}

export interface VerifyTurnstileTokenInput {
  secretKey?: string | undefined;
  token?: string | undefined;
  remoteIp?: string | undefined;
  idempotencyKey: string;
}

export const turnstileConfigured = (secretKey?: string): boolean => {
  return secretKey !== undefined && secretKey.trim().length > 0;
};

export const verifyTurnstileToken = async (input: VerifyTurnstileTokenInput): Promise<boolean> => {
  const secret = input.secretKey?.trim();
  const token = input.token?.trim();

  if (secret === undefined || secret.length === 0 || token === undefined || token.length === 0) {
    return false;
  }

  const response = await fetch(TURNSTILE_SITEVERIFY_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      secret,
      response: token,
      idempotency_key: input.idempotencyKey,
      ...(input.remoteIp === undefined || input.remoteIp.length === 0
        ? {}
        : { remoteip: input.remoteIp }),
    }),
  });

  if (!response.ok) {
    return false;
  }

  const result = (await response.json()) as TurnstileSiteverifyResponse;
  return result.success === true;
};
