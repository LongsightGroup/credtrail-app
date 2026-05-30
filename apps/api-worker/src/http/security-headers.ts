import type { AppBindings } from "../app";

const CLOUDFLARE_TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";
const STRICT_TRANSPORT_SECURITY = "max-age=31536000; includeSubDomains";

const contentSecurityPolicyDirectives = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  `script-src 'self' 'report-sample' ${CLOUDFLARE_TURNSTILE_ORIGIN}`,
  "script-src-attr 'none'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https: http:",
  "font-src 'self'",
  `connect-src 'self' ${CLOUDFLARE_TURNSTILE_ORIGIN}`,
  `frame-src 'self' ${CLOUDFLARE_TURNSTILE_ORIGIN}`,
  "form-action 'self'",
] as const;

export const CONTENT_SECURITY_POLICY = contentSecurityPolicyDirectives.join("; ");

const setHeaderIfAbsent = (headers: Headers, name: string, value: string): void => {
  if (!headers.has(name)) {
    headers.set(name, value);
  }
};

const strictTransportSecurityEnabled = (env: Pick<AppBindings, "APP_ENV">): boolean => {
  return env.APP_ENV !== "development";
};

export const applySecurityHeaders = (headers: Headers, env: Pick<AppBindings, "APP_ENV">): void => {
  setHeaderIfAbsent(headers, "Content-Security-Policy", CONTENT_SECURITY_POLICY);
  setHeaderIfAbsent(headers, "X-Content-Type-Options", "nosniff");

  if (strictTransportSecurityEnabled(env)) {
    setHeaderIfAbsent(headers, "Strict-Transport-Security", STRICT_TRANSPORT_SECURITY);
  }
};
