import type { AppBindings } from "../app";

const CLOUDFLARE_TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";
const CLOUDFLARE_WEB_ANALYTICS_SCRIPT_ORIGIN = "https://static.cloudflareinsights.com";
const CLOUDFLARE_WEB_ANALYTICS_BEACON_ORIGIN = "https://cloudflareinsights.com";
const STRICT_TRANSPORT_SECURITY = "max-age=31536000; includeSubDomains";
const REFERRER_POLICY = "strict-origin-when-cross-origin";

const BASE_CONTENT_SECURITY_POLICY_DIRECTIVES = {
  "default-src": ["'self'"],
  "base-uri": ["'none'"],
  "object-src": ["'none'"],
  "script-src": ["'self'", "'report-sample'", CLOUDFLARE_WEB_ANALYTICS_SCRIPT_ORIGIN],
  "script-src-attr": ["'none'"],
  "style-src": ["'self'"],
  "img-src": ["'self'", "data:", "blob:", "https:", "http:"],
  "font-src": ["'self'"],
  "connect-src": ["'self'", CLOUDFLARE_WEB_ANALYTICS_BEACON_ORIGIN],
  "frame-src": ["'self'"],
  "form-action": ["'self'"],
} as const satisfies Record<string, readonly string[]>;

const TURNSTILE_PATHS = new Set(["/login"]);

const reportingPagePathPattern = /^\/tenants\/[^/]+\/admin\/reporting(?:\/.*)?$/;
const executiveDashboardPagePathPattern = /^\/tenants\/[^/]+\/executive$/;

const pathAllowsTurnstile = (pathname: string): boolean => {
  return TURNSTILE_PATHS.has(pathname);
};

const pathAllowsInlineStyles = (pathname: string): boolean => {
  return (
    reportingPagePathPattern.test(pathname) || executiveDashboardPagePathPattern.test(pathname)
  );
};

export const contentSecurityPolicyForPath = (pathname: string): string => {
  const directives: Record<string, string[]> = Object.fromEntries(
    Object.entries(BASE_CONTENT_SECURITY_POLICY_DIRECTIVES).map(([name, values]) => [
      name,
      [...values],
    ]),
  );

  if (pathAllowsTurnstile(pathname)) {
    directives["script-src"]?.push(CLOUDFLARE_TURNSTILE_ORIGIN);
    directives["connect-src"]?.push(CLOUDFLARE_TURNSTILE_ORIGIN);
    directives["frame-src"]?.push(CLOUDFLARE_TURNSTILE_ORIGIN);
  }

  if (pathAllowsInlineStyles(pathname)) {
    directives["style-src"]?.push("'unsafe-inline'");
  }

  return Object.entries(directives)
    .map(([name, values]) => `${name} ${values.join(" ")}`)
    .join("; ");
};

const setHeaderIfAbsent = (headers: Headers, name: string, value: string): void => {
  if (!headers.has(name)) {
    headers.set(name, value);
  }
};

const strictTransportSecurityEnabled = (env: Pick<AppBindings, "APP_ENV">): boolean => {
  return env.APP_ENV !== "development";
};

export const applySecurityHeaders = (
  headers: Headers,
  env: Pick<AppBindings, "APP_ENV">,
  requestUrl: URL,
): void => {
  setHeaderIfAbsent(
    headers,
    "Content-Security-Policy",
    contentSecurityPolicyForPath(requestUrl.pathname),
  );
  setHeaderIfAbsent(headers, "X-Content-Type-Options", "nosniff");
  setHeaderIfAbsent(headers, "Referrer-Policy", REFERRER_POLICY);

  if (strictTransportSecurityEnabled(env)) {
    setHeaderIfAbsent(headers, "Strict-Transport-Security", STRICT_TRANSPORT_SECURITY);
  }
};
