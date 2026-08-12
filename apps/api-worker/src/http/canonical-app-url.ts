/** Parses the one configured public application origin used in externally visible URLs. */
export const canonicalAppOrigin = (configuredOrigin: string): string => {
  const value = configuredOrigin.trim();

  if (value.length === 0) {
    throw new Error("PUBLIC_APP_ORIGIN must be configured");
  }

  let origin: URL;

  try {
    origin = new URL(value);
  } catch {
    throw new Error("PUBLIC_APP_ORIGIN must be an absolute HTTP or HTTPS origin");
  }

  if (
    (origin.protocol !== "https:" && origin.protocol !== "http:") ||
    origin.username.length > 0 ||
    origin.password.length > 0 ||
    origin.pathname !== "/" ||
    origin.search.length > 0 ||
    origin.hash.length > 0
  ) {
    throw new Error("PUBLIC_APP_ORIGIN must be an absolute HTTP or HTTPS origin");
  }

  if (
    origin.protocol === "http:" &&
    origin.hostname !== "localhost" &&
    origin.hostname !== "127.0.0.1"
  ) {
    throw new Error("PUBLIC_APP_ORIGIN may use HTTP only for local development");
  }

  return origin.origin;
};

/** Builds an externally visible application URL without consulting the request host. */
export const canonicalAppUrl = (configuredOrigin: string, path: string): string => {
  if (!path.startsWith("/") || path.startsWith("//")) {
    throw new Error("Canonical application paths must be root-relative");
  }

  const origin = canonicalAppOrigin(configuredOrigin);
  const url = new URL(path, origin);

  if (url.origin !== origin) {
    throw new Error("Canonical application paths must remain on PUBLIC_APP_ORIGIN");
  }

  return url.toString();
};

/** Rebuilds an incoming application URL on the configured public origin. */
export const canonicalAppRequestUrl = (configuredOrigin: string, requestUrl: string): string => {
  const incomingUrl = new URL(requestUrl);
  const canonicalUrl = new URL(canonicalAppOrigin(configuredOrigin));
  canonicalUrl.pathname = incomingUrl.pathname;
  canonicalUrl.search = incomingUrl.search;
  return canonicalUrl.toString();
};
