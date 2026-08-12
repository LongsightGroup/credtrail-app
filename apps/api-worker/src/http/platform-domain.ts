/** Parses the configured public host used by issuer identities and request routing. */
export const canonicalPlatformDomain = (configuredDomain: string): string => {
  const value = configuredDomain.trim();

  if (value.length === 0) {
    throw new Error("PLATFORM_DOMAIN must be configured");
  }

  if (/[/?#@:]/u.test(value)) {
    throw new Error("PLATFORM_DOMAIN must be a hostname without a scheme, path, or port");
  }

  let url: URL;

  try {
    url = new URL(`https://${value}`);
  } catch {
    throw new Error("PLATFORM_DOMAIN must be a valid hostname");
  }

  if (url.hostname.length === 0 || url.pathname !== "/" || url.search !== "" || url.hash !== "") {
    throw new Error("PLATFORM_DOMAIN must be a valid hostname");
  }

  const hostname = url.hostname.toLowerCase();
  const labels = hostname.split(".");

  if (
    hostname.length > 253 ||
    labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))
  ) {
    throw new Error("PLATFORM_DOMAIN must be a valid hostname");
  }

  return hostname;
};
