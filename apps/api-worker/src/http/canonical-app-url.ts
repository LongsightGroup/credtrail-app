/**
 * Builds an externally visible application URL from the configured public platform domain.
 * Request hosts are intentionally excluded because they may be private Worker addresses.
 */
export const canonicalAppUrl = (platformDomain: string, path: string): string => {
  const domain = platformDomain.trim();

  if (
    domain.length === 0 ||
    domain.includes("/") ||
    domain.includes("@") ||
    domain.includes("?") ||
    domain.includes("#")
  ) {
    throw new Error("PLATFORM_DOMAIN must be a non-empty public hostname");
  }

  return new URL(path, `https://${domain}`).toString();
};
