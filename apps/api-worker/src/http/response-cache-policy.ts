const hasExplicitPublicCachePolicy = (responseHeaders: Headers): boolean => {
  const cacheControl = responseHeaders.get("cache-control");

  if (cacheControl === null) {
    return false;
  }

  return cacheControl
    .split(",")
    .map((directive) => directive.trim().toLowerCase())
    .includes("public");
};

/** Defaults responses to private storage while preserving deliberate public cache policies. */
export const applyResponseCachePolicy = (responseHeaders: Headers): void => {
  if (responseHeaders.has("set-cookie")) {
    responseHeaders.set("Cache-Control", "no-store");
    return;
  }

  if (hasExplicitPublicCachePolicy(responseHeaders)) {
    return;
  }

  responseHeaders.set("Cache-Control", "no-store");
};
