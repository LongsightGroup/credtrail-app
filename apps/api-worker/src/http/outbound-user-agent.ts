/** Identifies server-initiated CredTrail HTTP requests to upstream services. */
export const CREDTRAIL_OUTBOUND_USER_AGENT = "CredTrail/1.0 (+https://credtrail.org)";

/**
 * Adds CredTrail's identifying header to a server-initiated HTTP request.
 *
 * The caller may provide a more specific value when an upstream service requires one.
 */
export const withCredTrailUserAgent = (headers?: HeadersInit): Headers => {
  const outboundHeaders = new Headers(headers);

  if (!outboundHeaders.has("user-agent")) {
    outboundHeaders.set("user-agent", CREDTRAIL_OUTBOUND_USER_AGENT);
  }

  return outboundHeaders;
};
