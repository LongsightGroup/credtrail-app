/** A user-facing outcome that the login page can present. */
export type LoginReason =
  | "auth_required"
  | "break_glass_unavailable"
  | "google_failed"
  | "google_unavailable"
  | "signed_out"
  | "sso_failed"
  | "sso_required"
  | "sso_unavailable";

/** Parses an untrusted login reason query value into the supported finite contract. */
export const parseLoginReason = (value: string | undefined): LoginReason | undefined => {
  switch (value?.trim()) {
    case "auth_required":
      return "auth_required";
    case "break_glass_unavailable":
      return "break_glass_unavailable";
    case "google_failed":
      return "google_failed";
    case "google_unavailable":
      return "google_unavailable";
    case "signed_out":
      return "signed_out";
    case "sso_failed":
      return "sso_failed";
    case "sso_required":
      return "sso_required";
    case "sso_unavailable":
      return "sso_unavailable";
    default:
      return undefined;
  }
};

/** Builds the canonical relative login URL with encoded, non-empty query parameters. */
export const buildLoginPath = (
  input: {
    readonly tenantId?: string | undefined;
    readonly nextPath?: string | undefined;
    readonly reason?: LoginReason | undefined;
  } = {},
): string => {
  const url = new URL("/login", "https://credtrail.local");
  const tenantId = input.tenantId?.trim();
  const nextPath = input.nextPath?.trim();

  if (tenantId !== undefined && tenantId.length > 0) {
    url.searchParams.set("tenantId", tenantId);
  }

  if (nextPath !== undefined && nextPath.length > 0) {
    url.searchParams.set("next", nextPath);
  }

  if (input.reason !== undefined) {
    url.searchParams.set("reason", input.reason);
  }

  return `${url.pathname}${url.search}`;
};
