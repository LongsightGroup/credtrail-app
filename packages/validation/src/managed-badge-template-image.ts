/** The immutable CredTrail asset addressed by one managed badge-artwork URL. */
export interface ManagedBadgeTemplateImageReference {
  readonly tenantId: string;
  readonly badgeTemplateId: string;
  readonly assetId: string;
  readonly path: string;
}

interface ManagedBadgeTemplateImageIdentity {
  readonly tenantId: string;
  readonly badgeTemplateId: string;
  readonly assetId: string;
}

const nonEmptyPathSegment = (value: string): string | null => {
  try {
    const decoded = decodeURIComponent(value).trim();
    return decoded.length === 0 || decoded.includes("/") ? null : decoded;
  } catch {
    return null;
  }
};

/** Builds the stable public path for one immutable CredTrail badge-artwork object. */
export const managedBadgeTemplateImagePath = (
  identity: ManagedBadgeTemplateImageIdentity,
): string => {
  return `/badges/assets/${encodeURIComponent(identity.tenantId)}/${encodeURIComponent(
    identity.badgeTemplateId,
  )}/${encodeURIComponent(identity.assetId)}`;
};

/**
 * Resolves a URL only when it addresses the expected template's managed immutable artwork route.
 * The URL host is deliberately ignored; callers rebuild it from the configured public domain.
 */
export const resolveManagedBadgeTemplateImageReference = (input: {
  readonly imageUri: string;
  readonly tenantId: string;
  readonly badgeTemplateId: string;
}): ManagedBadgeTemplateImageReference | null => {
  let url: URL;

  try {
    url = new URL(input.imageUri);
  } catch {
    return null;
  }

  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    return null;
  }

  const segments = url.pathname.split("/");

  if (
    segments.length !== 6 ||
    segments[0] !== "" ||
    segments[1] !== "badges" ||
    segments[2] !== "assets"
  ) {
    return null;
  }

  const tenantId = nonEmptyPathSegment(segments[3] ?? "");
  const badgeTemplateId = nonEmptyPathSegment(segments[4] ?? "");
  const assetId = nonEmptyPathSegment(segments[5] ?? "");

  if (
    tenantId === null ||
    badgeTemplateId === null ||
    assetId === null ||
    tenantId !== input.tenantId ||
    badgeTemplateId !== input.badgeTemplateId
  ) {
    return null;
  }

  return {
    tenantId,
    badgeTemplateId,
    assetId,
    path: managedBadgeTemplateImagePath({ tenantId, badgeTemplateId, assetId }),
  };
};

/** Returns whether a template points at artwork in its own managed immutable namespace. */
export const usesManagedBadgeTemplateImageReference = (input: {
  readonly tenantId: string;
  readonly badgeTemplateId: string;
  readonly imageUri: string | null;
}): boolean => {
  return (
    input.imageUri !== null &&
    resolveManagedBadgeTemplateImageReference({
      imageUri: input.imageUri,
      tenantId: input.tenantId,
      badgeTemplateId: input.badgeTemplateId,
    }) !== null
  );
};
