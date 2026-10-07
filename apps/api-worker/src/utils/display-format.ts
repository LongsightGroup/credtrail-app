import type { LinkedInOrganizationId } from "@credtrail/validation";

interface LinkedInAddToProfileInput {
  organizationId: LinkedInOrganizationId | null;
  badgeName: string;
  issuerName: string;
  issuedAtIso: string;
  /** Expiry of the credential, when it has one: LinkedIn shows it as the certification's expiration date. */
  validUntilIso?: string | null | undefined;
  credentialUrl: string;
  credentialId: string;
}

const linkedInIssuedDateFromIso = (
  issuedAtIso: string,
): {
  issueYear: string;
  issueMonth: string;
} | null => {
  const timestampMs = Date.parse(issuedAtIso);

  if (!Number.isFinite(timestampMs)) {
    return null;
  }

  const issuedAtDate = new Date(timestampMs);
  return {
    issueYear: String(issuedAtDate.getUTCFullYear()),
    issueMonth: String(issuedAtDate.getUTCMonth() + 1),
  };
};

export const formatIsoTimestamp = (timestampIso: string): string => {
  const timestampMs = Date.parse(timestampIso);

  if (!Number.isFinite(timestampMs)) {
    return timestampIso;
  }

  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(timestampMs));
};

export const linkedInAddToProfileUrl = (input: LinkedInAddToProfileInput): string => {
  const linkedInUrl = new URL("https://www.linkedin.com/profile/add");
  linkedInUrl.searchParams.set("startTask", "CERTIFICATION_NAME");
  linkedInUrl.searchParams.set("name", input.badgeName);
  linkedInUrl.searchParams.set("certUrl", input.credentialUrl);

  const credentialId = input.credentialId.trim();

  if (credentialId.length > 0) {
    linkedInUrl.searchParams.set("certId", credentialId);
  }

  const issuerName = input.issuerName.trim();

  if (input.organizationId !== null) {
    linkedInUrl.searchParams.set("organizationId", input.organizationId);
  } else if (issuerName.length > 0 && issuerName !== "Unknown issuer") {
    linkedInUrl.searchParams.set("organizationName", issuerName);
  }

  const issuedDate = linkedInIssuedDateFromIso(input.issuedAtIso);

  if (issuedDate !== null) {
    linkedInUrl.searchParams.set("issueYear", issuedDate.issueYear);
    linkedInUrl.searchParams.set("issueMonth", issuedDate.issueMonth);
  }
  const expirationDate =
    input.validUntilIso === undefined || input.validUntilIso === null
      ? null
      : linkedInIssuedDateFromIso(input.validUntilIso);
  if (expirationDate !== null) {
    linkedInUrl.searchParams.set("expirationYear", expirationDate.issueYear);
    linkedInUrl.searchParams.set("expirationMonth", expirationDate.issueMonth);
  }

  return linkedInUrl.toString();
};
