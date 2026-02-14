interface LinkedInAddToProfileInput {
  badgeName: string;
  issuerName: string;
  issuedAtIso: string;
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

export const escapeHtml = (value: string): string => {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
};

export const formatIsoTimestamp = (timestampIso: string): string => {
  const timestampMs = Date.parse(timestampIso);

  if (!Number.isFinite(timestampMs)) {
    return timestampIso;
  }

  return new Intl.DateTimeFormat('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(timestampMs));
};

export const linkedInAddToProfileUrl = (input: LinkedInAddToProfileInput): string => {
  const linkedInUrl = new URL('https://www.linkedin.com/profile/add');
  linkedInUrl.searchParams.set('startTask', 'CERTIFICATION_NAME');
  linkedInUrl.searchParams.set('name', input.badgeName);
  linkedInUrl.searchParams.set('certUrl', input.credentialUrl);

  const credentialId = input.credentialId.trim();

  if (credentialId.length > 0) {
    linkedInUrl.searchParams.set('certId', credentialId);
  }

  const issuerName = input.issuerName.trim();

  if (issuerName.length > 0 && issuerName !== 'Unknown issuer') {
    linkedInUrl.searchParams.set('organizationName', issuerName);
  }

  const issuedDate = linkedInIssuedDateFromIso(input.issuedAtIso);

  if (issuedDate !== null) {
    linkedInUrl.searchParams.set('issueYear', issuedDate.issueYear);
    linkedInUrl.searchParams.set('issueMonth', issuedDate.issueMonth);
  }

  return linkedInUrl.toString();
};
