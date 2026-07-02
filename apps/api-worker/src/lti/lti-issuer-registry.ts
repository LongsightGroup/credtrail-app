import { normalizeLtiIssuer } from "@credtrail/db";

export interface LtiIssuerRegistryEntry {
  authorizationEndpoint: string;
  clientId: string;
  tenantId: string;
  platformJwksEndpoint?: string;
  tokenEndpoint?: string;
}

export type LtiIssuerRegistry = Record<string, LtiIssuerRegistryEntry>;

export { normalizeLtiIssuer };

const ltiIssuerRegistryEntriesByIssuer = (
  registry: LtiIssuerRegistry,
  issuer: string,
): ReadonlyArray<{ readonly issuer: string; readonly entry: LtiIssuerRegistryEntry }> => {
  const normalizedIssuer = normalizeLtiIssuer(issuer);
  const matches: Array<{ readonly issuer: string; readonly entry: LtiIssuerRegistryEntry }> = [];

  for (const [candidateIssuer, entry] of Object.entries(registry)) {
    const normalizedCandidateIssuer = normalizeLtiIssuer(candidateIssuer);

    if (normalizedCandidateIssuer === normalizedIssuer) {
      matches.push({
        issuer: normalizedCandidateIssuer,
        entry,
      });
    }
  }

  return matches;
};

/**
 * Finds an LTI issuer registry entry by normalized issuer and client identifier.
 */
export const findLtiIssuerRegistryEntry = (
  registry: LtiIssuerRegistry,
  issuer: string,
  clientId: string,
): { readonly issuer: string; readonly entry: LtiIssuerRegistryEntry } | null => {
  const issuerMatches = ltiIssuerRegistryEntriesByIssuer(registry, issuer);

  for (const issuerMatch of issuerMatches) {
    if (issuerMatch.entry.clientId === clientId) {
      return issuerMatch;
    }
  }

  return null;
};

export type LtiLoginIssuerResolution =
  | {
      readonly status: "resolved";
      readonly issuer: string;
      readonly entry: LtiIssuerRegistryEntry;
      readonly clientId: string;
    }
  | {
      readonly status: "unknown_issuer";
      readonly issuer: string;
    }
  | {
      readonly status: "client_id_mismatch";
      readonly issuer: string;
      readonly entry: LtiIssuerRegistryEntry;
      readonly requestedClientId: string;
    };

/**
 * Resolves the registered issuer for an OIDC login initiation.
 *
 * LTI OIDC login may omit `client_id`; when omitted, CredTrail uses the
 * issuer's configured client identifier. When `client_id` is present, it must
 * exactly match the configured registration for the normalized issuer.
 */
export const resolveLtiLoginIssuer = (
  registry: LtiIssuerRegistry,
  loginRequest: {
    readonly iss: string;
    readonly client_id?: string | undefined;
  },
): LtiLoginIssuerResolution => {
  const issuerMatches = ltiIssuerRegistryEntriesByIssuer(registry, loginRequest.iss);
  const [issuerMatch] = issuerMatches;

  if (issuerMatch === undefined) {
    return {
      status: "unknown_issuer",
      issuer: normalizeLtiIssuer(loginRequest.iss),
    };
  }

  if (loginRequest.client_id !== undefined) {
    const clientMatch = issuerMatches.find(
      (candidate) => candidate.entry.clientId === loginRequest.client_id,
    );

    if (clientMatch !== undefined) {
      return {
        status: "resolved",
        issuer: clientMatch.issuer,
        entry: clientMatch.entry,
        clientId: clientMatch.entry.clientId,
      };
    }

    return {
      status: "client_id_mismatch",
      issuer: issuerMatch.issuer,
      entry: issuerMatch.entry,
      requestedClientId: loginRequest.client_id,
    };
  }

  return {
    status: "resolved",
    issuer: issuerMatch.issuer,
    entry: issuerMatch.entry,
    clientId: issuerMatch.entry.clientId,
  };
};
