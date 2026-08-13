import type { PublicBadgeViewModel } from "../badges/public-badge-model";

export const walletCredentialOfferPayload = (
  requestUrl: string,
  model: PublicBadgeViewModel,
  options?: {
    preAuthorizedCode?: string | undefined;
    offerExpiresAt?: string | undefined;
    tokenEndpointPath?: string | undefined;
    credentialEndpointPath?: string | undefined;
  },
): Record<string, unknown> => {
  const assertion = model.assertion;
  const requestBaseUrl = new URL(requestUrl);
  const publicBadgePath = `/badges/${encodeURIComponent(assertion.publicId)}`;
  const verificationPath = `${publicBadgePath}/verification`;
  const credentialJsonldPath = `${publicBadgePath}/jsonld`;
  const credentialDownloadPath = `${publicBadgePath}/download`;
  const preAuthorizedCode = options?.preAuthorizedCode ?? `public-badge:${assertion.publicId}`;
  const tokenEndpointPath = options?.tokenEndpointPath ?? "/credentials/v1/token";
  const credentialEndpointPath = options?.credentialEndpointPath ?? "/credentials/v1/credentials";

  return {
    credential_issuer: requestBaseUrl.origin,
    credential_endpoint: new URL(credentialEndpointPath, requestBaseUrl).toString(),
    credential_configuration_ids: ["OpenBadgeCredential"],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": preAuthorizedCode,
        tx_code_required: false,
      },
    },
    credentials: [
      {
        format: "ldp_vc",
        types: ["VerifiableCredential", "OpenBadgeCredential"],
      },
    ],
    x_credtrail: {
      token_endpoint: new URL(tokenEndpointPath, requestBaseUrl).toString(),
      credential_endpoint: new URL(credentialEndpointPath, requestBaseUrl).toString(),
      public_badge_url: new URL(publicBadgePath, requestBaseUrl).toString(),
      verification_url: new URL(verificationPath, requestBaseUrl).toString(),
      credential_jsonld_url: new URL(credentialJsonldPath, requestBaseUrl).toString(),
      credential_download_url: new URL(credentialDownloadPath, requestBaseUrl).toString(),
      ...(options?.offerExpiresAt === undefined
        ? {}
        : {
            offer_expires_at: options.offerExpiresAt,
          }),
    },
  };
};
